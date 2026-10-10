"""Synthetic bounded preparation headers."""
from dataclasses import FrozenInstanceError, fields
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from uuid import UUID

from tests.test_storage import _module, _disk, _Db


class ListingApiTests(unittest.TestCase):
    def setUp(self):
        self.s = _module()
        runtime = os.environ.get("WP01_PREPARATION_TEST_RUNTIME")
        self.assertTrue(runtime, "Registered runtime required")
        owned = tempfile.TemporaryDirectory(prefix="listing-", dir=runtime)
        self.addCleanup(owned.cleanup)
        self.root = Path(owned.name) / "store"
        self.a = self.s.create_package(self.root, "A", "Synthetic tender")
        self.utc = "2026-10-10T00:00:00+00:00"
        payload = dict(payload_version=1, checklist_row=dict(
            name="Synthetic row", status="NEEDS_REVIEW",
            next_action="Review source", submission_summary="Unconfirmed"),
            doc_refs=[], source_spans=[])
        self.raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        self.sha = hashlib.sha256(self.raw.encode()).hexdigest()

    def db(self):
        return sqlite3.connect(self.root / "app.sqlite3", factory=_Db)

    def upgrade(self):
        self.assertEqual(self.s.upgrade_preparation_store(self.root), 2)

    def seed(self, n, owner=None, stamp=None):
        pid = str(UUID(int=n))
        with self.db() as db:
            db.execute("INSERT INTO preparations VALUES(?,?,?,?,?,?)",
                       (pid, (owner or self.a).package_uuid, 1,
            stamp or self.utc, self.raw, self.sha))
        return pid

    def listing(self, package="A"):
        self.assertTrue(callable(getattr(self.s, "list_preparations", None)),
            "Listing API absent")
        return self.s.list_preparations(self.root, package)

    def refusal(self, code, package="A"):
        before = _disk(self.root)
        with self.assertRaises(self.s.StorageError) as failure:
            self.listing(package)
        self.assertEqual(failure.exception.code, code, failure.exception)
        self.assertEqual(_disk(self.root), before)

    def test_empty_v2(self):
        self.upgrade()
        before = _disk(self.root)
        self.assertEqual(self.listing(), ())
        self.assertEqual(_disk(self.root), before)

    def test_owner_isolation(self):
        other = self.s.create_package(self.root, "B", "Other synthetic tender")
        self.upgrade()
        first = self.seed(2)
        second = self.seed(1, other)
        self.assertEqual(tuple(x.preparation_id for x in self.listing()), (first,))
        self.assertEqual(tuple(x.preparation_id for x in self.listing("B")), (second,))
        with self.db() as db:
            db.execute("UPDATE preparations SET created_utc=? WHERE package_uuid=?",
                       ("not-a-time", other.package_uuid))
        self.assertEqual(tuple(x.preparation_id for x in self.listing()), (first,))
        self.refusal("INTEGRITY_HOLD", "B")

    def test_stable_uuid_order(self):
        self.upgrade()
        for n, day in ((3, 1), (1, 3), (2, 2)):
            self.seed(n, stamp="2026-10-%02dT00:00:00+00:00" % day)
        rows = self.listing()
        self.assertIsInstance(rows, tuple)
        self.assertEqual([x.preparation_id for x in rows],
            [str(UUID(int=x)) for x in (1, 2, 3)])
        self.assertEqual([x.created_utc for x in rows],
            ["2026-10-%02dT00:00:00+00:00" % x for x in (3, 2, 1)])
        self.assertEqual([x.payload_version for x in rows], [1, 1, 1])
        self.assertEqual([x.payload_sha256 for x in rows], [self.sha] * 3)
        self.assertEqual([x.name for x in fields(self.s.PreparationSummary)],
            ["preparation_id", "created_utc", "payload_version",
            "payload_sha256"])
        self.assertTrue(all(isinstance(x, self.s.PreparationSummary) for x in rows))
        with self.assertRaises(FrozenInstanceError):
            rows[0].created_utc = "changed"
        self.assertEqual(self.listing(), rows)

    def test_v1_refusal_no_upgrade(self):
        self.refusal("CONFIG_ERROR")
        with self.db() as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertNotIn("preparations",
            {x[0] for x in db.execute("SELECT name FROM sqlite_master")})

    def test_readonly_no_schema_change(self):
        self.upgrade()
        pid = self.seed(1)
        with self.db() as db:
            db.execute("PRAGMA ignore_check_constraints=ON")
            db.execute("UPDATE preparations SET payload_json=?", (b"invalid" * 200000,))
            schema = db.execute("SELECT * FROM sqlite_master ORDER BY name").fetchall()
        before = _disk(self.root)
        queries = []
        execute = self.s._Database.execute
        def observed(db, sql, *args):
            query = sql.lower()
            if "from preparations" in query:
                queries.append(query)
                self.assertNotIn("payload_json", query.partition("from preparations")[0])
            return execute(db, sql, *args)
        with patch.object(self.s._Database, "execute", observed), patch.object(
                self.s, "_preparation_row", side_effect=AssertionError("Payload read")), patch.object(
                self.s, "_preparation_decode", side_effect=AssertionError("Payload decode")), patch.object(
                self.s, "_view", side_effect=AssertionError("History materialized")):
            rows = self.listing()
        self.assertTrue(queries, "No header query")
        self.assertEqual([(x.preparation_id, x.created_utc, x.payload_version,
            x.payload_sha256) for x in rows],
            [(pid, self.utc, 1, self.sha)])
        self.assertEqual(_disk(self.root), before)
        with self.db() as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 2)
            self.assertEqual(db.execute("SELECT * FROM sqlite_master ORDER BY name").fetchall(),
            schema)

    def test_bounded_overflow_no_truncation(self):
        self.upgrade()
        self.assertEqual(self.s.MAX_ENTRIES, 4096)
        with self.db() as db:
            db.executemany("INSERT INTO preparations VALUES(?,?,?,?,?,?)",
            [(str(UUID(int=n)), self.a.package_uuid, 1,
            self.utc, self.raw, self.sha)
            for n in range(1, 4097)])
        before = _disk(self.root)
        rows = self.listing()
        self.assertEqual(len(rows), 4096)
        self.assertEqual(rows[0].preparation_id, str(UUID(int=1)))
        self.assertEqual(rows[-1].preparation_id, str(UUID(int=4096)))
        self.assertEqual(_disk(self.root), before)
        self.seed(4097)
        self.refusal("STORE_BUDGET_EXCEEDED")

    def test_malformed_header_hold(self):
        self.upgrade()
        pid = self.seed(1)
        cases = [
            ("preparation_id", "x" * 36),
            ("preparation_id", "00000000-0000-0000-0000-00000000000A"),
            ("preparation_id", "x" * 65536),
            ("created_utc", "not-time"),
            ("created_utc", "2026-10-10T00:00:00"),
            ("created_utc", "2026-10-10T01:00:00+01:00"),
            ("created_utc", "2026-10-10T00:00:00Z"),
            ("created_utc", "x" * 65536),
            ("payload_version", 2),
            ("payload_version", b"x" * 65536),
            ("payload_sha256", "g" * 64),
            ("payload_sha256", "a" * 63),
            ("payload_sha256", "a" * 65536)]
        for field, value in cases:
            with self.subTest(field=field, value_type=type(value).__name__,
            size=len(value) if not isinstance(value, int) else value):
                with self.db() as db:
                    db.execute("PRAGMA ignore_check_constraints=ON")
                    db.execute("UPDATE preparations SET " + field + "=?", (value,))
                self.refusal("INTEGRITY_HOLD")
                with self.db() as db:
                    db.execute("DELETE FROM preparations")
                self.assertEqual(self.seed(1), pid)
