"""Synthetic WP-V1 persistence regressions; no real hospital or legal acceptance."""
from contextlib import ExitStack
from copy import deepcopy
import ctypes
from dataclasses import FrozenInstanceError
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from tests.test_storage import _module, _disk, _Db, LIMITS, FIXTURES


class TestPreparationStore(unittest.TestCase):
    def setUp(self):
        self.s = _module()
        for name in ("upgrade_preparation_store", "save_preparation", "open_preparation"):
            self.assertTrue(callable(getattr(self.s, name, None)), "Approved preparation API absent: " + name)
        runtime = os.environ.get("WP01_PREPARATION_TEST_RUNTIME")
        self.assertTrue(runtime, "Register WP01_PREPARATION_TEST_RUNTIME before tests")
        self.temp = tempfile.TemporaryDirectory(prefix="prep-", dir=runtime)
        self.addCleanup(self.temp.cleanup)
        self.case = Path(self.temp.name)
        self.store = self.case / "store"
        self.inputs = self.case / "inputs"
        self.inputs.mkdir()
        self.s.create_package(self.store, "A", "Synthetic tender")
        self.preparation_id = str(uuid4())

    def db(self):
        return sqlite3.connect(self.store / "app.sqlite3", factory=_Db)

    def imported(self, package="A", limits=None):
        source = self.inputs / (package + ".pdf")
        source.write_bytes((FIXTURES / "text_unicode.pdf").read_bytes())
        result = self.s.import_pdf(self.store, package, source, limits or LIMITS())
        self.assertEqual(result.outcome, "IMPORTED", result.diagnostics)
        return result.record

    def payload(self, records=()):
        refs = [dict(package_id=r.package_id, package_uuid=r.package_uuid, file_id=r.file_id,
                     file_version=r.version, sha256=r.sha256, byte_count=r.byte_count,
                     managed_relative_path=r.managed_relative_path) for r in records]
        spans = []
        if records:
            page = records[0].report.pages[0]
            spans = [dict(doc_ref=0, page=page.page_index + 1, locator=page.locator,
                          start=0, end=min(12, len(page.text)), text=page.text[:12])]
        return dict(payload_version=1, checklist_row=dict(name="Synthetic review row",
                    status="NEEDS_REVIEW", next_action="Confirm source and facts",
                    submission_summary="Unconfirmed synthetic fixture"),
                    doc_refs=refs, source_spans=spans)

    def boot(self, qi=False):
        record = self.imported()
        records = [record]
        if qi:
            self.s.create_package(self.store, "QI", "Synthetic separate company owner")
            records.append(self.imported("QI"))
        self.assertEqual(self.s.upgrade_preparation_store(self.store), 2)
        return records, self.payload(records)

    def save(self, payload):
        return self.s.save_preparation(self.store, "A", self.preparation_id, payload)

    def reopen(self):
        return self.s.open_preparation(self.store, "A", self.preparation_id)

    def rejected_unchanged(self, operation, code=None):
        before = _disk(self.store)
        with self.assertRaises(self.s.StorageError) as failure:
            operation()
        if code:
            self.assertEqual(failure.exception.code, code, failure.exception)
        self.assertEqual(_disk(self.store), before, "Refusal must preserve snapshot/store bytes")
        return failure.exception

    def journal(self, package="A", phase="RESERVED", diagnostic=""):
        with self.db() as db:
            owner = db.execute("SELECT package_uuid FROM packages WHERE package_id=?", (package,)).fetchone()[0]
            file_id, operation = str(uuid4()), str(uuid4())
            db.execute("INSERT INTO import_journal VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (operation, owner, file_id, "synthetic.pdf", 1, "a" * 64, 1,
                        "packages/" + owner + "/originals/" + file_id + ".pdf",
                        "staging/" + operation + ".part", "null", phase, diagnostic, "now"))
        return operation

    def test_default_store_stays_v1_and_save_requires_explicit_upgrade(self):
        with self.db() as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertNotIn("preparations", {r[0] for r in db.execute("SELECT name FROM sqlite_master")})
        error = self.rejected_unchanged(lambda: self.save(self.payload()), "CONFIG_ERROR")
        self.assertIn("upgrade", str(error).lower())
        self.assertEqual(self.s.list_packages(self.store)[0].package_id, "A")

    def test_upgrade_preserves_history_and_is_idempotent(self):
        record = self.imported()
        raw = (self.store / record.managed_relative_path).read_bytes()
        with self.db() as db:
            before = db.execute("SELECT * FROM files").fetchall()
        self.assertEqual(self.s.upgrade_preparation_store(self.store), 2)
        with self.db() as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 2)
            self.assertEqual(db.execute("SELECT * FROM files").fetchall(), before)
            self.assertEqual({r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")},
                             {"packages", "files", "import_journal", "preparations"})
        frozen = _disk(self.store)
        self.assertEqual(self.s.upgrade_preparation_store(self.store), 2)
        self.assertEqual(_disk(self.store), frozen)
        self.assertEqual((self.store / record.managed_relative_path).read_bytes(), raw)

    def test_upgrade_ddl_and_version_roll_back_together(self):
        original = self.s._Database.execute
        def fail_version(db, sql, *args):
            if sql.strip() == "PRAGMA user_version=2":
                raise sqlite3.OperationalError("synthetic failure after preparations DDL")
            return original(db, sql, *args)
        with patch.object(self.s._Database, "execute", fail_version):
            self.rejected_unchanged(lambda: self.s.upgrade_preparation_store(self.store), "STORE_INVALID")
        with self.db() as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertNotIn("preparations", {r[0] for r in db.execute("SELECT name FROM sqlite_master")})
        self.assertEqual(self.s.upgrade_preparation_store(self.store), 2)

    def test_old_reader_refuses_explicitly_upgraded_store(self):
        self.s.upgrade_preparation_store(self.store)
        old = Path(os.environ["WP01_PREPARATION_BEFORE_STORAGE"])
        script = """import importlib.util,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('legal_tool.previous_storage',sys.argv[1])
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
try:m.list_packages(Path(sys.argv[2]))
except m.StorageError as e:
 assert e.code=='STORE_INVALID' and 'schema' in str(e).lower();print(e.code)
else:raise AssertionError('Old binary adopted upgraded schema')
"""
        before = _disk(self.store)
        result = subprocess.run([sys.executable, "-B", "-c", script, str(old), str(self.store)],
                                cwd=FIXTURES.parents[1], capture_output=True, text=True, timeout=5,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("STORE_INVALID", result.stdout)
        self.assertEqual(_disk(self.store), before)

    def test_foreign_schema_versions_are_not_migrated(self):
        for version in (0, 2, 3, 2147483647):
            with self.subTest(version=version):
                with self.db() as db:
                    db.execute("PRAGMA user_version=" + str(version))
                self.rejected_unchanged(lambda: self.s.upgrade_preparation_store(self.store), "STORE_INVALID")
        with self.db() as db:
            db.execute("PRAGMA user_version=1")

    def test_v1_cannot_adopt_extra_preparation_table(self):
        with self.db() as db:
            db.execute("CREATE TABLE preparations(unapproved TEXT)")
        self.rejected_unchanged(lambda: self.s.upgrade_preparation_store(self.store), "STORE_INVALID")

    def test_v2_schema_requires_columns_constraints_and_active_index(self):
        self.s.upgrade_preparation_store(self.store)
        with self.db() as db:
            schema = dict(db.execute("SELECT name,sql FROM sqlite_master WHERE sql IS NOT NULL"))
        variants = [
            ("preparations", " REFERENCES packages(package_uuid) ON DELETE RESTRICT", ""),
            ("preparations", "ON DELETE RESTRICT", "ON DELETE CASCADE"),
            ("preparations", "preparation_id TEXT PRIMARY KEY", "preparation_id TEXT"),
            ("preparations", "CHECK(length(preparation_id)=36)", ""),
            ("preparations", "CHECK(typeof(payload_version)='integer' AND payload_version=1)", ""),
            ("preparations", "CHECK(length(CAST(payload_json AS BLOB)) BETWEEN 1 AND 65536)", ""),
            ("preparations", "CHECK(length(payload_sha256)=64)", ""),
            ("preparations", "created_utc TEXT NOT NULL", "created_utc TEXT"),
            ("files", "CHECK(typeof(version)='integer' AND version>0)", ""),
            ("one_active_import", "CREATE UNIQUE INDEX", "CREATE INDEX"),
            ("one_active_import", ",'HOLD'", ""),
        ]
        for index, (table, old, new) in enumerate(variants):
            with self.subTest(table=table, constraint=old):
                root = self.case / ("bad-" + str(index)); root.mkdir()
                statements = dict(schema)
                self.assertIn(old, statements[table])
                statements[table] = statements[table].replace(old, new)
                with sqlite3.connect(root / "app.sqlite3", factory=_Db) as db:
                    for sql in statements.values():
                        db.execute(sql)
                    db.execute("PRAGMA user_version=2")
                before = _disk(root)
                with self.assertRaises(self.s.StorageError) as error:
                    self.s.list_packages(root)
                self.assertEqual(error.exception.code, "STORE_INVALID")
                self.assertIn("schema", str(error.exception).lower())
                self.assertEqual(_disk(root), before)

    def test_v1_missing_check_or_trigger_is_not_supported(self):
        with self.db() as db:
            schema = dict(db.execute("SELECT name,sql FROM sqlite_master WHERE sql IS NOT NULL"))
        for index, trigger in enumerate((False, True)):
            root = self.case / ("v1-" + str(index)); root.mkdir()
            with sqlite3.connect(root / "app.sqlite3", factory=_Db) as db:
                for name, sql in schema.items():
                    if not trigger and name == "files":
                        sql = sql.replace("CHECK(typeof(version)='integer' AND version>0)", "")
                    db.execute(sql)
                db.execute("PRAGMA user_version=1")
                if trigger:
                    db.execute("CREATE TRIGGER hidden_write AFTER INSERT ON packages BEGIN DELETE FROM packages; END")
            before = _disk(root)
            with self.assertRaises(self.s.StorageError) as error:
                self.s.upgrade_preparation_store(root)
            self.assertEqual(error.exception.code, "STORE_INVALID")
            self.assertEqual(_disk(root), before)

    def test_upgrade_refuses_active_import_and_relevant_hold(self):
        for phase in ("RESERVED", "STAGED", "RENAMED", "HOLD"):
            operation = self.journal(phase=phase)
            self.rejected_unchanged(lambda: self.s.upgrade_preparation_store(self.store))
            with self.db() as db:
                db.execute("DELETE FROM import_journal WHERE operation_id=?", (operation,))
        record = self.imported()
        (self.store / record.managed_relative_path).unlink()
        self.rejected_unchanged(lambda: self.s.upgrade_preparation_store(self.store), "INTEGRITY_HOLD")

    def test_upgrade_preserves_unclassified_sidecars(self):
        for suffix in ("-journal", "-wal", "-shm"):
            path = self.store / ("app.sqlite3" + suffix)
            path.write_bytes(b"synthetic unclassified sidecar")
            self.rejected_unchanged(lambda: self.s.upgrade_preparation_store(self.store), "RECOVERY_HOLD")
            path.unlink()

    def test_save_reopens_exact_needs_review_without_external_reparse(self):
        records, payload = self.boot()
        result = self.save(payload)
        self.assertEqual(result.package_id, "A")
        self.assertEqual(result.preparation_id, self.preparation_id)
        self.assertEqual(result.payload_version, 1)
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        self.assertEqual(result.payload_sha256, hashlib.sha256(canonical.encode()).hexdigest())
        self.assertEqual(result.payload["checklist_row"]["status"], "NEEDS_REVIEW")
        for source in self.inputs.iterdir():
            source.unlink()
        before = _disk(self.store)
        with patch.object(self.s.worker, "inspect_bounded", side_effect=AssertionError("No reopen reparsing")):
            reopened = self.reopen()
        self.assertEqual(result, reopened)
        self.assertEqual(_disk(self.store), before)

    def test_uuid_retry_uses_stored_timestamp_and_checksum(self):
        _, payload = self.boot()
        saved = self.save(payload)
        before = _disk(self.store)
        reordered = dict(reversed(list(payload.items())))
        with patch.object(self.s, "_now", return_value="must not replace stored timestamp"):
            retry = self.save(reordered)
        self.assertEqual(retry, saved)
        self.assertEqual(_disk(self.store), before)
        with self.db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM preparations").fetchone()[0], 1)

    def test_uuid_conflict_and_cross_package_reuse_reject(self):
        _, payload = self.boot()
        self.save(payload)
        changed = deepcopy(payload); changed["checklist_row"]["next_action"] = "Different content"
        self.rejected_unchanged(lambda: self.save(changed), "PREPARATION_CONFLICT")
        self.s.create_package(self.store, "B", "Other tender")
        self.rejected_unchanged(lambda: self.s.save_preparation(self.store, "B", self.preparation_id, payload),
                                "PREPARATION_CONFLICT")
        self.rejected_unchanged(lambda: self.s.open_preparation(self.store, "B", self.preparation_id),
                                "PREPARATION_NOT_FOUND")

    def test_lost_commit_acknowledgment_retry_is_not_a_second_snapshot(self):
        _, payload = self.boot()
        original = self.s._Database.execute
        def lost_ack(db, sql, *args):
            result = original(db, sql, *args)
            if sql == "COMMIT":
                raise sqlite3.OperationalError("synthetic committed response loss")
            return result
        with patch.object(self.s._Database, "execute", lost_ack):
            with self.assertRaises(self.s.StorageError):
                self.save(payload)
        stored = self.reopen()
        self.assertEqual(self.save(payload), stored)
        with self.db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM preparations").fetchone()[0], 1)

    def test_returned_snapshot_is_deeply_immutable_and_input_is_detached(self):
        _, payload = self.boot()
        saved = self.save(payload)
        with self.assertRaises(FrozenInstanceError):
            saved.created_utc = "changed"
        with self.assertRaises(TypeError):
            saved.payload["checklist_row"]["status"] = "changed"
        with self.assertRaises(TypeError):
            saved.payload["doc_refs"][0]["file_version"] = 7
        with self.assertRaises((AttributeError, TypeError)):
            saved.payload["source_spans"].append({})
        payload["checklist_row"]["name"] = "caller mutation"
        self.assertEqual(self.reopen(), saved)

    def test_multiple_snapshots_preserve_each_history(self):
        _, payload = self.boot()
        first = self.save(payload)
        self.preparation_id = str(uuid4())
        payload["checklist_row"]["next_action"] = "Later independent snapshot"
        second = self.save(payload)
        self.assertNotEqual(first.preparation_id, second.preparation_id)
        self.assertEqual(self.s.open_preparation(self.store, "A", first.preparation_id), first)
        self.assertEqual(self.reopen(), second)

    def test_payload_limits_keys_types_depth_utf8_and_nonfinite(self):
        _, payload = self.boot()
        changes = [
            ("payload_version", True), ("payload_version", 2), ("doc_refs", [payload["doc_refs"][0]] * 9),
            ("source_spans", [payload["source_spans"][0]] * 257),
            ("checklist_row", [payload["checklist_row"]]),
        ]
        for key, value in changes:
            bad = deepcopy(payload); bad[key] = value
            with self.subTest(field=key):
                self.rejected_unchanged(lambda: self.save(bad), "PREPARATION_INVALID")
        for value in ("\ud800", "x" * 65536, float("nan"), float("inf"), float("-inf"), 1, None):
            bad = deepcopy(payload); bad["checklist_row"]["name"] = value
            with self.subTest(kind=type(value).__name__):
                self.rejected_unchanged(lambda: self.save(bad), "PREPARATION_INVALID")
        deep = "leaf"
        for _ in range(20):
            deep = {"x": deep}
        for key, value in [("unexpected", deep), (1, "nonstring key"), ("x" * 129, None)]:
            bad = deepcopy(payload); bad[key] = value
            self.rejected_unchanged(lambda: self.save(bad), "PREPARATION_INVALID")
        bad = deepcopy(payload); bad["checklist_row"]["extra"] = "unapproved"
        self.rejected_unchanged(lambda: self.save(bad), "PREPARATION_INVALID")

    def test_exact_64k_payload_boundary_is_not_silently_truncated(self):
        records, payload = self.boot()
        page = records[0].report.pages[0]
        def canonical(value):
            return json.dumps(value, ensure_ascii=False, sort_keys=True,
                              separators=(",", ":"), allow_nan=False).encode("utf-8")
        # Use exact persisted text; every span and row field remains independently valid.
        fitting = None
        for length in range(1, len(page.text) + 1):
            payload["source_spans"] = [dict(doc_ref=0, page=page.page_index + 1,
                locator=page.locator, start=0, end=length, text=page.text[:length])
                for _ in range(256)]
            if len(canonical(payload)) > 65536:
                break
            fitting = deepcopy(payload)
        self.assertIsNotNone(fitting)
        payload = fitting
        padding = 65536 - len(canonical(payload))
        self.assertGreaterEqual(padding, 0)
        payload["checklist_row"]["next_action"] += "x" * padding
        larger = deepcopy(payload)
        larger["checklist_row"]["next_action"] += "x"
        for value in (payload, larger):
            for field, limit in (("name", 200), ("status", 32),
                                 ("next_action", 2048), ("submission_summary", 2048)):
                self.assertTrue(0 < len(value["checklist_row"][field]) <= limit, field)
        self.assertEqual(len(canonical(payload)), 65536)
        self.assertEqual(len(canonical(larger)), 65537)
        saved = self.save(payload)
        self.assertEqual(saved.payload_sha256, hashlib.sha256(canonical(payload)).hexdigest())
        self.assertEqual(self.reopen(), saved)
        self.assertEqual(dict(saved.payload["checklist_row"]), payload["checklist_row"])
        self.assertEqual([dict(span) for span in saved.payload["source_spans"]], payload["source_spans"])
        self.preparation_id = str(uuid4())
        error = self.rejected_unchanged(lambda: self.save(larger), "PREPARATION_INVALID")
        self.assertIn("64KiB", str(error))
        self.assertEqual(self.s.open_preparation(self.store, "A", saved.preparation_id), saved)
        with self.db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM preparations").fetchone()[0], 1)
        # Keep the independent smaller row-field rejection coverage.
        bad = self.payload()
        bad["checklist_row"]["next_action"] = "é" * 2049
        self.assertLess(len(canonical(bad)), 65536)
        error = self.rejected_unchanged(lambda: self.save(bad), "PREPARATION_INVALID")
        self.assertIn("next_action", str(error))

    def test_docrefs_require_exact_owner_file_version_hash_bytes_and_path(self):
        records, payload = self.boot(qi=True)
        self.assertEqual(self.save(payload).payload["doc_refs"][1]["package_id"], "QI")
        changes = [("package_id", "A"), ("package_uuid", records[0].package_uuid),
                   ("file_id", str(uuid4())), ("file_version", 2), ("file_version", True),
                   ("sha256", "a" * 64), ("byte_count", records[1].byte_count + 1),
                   ("managed_relative_path", "../foreign.pdf")]
        for field, value in changes:
            self.preparation_id = str(uuid4())
            bad = deepcopy(payload); bad["doc_refs"][1][field] = value
            with self.subTest(field=field):
                self.rejected_unchanged(lambda: self.save(bad), "INTEGRITY_HOLD")

    def test_source_spans_match_persisted_page_locator_offsets_and_text(self):
        _, payload = self.boot()
        for field, value in [("doc_ref", 8), ("doc_ref", True), ("page", 0), ("page", True),
                             ("locator", "invented-page"), ("start", -1), ("start", False),
                             ("end", 100000), ("text", "invented text")]:
            bad = deepcopy(payload); bad["source_spans"][0][field] = value
            with self.subTest(field=field):
                self.rejected_unchanged(lambda: self.save(bad))

    def test_truncated_and_unreadable_reports_cannot_supply_fabricated_spans(self):
        truncated = self.imported(limits=LIMITS(max_excerpt_page_chars=4, max_excerpt_file_chars=4))
        self.assertTrue(any("EXCERPT_TRUNCATED" in x for x in truncated.report.pages[0].warnings))
        self.s.upgrade_preparation_store(self.store)
        self.rejected_unchanged(lambda: self.save(self.payload([truncated])), "INTEGRITY_HOLD")
        payload = self.payload([truncated]); payload["source_spans"] = []
        self.assertEqual(self.save(payload).payload["checklist_row"]["status"], "NEEDS_REVIEW")
        source = self.inputs / "corrupt.pdf"; source.write_bytes((FIXTURES / "corrupt.pdf").read_bytes())
        result = self.s.import_pdf(self.store, "A", source, LIMITS())
        self.assertEqual(result.outcome, "IMPORTED")
        bad = self.payload(); bad["doc_refs"] = self.payload([truncated])["doc_refs"]
        # Corrupt report has no page; choose its exact identity but never invent a page.
        bad["doc_refs"] = [dict(package_id=result.record.package_id, package_uuid=result.record.package_uuid,
                               file_id=result.record.file_id, file_version=result.record.version,
                               sha256=result.record.sha256, byte_count=result.record.byte_count,
                               managed_relative_path=result.record.managed_relative_path)]
        bad["source_spans"] = [dict(doc_ref=0, page=1, locator="page-1", start=0, end=1, text="x")]
        self.preparation_id = str(uuid4())
        self.rejected_unchanged(lambda: self.save(bad), "INTEGRITY_HOLD")

    def test_save_refuses_any_active_import_even_unreferenced_owner(self):
        _, payload = self.boot()
        self.s.create_package(self.store, "B", "Unreferenced owner")
        for phase in ("RESERVED", "STAGED", "RENAMED", "HOLD"):
            operation = self.journal("B", phase)
            with self.subTest(phase=phase):
                self.rejected_unchanged(lambda: self.save(payload))
            with self.db() as db:
                db.execute("DELETE FROM import_journal WHERE operation_id=?", (operation,))
        self.assertEqual(self.save(payload).payload["checklist_row"]["status"], "NEEDS_REVIEW")

    def test_durable_committed_marker_blocks_owner_and_cross_owner_reads(self):
        _, payload = self.boot(qi=True)
        saved = self.save(payload)
        operation = self.journal("QI", "COMMITTED", self.s._COMMITTED_HOLD_TAG + "synthetic unresolved commit")
        self.rejected_unchanged(lambda: self.save(payload), "INTEGRITY_HOLD")
        self.rejected_unchanged(self.reopen, "INTEGRITY_HOLD")
        with self.db() as db:
            self.assertEqual(db.execute("SELECT phase FROM import_journal WHERE operation_id=?", (operation,)).fetchone()[0],
                             "COMMITTED")
            self.assertEqual(db.execute("SELECT payload_sha256 FROM preparations WHERE preparation_id=?",
                                        (saved.preparation_id,)).fetchone()[0], saved.payload_sha256)

    def test_unreferenced_bad_file_in_relevant_owner_blocks_snapshot(self):
        records, payload = self.boot(qi=True)
        source = self.inputs / "other.pdf"; source.write_bytes((FIXTURES / "mixed.pdf").read_bytes())
        other = self.s.import_pdf(self.store, "QI", source, LIMITS())
        self.assertEqual(other.outcome, "IMPORTED")
        self.save(payload)
        (self.store / other.record.managed_relative_path).unlink()
        self.rejected_unchanged(self.reopen, "INTEGRITY_HOLD")

    def test_missing_or_tampered_managed_original_holds_without_snapshot_rewrite(self):
        records, payload = self.boot()
        saved = self.save(payload)
        path = self.store / records[0].managed_relative_path
        raw = path.read_bytes()
        for content in (None, b"synthetic tamper"):
            if content is None:
                path.unlink()
            else:
                path.write_bytes(content)
            self.rejected_unchanged(self.reopen, "INTEGRITY_HOLD")
            self.rejected_unchanged(lambda: self.save(payload), "INTEGRITY_HOLD")
            path.write_bytes(raw)
        self.assertEqual(self.reopen(), saved)

    def test_saved_json_checksum_version_and_timestamp_uncertainty_holds(self):
        _, payload = self.boot()
        saved = self.save(payload)
        with self.db() as db:
            original = db.execute("SELECT * FROM preparations WHERE preparation_id=?", (self.preparation_id,)).fetchone()
            columns = [r[1] for r in db.execute("PRAGMA table_info(preparations)")]
        for field, value in [("payload_json", "{}"), ("payload_json", '{"x":1,"x":2}'),
                             ("payload_sha256", "b" * 64), ("created_utc", "not a timestamp")]:
            with self.db() as db:
                db.execute("UPDATE preparations SET " + field + "=? WHERE preparation_id=?", (value, self.preparation_id))
            self.rejected_unchanged(self.reopen, "INTEGRITY_HOLD")
            with self.db() as db:
                db.execute("UPDATE preparations SET " + field + "=? WHERE preparation_id=?",
                           (original[columns.index(field)], self.preparation_id))
        self.assertEqual(self.reopen(), saved)

    def test_relocation_preserves_portable_refs_and_exact_snapshot(self):
        _, payload = self.boot(qi=True)
        saved = self.save(payload)
        moved = self.case / "relocated"
        self.store.rename(moved); self.store = moved
        for source in self.inputs.iterdir():
            source.unlink()
        self.assertEqual(self.reopen(), saved)

    def test_write_budget_reserves_database_pages_and_rollback_journal(self):
        _, payload = self.boot()
        observed = []
        original = self.s._budget
        def budget(root, reserve=0, **kwargs):
            if reserve:
                observed.append(reserve)
            return original(root, reserve, **kwargs)
        with patch.object(self.s, "_budget", budget):
            self.save(payload)
        with self.db() as db:
            db_bytes = db.execute("PRAGMA page_size").fetchone()[0] * db.execute("PRAGMA page_count").fetchone()[0]
        self.assertTrue(observed)
        self.assertGreater(max(observed), db_bytes + len(json.dumps(payload).encode()))
        self.preparation_id = str(uuid4())
        with patch.object(self.s, "MAX_STORE_BYTES", original(self.store) + 4096):
            self.rejected_unchanged(lambda: self.save(payload), "STORE_BUDGET_EXCEEDED")

    def test_upgrade_budget_refusal_does_not_create_table(self):
        total = self.s._budget(self.store)
        with patch.object(self.s, "MAX_STORE_BYTES", total + 4096):
            self.rejected_unchanged(lambda: self.s.upgrade_preparation_store(self.store), "STORE_BUDGET_EXCEEDED")

    def test_native_database_admission_and_handle_cleanup(self):
        _, payload = self.boot()
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = ctypes.c_void_p
        kernel.GetProcessHandleCount.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        def count():
            value = ctypes.c_uint32()
            self.assertTrue(kernel.GetProcessHandleCount(kernel.GetCurrentProcess(), ctypes.byref(value)))
            return value.value
        before = count()
        for _ in range(20):
            self.preparation_id = str(uuid4())
            self.assertEqual(self.save(payload), self.reopen())
        self.assertEqual(count(), before)
        native = self.s.pdf.kernel32
        disk_before = _disk(self.store)
        handle = native.CreateFileW(str(self.store / "app.sqlite3"), 0x10000, 3, None, self.s.pdf.OPEN_EXISTING, 0x80, None)
        self.assertTrue(handle and handle != self.s.pdf.INVALID_HANDLE_VALUE)
        try:
            with self.assertRaises(self.s.StorageError) as refused:
                self.reopen()
            self.assertEqual(refused.exception.code, "ROOT_UNSAFE")
        finally:
            native.CloseHandle(handle)
        self.assertEqual(_disk(self.store), disk_before)
        self.assertEqual(self.reopen().preparation_id, self.preparation_id)

    def test_preopened_original_writer_and_native_gate_conflict_refuse_save(self):
        records, payload = self.boot()
        native = self.s.pdf.kernel32
        handle = native.CreateFileW(str(self.store / records[0].managed_relative_path),
                                    0x40000000, 3, None, self.s.pdf.OPEN_EXISTING, 0x80, None)
        self.assertTrue(handle and handle != self.s.pdf.INVALID_HANDLE_VALUE)
        try:
            self.rejected_unchanged(lambda: self.save(payload), "INTEGRITY_HOLD")
        finally:
            native.CloseHandle(handle)
        disk_before = _disk(self.store)
        with self.s._store(self.store) as (_, db), self.s._transaction(db):
            with self.assertRaises(self.s.StorageError) as refused:
                self.save(payload)
            self.assertEqual(refused.exception.code, "DATABASE_BUSY")
        self.assertEqual(_disk(self.store), disk_before)
        self.assertEqual(self.save(payload).preparation_id, self.preparation_id)

    def test_schema2_preserves_import_concurrency_between_packages(self):
        self.s.create_package(self.store, "B", "Synthetic concurrent owner")
        self.s.upgrade_preparation_store(self.store)
        source_a = self.inputs / "A.pdf"; source_b = self.inputs / "B.pdf"
        source_a.write_bytes((FIXTURES / "text_unicode.pdf").read_bytes())
        source_b.write_bytes((FIXTURES / "mixed.pdf").read_bytes())
        results = []
        def checkpoint(phase, *args):
            if phase == "RESERVED" and not results:
                results.append("started")
                results.append(self.s.import_pdf(self.store, "B", source_b, LIMITS()))
        with patch.object(self.s, "_checkpoint", checkpoint):
            result_a = self.s.import_pdf(self.store, "A", source_a, LIMITS())
        self.assertEqual(result_a.outcome, "IMPORTED", result_a.diagnostics)
        self.assertEqual(results[1].outcome, "IMPORTED", results[1].diagnostics)
        self.assertEqual(len(self.s.open_package(self.store, "A").files), 1)
        self.assertEqual(len(self.s.open_package(self.store, "B").files), 1)
