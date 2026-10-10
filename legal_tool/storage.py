"""WP01 local package/intake provider; original availability is not readability."""
from contextlib import contextmanager, ExitStack, nullcontext
import ctypes
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import threading
from types import MappingProxyType
from uuid import UUID, uuid4

from . import pdf_read as pdf
from . import worker

MAX_STORE_BYTES = 96 * 1024 * 1024
MAX_REPORT_BYTES = 2 * 1024 * 1024
MAX_ENTRIES = 4096
_ACTIVE_PHASES = ("RESERVED", "STAGED", "RENAMED", "HOLD")
_COMMITTED_HOLD_TAG = "RECOVERY_HOLD: UNPROVED_COMMITTED_V1\n"
_ERROR_CODES = frozenset(("INVALID_PACKAGE_ID", "INVALID_NAME", "INVALID_SOURCE_NAME", "PATH_REFUSED",
    "ROOT_UNSAFE", "STORE_NOT_FOUND", "STORE_INVALID", "STORE_BUDGET_EXCEEDED", "DISK_SPACE_LIMIT",
    "PACKAGE_EXISTS", "PACKAGE_NOT_FOUND", "CONFIG_ERROR", "PATH_NOT_FOUND", "SOURCE_REFUSED",
    "FILE_SIZE_LIMIT", "DATABASE_BUSY", "IO_FAILED", "IMPORT_BUSY", "RECOVERY_HOLD", "INTEGRITY_HOLD",
    "REPORT_CONTRACT_REJECTED", "VERSION_LIMIT", "PLATFORM_UNSUPPORTED",
    "PREPARATION_INVALID", "PREPARATION_CONFLICT", "PREPARATION_NOT_FOUND"))

class StorageError(Exception):
    """Finite technical error; never legal approval or a repaired input report."""
    def __init__(self, code, message="Storage operation failed"):
        self.code = code if type(code) is str and code in _ERROR_CODES else "IO_FAILED"
        try:
            raw = (self.code + ": " + str(message)).encode("utf-8", errors="replace")
            self.diagnostic = raw[:4096].decode("utf-8", errors="ignore")
        except Exception:
            self.diagnostic = self.code + ": Storage operation failed"
        super().__init__(self.diagnostic)

@dataclass(frozen=True)
class Package:
    package_uuid: str
    package_id: str
    name: str
    created_utc: str

@dataclass(frozen=True)
class FileRecord:
    package_id: str
    package_uuid: str
    file_id: str
    source_name: str
    version: int
    sha256: str
    managed_relative_path: str
    byte_count: int
    imported_utc: str
    availability: str
    report: pdf.ReadReport | None
    diagnostics: tuple[str, ...] = ()

    @property
    def read_state(self):
        return self.report.read_state if self.report else "UNKNOWN"

@dataclass(frozen=True)
class PackageView:
    package: Package
    files: tuple[FileRecord, ...]
    diagnostics: tuple[str, ...] = ()

@dataclass(frozen=True)
class ImportResult:
    operation_id: str
    outcome: str
    record: FileRecord | None = None
    diagnostics: tuple[str, ...] = ()

    @property
    def report(self):
        return self.record.report if self.record else None

@dataclass(frozen=True)
class RecoveryItem:
    package_id: str
    operation_id: str
    outcome: str
    diagnostic: str

@dataclass(frozen=True)
class RecoveryReport:
    entries: tuple[RecoveryItem, ...]

def _now():
    return datetime.now(timezone.utc).isoformat()

def _validate_package_id(value):
    if type(value) is not str or not re.fullmatch(r"[A-Z0-9_-]{1,64}", value):
        raise StorageError("INVALID_PACKAGE_ID", "Confirm an uppercase ASCII ID of1-64 letters/digits/_/-")
    return value

def _utf8(value, code):
    try:
        if type(value) is not str:
            raise ValueError()
        return value.encode("utf-8")
    except (ValueError, UnicodeError):
        raise StorageError(code, "Value must encode as strict UTF-8") from None

def _validate_name(value):
    _utf8(value, "INVALID_NAME")
    if len(value) > 200:
        raise StorageError("INVALID_NAME", "Package name exceeds200 characters")
    return value

def _validate_source_name(value):
    encoded = _utf8(value, "INVALID_SOURCE_NAME")
    if not value or len(encoded) > 1024 or any(c in value for c in "/\\:\x00"):
        raise StorageError("INVALID_SOURCE_NAME", "Filename must be bounded leaf metadata")
    return value

def _uuid(value):
    try:
        if type(value) is not str or str(UUID(value)) != value:
            raise ValueError()
    except (ValueError, AttributeError, TypeError):
        raise StorageError("INTEGRITY_HOLD", "Invalid managed UUID identity") from None
    return value

def _path_policy(path):
    if not isinstance(path, Path):
        raise StorageError("PATH_REFUSED", "A local Path is required")
    text = str(path)
    _utf8(text, "PATH_REFUSED")
    if text.startswith(("\\\\", "//", "\\??\\")) or "\x00" in text:
        raise StorageError("PATH_REFUSED", "Network/device namespace is refused")
    return Path(os.path.abspath(text))

def _managed_paths(root, package_uuid, file_id, operation_id):
    for value in (package_uuid, file_id, operation_id):
        _uuid(value)
    relative = "packages/" + package_uuid + "/originals/" + file_id + ".pdf"
    return root / "staging" / (operation_id + ".part"), root / relative, relative

def _validated_limits(limits):
    try:
        return pdf._revalidate_limits(limits)
    except Exception:
        raise StorageError("CONFIG_ERROR", "Invalid or mutated ImportLimits") from None

def _same_wire_tree(left, right):
    """Exact types at every node: False and0 cannot become unchanged input."""
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        if not all(type(k) is str for k in left) or not all(type(k) is str for k in right):
            return False
        return left.keys() == right.keys() and all(_same_wire_tree(left[k], right[k]) for k in left)
    if type(left) is list:
        return len(left) == len(right) and all(_same_wire_tree(a, b) for a, b in zip(left, right))
    return left == right

def _checked_report(path, data, limits, sha256):
    try:
        checked = pdf.publish_report(path, limits, data, sha256, is_child_payload=True)
        if not _same_wire_tree(data, pdf._report_to_wire(checked)):
            raise ValueError()
        return checked
    except Exception:
        raise StorageError("REPORT_CONTRACT_REJECTED", "Shared received publication changed or rejected the report") from None

def _encode_report(path, report, limits, sha256):
    try:
        wire = pdf._report_to_wire(report)
        _checked_report(path, wire, limits, sha256)
        payload = {k:v for k,v in wire.items() if k != "path"}
        text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        if len(text.encode("utf-8")) > MAX_REPORT_BYTES:
            raise ValueError()
        return text
    except StorageError:
        raise
    except Exception:
        raise StorageError("REPORT_CONTRACT_REJECTED", "Report cannot fit the UTF-8 storage envelope") from None

def _decode_report(path, payload, limits, sha256):
    try:
        if type(payload) is not str or len(payload.encode("utf-8")) > MAX_REPORT_BYTES:
            raise ValueError()
        values = json.loads(payload)
        expected = {f.name for f in fields(pdf.ReadReport)} - {"path"}
        if type(values) is not dict or values.keys() != expected:
            raise ValueError()
        values["path"] = str(path)
        return _checked_report(path, values, limits, sha256)
    except StorageError:
        raise
    except Exception:
        raise StorageError("REPORT_CONTRACT_REJECTED", "Invalid persisted report envelope") from None

def _decode_limits(payload):
    try:
        if type(payload) is not str or len(payload.encode()) > 4096:
            raise ValueError()
        values = json.loads(payload)
        if type(values) is not dict or values.keys() != {f.name for f in fields(pdf.ImportLimits)}:
            raise ValueError()
        return _validated_limits(pdf.ImportLimits(**values))
    except Exception:
        raise StorageError("INTEGRITY_HOLD", "Invalid recorded inspection limits") from None

def _identity(handle):
    info = pdf.BY_HANDLE_FILE_INFORMATION()
    if not pdf.kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
        raise StorageError("ROOT_UNSAFE", "Cannot prove native ownership identity")
    if info.dwFileAttributes & 0x400:
        raise StorageError("ROOT_UNSAFE", "Reparse identity refused")
    return [info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow]

@contextmanager
def _directory_guard(path, create=False, anchor=None):
    """Verify every ancestor; pin the owned store subtree against namespace swaps."""
    if os.name != "nt":
        raise StorageError("PLATFORM_UNSUPPORTED", "Managed-file IO requires native Windows")
    path = _path_policy(path)
    anchor = path if anchor is None else _path_policy(anchor)
    if not path.is_relative_to(anchor):
        raise StorageError("ROOT_UNSAFE", "Directory escaped the guarded store")
    handles = []
    markers = set()
    try:
        for directory in reversed((path, *path.parents)):
            attrs = pdf.kernel32.GetFileAttributesW(str(directory))
            if attrs == 0xFFFFFFFF:
                if not create or not directory.is_relative_to(anchor):
                    raise StorageError("STORE_NOT_FOUND", "Managed directory is missing")
                directory.mkdir(exist_ok=False)
                attrs = pdf.kernel32.GetFileAttributesW(str(directory))
            if attrs == 0xFFFFFFFF or attrs & 0x400 or not attrs & 0x10:
                raise StorageError("ROOT_UNSAFE", "Managed ancestor must be a regular directory")
            if not directory.is_relative_to(anchor):
                continue
            # FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES: attributes alone do not pin rename.
            handle = pdf.kernel32.CreateFileW(str(directory), 0x81, pdf.FILE_SHARE_READ, None,
                                             pdf.OPEN_EXISTING, 0x02000000 | 0x00200000, None)
            if not handle or handle == pdf.INVALID_HANDLE_VALUE:
                raise StorageError("ROOT_UNSAFE", "Cannot pin managed directory")
            handles.append(handle)
            identity = _identity(handle)
            final = ctypes.create_unicode_buffer(1024)
            count = pdf.kernel32.GetFinalPathNameByHandleW(handle, final, 1024, 0)
            actual = final.value[4:] if final.value.startswith("\\\\?\\") else final.value
            if not count or count >= 1024 or os.path.normcase(os.path.abspath(actual)) != os.path.normcase(str(directory)):
                raise StorageError("ROOT_UNSAFE", "Managed ancestor identity mismatch")
            # Keep the directory nonempty without adopting or persisting a foreign marker.
            marker = directory / (".lt-guard-" + str(uuid4()) + ".tmp")
            marker_handle = pdf.kernel32.CreateFileW(str(marker), pdf.GENERIC_READ | 0x10000,
                pdf.FILE_SHARE_READ, None, 1, 0x04200100, None)  # CREATE_NEW, DELETE_ON_CLOSE, OPEN_REPARSE_POINT.
            if not marker_handle or marker_handle == pdf.INVALID_HANDLE_VALUE:
                raise StorageError("ROOT_UNSAFE", "Cannot create owned temporary guard")
            handles.append(marker_handle)
            markers.add(marker)
            _identity(marker_handle)
            # Overlap handles during handoff; allow child writes while still denying directory deletion.
            operational = pdf.kernel32.CreateFileW(str(directory), 0x81, 3, None,
                                                   pdf.OPEN_EXISTING, 0x02200000, None)
            if not operational or operational == pdf.INVALID_HANDLE_VALUE:
                raise StorageError("ROOT_UNSAFE", "Cannot establish operational directory guard")
            handles.append(operational)
            if _identity(operational) != identity:
                raise StorageError("ROOT_UNSAFE", "Directory changed during guard handoff")
            if not pdf.kernel32.CloseHandle(handle):
                raise StorageError("ROOT_UNSAFE", "Cannot release bootstrap directory guard")
            handles.remove(handle)
        yield frozenset(markers)
    except StorageError:
        raise
    except Exception:
        raise StorageError("ROOT_UNSAFE", "Managed directory admission failed") from None
    finally:
        for handle in reversed(handles):
            pdf.kernel32.CloseHandle(handle)

def _budget(root, reserve=0, *, reserve_entries=0):
    total = 0
    entries = reserve_entries
    todo = [root]
    while todo:
        with os.scandir(todo.pop()) as items:
            for item in items:
                info = item.stat(follow_symlinks=False)
                entries += 1
                if entries > MAX_ENTRIES or getattr(info, "st_file_attributes", 0) & 0x400:
                    raise StorageError("ROOT_UNSAFE", "Unbounded or reparse store inventory")
                if item.is_dir(follow_symlinks=False):
                    todo.append(Path(item.path))
                else:
                    total += info.st_size
                if total + reserve > MAX_STORE_BYTES:
                    raise StorageError("STORE_BUDGET_EXCEEDED", "Projected store/sidecar/staging quota exceeded")
    if total + reserve > MAX_STORE_BYTES:
        raise StorageError("STORE_BUDGET_EXCEEDED", "Projected store quota exceeded")
    if reserve and shutil.disk_usage(root).free < reserve:
        raise StorageError("DISK_SPACE_LIMIT", "Insufficient free space for bounded import")
    return total


_sql_owners = threading.local()
_sql_uncertain = set()

class _SqlGate:
    """Nonwaiting cooperative writers in one supported Windows session, keyed by pinned root."""
    def __init__(self, root):
        self.root = root
        self.depth = 0
        self.native = ctypes.WinDLL("kernel32", use_last_error=True)
        for name, args, result in (
                ("CreateMutexW", [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p], ctypes.c_void_p),
                ("WaitForSingleObject", [ctypes.c_void_p, ctypes.c_uint32], ctypes.c_uint32),
                ("ReleaseMutex", [ctypes.c_void_p], ctypes.c_int),
                ("CloseHandle", [ctypes.c_void_p], ctypes.c_int),
                ("GetFileType", [ctypes.c_void_p], ctypes.c_uint32)):
            function = getattr(self.native, name)
            function.argtypes, function.restype = args, result
        pin = pdf.kernel32.CreateFileW(str(root), 0x81, 3, None, pdf.OPEN_EXISTING, 0x02200000, None)
        if not pin or pin == pdf.INVALID_HANDLE_VALUE:
            raise StorageError("ROOT_UNSAFE", "Cannot identify pinned database root")
        try:
            self.name = r"Global\LegalTool.Database." + ":".join(map(str, _identity(pin)))
        finally:
            pdf.kernel32.CloseHandle(pin)
        self.handle = self.native.CreateMutexW(None, False, self.name)
        if not self.handle:
            raise StorageError("ROOT_UNSAFE", "Cannot establish database admission mutex")

    def enter(self):
        owners = getattr(_sql_owners, "active", None)
        if owners is None:
            owners = _sql_owners.active = {}
        owner = owners.get(self.name)
        if owner is not None:
            if owner is not self:
                raise StorageError("DATABASE_BUSY", "Another connection owns database admission")
            self.depth += 1
            return
        if self.name in _sql_uncertain:
            raise StorageError("RECOVERY_HOLD", "Abandoned database admission; preserve the store")
        result = self.native.WaitForSingleObject(self.handle, 0)
        if result == 258:
            raise StorageError("DATABASE_BUSY", "Database admission is owned by a live writer")
        if result not in (0, 128):
            raise StorageError("ROOT_UNSAFE", "Cannot prove database admission ownership")
        owners[self.name] = self
        self.depth = 1
        try:
            if result == 128:
                _sql_uncertain.add(self.name)
                raise StorageError("RECOVERY_HOLD", "Abandoned database admission; preserve the store")
            # Presence is deliberately unclassified. SQLite must not roll it back for us.
            for suffix in ("-journal", "-wal", "-shm"):
                try:
                    (self.root / ("app.sqlite3" + suffix)).lstat()
                except FileNotFoundError:
                    continue
                except OSError:
                    raise StorageError("ROOT_UNSAFE", "Cannot inspect SQLite sidecar") from None
                raise StorageError("RECOVERY_HOLD", "Unclassified SQLite sidecar; preserve database and sidecars")
        except BaseException:
            self.leave()
            raise

    def leave(self):
        self.depth -= 1
        if self.depth:
            return
        del _sql_owners.active[self.name]
        if not self.native.ReleaseMutex(self.handle):
            _sql_uncertain.add(self.name)
            raise StorageError("ROOT_UNSAFE", "Cannot release database admission ownership")

    @contextmanager
    def hold(self):
        self.enter()
        try:
            yield
        finally:
            self.leave()

    def close(self):
        if not self.native.CloseHandle(self.handle):
            raise StorageError("ROOT_UNSAFE", "Cannot close database admission handle")

class _SqlCursor:
    """Provider cursors consume one bounded result or iterate through exhaustion."""
    def __init__(self, db, cursor):
        self.db, self.cursor, self.closed = db, cursor, False
        db.cursors.add(self)

    def close(self):
        if self.closed:
            return
        try:
            self.cursor.close()
        finally:
            self.closed = True
            self.db.cursors.discard(self)
            self.db.gate.leave()

    def fetchone(self):
        try:
            return self.cursor.fetchone()
        finally:
            self.close()

    def fetchmany(self, size):
        try:
            return self.cursor.fetchmany(size)
        finally:
            self.close()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        finally:
            self.close()

    def __iter__(self):
        return self

    def __next__(self):
        try:
            return next(self.cursor)
        except BaseException:
            self.close()
            raise

class _Database:
    """Keep each SQL segment admitted through result consumption and cleanup."""
    def __init__(self, connection, gate):
        self.connection, self.gate, self.cursors = connection, gate, set()
        self.closed = False

    @property
    def in_transaction(self):
        return self.connection.in_transaction

    def execute(self, *args):
        if self.closed:
            raise StorageError("ROOT_UNSAFE", "Closed owned connection cannot be reused")
        self.gate.enter()
        try:
            cursor = self.connection.execute(*args)
        except BaseException:
            self.gate.leave()
            raise
        result = _SqlCursor(self, cursor)
        if cursor.description is None:
            result.close()
        return result

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            for cursor in tuple(self.cursors):
                cursor.close()
        finally:
            self.connection.close()

@contextmanager
def _transaction(db):
    with db.gate.hold() if isinstance(db, _Database) else nullcontext():
        try:
            db.execute("BEGIN IMMEDIATE")
            yield
            db.execute("COMMIT")
        except BaseException as failure:
            try:
                if db.in_transaction:
                    db.execute("ROLLBACK")
            except BaseException:
                try:
                    db.close()
                except BaseException:
                    failure.add_note("Rollback and owned connection close failed; preserve the store")
            raise

def _sql_error(exc):
    if getattr(exc, "sqlite_errorcode", None) in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
        return StorageError("DATABASE_BUSY", "SQLite busy deadline reached")
    return StorageError("STORE_INVALID", "SQLite operation failed; preserve the store")

def _initialize_schema(db):
    db.execute("PRAGMA foreign_keys=ON")
    statements = [
        """CREATE TABLE packages(
        package_uuid TEXT PRIMARY KEY CHECK(length(package_uuid)=36),
        package_id TEXT UNIQUE NOT NULL CHECK(length(package_id) BETWEEN 1 AND 64),
        name TEXT NOT NULL CHECK(length(name)<=200), created_utc TEXT NOT NULL)""",
        """CREATE TABLE files(
        file_id TEXT PRIMARY KEY CHECK(length(file_id)=36),
        package_uuid TEXT NOT NULL REFERENCES packages(package_uuid) ON DELETE RESTRICT,
        source_name TEXT COLLATE BINARY NOT NULL CHECK(length(CAST(source_name AS BLOB)) BETWEEN 1 AND 1024),
        version INTEGER NOT NULL CHECK(typeof(version)='integer' AND version>0),
        sha256 TEXT NOT NULL CHECK(length(sha256)=64),
        relative_path TEXT UNIQUE NOT NULL,
        byte_count INTEGER NOT NULL CHECK(typeof(byte_count)='integer' AND byte_count BETWEEN 1 AND 20971520),
        report_json TEXT NOT NULL CHECK(length(CAST(report_json AS BLOB))<=2097152),
        limits_json TEXT NOT NULL, imported_utc TEXT NOT NULL,
        UNIQUE(package_uuid,sha256), UNIQUE(package_uuid,source_name,version))""",
        """CREATE TABLE import_journal(
        operation_id TEXT PRIMARY KEY CHECK(length(operation_id)=36),
        package_uuid TEXT NOT NULL REFERENCES packages(package_uuid) ON DELETE RESTRICT,
        file_id TEXT NOT NULL CHECK(length(file_id)=36), source_name TEXT NOT NULL,
        version INTEGER NOT NULL CHECK(version>0), sha256 TEXT NOT NULL CHECK(length(sha256)=64),
        byte_count INTEGER NOT NULL CHECK(byte_count BETWEEN 1 AND 20971520),
        relative_path TEXT NOT NULL, part_relative_path TEXT NOT NULL,
        owner_json TEXT NOT NULL, phase TEXT NOT NULL CHECK(phase IN('RESERVED','STAGED','RENAMED','COMMITTED','ROLLED_BACK','HOLD')),
        diagnostic TEXT NOT NULL, created_utc TEXT NOT NULL)""",
        """CREATE UNIQUE INDEX one_active_import ON import_journal(package_uuid)
        WHERE phase IN('RESERVED','STAGED','RENAMED','HOLD')""",
    ]
    with _transaction(db):
        for sql in statements:
            db.execute(sql)
        db.execute("PRAGMA user_version=1")

def _validate_schema(db):
    """Prove separate supported v1/v2 constraints without persistent repair."""
    def unique_keys(connection, table):
        indexes = connection.execute('SELECT name FROM pragma_index_list(?) WHERE "unique"=1 AND partial=0', (table,))
        return {tuple(tuple(row) for row in connection.execute(
                    'SELECT name,coll FROM pragma_index_xinfo(?) WHERE "key"=1 ORDER BY seqno', (name,)))
                for (name,) in indexes}

    reference = sqlite3.connect(":memory:", isolation_level=None)
    try:
        _initialize_schema(reference)
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version not in (1, 2):
            raise StorageError("STORE_INVALID", "Unsupported schema version; no migration/repair")
        tables = ("packages", "files", "import_journal")
        if version == 2:
            reference.execute(_PREPARATION_SQL)
            tables += ("preparations",)
        if db.execute("SELECT 1 FROM sqlite_master WHERE type IN('trigger','view') LIMIT 1").fetchone():
            raise StorageError("STORE_INVALID", "Unsupported schema trigger/view; no migration/repair")
        for table in tables:
            shape = "SELECT cid,name,type,\"notnull\",dflt_value,pk FROM pragma_table_info(?)"
            if [tuple(row) for row in db.execute(shape, (table,))] != [tuple(row) for row in reference.execute(shape, (table,))]:
                raise StorageError("STORE_INVALID", "Unsupported schema columns: " + table + "; no migration/repair")
            declaration = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
            supported = reference.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
            if declaration is None or _schema_checks(declaration[0]) != _schema_checks(supported[0]):
                raise StorageError("STORE_INVALID", "Unsupported schema CHECK constraints: " + table + "; no migration/repair")
            query = 'SELECT "table","from","to",on_update,on_delete,"match" FROM pragma_foreign_key_list(?)'
            actual = {tuple(row) for row in db.execute(query, (table,))}
            expected = {tuple(row) for row in reference.execute(query, (table,))}
            if actual != expected:
                raise StorageError("STORE_INVALID", "Unsupported schema foreign keys: " + table + "; no migration/repair")
            if not unique_keys(reference, table) <= unique_keys(db, table):
                raise StorageError("STORE_INVALID", "Unsupported schema uniqueness: " + table + "; no migration/repair")
        index = db.execute('SELECT "unique",partial FROM pragma_index_list(?) WHERE name=?',
                           ("import_journal", "one_active_import")).fetchone()
        columns = tuple(tuple(row) for row in db.execute(
            'SELECT name,coll FROM pragma_index_xinfo(?) WHERE "key"=1 ORDER BY seqno', ("one_active_import",)))
        definition = db.execute("SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name='import_journal' AND name='one_active_import'").fetchone()
        # Match the complete supported declaration: SQL comments cannot supply a predicate.
        predicate = re.fullmatch(
            r'\s*CREATE\s+UNIQUE\s+INDEX\s+(?:one_active_import|"one_active_import")\s+'
            r'ON\s+(?:import_journal|"import_journal")\s*\(\s*(?:package_uuid|"package_uuid")(?:\s+(?:ASC|DESC))?\s*\)\s+'
            r'WHERE\s+(?:phase|"phase")\s+IN\s*\(([^()]*)\)\s*', definition[0], re.I | re.S) if definition else None
        literals = re.fullmatch(r"\s*'[^']*'\s*(?:,\s*'[^']*'\s*)*", predicate[1]) if predicate else None
        if (index is None or tuple(index) != (1, 1) or columns != (("package_uuid", "BINARY"),)
                or literals is None or len(re.findall(r"'([^']*)'", predicate[1])) != len(_ACTIVE_PHASES)
                or set(re.findall(r"'([^']*)'", predicate[1])) != set(_ACTIVE_PHASES)):
            raise StorageError("STORE_INVALID", "Unsupported schema one_active_import index; no migration/repair")
    finally:
        reference.close()

@contextmanager
def _store(root, create=False):
    root = _path_policy(root)
    db = None
    db_pin = None
    gate = None
    with _directory_guard(root, create) as markers:
        try:
            gate = _SqlGate(root)
            with gate.hold():
                _budget(root, 65536 if create else 0)
                path = root / "app.sqlite3"
                new = not path.exists()
                if new:
                    if not create:
                        raise StorageError("STORE_NOT_FOUND", "No existing SQLite store")
                    if any(child not in markers for child in root.iterdir()):
                        raise StorageError("ROOT_UNSAFE", "Do not adopt an unknown nonempty store")
                elif pdf._check_path_admission(path) or not path.is_file():
                    raise StorageError("ROOT_UNSAFE", "Unsafe SQLite file identity")
                # Pin the pathname before SQLite opens it; read/write sharing preserves normal transactions.
                db_pin = pdf.kernel32.CreateFileW(str(path), 0x81, 3, None,
                                                 1 if new else pdf.OPEN_EXISTING, 0x00200080, None)
                if not db_pin or db_pin == pdf.INVALID_HANDLE_VALUE:
                    db_pin = None
                    raise StorageError("ROOT_UNSAFE", "Cannot pin SQLite file")
                _identity(db_pin)
                info = pdf.BY_HANDLE_FILE_INFORMATION()
                if (gate.native.GetFileType(db_pin) != 1
                        or not pdf.kernel32.GetFileInformationByHandle(db_pin, ctypes.byref(info))
                        or info.dwFileAttributes & 0x410 or info.nNumberOfLinks != 1):
                    raise StorageError("ROOT_UNSAFE", "SQLite pin must be a regular disk file with exactly one link")
                db = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=2.0, isolation_level=None)
                db.row_factory = sqlite3.Row
                db = _Database(db, gate)
                db.execute("PRAGMA foreign_keys=ON")
                if new:
                    db.execute("PRAGMA journal_mode=DELETE").fetchone()
                    _initialize_schema(db)
                if db.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
                    raise StorageError("STORE_INVALID", "Foreign keys must be enabled")
                version = db.execute("PRAGMA user_version").fetchone()[0]
                if version not in (1, 2):
                    raise StorageError("STORE_INVALID", "Unsupported store schema; no migration/repair")
                tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                expected_tables = {"packages", "files", "import_journal"} | ({"preparations"} if version == 2 else set())
                if tables != expected_tables or db.execute("PRAGMA foreign_key_check").fetchone():
                    raise StorageError("STORE_INVALID", "Schema/foreign ownership is untrustworthy")
                _validate_schema(db)
                if db.execute("PRAGMA journal_mode").fetchone()[0].lower() != "delete":
                    raise StorageError("STORE_INVALID", "Unexpected journal mode; preserve sidecars")
                db.execute("PRAGMA synchronous=FULL")
            yield root, db
        except sqlite3.Error as exc:
            raise _sql_error(exc) from None
        finally:
            try:
                if db is not None:
                    db.close()
            finally:
                try:
                    if db_pin is not None:
                        pdf.kernel32.CloseHandle(db_pin)
                finally:
                    if gate is not None:
                        gate.close()

def _package(row):
    if row is None:
        raise StorageError("PACKAGE_NOT_FOUND", "Confirmed package does not exist")
    _uuid(row["package_uuid"])
    _validate_package_id(row["package_id"])
    _validate_name(row["name"])
    return Package(row["package_uuid"], row["package_id"], row["name"], row["created_utc"])

def _find_package(db, package_id):
    return _package(db.execute("SELECT * FROM packages WHERE package_id=?", (package_id,)).fetchone())

def create_package(root: Path, package_id: str, name: str) -> Package:
    """Caller confirms uppercase immutable ID; invalid input writes nothing."""
    _validate_package_id(package_id)
    _validate_name(name)
    root = _path_policy(root)
    with _store(root, create=True) as (root, db):
        with _transaction(db):
            if db.execute("SELECT 1 FROM packages WHERE package_id=?", (package_id,)).fetchone():
                raise StorageError("PACKAGE_EXISTS", "Confirmed package ID is already used")
            package = Package(str(uuid4()), package_id, name, _now())
            db.execute("INSERT INTO packages VALUES(?,?,?,?)", (package.package_uuid, package.package_id, package.name, package.created_utc))
        return package

def list_packages(root: Path) -> list[Package]:
    with _store(root) as (root, db):
        rows = db.execute("SELECT * FROM packages ORDER BY package_id").fetchmany(MAX_ENTRIES + 1)
        if len(rows) > MAX_ENTRIES:
            raise StorageError("STORE_BUDGET_EXCEEDED", "Package inventory exceeds bounded read")
        return [_package(row) for row in rows]

def _verify_original(path, size, sha256, limits):
    if not re.fullmatch(r"[0-9a-f]{64}", sha256) or type(size) is not int or not 1 <= size <= limits.max_file_bytes:
        raise StorageError("INTEGRITY_HOLD", "Invalid original byte identity")
    if pdf._check_path_admission(path) or not path.is_file():
        raise StorageError("INTEGRITY_HOLD", "Original missing or unsafe")
    raw, error, observed = pdf._read_file_snapshot(path, limits.max_file_bytes)
    if error or raw is None or observed != size or hashlib.sha256(raw).hexdigest() != sha256:
        raise StorageError("INTEGRITY_HOLD", "Original hash/size cannot be verified")

def _record(root, package, row):
    report = None
    diagnostic = ()
    availability = "AVAILABLE"
    try:
        file_id = _uuid(row["file_id"])
        if row["package_uuid"] != package.package_uuid:
            raise StorageError("INTEGRITY_HOLD", "Record belongs to another package")
        _validate_source_name(row["source_name"])
        if type(row["version"]) is not int or row["version"] < 1:
            raise StorageError("INTEGRITY_HOLD", "Invalid immutable version")
        # File location is independently derived from package/file IDs, never a DB path.
        relative = "packages/" + package.package_uuid + "/originals/" + file_id + ".pdf"
        if row["relative_path"] != relative:
            raise StorageError("INTEGRITY_HOLD", "Foreign or malformed managed relative identity")
        path = root / relative
        limits = _decode_limits(row["limits_json"])
        report = _decode_report(path, row["report_json"], limits, row["sha256"])
        with _directory_guard(path.parent, anchor=root):
            _verify_original(path, row["byte_count"], row["sha256"], limits)
    except StorageError as exc:
        availability, diagnostic = "HOLD", (str(exc),)
    return FileRecord(package.package_id, package.package_uuid, row["file_id"], row["source_name"],
                      row["version"], row["sha256"], row["relative_path"], row["byte_count"], row["imported_utc"],
                      availability, report, diagnostic)

def _view(root, db, package):
    rows = db.execute("SELECT * FROM files WHERE package_uuid=? ORDER BY source_name COLLATE BINARY,version",
                      (package.package_uuid,)).fetchmany(MAX_ENTRIES + 1)
    if len(rows) > MAX_ENTRIES:
        raise StorageError("STORE_BUDGET_EXCEEDED", "File inventory exceeds bounded read")
    records = tuple(_record(root, package, row) for row in rows)
    diagnostics = [message for record in records for message in record.diagnostics]
    if _recovery_block(db, package.package_uuid) or db.execute("SELECT 1 FROM import_journal WHERE package_uuid=? AND phase IN('RESERVED','STAGED','RENAMED','HOLD')",
                  (package.package_uuid,)).fetchone():
        diagnostics.append(str(StorageError("RECOVERY_HOLD", "Incomplete same-package import; originals retained")))
    return PackageView(package, records, tuple(diagnostics[:MAX_ENTRIES]))

def open_package(root: Path, package_id: str) -> PackageView:
    _validate_package_id(package_id)
    with _store(root) as (root, db):
        return _view(root, db, _find_package(db, package_id))

class _CopyFailure(StorageError):
    def __init__(self, owner):
        super().__init__("IO_FAILED", "Partial write/flush failed")
        self.owner = owner

def _copy_snapshot(raw, part):
    import msvcrt
    owner = None
    try:
        with part.open("xb") as handle:
            owner = _identity(msvcrt.get_osfhandle(handle.fileno()))
            for offset in range(0, len(raw), 65536):
                handle.write(raw[offset:offset+65536])
            handle.flush()
            os.fsync(handle.fileno())
        return owner
    except FileExistsError:
        raise StorageError("RECOVERY_HOLD", "Foreign partial name exists; preserve it") from None
    except Exception:
        raise _CopyFailure(owner) from None

def _checkpoint(phase, root, operation_id):
    """No-op boundary used by owned native interruption fixtures only."""

def _committed_hold(diagnostic):
    """Only the bounded recovery tag identifies persistent COMMITTED uncertainty."""
    if (type(diagnostic) is not str or not len(_COMMITTED_HOLD_TAG) < len(diagnostic) <= 4096
            or not diagnostic.startswith(_COMMITTED_HOLD_TAG)):
        return False
    try:
        return len(_COMMITTED_HOLD_TAG) < len(diagnostic.encode("utf-8")) <= 4096
    except UnicodeError:
        return False

def _recovery_block(db, package_uuid):
    return db.execute("""SELECT 1 FROM import_journal WHERE package_uuid=?
        AND phase COLLATE BINARY IN('COMMITTED','HOLD')
        AND substr(diagnostic,1,?) COLLATE BINARY=?
        AND length(CAST(diagnostic AS BLOB)) BETWEEN ? AND 4096 LIMIT 1""",
        (package_uuid, len(_COMMITTED_HOLD_TAG), _COMMITTED_HOLD_TAG, len(_COMMITTED_HOLD_TAG) + 1)).fetchone() is not None

def _phase(db, operation_id, phase, diagnostic="", owner=None, *, recovery_hold=False):
    with nullcontext() if db.in_transaction else _transaction(db):
        current = db.execute("SELECT phase,diagnostic FROM import_journal WHERE operation_id=?", (operation_id,)).fetchone()
        if current is None or _committed_hold(current[1]):
            return  # A recovery integrity marker requires separately approved reconciliation.
        committed_hold = recovery_hold and phase == "HOLD" and _committed_hold(diagnostic)
        if current[0] == "COMMITTED" and not committed_hold:
            return
        if recovery_hold and phase == "HOLD" and db.execute("""SELECT 1 FROM import_journal WHERE operation_id!=?
                AND package_uuid=(SELECT package_uuid FROM import_journal WHERE operation_id=?)
                AND phase IN('RESERVED','STAGED','RENAMED','HOLD')""", (operation_id, operation_id)).fetchone():
            # The unique active index admits one package blocker; retain every other diagnostic.
            db.execute("UPDATE import_journal SET diagnostic=? WHERE operation_id=?", (diagnostic, operation_id))
            return
        if owner is None:
            db.execute("UPDATE import_journal SET phase=?,diagnostic=? WHERE operation_id=? AND (phase!='COMMITTED' OR ?)",
                       (phase, diagnostic, operation_id, committed_hold))
        else:
            db.execute("UPDATE import_journal SET phase=?,diagnostic=?,owner_json=? WHERE operation_id=? AND (phase!='COMMITTED' OR ?)",
                       (phase, diagnostic, json.dumps(owner), operation_id, committed_hold))

def _finalize(db, values, operation_id):
    with _transaction(db):
        row = db.execute("SELECT * FROM import_journal WHERE operation_id=?", (operation_id,)).fetchone()
        if row is None or _committed_hold(row["diagnostic"]) or row["phase"] != "RENAMED" or row["file_id"] != values[0] or row["package_uuid"] != values[1]:
            raise StorageError("RECOVERY_HOLD", "Final journal identity cannot be proved")
        db.execute("INSERT INTO files VALUES(?,?,?,?,?,?,?,?,?,?)", values)
        db.execute("UPDATE import_journal SET phase='COMMITTED',diagnostic='' WHERE operation_id=?", (operation_id,))

def _rollback_partial(root, db, operation_id, part, final, owner):
    """Only a proved-owned, unrenamed partial may be removed synchronously."""
    if final.exists():
        return False
    if part.exists():
        if owner is None or pdf._check_path_admission(part):
            return False
        handle = pdf.kernel32.CreateFileW(str(part), 0x10080, pdf.FILE_SHARE_READ, None,
                                         pdf.OPEN_EXISTING, 0x00200000, None)
        if not handle or handle == pdf.INVALID_HANDLE_VALUE:
            return False
        try:
            if not _same_wire_tree(_identity(handle), owner):
                return False
            disposition = ctypes.c_byte(1)
            delete = pdf.kernel32.SetFileInformationByHandle
            delete.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
            delete.restype = ctypes.c_int
            if not delete(handle, 4, ctypes.byref(disposition), ctypes.sizeof(disposition)):
                return False
        finally:
            pdf.kernel32.CloseHandle(handle)
    _phase(db, operation_id, "ROLLED_BACK", str(StorageError("IO_FAILED", "Known pre-rename rollback")), owner)
    return True

def import_pdf(root: Path, package_id: str, source_path: Path, limits: pdf.ImportLimits) -> ImportResult:
    """Capture first, retain a managed original, then persist the shared report."""
    operation_id = ""
    try:
        limits = _validated_limits(limits)
        _validate_package_id(package_id)
        source = _path_policy(source_path)
        root = _path_policy(root)
        name = _validate_source_name(source.name)
        if source.suffix.lower() != ".pdf":
            raise StorageError("SOURCE_REFUSED", "Only admitted PDF originals are retained")
        if pdf._check_path_admission(source) or not source.is_file():
            raise StorageError("SOURCE_REFUSED", "Source must be a regular local non-reparse file")
        raw, error, size = pdf._read_file_snapshot(source, limits.max_file_bytes)
        if size > limits.max_file_bytes:
            raise StorageError("FILE_SIZE_LIMIT", "Source exceeds the existing file limit")
        if error or raw is None or not size:
            raise StorageError("SOURCE_REFUSED", "Stable nonempty source capture failed")
        digest = hashlib.sha256(raw).hexdigest()
        with _store(root) as (root, db):
            package = _find_package(db, package_id)
            if _recovery_block(db, package.package_uuid):
                return ImportResult("", "HOLD", diagnostics=(str(StorageError("RECOVERY_HOLD", "Unproved same-package commit; originals retained")),))
            pending = db.execute("SELECT phase FROM import_journal WHERE package_uuid=? AND phase IN('RESERVED','STAGED','RENAMED','HOLD')",
                                 (package.package_uuid,)).fetchone()
            if pending:
                code = "RECOVERY_HOLD" if pending[0] == "HOLD" else "IMPORT_BUSY"
                return ImportResult("", "HOLD" if code == "RECOVERY_HOLD" else "REJECTED", diagnostics=(str(StorageError(code)),))
            view = _view(root, db, package)
            if any(record.availability != "AVAILABLE" for record in view.files):
                return ImportResult("", "HOLD", diagnostics=(str(StorageError("INTEGRITY_HOLD", "Same-package original/report is held")),))
            duplicate = next((record for record in view.files if record.sha256 == digest), None)
            if duplicate:
                return ImportResult("", "DUPLICATE", duplicate)
            _budget(root, size + MAX_REPORT_BYTES + 65536)
            operation_id, file_id = str(uuid4()), str(uuid4())
            part, final, relative = _managed_paths(root, package.package_uuid, file_id, operation_id)
            owner = None
            reserved = False
            renamed = False
            with ExitStack() as guards:
                guards.enter_context(_directory_guard(part.parent, create=True, anchor=root))
                guards.enter_context(_directory_guard(final.parent, create=True, anchor=root))
                try:
                    with _transaction(db):
                        # Admission can race recovery; recheck its durable marker under the write lock.
                        if _recovery_block(db, package.package_uuid):
                            return ImportResult("", "HOLD", diagnostics=(str(StorageError("RECOVERY_HOLD", "Unproved same-package commit; originals retained")),))
                        version = db.execute("SELECT COALESCE(MAX(version),0)+1 FROM files WHERE package_uuid=? AND source_name=? COLLATE BINARY",
                                             (package.package_uuid, name)).fetchone()[0]
                        if version > 2147483647:
                            raise StorageError("VERSION_LIMIT", "Filename version bound reached")
                        db.execute("INSERT INTO import_journal VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                   (operation_id, package.package_uuid, file_id, name, version, digest, size,
                                    relative, "staging/" + operation_id + ".part", "null", "RESERVED", "", _now()))
                    reserved = True
                    _checkpoint("RESERVED", root, operation_id)
                    owner = _copy_snapshot(raw, part)
                    raw = None
                    _verify_original(part, size, digest, limits)
                    _phase(db, operation_id, "STAGED", owner=owner)
                    _checkpoint("STAGED", root, operation_id)
                    os.rename(part, final)  # Native Windows: existing destination is never replaced.
                    renamed = True
                    _verify_original(final, size, digest, limits)
                    _phase(db, operation_id, "RENAMED")
                    _checkpoint("RENAMED", root, operation_id)
                    report = worker.inspect_bounded(final, limits)
                    encoded = _encode_report(final, report, limits, digest)
                    _verify_original(final, size, digest, limits)
                    values = (file_id, package.package_uuid, name, version, digest, relative, size,
                              encoded, json.dumps(asdict(limits), separators=(",", ":")), _now())
                    _finalize(db, values, operation_id)
                    _checkpoint("COMMITTED", root, operation_id)
                    row = db.execute("SELECT * FROM files WHERE file_id=?", (file_id,)).fetchone()
                    return ImportResult(operation_id, "IMPORTED", _record(root, package, row))
                except Exception as exc:
                    raw = None
                    error = exc if isinstance(exc, StorageError) else _sql_error(exc) if isinstance(exc, sqlite3.Error) else StorageError("IO_FAILED")
                    if isinstance(exc, _CopyFailure):
                        owner = exc.owner
                    if reserved:
                        try:
                            if not renamed and error.code != "RECOVERY_HOLD" and _rollback_partial(root, db, operation_id, part, final, owner):
                                return ImportResult(operation_id, "FAILED", diagnostics=(str(error),))
                            _phase(db, operation_id, "HOLD", str(error), owner)
                        except Exception:
                            pass  # Uncertain persistence retains bytes and the durable pre-failure journal.
                        return ImportResult(operation_id, "HOLD", diagnostics=(str(StorageError("RECOVERY_HOLD", "Original/partial retained; commit identity uncertain")), str(error)))
                    raise error
    except Exception as exc:
        error = exc if isinstance(exc, StorageError) else StorageError("IO_FAILED", "Import admission failed")
        return ImportResult(operation_id, "REJECTED", diagnostics=(str(error),))

def recover_imports(root: Path) -> RecoveryReport:
    """Classify recorded operations; never delete or auto-finalize interrupted bytes."""
    entries = []
    with _store(root) as (root, db):
        rows = db.execute("SELECT j.*,p.package_id FROM import_journal j JOIN packages p USING(package_uuid) ORDER BY j.operation_id").fetchmany(MAX_ENTRIES + 1)
        if len(rows) > MAX_ENTRIES:
            raise StorageError("STORE_BUDGET_EXCEEDED", "Journal exceeds bounded recovery read")
        for snapshot in rows:
            with _transaction(db):
                row = db.execute("SELECT j.*,p.package_id FROM import_journal j JOIN packages p USING(package_uuid) WHERE j.operation_id=?", (snapshot["operation_id"],)).fetchone()
                if row is None:
                    raise StorageError("STORE_INVALID", "Journal disappeared during recovery; preserve the store")
                outcome = "HOLD"
                diagnostic = str(StorageError("RECOVERY_HOLD", "Interrupted or unproved import; retain bytes"))
                if _committed_hold(row["diagnostic"]):
                    diagnostic = row["diagnostic"]
                else:
                    try:
                        _validate_package_id(row["package_id"])
                        part, final, relative = _managed_paths(root, row["package_uuid"], row["file_id"], row["operation_id"])
                        if row["relative_path"] != relative or row["part_relative_path"] != "staging/" + row["operation_id"] + ".part":
                            raise StorageError("INTEGRITY_HOLD", "Journal relative identity is foreign")
                        if row["phase"] == "COMMITTED":
                            saved = db.execute("SELECT * FROM files WHERE file_id=? AND package_uuid=?", (row["file_id"], row["package_uuid"])).fetchone()
                            package = _find_package(db, row["package_id"])
                            if saved is not None and _record(root, package, saved).availability == "AVAILABLE" and all(_same_wire_tree(saved[k], row[k]) for k in ("source_name", "version", "sha256", "byte_count", "relative_path")):
                                outcome, diagnostic = "COMMITTED", ""
                        elif row["phase"] == "ROLLED_BACK" and not part.exists() and not final.exists():
                            outcome, diagnostic = "ROLLED_BACK", ""
                    except StorageError as exc:
                        diagnostic = str(exc)
                    if outcome == "HOLD":
                        if row["phase"] == "COMMITTED":
                            # Recovery is the only producer; preserve a reason within the existing 4096-byte cap.
                            reason = diagnostic.encode("utf-8", errors="replace")[:4096 - len(_COMMITTED_HOLD_TAG)]
                            diagnostic = _COMMITTED_HOLD_TAG + reason.decode("utf-8", errors="ignore")
                        _phase(db, row["operation_id"], "HOLD", diagnostic, recovery_hold=True)
            entries.append(RecoveryItem(row["package_id"], row["operation_id"], outcome, diagnostic))
    return RecoveryReport(tuple(entries))

MAX_PREPARATION_BYTES = 64 * 1024
_PREPARATION_SQL = """CREATE TABLE preparations(
    preparation_id TEXT PRIMARY KEY NOT NULL CHECK(length(preparation_id)=36),
    package_uuid TEXT NOT NULL REFERENCES packages(package_uuid) ON DELETE RESTRICT,
    payload_version INTEGER NOT NULL CHECK(typeof(payload_version)='integer' AND payload_version=1),
    created_utc TEXT NOT NULL CHECK(length(CAST(created_utc AS BLOB)) BETWEEN 1 AND 64),
    payload_json TEXT NOT NULL CHECK(length(CAST(payload_json AS BLOB)) BETWEEN 1 AND 65536),
    payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256)=64))"""


@dataclass(frozen=True)
class PreparationSnapshot:
    package_id: str
    preparation_id: str
    payload_version: int
    created_utc: str
    payload_sha256: str
    payload: object


@dataclass(frozen=True)
class PreparationSummary:
    preparation_id: str
    created_utc: str
    payload_version: int
    payload_sha256: str


def _schema_checks(sql):
    # Consume comments as tokens: commented-out constraints cannot prove admission.
    tokens = re.findall(r"--[^\n]*|/\*[\s\S]*?\*/|'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|"
                        r"[A-Za-z_][A-Za-z_0-9]*|\d+|<>|<=|>=|!=|[^\s]", sql)
    tokens = [t if t.startswith("'") else t.strip('"').lower() for t in tokens
              if not t.startswith(("--", "/*"))]
    checks = []
    for i, token in enumerate(tokens):
        if token != "check" or i + 1 == len(tokens) or tokens[i + 1] != "(":
            continue
        start, depth = i + 2, 1
        for end in range(start, len(tokens)):
            depth += (tokens[end] == "(") - (tokens[end] == ")")
            if depth == 0:
                checks.append(tuple(tokens[start:end]))
                break
        else:
            raise StorageError("STORE_INVALID", "Unsupported schema CHECK declaration")
    return sorted(checks)


def _freeze_preparation(value):
    if type(value) is dict:
        return MappingProxyType({k: _freeze_preparation(v) for k, v in value.items()})
    if type(value) is list:
        return tuple(_freeze_preparation(v) for v in value)
    return value


def _preparation_payload(value):
    """Closed version-1 wire payload; canonicalize only caller data, never saved bytes."""
    def invalid(message):
        raise StorageError("PREPARATION_INVALID", message)
    remaining = 4096
    def check(item, depth=0):
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > 16:
            invalid("JSON nodes/depth exceed bounded preparation")
        kind = type(item)
        if kind is dict:
            if len(item) > 256:
                invalid("Too many JSON keys")
            for key, child in item.items():
                raw = _utf8(key, "PREPARATION_INVALID")
                if not 1 <= len(raw) <= 128 or "\x00" in key:
                    invalid("Invalid bounded JSON key")
                check(child, depth + 1)
        elif kind is list:
            if len(item) > 256:
                invalid("Too many JSON list entries")
            for child in item:
                check(child, depth + 1)
        elif kind is str:
            if len(_utf8(item, "PREPARATION_INVALID")) > MAX_PREPARATION_BYTES:
                invalid("String exceeds preparation envelope")
        elif kind is int:
            if not -(2**53 - 1) <= item <= 2**53 - 1:
                invalid("JSON integer exceeds exact wire range")
        elif kind is float:
            if not math.isfinite(item):
                invalid("Nonfinite JSON value")
        elif kind not in (bool, type(None)):
            invalid("Only exact JSON types are supported")
    def keys(item, expected):
        if type(item) is not dict or set(item) != set(expected):
            invalid("Unsupported preparation fields")
    check(value)
    keys(value, ("payload_version", "checklist_row", "doc_refs", "source_spans"))
    if type(value["payload_version"]) is not int or value["payload_version"] != 1:
        invalid("Unsupported preparation payload version")
    row = value["checklist_row"]
    keys(row, ("name", "status", "next_action", "submission_summary"))
    for field, limit in (("name", 200), ("status", 32), ("next_action", 2048), ("submission_summary", 2048)):
        if type(row[field]) is not str or not row[field] or len(row[field]) > limit or "\x00" in row[field]:
            invalid("Invalid checklist row " + field)
    if row["status"] not in ("NEEDS_REVIEW", "PRESENT_UNCHECKED", "NOT_FOUND", "UNREADABLE", "CONFLICT", "NOT_APPLICABLE"):
        invalid("Unsupported checklist status")
    refs, spans = value["doc_refs"], value["source_spans"]
    if type(refs) is not list or len(refs) > 8 or type(spans) is not list or len(spans) > 256:
        invalid("Preparation reference/span count exceeds bounds")
    for ref in refs:
        keys(ref, ("package_id", "package_uuid", "file_id", "file_version", "sha256", "byte_count", "managed_relative_path"))
    for span in spans:
        keys(span, ("doc_ref", "page", "locator", "start", "end", "text"))
    try:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(text.encode("utf-8")) > MAX_PREPARATION_BYTES:
            invalid("Canonical preparation exceeds64KiB; no truncation")
        return text, json.loads(text)
    except StorageError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError):
        invalid("Preparation cannot encode as canonical UTF-8 JSON")


def _preparation_uuid(value):
    try:
        return _uuid(value)
    except StorageError:
        raise StorageError("PREPARATION_INVALID", "Preparation ID must be a canonical UUID") from None


def _preparation_write_admission(db):
    active = db.execute("SELECT phase FROM import_journal WHERE phase IN('RESERVED','STAGED','RENAMED','HOLD') LIMIT 1").fetchone()
    if active:
        raise StorageError("RECOVERY_HOLD" if active[0] == "HOLD" else "IMPORT_BUSY",
                           "Preparation writes require no active import in this store")


def _preparation_budget(root, db, payload_bytes=0):
    # Conservatively reserve new B-tree/overflow pages AND every old page's rollback image.
    page_size = db.execute("PRAGMA page_size").fetchone()[0]
    pages = db.execute("PRAGMA page_count").fetchone()[0]
    if not 512 <= page_size <= 65536 or not 0 < pages <= MAX_STORE_BYTES // page_size:
        raise StorageError("STORE_INVALID", "Untrustworthy database page budget")
    growth = ((payload_bytes + page_size - 1) // page_size + 16) * page_size
    _budget(root, growth + pages * (page_size + 8) + 65536, reserve_entries=1)


def _preparation_sources(root, db, package, payload, pins):
    """Verify each relevant owner; keep exact originals pinned through the SQL segment."""
    owners = {package.package_id: package}
    rows = []
    for ref in payload["doc_refs"]:
        try:
            owner = _find_package(db, ref["package_id"])
            _uuid(ref["file_id"])
            if (ref["package_uuid"] != owner.package_uuid or type(ref["file_version"]) is not int
                    or not 1 <= ref["file_version"] <= 2147483647 or type(ref["byte_count"]) is not int
                    or not 1 <= ref["byte_count"] <= 20971520 or type(ref["sha256"]) is not str
                    or re.fullmatch(r"[0-9a-f]{64}", ref["sha256"]) is None):
                raise ValueError()
            row = db.execute("SELECT * FROM files WHERE file_id=? AND package_uuid=?",
                             (ref["file_id"], owner.package_uuid)).fetchone()
            if row is None or any(not _same_wire_tree(ref[k], row[v]) for k, v in (
                    ("file_version", "version"), ("sha256", "sha256"), ("byte_count", "byte_count"),
                    ("managed_relative_path", "relative_path"))):
                raise ValueError()
            relative = "packages/" + owner.package_uuid + "/originals/" + ref["file_id"] + ".pdf"
            if ref["managed_relative_path"] != relative:
                raise ValueError()
        except (StorageError, ValueError, TypeError):
            raise StorageError("INTEGRITY_HOLD", "DocRef does not prove its managed owner/file/version/hash/bytes") from None
        owners[owner.package_id] = owner
        rows.append((owner, row, root / relative))
    views = {}
    for owner_id, owner in owners.items():
        view = _view(root, db, owner)
        if view.diagnostics:
            raise StorageError("INTEGRITY_HOLD", "Relevant preparation owner is held: " + owner_id)
        views[owner_id] = {record.file_id: record for record in view.files}
    records = []
    for owner, row, path in rows:
        pins.enter_context(_directory_guard(path.parent, anchor=root))
        handle = pdf.kernel32.CreateFileW(str(path), pdf.GENERIC_READ, pdf.FILE_SHARE_READ, None,
                                         pdf.OPEN_EXISTING, 0x00200080, None)
        if not handle or handle == pdf.INVALID_HANDLE_VALUE:
            raise StorageError("INTEGRITY_HOLD", "Cannot pin referenced original against writes/replacement")
        pins.callback(pdf.kernel32.CloseHandle, handle)
        info = pdf.BY_HANDLE_FILE_INFORMATION()
        if (not pdf.kernel32.GetFileInformationByHandle(handle, ctypes.byref(info))
                or info.dwFileAttributes & 0x410 or info.nNumberOfLinks != 1
                or pdf.kernel32.GetFileType(handle) != 1):
            raise StorageError("INTEGRITY_HOLD", "Referenced original pin is not a single regular disk file")
        _verify_original(path, row["byte_count"], row["sha256"], _decode_limits(row["limits_json"]))
        records.append(views[owner.package_id][row["file_id"]])
    for span in payload["source_spans"]:
        try:
            index, page_number, start, end = (span[k] for k in ("doc_ref", "page", "start", "end"))
            if (any(type(x) is not int for x in (index, page_number, start, end))
                    or not 0 <= index < len(records) or not 1 <= page_number <= 200
                    or not 0 <= start < end or type(span["text"]) is not str
                    or type(span["locator"]) is not str):
                raise ValueError()
            report = records[index].report
            page = report.pages[page_number - 1]
            if (not report.is_valid or page.page_index != page_number - 1 or page.state != "TEXT_EXTRACTABLE"
                    or any(w.startswith("EXCERPT_TRUNCATED") for w in (*report.warnings, *page.warnings))
                    or end > len(page.text) or span["locator"] != page.locator
                    or span["text"] != page.text[start:end]):
                raise ValueError()
        except (AttributeError, IndexError, TypeError, ValueError):
            raise StorageError("INTEGRITY_HOLD", "SourceSpan does not match complete persisted page/locator/text") from None


def _preparation_row(db, preparation_id):
    # Even corrupt rows written outside provider CHECKs cannot allocate an unbounded payload.
    return db.execute("""SELECT substr(preparation_id,1,37) AS preparation_id,
        substr(package_uuid,1,37) AS package_uuid, payload_version,
        substr(created_utc,1,65) AS created_utc,
        substr(CAST(payload_json AS BLOB),1,65537) AS payload_json,
        substr(payload_sha256,1,65) AS payload_sha256
        FROM preparations WHERE preparation_id=?""", (preparation_id,)).fetchone()


def _preparation_decode(package, row):
    try:
        if row is None:
            raise StorageError("PREPARATION_NOT_FOUND", "Saved preparation is absent for this package")
        _uuid(row["preparation_id"])
        if row["package_uuid"] != package.package_uuid:
            raise StorageError("PREPARATION_NOT_FOUND", "Saved preparation belongs to another package")
        if type(row["payload_version"]) is not int or row["payload_version"] != 1:
            raise ValueError()
        created = row["created_utc"]
        stamp = datetime.fromisoformat(created)
        if (len(_utf8(created, "INTEGRITY_HOLD")) > 64 or stamp.tzinfo is None
                or stamp.utcoffset().total_seconds() != 0 or stamp.isoformat() != created):
            raise ValueError()
        raw = row["payload_json"]
        if type(raw) is not bytes or not 1 <= len(raw) <= MAX_PREPARATION_BYTES:
            raise ValueError()
        def pairs(items):
            value = {}
            for key, child in items:
                if key in value:
                    raise ValueError()
                value[key] = child
            return value
        def constant(value):
            raise ValueError()
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
        text, value = _preparation_payload(value)
        digest = hashlib.sha256(raw).hexdigest()
        if text.encode("utf-8") != raw or row["payload_sha256"] != digest:
            raise ValueError()
        return PreparationSnapshot(package.package_id, row["preparation_id"], 1, created,
                                   digest, _freeze_preparation(value)), value
    except StorageError as error:
        if error.code == "PREPARATION_NOT_FOUND":
            raise
        raise StorageError("INTEGRITY_HOLD", "Saved preparation contract/checksum is untrustworthy; preserve snapshot") from None
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise StorageError("INTEGRITY_HOLD", "Saved preparation contract/checksum is untrustworthy; preserve snapshot") from None


def upgrade_preparation_store(root: Path) -> int:
    """Explicit, idempotent schema1->2 upgrade of an existing, quiescent admitted store."""
    with _store(root) as (root, db), _transaction(db):
        _preparation_write_admission(db)
        packages = db.execute("SELECT * FROM packages").fetchmany(MAX_ENTRIES + 1)
        if len(packages) > MAX_ENTRIES:
            raise StorageError("STORE_BUDGET_EXCEEDED", "Upgrade package inventory exceeds bounds")
        for row in packages:
            if _view(root, db, _package(row)).diagnostics:
                raise StorageError("INTEGRITY_HOLD", "Upgrade requires proved original/report ownership")
        if db.execute("PRAGMA user_version").fetchone()[0] == 2:
            return 2
        _preparation_budget(root, db)
        db.execute(_PREPARATION_SQL)
        db.execute("PRAGMA user_version=2")
    return 2


def save_preparation(root: Path, package_id: str, preparation_id: str, payload) -> PreparationSnapshot:
    """Append one bounded snapshot; canonical UUID retries never replace history."""
    _validate_package_id(package_id)
    _preparation_uuid(preparation_id)
    text, value = _preparation_payload(payload)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    with _store(root) as (root, db), ExitStack() as pins, _transaction(db):
        if db.execute("PRAGMA user_version").fetchone()[0] != 2:
            raise StorageError("CONFIG_ERROR", "Explicit upgrade_preparation_store is required; no auto migration")
        package = _find_package(db, package_id)
        _preparation_write_admission(db)
        previous = _preparation_row(db, preparation_id)
        if previous is not None:
            if previous["package_uuid"] != package.package_uuid:
                raise StorageError("PREPARATION_CONFLICT", "Preparation UUID already belongs to another package")
            saved, old_value = _preparation_decode(package, previous)
            if saved.payload_sha256 != digest or previous["payload_json"] != text.encode("utf-8"):
                raise StorageError("PREPARATION_CONFLICT", "Preparation UUID already has different canonical content")
            _preparation_sources(root, db, package, old_value, pins)
            return saved
        _preparation_sources(root, db, package, value, pins)
        _preparation_budget(root, db, len(text.encode("utf-8")))
        created = _now()
        db.execute("INSERT INTO preparations VALUES(?,?,?,?,?,?)",
                   (preparation_id, package.package_uuid, 1, created, text, digest))
        return PreparationSnapshot(package_id, preparation_id, 1, created, digest, _freeze_preparation(value))


def open_preparation(root: Path, package_id: str, preparation_id: str) -> PreparationSnapshot:
    """Load exact saved data and prove managed sources, without external parsing or writes."""
    _validate_package_id(package_id)
    _preparation_uuid(preparation_id)
    with _store(root) as (root, db), db.gate.hold(), ExitStack() as pins:
        if db.execute("PRAGMA user_version").fetchone()[0] != 2:
            raise StorageError("CONFIG_ERROR", "Explicit upgrade_preparation_store is required; no auto migration")
        package = _find_package(db, package_id)
        saved, value = _preparation_decode(package, _preparation_row(db, preparation_id))
        _preparation_sources(root, db, package, value, pins)
        return saved


def list_preparations(root: Path, package_id: str) -> tuple[PreparationSummary, ...]:
    """Read bounded saved headers for one owner; payloads remain unopened."""
    _validate_package_id(package_id)
    with _store(root) as (root, db), db.gate.hold():
        if db.execute("PRAGMA user_version").fetchone()[0] != 2:
            raise StorageError("CONFIG_ERROR", "Explicit upgrade_preparation_store is required; no auto migration")
        package = _find_package(db, package_id)
        rows = db.execute("""SELECT substr(preparation_id,1,37) AS preparation_id,
            substr(created_utc,1,65) AS created_utc,
            CASE WHEN typeof(payload_version)='integer' THEN payload_version END AS payload_version,
            substr(payload_sha256,1,65) AS payload_sha256
            FROM preparations WHERE package_uuid=? ORDER BY preparation_id""",
            (package.package_uuid,)).fetchmany(MAX_ENTRIES + 1)
        if len(rows) > MAX_ENTRIES:
            raise StorageError("STORE_BUDGET_EXCEEDED", "Preparation inventory exceeds bounded read")
        summaries = []
        for row in rows:
            try:
                _uuid(row["preparation_id"])
                created = row["created_utc"]
                stamp = datetime.fromisoformat(created)
                if (len(_utf8(created, "INTEGRITY_HOLD")) > 64 or stamp.tzinfo is None
                        or stamp.utcoffset().total_seconds() != 0 or stamp.isoformat() != created
                        or type(row["payload_version"]) is not int or row["payload_version"] != 1
                        or re.fullmatch(r"[0-9a-f]{64}", row["payload_sha256"]) is None):
                    raise ValueError()
                summaries.append(PreparationSummary(row["preparation_id"], created,
                    row["payload_version"], row["payload_sha256"]))
            except (StorageError, ValueError, TypeError, UnicodeError, OverflowError):
                raise StorageError("INTEGRITY_HOLD",
                    "Saved preparation header is untrustworthy; preserve snapshot") from None
        return tuple(summaries)
