"""WP01 local package/intake provider; original availability is not readability."""
from contextlib import contextmanager, ExitStack, nullcontext
import ctypes
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import threading
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
    "REPORT_CONTRACT_REJECTED", "VERSION_LIMIT", "PLATFORM_UNSUPPORTED"))

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

def _budget(root, reserve=0):
    total = 0
    entries = 0
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
    """Nonwaiting cooperative writers across Windows sessions, keyed by pinned root."""
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
    """Prove the version-1 constraints without changing the persistent schema."""
    def unique_keys(connection, table):
        indexes = connection.execute('SELECT name FROM pragma_index_list(?) WHERE "unique"=1 AND partial=0', (table,))
        return {tuple(tuple(row) for row in connection.execute(
                    'SELECT name,coll FROM pragma_index_xinfo(?) WHERE "key"=1 ORDER BY seqno', (name,)))
                for (name,) in indexes}

    reference = sqlite3.connect(":memory:", isolation_level=None)
    try:
        _initialize_schema(reference)
        for table in ("packages", "files", "import_journal"):
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
                if db.execute("PRAGMA user_version").fetchone()[0] != 1:
                    raise StorageError("STORE_INVALID", "Unsupported store schema; no migration/repair")
                tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if tables != {"packages", "files", "import_journal"} or db.execute("PRAGMA foreign_key_check").fetchone():
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
