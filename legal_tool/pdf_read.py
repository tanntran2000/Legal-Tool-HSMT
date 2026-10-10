"""Bounded PDF reading models, types, and inspection API."""

import ctypes
from ctypes import wintypes
import hashlib
import io
import math
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
import os
from typing import List, Optional, Tuple
import zlib

from pypdf import PdfReader

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
kernel32.GetFileAttributesW.restype = wintypes.DWORD

kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
kernel32.CreateFileW.restype = wintypes.HANDLE

kernel32.GetFileType.argtypes = [wintypes.HANDLE]
kernel32.GetFileType.restype = wintypes.DWORD


class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", wintypes.FILETIME),
        ("ftLastAccessTime", wintypes.FILETIME),
        ("ftLastWriteTime", wintypes.FILETIME),
        ("dwVolumeSerialNumber", wintypes.DWORD),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("nNumberOfLinks", wintypes.DWORD),
        ("nFileIndexHigh", wintypes.DWORD),
        ("nFileIndexLow", wintypes.DWORD),
    ]


kernel32.GetFileInformationByHandle.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(BY_HANDLE_FILE_INFORMATION),
]
kernel32.GetFileInformationByHandle.restype = wintypes.BOOL

kernel32.GetFinalPathNameByHandleW.argtypes = [
    wintypes.HANDLE,
    wintypes.LPWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
]
kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD

kernel32.ReadFile.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,
]
kernel32.ReadFile.restype = wintypes.BOOL

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_TYPE_DISK = 0x0001
FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value


def _read_file_snapshot(
    resolved_path: Path, max_bytes: int
) -> Tuple[Optional[bytes], Optional[str], Optional[int]]:
    """Capture an immutable byte snapshot using a stable, read-only Win32 disk handle.

    Verifies opened handle type, attributes, final path identity, and ancestors before
    and during reading. Fails closed on any guard failure or identity mismatch.
    Returns (raw_bytes, error_warning, observed_size).
    """
    str_path = str(resolved_path)
    expected_norm = os.path.normcase(os.path.abspath(str_path))

    h = kernel32.CreateFileW(
        str_path,
        GENERIC_READ,
        FILE_SHARE_READ,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if h == INVALID_HANDLE_VALUE or not h:
        err = kernel32.GetLastError()
        return None, f"OPEN_FAILED: unable to open file handle (error {err})", None

    try:
        file_type = kernel32.GetFileType(h)
        if file_type != FILE_TYPE_DISK:
            return None, "PATH_ADMISSION_FAILED: opened handle is not a disk file", None

        info = BY_HANDLE_FILE_INFORMATION()
        if not kernel32.GetFileInformationByHandle(h, ctypes.byref(info)):
            return None, "PATH_ADMISSION_FAILED: unable to retrieve file information from handle", None

        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
            return None, "REPARSE_POINT_REFUSED: opened handle points to a reparse point", None

        st_size = (info.nFileSizeHigh << 32) + info.nFileSizeLow
        if st_size > max_bytes:
            return None, None, st_size

        buf = ctypes.create_unicode_buffer(1024)
        res = kernel32.GetFinalPathNameByHandleW(h, buf, 1024, 0)
        if res == 0 or res > 1024:
            return None, "PATH_ADMISSION_FAILED: unable to resolve final path from opened handle", None

        final_raw = buf.value
        clean_final = final_raw[4:] if final_raw.startswith("\\\\?\\") else final_raw
        final_norm = os.path.normcase(os.path.abspath(clean_final))

        if final_norm != expected_norm:
            return (
                None,
                f"PATH_ADMISSION_FAILED: opened path identity mismatch (expected {expected_norm}, got {final_norm})",
                None,
            )

        anc_error = _check_path_admission(Path(clean_final))
        if anc_error is not None:
            return None, anc_error, None

        chunks = []
        total_read = 0
        chunk_size = 65536
        read_buf = ctypes.create_string_buffer(chunk_size)
        bytes_read = wintypes.DWORD(0)

        while total_read <= max_bytes:
            to_read = min(chunk_size, (max_bytes + 1) - total_read)
            ok = kernel32.ReadFile(h, read_buf, to_read, ctypes.byref(bytes_read), None)
            if not ok:
                return None, "READ_ERROR: ReadFile failed while capturing snapshot", None
            if bytes_read.value == 0:
                break
            chunks.append(read_buf.raw[: bytes_read.value])
            total_read += bytes_read.value

        raw_bytes = b"".join(chunks)
        return raw_bytes, None, total_read

    except Exception as exc:
        return None, f"PATH_ADMISSION_FAILED: unexpected handle verification failure ({exc})", None
    finally:
        kernel32.CloseHandle(h)


def _check_path_admission(path: Path) -> Optional[str]:
    """Check path and all ancestor directories for symlinks or reparse points (junctions).

    Fails closed on any error, returning a diagnostic string, or None if safely admitted.
    """
    try:
        orig = Path(path)
        for cur in (orig, *orig.parents):
            s = str(cur)
            if not s or cur == cur.parent:
                continue
            attrs = kernel32.GetFileAttributesW(s)
            if attrs == 0xFFFFFFFF:
                return "PATH_ADMISSION_FAILED: unable to verify file attributes"
            if attrs & 0x400:  # FILE_ATTRIBUTE_REPARSE_POINT (0x400)
                return "REPARSE_POINT_REFUSED: symlink or reparse point refused"
            if cur.is_symlink():
                return "REPARSE_POINT_REFUSED: symlink or reparse point refused"
        return None
    except Exception as exc:
        return f"PATH_ADMISSION_FAILED: path inspection failed ({exc})"


@dataclass(frozen=True)
class ImportLimits:
    """Safe resource bounds for PDF inspection and ingestion."""

    max_file_bytes: int = 20 * 1024 * 1024  # 20 MiB per file ceiling
    max_pages: int = 200  # Approved upper bound for WP01 ceiling
    max_stream_bytes: int = 2 * 1024 * 1024  # 2 MiB decoded content stream per page ceiling
    timeout_seconds: float = 20.0  # 20 seconds execution limit ceiling
    worker_memory_mb: int = 512  # 512 MiB worker memory cap ceiling
    max_excerpt_page_chars: int = 2000  # Excerpt bound per page ceiling
    max_excerpt_file_chars: int = 100000  # Aggregate excerpt bound ceiling

    def __post_init__(self):
        """Strict validation of all resource bounds against types, positivity, and approved ceilings."""
        # Type validations: reject bool and non-int for integer limits
        for name in (
            "max_file_bytes",
            "max_pages",
            "max_stream_bytes",
            "worker_memory_mb",
            "max_excerpt_page_chars",
            "max_excerpt_file_chars",
        ):
            val = getattr(self, name)
            if type(val) is bool or not isinstance(val, int):
                raise ValueError(f"Limit '{name}' must be an integer, got {type(val).__name__}")

        # Float / timeout validation
        if type(self.timeout_seconds) is bool or not isinstance(self.timeout_seconds, (int, float)):
            raise ValueError(f"Limit 'timeout_seconds' must be numeric, got {type(self.timeout_seconds).__name__}")
        if not math.isfinite(self.timeout_seconds):
            raise ValueError("Limit 'timeout_seconds' must be a finite number")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 20.0:
            raise ValueError(f"Limit 'timeout_seconds' must be within (0, 20.0], got {self.timeout_seconds}")

        # Int bounds and ceilings
        if self.max_file_bytes <= 0 or self.max_file_bytes > 20 * 1024 * 1024:
            raise ValueError(f"Limit 'max_file_bytes' must be within [1, 20971520], got {self.max_file_bytes}")
        if self.max_pages <= 0 or self.max_pages > 200:
            raise ValueError(f"Limit 'max_pages' must be within [1, 200], got {self.max_pages}")
        if self.max_stream_bytes <= 0 or self.max_stream_bytes > 2 * 1024 * 1024:
            raise ValueError(f"Limit 'max_stream_bytes' must be within [1, 2097152], got {self.max_stream_bytes}")
        if self.worker_memory_mb <= 0 or self.worker_memory_mb > 512:
            raise ValueError(f"Limit 'worker_memory_mb' must be within [1, 512], got {self.worker_memory_mb}")
        if self.max_excerpt_page_chars <= 0 or self.max_excerpt_page_chars > 2000:
            raise ValueError(f"Limit 'max_excerpt_page_chars' must be within [1, 2000], got {self.max_excerpt_page_chars}")
        if self.max_excerpt_file_chars <= 0 or self.max_excerpt_file_chars > 100000:
            raise ValueError(f"Limit 'max_excerpt_file_chars' must be within [1, 100000], got {self.max_excerpt_file_chars}")


@dataclass
class PageReading:
    """Reading diagnostics and extracted text for an individual page."""

    page_index: int
    state: str  # TEXT_EXTRACTABLE, IMAGE_ONLY, MIXED, UNKNOWN
    text: str = ""
    locator: str = ""
    warnings: List[str] = field(default_factory=list)


@dataclass
class ReadReport:
    """Overall inspection report for a PDF document."""

    path: Path
    page_count: int = 0
    read_state: str = "UNKNOWN"  # TEXT_EXTRACTABLE, IMAGE_ONLY, MIXED, LOCKED, CORRUPT, UNSUPPORTED, LIMIT, UNKNOWN
    pages: List[PageReading] = field(default_factory=list)
    parser_version: str = "pypdf/6.10.0"
    rule_version: str = "wp01-v2-dq"
    sha256: str = ""
    warnings: List[str] = field(default_factory=list)
    is_valid: bool = False
    excerpt: str = ""


PARSER_VERSION = "pypdf/6.10.0"
RULE_VERSION = "wp01-v2-dq"
ALLOWED_PAGE_STATES = {"TEXT_EXTRACTABLE", "IMAGE_ONLY", "MIXED", "UNKNOWN"}
ALLOWED_COMPLETED_DOC_STATES = {"TEXT_EXTRACTABLE", "IMAGE_ONLY", "MIXED", "UNKNOWN"}
ALLOWED_FAILURE_DOC_STATES = {"LOCKED", "CORRUPT", "UNSUPPORTED", "LIMIT"}
ALLOWED_DOC_STATES = ALLOWED_COMPLETED_DOC_STATES | ALLOWED_FAILURE_DOC_STATES

ALLOWED_MISSING_HASH_PREFIXES = (
    "CONFIG_ERROR",
    "UNC_PATH_REFUSED",
    "DEVICE_PATH_REFUSED",
    "PATH_NOT_FOUND",
    "NOT_A_REGULAR_FILE",
    "PATH_ADMISSION_FAILED",
    "REPARSE_POINT_REFUSED",
    "OPEN_FAILED",
    "READ_ERROR",
    "FILE_SIZE_LIMIT_EXCEEDED",
    "UNSUPPORTED_FORMAT",
    "LIMIT_GUARD_UNAVAILABLE",
    "TIMEOUT_LIMIT_EXCEEDED",
    "CHILD_PROCESS_ERROR",
    "WORKER_EXECUTION_ERROR",
)


def _cap_diagnostic_utf8(diagnostic: str, max_bytes: int = 4096) -> str:
    """Ensure diagnostic string encodes to <= max_bytes in UTF-8, truncated at a valid codepoint boundary."""
    raw = str(diagnostic).encode("utf-8", errors="replace")
    return raw[:max_bytes].decode("utf-8", errors="ignore")


def derive_document_state(pages: List[PageReading]) -> str:
    """Derive aggregate document state from sequential page states."""
    page_states = [p.state for p in pages]
    if any(s == "MIXED" for s in page_states) or ("TEXT_EXTRACTABLE" in page_states and "IMAGE_ONLY" in page_states):
        return "MIXED"
    if any(s == "TEXT_EXTRACTABLE" for s in page_states):
        return "TEXT_EXTRACTABLE"
    if any(s == "IMAGE_ONLY" for s in page_states):
        return "IMAGE_ONLY"
    return "UNKNOWN"


def derive_excerpt(pages: List[PageReading], max_chars: int) -> str:
    """Derive document excerpt strictly from page texts up to max_chars."""
    return "\n\n".join(p.text for p in pages if p.text)[:max_chars]


def calculate_aggregate_warning_bytes(doc_warnings: List[str], pages: List[PageReading]) -> int:
    """Calculate aggregate UTF-8 byte size of all document and page warnings joined by newline."""
    all_msgs = list(doc_warnings)
    for p in pages:
        all_msgs.extend(p.warnings)
    if not all_msgs:
        return 0
    return len("\n".join(all_msgs).encode("utf-8"))


def _path_is_utf8(path: Path | str) -> bool:
    """Require a serializable path for admission and report identity."""
    try:
        str(path).encode("utf-8")
    except UnicodeError:
        return False
    return True


def _build_failure_report(
    admitted_path: Path,
    read_state: str,
    warnings: List[str],
    page_count: int = 0,
    sha256: str = "",
) -> ReadReport:
    """Construct a uniform terminal failure report with empty pages and excerpt."""
    bounded_warnings: List[str] = []
    total_bytes = 0
    for w in warnings:
        capped = _cap_diagnostic_utf8(str(w), 4096)
        wb = len(capped.encode("utf-8"))
        sep = 1 if bounded_warnings else 0
        if total_bytes + sep + wb <= 4096:
            bounded_warnings.append(capped)
            total_bytes += sep + wb
        else:
            rem = 4096 - total_bytes - sep
            if rem > 0:
                short = _cap_diagnostic_utf8(capped, rem)
                if short:
                    bounded_warnings.append(short)
            break
    if not bounded_warnings:
        first_w = str(warnings[0]) if warnings else "FAILURE"
        bounded_warnings = [_cap_diagnostic_utf8(first_w, 4096)]

    return ReadReport(
        # This sentinel marks an input that cannot have an admitted UTF-8 identity.
        path=admitted_path if _path_is_utf8(admitted_path) else Path("<unadmitted-path>"),
        page_count=page_count,
        read_state=read_state,
        pages=[],
        parser_version=PARSER_VERSION,
        rule_version=RULE_VERSION,
        sha256=sha256,
        warnings=bounded_warnings,
        is_valid=False,
        excerpt="",
    )


def _revalidate_limits(limits: Optional[ImportLimits]) -> ImportLimits:
    """Reconstruct all bounds, including existing instances, before resource use."""
    return ImportLimits(**asdict(limits)) if limits is not None else ImportLimits()


def _report_to_wire(report: ReadReport) -> dict:
    """Adapt DTO containers without repairing, filtering or coercing field values."""
    data = {f.name: getattr(report, f.name) for f in fields(ReadReport)}
    if not isinstance(data["path"], Path):
        raise _ReportContractError("DTO path must be a Path")
    data["path"] = str(data["path"])
    if type(data["pages"]) is list:
        if any(type(page) is not PageReading for page in data["pages"]):
            raise _ReportContractError("DTO page must be a PageReading")
        data["pages"] = [
            {f.name: getattr(page, f.name) for f in fields(PageReading)}
            for page in data["pages"]
        ]
    return data


class _ReportContractError(ValueError):
    """Fixed, bounded reason from the shared validation policy."""


_REPORT_FIELD_TYPES = {
    "path": str, "page_count": int, "read_state": str, "pages": list,
    "parser_version": str, "rule_version": str, "sha256": str,
    "warnings": list, "is_valid": bool, "excerpt": str,
}
_PAGE_FIELD_TYPES = {
    "page_index": int, "state": str, "text": str, "locator": str, "warnings": list,
}


def _require_report_fields(data: dict, schema: dict, location: str) -> None:
    if type(data) is not dict:
        raise _ReportContractError(location + " must be an object")
    if data.keys() != schema.keys():
        raise _ReportContractError(location + " unexpected or missing fields")
    for name, expected_type in schema.items():
        if name not in data or type(data[name]) is not expected_type:
            raise _ReportContractError(location + " missing or invalid " + name)


def _validate_warnings(warnings: List[str]) -> None:
    for warning in warnings:
        if type(warning) is not str:
            raise _ReportContractError("warning must be a string")
        warning.encode("utf-8")


def _missing_hash_code(warnings: List[str]) -> str:
    return next((code for warning in warnings for code in ALLOWED_MISSING_HASH_PREFIXES
                 if warning.startswith(code + ":")), "")


def _validate_report(
    admitted_path: Path, limits: ImportLimits, data: dict, captured_sha256: str,
    *, historical: bool = False,
) -> ReadReport:
    """One predicate for DTO adaptations and received wire fields; no repairs."""
    _require_report_fields(data, _REPORT_FIELD_TYPES, "report")
    _validate_warnings(data["warnings"])
    data["excerpt"].encode("utf-8")
    if not _path_is_utf8(data["path"]) or not _path_is_utf8(admitted_path):
        raise _ReportContractError("report path must encode as UTF-8")
    versions = ("wp01-v1", RULE_VERSION) if historical else (RULE_VERSION,)
    if data["parser_version"] != PARSER_VERSION or data["rule_version"] not in versions:
        raise _ReportContractError("unexpected parser or rule version")
    try:
        identity_matches = os.path.normcase(os.path.abspath(data["path"])) == os.path.normcase(
            os.path.abspath(str(admitted_path)))
    except Exception:
        raise _ReportContractError("invalid report path") from None
    if not identity_matches:
        raise _ReportContractError("report path does not match admitted source")

    count, valid, state = data["page_count"], data["is_valid"], data["read_state"]
    if count < 0:
        raise _ReportContractError("negative page_count")
    allowed_states = ALLOWED_COMPLETED_DOC_STATES if valid else ALLOWED_FAILURE_DOC_STATES
    if state not in allowed_states:
        raise _ReportContractError("read_state and is_valid are inconsistent")
    if valid:
        if count > limits.max_pages or len(data["pages"]) != count:
            raise _ReportContractError("completed page inventory does not match bounded count")
    elif data["pages"] or data["excerpt"]:
        raise _ReportContractError("failure must have empty pages and excerpt")

    child_sha = data["sha256"]
    if state == "LOCKED" and not child_sha:
        raise _ReportContractError("LOCKED report requires captured sha256")
    if child_sha:
        if len(child_sha) != 64 or any(c not in "0123456789abcdef" for c in child_sha):
            raise _ReportContractError("invalid sha256")
        if captured_sha256 and child_sha != captured_sha256:
            raise _ReportContractError("sha256 does not match captured source")
    elif valid or count != 0 or not _missing_hash_code(data["warnings"]):
        raise _ReportContractError("missing sha256 without count0 and an exact permitted error code")

    pages: List[PageReading] = []
    total_chars = 0
    for index, page in enumerate(data["pages"]):
        _require_report_fields(page, _PAGE_FIELD_TYPES, "page")
        _validate_warnings(page["warnings"])
        page["text"].encode("utf-8")
        if page["page_index"] != index:
            raise _ReportContractError("invalid sequential page_index")
        if page["locator"] != f"page-{index + 1}":
            raise _ReportContractError("invalid page locator")
        if page["state"] not in ALLOWED_PAGE_STATES:
            raise _ReportContractError("invalid page state")
        if len(page["text"]) > limits.max_excerpt_page_chars:
            raise _ReportContractError("page text exceeds excerpt budget")
        total_chars += len(page["text"])
        pages.append(PageReading(
            page_index=index, state=page["state"], text=page["text"],
            locator=page["locator"], warnings=list(page["warnings"]),
        ))
    if total_chars > limits.max_excerpt_file_chars:
        raise _ReportContractError("cumulative page text exceeds excerpt budget")
    if valid and (state != derive_document_state(pages)
                  or data["excerpt"] != derive_excerpt(pages, limits.max_excerpt_file_chars)):
        raise _ReportContractError("document state or excerpt does not match retained pages")
    return ReadReport(
        path=admitted_path, page_count=count, read_state=state, pages=pages,
        parser_version=data["parser_version"], rule_version=data["rule_version"],
        sha256=child_sha, warnings=list(data["warnings"]), is_valid=valid, excerpt=data["excerpt"],
    )


_PAGE_DIAGNOSTICS = {
    "EXCERPT_TRUNCATED": (1, 0),
    "TEXT_QUALITY": (0, 1),
    "EXCERPT_TRUNCATED;Q": (1, 1),
}
_RESERVED_DIAGNOSTICS = ("EXCERPT_TRUNCATED", "TEXT_QUALITY", "D2")


def _page_diagnostic_flags(page: PageReading) -> tuple[int, int]:
    flags = (0, 0)
    for index, warning in enumerate(page.warnings):
        if warning.startswith(_RESERVED_DIAGNOSTICS):
            if index != 0 or warning not in _PAGE_DIAGNOSTICS:
                raise _ReportContractError("invalid reserved page diagnostic")
            flags = _PAGE_DIAGNOSTICS[warning]
    if flags[1] and page.state not in {"MIXED", "UNKNOWN"}:
        raise _ReportContractError("quality diagnostic contradicts page state")
    return flags


def _diagnostic_summary(pages: List[PageReading]) -> str:
    """Count retained states and tokens without dropping unknown facts."""
    flags = [_page_diagnostic_flags(page) for page in pages]
    truncated = sum(flag[0] for flag in flags)
    quality = sum(flag[1] for flag in flags)
    states = [page.state for page in pages]
    summary = (f"D2;P={len(pages)};T={truncated};Q={quality};"
               f"M={states.count('MIXED')};I={states.count('IMAGE_ONLY')};U={states.count('UNKNOWN')}")
    return ("EXCERPT_TRUNCATED;" if truncated else "") + summary


def _validate_v2_diagnostics(report: ReadReport) -> None:
    """Require canonical counts/tokens only after raw warning-byte admission."""
    if not report.is_valid:
        return
    if not report.warnings or report.warnings[0] != _diagnostic_summary(report.pages):
        raise _ReportContractError("document diagnostic summary contradicts retained pages")
    if any(warning.startswith(_RESERVED_DIAGNOSTICS) for warning in report.warnings[1:]):
        raise _ReportContractError("invalid reserved document diagnostic")


def _publish_report(
    admitted_path: Path,
    limits: ImportLimits,
    raw_report: ReadReport | dict,
    captured_sha256: str = "",
    is_child_payload: bool = False,
    *, historical: bool = False,
) -> ReadReport:
    """Publish only reports accepted by the common shape/identity/state predicate.

    Parent capture is comparison context. A legitimate empty report hash remains
    empty. Received overflow is rejected; consistent generated overflow retains
    its observed count/hash under LIMIT_DIAGNOSTIC_BUDGET.
    """
    received = is_child_payload or type(raw_report) is dict
    try:
        data = _report_to_wire(raw_report) if type(raw_report) is ReadReport else raw_report
        report = _validate_report(admitted_path, limits, data, captured_sha256, historical=historical)
        warning_bytes = calculate_aggregate_warning_bytes(report.warnings, report.pages)
        if warning_bytes <= 4096 and report.rule_version == RULE_VERSION:
            _validate_v2_diagnostics(report)
    except _ReportContractError as exc:
        reason = str(exc)
    except UnicodeError:
        reason = "report text, excerpt or warnings must encode as UTF-8"
    except Exception:
        reason = "malformed report object"
    else:
        if warning_bytes <= 4096:
            return report
        if not received:
            diagnostics = [f"LIMIT_DIAGNOSTIC_BUDGET: aggregate warnings {warning_bytes} exceed budget 4096"]
            if not report.sha256:
                code = _missing_hash_code(report.warnings)
                diagnostics.append(code + ": originating failure exceeded diagnostic budget")
            return _build_failure_report(
                admitted_path, "LIMIT", diagnostics,
                page_count=report.page_count, sha256=report.sha256,
            )
        reason = "aggregate warning bytes exceed 4096 budget"
    return _build_failure_report(admitted_path, "LIMIT", ["CHILD_PROCESS_ERROR: " + reason])


def publish_report(
    admitted_path: Path, limits: ImportLimits, raw_report: ReadReport | dict,
    captured_sha256: str = "", is_child_payload: bool = False,
) -> ReadReport:
    """Fresh producers and received worker output require the current rule."""
    return _publish_report(admitted_path, limits, raw_report, captured_sha256, is_child_payload)


def _publish_persisted_report(
    path: Path, limits: ImportLimits, data: dict, captured_sha256: str,
) -> ReadReport:
    """Explicit stored-report context; legacy facts are readable, never upgraded."""
    return _publish_report(path, limits, data, captured_sha256, True, historical=True)


def _get_page_count_bounded(reader: PdfReader, max_pages: int) -> Tuple[int, bool]:
    """Calculate page count boundedly by traversing leaves without trusting declared /Count blindly."""
    try:
        root = reader.root_object
        if "/Pages" not in root:
            return 0, True

        pages_node = root["/Pages"]
        if hasattr(pages_node, "get_object"):
            pages_node = pages_node.get_object()

        # Early refusal if declared /Count is already over cap
        if "/Count" in pages_node:
            try:
                cnt = int(pages_node["/Count"])
                if cnt > max_pages:
                    if reader.flattened_pages is None:
                        reader.flattened_pages = []
                    return cnt, False
            except Exception:
                pass

        # Bounded leaf traversal with cycle detection and max-node budget
        visited = set()
        stack = [pages_node]
        leaf_count = 0
        max_traversal_nodes = 500

        while stack:
            if len(visited) > max_traversal_nodes:
                if reader.flattened_pages is None:
                    reader.flattened_pages = []
                return leaf_count, False

            curr = stack.pop()
            if hasattr(curr, "get_object"):
                curr_id = getattr(curr, "idnum", None)
                if curr_id is not None:
                    if curr_id in visited:
                        # Cycle detected
                        if reader.flattened_pages is None:
                            reader.flattened_pages = []
                        return leaf_count, False
                    visited.add(curr_id)
                curr = curr.get_object()

            if not isinstance(curr, dict):
                continue

            node_type = curr.get("/Type")
            if node_type == "/Page":
                leaf_count += 1
                if leaf_count > max_pages:
                    if reader.flattened_pages is None:
                        reader.flattened_pages = []
                    return leaf_count, False
            elif node_type == "/Pages" or "/Kids" in curr:
                kids = curr.get("/Kids", [])
                for kid in reversed(kids):
                    stack.append(kid)

        return leaf_count, (leaf_count <= max_pages)
    except Exception:
        if reader.flattened_pages is None:
            reader.flattened_pages = []
        return 0, True


def _decode_ascii85_bounded(data: bytes, max_bytes: int) -> bytes:
    """Decode ASCII85 byte stream bounded strictly by max_bytes + 1 output bytes."""
    if isinstance(data, str):
        data = data.encode("latin1")
    data = data.strip()
    if data.startswith(b"<~"):
        data = data[2:]
    if data.endswith(b"~>"):
        data = data[:-2]
    elif data.endswith(b">"):
        data = data[:-1]

    out = bytearray()
    group = []

    for b in data:
        if b in b" \t\n\r\v":
            continue
        if b == ord(b"z"):
            if group:
                raise ValueError("Invalid z inside ASCII85 group")
            out.extend(b"\x00\x00\x00\x00")
            if len(out) > max_bytes:
                return bytes(out[: max_bytes + 1])
            continue

        if b < 33 or b > 117:
            raise ValueError(f"Invalid ASCII85 character byte: {b}")

        group.append(b - 33)
        if len(group) == 5:
            val = (
                group[0] * 52200625
                + group[1] * 614125
                + group[2] * 7225
                + group[3] * 85
                + group[4]
            )
            if val > 0xFFFFFFFF:
                raise ValueError("ASCII85 value overflow")
            out.extend(val.to_bytes(4, "big"))
            group.clear()
            if len(out) > max_bytes:
                return bytes(out[: max_bytes + 1])

    if group:
        pad = 5 - len(group)
        for _ in range(pad):
            group.append(84)
        val = (
            group[0] * 52200625
            + group[1] * 614125
            + group[2] * 7225
            + group[3] * 85
            + group[4]
        )
        b_all = val.to_bytes(4, "big")
        out.extend(b_all[: 4 - pad])

    return bytes(out[: max_bytes + 1])


def _decode_asciihex_bounded(data: bytes, max_bytes: int) -> bytes:
    """Decode ASCIIHex byte stream bounded strictly by max_bytes + 1 output bytes."""
    if isinstance(data, str):
        data = data.encode("latin1")
    data = data.strip()
    if data.endswith(b">"):
        data = data[:-1]

    out = bytearray()
    curr = None

    for b in data:
        if b in b" \t\n\r\v":
            continue
        if 48 <= b <= 57:
            v = b - 48
        elif 65 <= b <= 70:
            v = b - 65 + 10
        elif 97 <= b <= 102:
            v = b - 97 + 10
        else:
            raise ValueError(f"Invalid character in ASCIIHex: {b}")

        if curr is None:
            curr = v
        else:
            out.append((curr << 4) | v)
            curr = None
            if len(out) > max_bytes:
                return bytes(out[: max_bytes + 1])

    if curr is not None:
        out.append(curr << 4)

    return bytes(out[: max_bytes + 1])


def _decode_stream_bounded(stm, max_bytes: int) -> int:
    """Decode content stream with strict byte limit and without calling unbounded decoders."""
    filters = stm.get("/Filter", ())
    if hasattr(filters, "get_object"):
        filters = filters.get_object()
    if not isinstance(filters, (list, tuple)):
        filters = (filters,) if filters else ()

    data = getattr(stm, "_data", b"")
    if not data:
        return 0

    for filt in filters:
        if filt == "/ASCII85Decode":
            # Intermediate filter bound is max_file_bytes; final filter bound is max_bytes
            bound = max_bytes if filt == filters[-1] else 20 * 1024 * 1024
            data = _decode_ascii85_bounded(data, bound)
            if len(data) > max_bytes and filt == filters[-1]:
                return max_bytes + 1
        elif filt == "/ASCIIHexDecode":
            bound = max_bytes if filt == filters[-1] else 20 * 1024 * 1024
            data = _decode_asciihex_bounded(data, bound)
            if len(data) > max_bytes and filt == filters[-1]:
                return max_bytes + 1
        elif filt == "/FlateDecode":
            dec = zlib.decompressobj()
            rem = max_bytes + 1
            out = dec.decompress(data, rem)
            if rem > len(out):
                out += dec.flush(rem - len(out))
            if len(out) > max_bytes or dec.unconsumed_tail:
                return max_bytes + 1
            data = out
        else:
            raise ValueError(f"Unsupported stream filter: {filt}")

    return len(data)


def _get_page_stream_size_bounded(page, max_stream_bytes: int) -> int:
    """Calculate cumulative decoded content stream size for a page up to max_stream_bytes + 1."""
    cnt_ref = page.get("/Contents")
    if cnt_ref is None:
        return 0

    cnt_obj = cnt_ref.get_object() if hasattr(cnt_ref, "get_object") else cnt_ref
    if cnt_obj is None:
        return 0

    streams = [cnt_obj] if not isinstance(cnt_obj, list) else [
        s.get_object() if hasattr(s, "get_object") else s for s in cnt_obj if s is not None
    ]

    total_decoded = 0
    for stm in streams:
        rem_cap = max_stream_bytes + 1 - total_decoded
        if rem_cap <= 0:
            return total_decoded + 1
        decoded_len = _decode_stream_bounded(stm, rem_cap)
        total_decoded += decoded_len
        if total_decoded > max_stream_bytes:
            return total_decoded

    return total_decoded


def _text_quality_suspect(text: str) -> bool:
    """Conservative diagnostic only; a negative result does not establish quality."""
    bad = sum((ord(c) < 32 and ord(c) not in (9, 10, 13)) or ord(c) == 65533 for c in text)
    return bad >= 8 and bad * 50 >= len(text)


def inspect_pdf(path: Path | str, limits: Optional[ImportLimits] = None) -> ReadReport:
    """Inspect a PDF document within approved resource limits using real pypdf 6.10.0."""
    str_path = str(path)
    resolved_path = Path(path)

    # Validate limits upfront
    try:
        actual_limits = _revalidate_limits(limits)
    except Exception as exc:
        return _build_failure_report(
            resolved_path,
            "LIMIT",
            [f"CONFIG_ERROR: invalid import limits ({exc})"],
        )

    # Encoding is part of admission, before filesystem or native resource use.
    if not _path_is_utf8(resolved_path):
        return _build_failure_report(
            resolved_path, "CORRUPT",
            ["PATH_ADMISSION_FAILED: source path cannot encode as UTF-8"],
        )

    # Reject UNC and device namespaces
    if str_path.startswith(("\\\\", "//")):
        return _build_failure_report(
            resolved_path,
            "CORRUPT",
            ["UNC_PATH_REFUSED: UNC network paths refused"],
        )
    if str_path.startswith(("\\\\?\\", "\\\\.\\")):
        return _build_failure_report(
            resolved_path,
            "CORRUPT",
            ["DEVICE_PATH_REFUSED: device namespaces refused"],
        )

    # Reject missing path
    if not resolved_path.exists():
        return _build_failure_report(
            resolved_path,
            "CORRUPT",
            ["PATH_NOT_FOUND: file does not exist"],
        )

    # Reject non-regular files and directories
    if not resolved_path.is_file():
        return _build_failure_report(
            resolved_path,
            "CORRUPT",
            ["NOT_A_REGULAR_FILE: path is not a regular file"],
        )

    # Fail closed on attribute verification failure or reparse point detection
    admission_error = _check_path_admission(resolved_path)
    if admission_error is not None:
        return _build_failure_report(
            resolved_path,
            "CORRUPT",
            [admission_error],
        )

    # Reject non-PDF extensions
    if resolved_path.suffix.lower() != ".pdf":
        return _build_failure_report(
            resolved_path,
            "UNSUPPORTED",
            ["UNSUPPORTED_FORMAT: input is not a recognized PDF format"],
        )

    # Capture immutable byte snapshot via stable Win32 handle
    raw_bytes, read_err, observed_size = _read_file_snapshot(resolved_path, actual_limits.max_file_bytes)
    if read_err is not None:
        return _build_failure_report(
            resolved_path,
            "CORRUPT",
            [read_err],
        )

    if observed_size is not None and observed_size > actual_limits.max_file_bytes:
        return _build_failure_report(
            resolved_path,
            "LIMIT",
            [f"FILE_SIZE_LIMIT_EXCEEDED: size {observed_size} exceeds {actual_limits.max_file_bytes}"],
        )

    if raw_bytes is None:
        return _build_failure_report(
            resolved_path,
            "CORRUPT",
            ["READ_ERROR: failed to capture byte snapshot"],
        )

    file_size = len(raw_bytes)
    if file_size > actual_limits.max_file_bytes:
        return _build_failure_report(
            resolved_path,
            "LIMIT",
            [f"FILE_SIZE_LIMIT_EXCEEDED: size exceeds {actual_limits.max_file_bytes}"],
        )

    sha256 = hashlib.sha256(raw_bytes).hexdigest()

    # Open with pypdf from the single immutable in-memory byte snapshot
    try:
        stream = io.BytesIO(raw_bytes)
        reader = PdfReader(stream, strict=True)
    except Exception:
        return _build_failure_report(
            resolved_path,
            "CORRUPT",
            ["CORRUPT_DOCUMENT: malformed or unreadable PDF payload"],
            sha256=sha256,
        )

    # Check encryption
    if reader.is_encrypted:
        return _build_failure_report(
            resolved_path,
            "LOCKED",
            ["LOCKED_DOCUMENT: document is password encrypted; decryption not attempted"],
            sha256=sha256,
        )

    # Bounded page traversal before flattening or expanding pages
    num_pages, is_within_bound = _get_page_count_bounded(reader, actual_limits.max_pages)
    if not is_within_bound:
        if reader.flattened_pages is None:
            reader.flattened_pages = []
        return _build_failure_report(
            resolved_path,
            "LIMIT",
            [f"PAGE_LIMIT_EXCEEDED: page count {num_pages} exceeds limit {actual_limits.max_pages}"],
            page_count=num_pages,
            sha256=sha256,
        )

    # Inspect individual pages with stream limit and shared excerpt budget
    pages: List[PageReading] = []
    remaining_file_excerpt_budget = actual_limits.max_excerpt_file_chars

    for idx, p in enumerate(reader.pages):
        page_warnings: List[str] = []

        # Check decoded content stream size before extraction
        try:
            s_len = _get_page_stream_size_bounded(p, actual_limits.max_stream_bytes)
            if s_len > actual_limits.max_stream_bytes:
                return _build_failure_report(
                    resolved_path,
                    "LIMIT",
                    [f"STREAM_LIMIT_EXCEEDED: decoded content stream exceeds {actual_limits.max_stream_bytes} bytes"],
                    page_count=num_pages,
                    sha256=sha256,
                )
        except Exception:
            return _build_failure_report(
                resolved_path,
                "CORRUPT",
                ["CORRUPT_DOCUMENT: malformed or unreadable PDF payload"],
                page_count=num_pages,
                sha256=sha256,
            )

        text_known = images_known = True
        try:
            raw_text = p.extract_text() or ""
        except Exception:
            raw_text = ""
            text_known = False

        try:
            num_images = len(p.images)
        except Exception:
            num_images = 0
            images_known = False

        has_text = len(raw_text.strip()) > 0
        has_images = num_images > 0
        quality_suspect = _text_quality_suspect(raw_text)

        if not (text_known and images_known):
            state = "UNKNOWN"
        elif (has_text or quality_suspect) and has_images:
            state = "MIXED"
        elif has_text and not quality_suspect:
            state = "TEXT_EXTRACTABLE"
        elif has_images:
            state = "IMAGE_ONLY"
        else:
            state = "UNKNOWN"

        if quality_suspect:
            page_warnings.append("TEXT_QUALITY")

        # Enforce shared excerpt budget across pages and file
        allowed_chars = min(actual_limits.max_excerpt_page_chars, remaining_file_excerpt_budget)
        page_text = raw_text[:allowed_chars]
        if len(raw_text) > actual_limits.max_excerpt_page_chars or len(raw_text) > remaining_file_excerpt_budget:
            page_warnings[:] = ["EXCERPT_TRUNCATED;Q" if quality_suspect else "EXCERPT_TRUNCATED"]

        remaining_file_excerpt_budget = max(0, remaining_file_excerpt_budget - len(page_text))

        pages.append(PageReading(
            page_index=idx,
            state=state,
            text=page_text,
            locator=f"page-{idx+1}",
            warnings=page_warnings,
        ))

    raw_report = ReadReport(
        path=resolved_path,
        page_count=num_pages,
        read_state=derive_document_state(pages),
        pages=pages,
        parser_version=PARSER_VERSION,
        rule_version=RULE_VERSION,
        sha256=sha256,
        warnings=[_diagnostic_summary(pages)],
        is_valid=True,
        excerpt=derive_excerpt(pages, actual_limits.max_excerpt_file_chars),
    )
    return publish_report(resolved_path, actual_limits, raw_report, captured_sha256=sha256)
