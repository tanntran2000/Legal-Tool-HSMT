"""Windows bounded process worker for isolated PDF inspection."""

import argparse
import ctypes
from ctypes import wintypes
import dataclasses
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from typing import Optional

from legal_tool.pdf_read import (
    ImportLimits,
    PageReading,
    ReadReport,
    inspect_pdf,
    _read_file_snapshot,
    _cap_diagnostic_utf8,
    _build_failure_report,
    publish_report,
    _report_to_wire,
    _revalidate_limits,
    _path_is_utf8,
)

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# 64-bit safe Windows kernel32 API declarations
kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
kernel32.CreateJobObjectW.restype = wintypes.HANDLE

kernel32.SetInformationJobObject.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    ctypes.c_void_p,
    wintypes.DWORD,
]
kernel32.SetInformationJobObject.restype = wintypes.BOOL

kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
kernel32.AssignProcessToJobObject.restype = wintypes.BOOL

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
kernel32.GetFileAttributesW.restype = wintypes.DWORD


# Windows Job Object structures
class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
        ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryLimit", ctypes.c_size_t),
        ("PeakJobMemoryLimit", ctypes.c_size_t),
    ]


JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JobObjectExtendedLimitInformation = 9
PROCESS_ALL_ACCESS = 0x1F0FFF




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
            if attrs & 0x400:  # FILE_ATTRIBUTE_REPARSE_POINT
                return "REPARSE_POINT_REFUSED: symlink or reparse point refused"
            if cur.is_symlink():
                return "REPARSE_POINT_REFUSED: symlink or reparse point refused"
        return None
    except Exception as exc:
        return f"PATH_ADMISSION_FAILED: path inspection failed ({exc})"


def _setup_job_object(memory_mb: int) -> int:
    """Create and configure Windows Job Object with memory and lifecycle bounds.

    Validates configuration strictly BEFORE acquiring OS handles to avoid resource leaks.
    """
    if type(memory_mb) is bool or not isinstance(memory_mb, (int, float)):
        return 0
    if not math.isfinite(memory_mb) or memory_mb <= 0 or memory_mb > 512:
        return 0

    limit_bytes = int(memory_mb * 1024 * 1024)

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        return 0

    try:
        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = (
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        )
        info.ProcessMemoryLimit = limit_bytes

        res = kernel32.SetInformationJobObject(
            wintypes.HANDLE(job),
            JobObjectExtendedLimitInformation,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if not res:
            kernel32.CloseHandle(wintypes.HANDLE(job))
            return 0
        return job
    except Exception:
        kernel32.CloseHandle(wintypes.HANDLE(job))
        return 0


def _read_stream_bytes_bounded(stream, max_bytes: int, result: list, overflow_event: threading.Event):
    """Read from process binary pipe with strict BYTE bound to prevent memory inflation."""
    chunks = []
    total = 0
    try:
        while True:
            to_read = min(4096, max_bytes + 1 - total)
            chunk = stream.read(to_read)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                overflow_event.set()
                break
    except Exception:
        pass
    result.append(b"".join(chunks)[:max_bytes])


def inspect_bounded(path: Path | str, limits: Optional[ImportLimits] = None) -> ReadReport:
    """Inspect a PDF document inside an isolated Windows process guarded by a Job Object."""
    str_path = str(path)
    resolved_path = Path(path)

    # Validate limits upfront before acquiring any system resources
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

    # Reject UNC and device paths upfront
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

    # Reject directory upfront
    if resolved_path.is_dir():
        return _build_failure_report(
            resolved_path,
            "CORRUPT",
            ["NOT_A_REGULAR_FILE: path is a directory"],
        )

    # Fail closed on path admission failure or reparse point
    admission_error = _check_path_admission(resolved_path)
    if admission_error is not None:
        return _build_failure_report(
            resolved_path,
            "CORRUPT",
            [admission_error],
        )

    # Preflight stable handle snapshot to bind expected hash
    raw_snapshot, snapshot_err, observed_size = _read_file_snapshot(
        resolved_path, actual_limits.max_file_bytes
    )
    if snapshot_err is not None:
        return _build_failure_report(
            resolved_path,
            "CORRUPT",
            [snapshot_err],
        )
    expected_sha256 = (
        hashlib.sha256(raw_snapshot).hexdigest() if raw_snapshot is not None else ""
    )

    # Guard setup: configure Job Object with memory bounds
    job = _setup_job_object(actual_limits.worker_memory_mb)
    if not job:
        return _build_failure_report(
            resolved_path,
            "LIMIT",
            ["LIMIT_GUARD_UNAVAILABLE: failed to initialize Windows Job Object guard"],
        )

    h_process = None
    p = None

    try:
        limits_dict = dataclasses.asdict(actual_limits)
        limits_json = json.dumps(limits_dict)

        cmd = [
            sys.executable,
            "-B",
            "-m",
            "legal_tool.worker",
            "--worker-child",
            "--path",
            str(resolved_path),
            "--limits-json",
            limits_json,
        ]

        # Use binary pipes for strict byte capping
        p = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, p.pid)
        if not h_process:
            p.kill()
            p.wait()
            return _build_failure_report(
                resolved_path,
                "LIMIT",
                ["LIMIT_GUARD_UNAVAILABLE: failed to open child process handle for Job Object"],
            )

        assigned = kernel32.AssignProcessToJobObject(wintypes.HANDLE(job), wintypes.HANDLE(h_process))
        kernel32.CloseHandle(wintypes.HANDLE(h_process))
        h_process = None

        if not assigned:
            p.kill()
            p.wait()
            return _build_failure_report(
                resolved_path,
                "LIMIT",
                ["LIMIT_GUARD_UNAVAILABLE: failed to assign child process to Job Object"],
            )

        # Release child to proceed with inspection
        p.stdin.write(b"PROCEED\n")
        p.stdin.flush()

        # Bounded byte drain threads: stdout <= 1 MiB, stderr <= 4 KiB
        stdout_bytes_list = []
        stderr_bytes_list = []
        overflow_event = threading.Event()

        t_out = threading.Thread(
            target=_read_stream_bytes_bounded,
            args=(p.stdout, 1024 * 1024, stdout_bytes_list, overflow_event),
            daemon=True,
        )
        t_err = threading.Thread(
            target=_read_stream_bytes_bounded,
            args=(p.stderr, 4096, stderr_bytes_list, overflow_event),
            daemon=True,
        )

        t_out.start()
        t_err.start()

        start_time = time.monotonic()
        deadline = actual_limits.timeout_seconds
        p_exited = False

        while time.monotonic() - start_time < deadline:
            if overflow_event.is_set():
                # Promptly terminate child on overflow without waiting for timeout
                p.kill()
                p.wait()
                break
            if p.poll() is not None:
                p_exited = True
                break
            time.sleep(0.005)
        else:
            p.kill()
            p.wait()
            return _build_failure_report(
                resolved_path,
                "LIMIT",
                [f"TIMEOUT_LIMIT_EXCEEDED: child process exceeded deadline of {actual_limits.timeout_seconds}s"],
            )

        t_out.join(timeout=0.5)
        t_err.join(timeout=0.5)

        raw_stdout = stdout_bytes_list[0] if stdout_bytes_list else b""
        raw_stderr = stderr_bytes_list[0] if stderr_bytes_list else b""

        if overflow_event.is_set():
            err_snip = raw_stderr[:200].decode("utf-8", errors="replace")
            warn = _cap_diagnostic_utf8(
                f"CHILD_PROCESS_ERROR: child process output exceeded byte limit: {err_snip}",
                4096,
            )
            return _build_failure_report(
                resolved_path,
                "LIMIT",
                [warn],
            )

        if p.returncode != 0:
            err_msg = raw_stderr.decode("utf-8", errors="replace").strip()
            warn = _cap_diagnostic_utf8(
                f"CHILD_PROCESS_ERROR: child process exited with code {p.returncode}: {err_msg}",
                4096,
            )
            return _build_failure_report(
                resolved_path,
                "LIMIT",
                [warn],
            )

        # Deserialize report from child JSON output
        try:
            stdout_text = raw_stdout.decode("utf-8")
            data = json.loads(stdout_text)
        except Exception:
            return _build_failure_report(
                resolved_path,
                "LIMIT",
                ["CHILD_PROCESS_ERROR: child returned invalid JSON"],
            )

        return publish_report(
            resolved_path,
            actual_limits,
            raw_report=data,
            captured_sha256=expected_sha256,
            is_child_payload=True,
        )

    except subprocess.TimeoutExpired:
        if p:
            try:
                p.kill()
                p.wait()
            except Exception:
                pass
        return _build_failure_report(
            resolved_path,
            "LIMIT",
            [f"TIMEOUT_LIMIT_EXCEEDED: child process exceeded deadline of {actual_limits.timeout_seconds}s"],
        )
    except OSError as exc:
        if p:
            try:
                p.kill()
                p.wait()
            except Exception:
                pass
        return _build_failure_report(
            resolved_path,
            "LIMIT",
            [f"LIMIT_GUARD_UNAVAILABLE: failed to spawn worker ({exc})"],
        )
    except Exception as exc:
        if p:
            try:
                p.kill()
                p.wait()
            except Exception:
                pass
        return _build_failure_report(
            resolved_path,
            "LIMIT",
            [f"WORKER_EXECUTION_ERROR: unexpected error ({exc})"],
        )
    finally:
        if h_process:
            kernel32.CloseHandle(wintypes.HANDLE(h_process))
        if p:
            for stream in (p.stdin, p.stdout, p.stderr):
                if stream:
                    try:
                        stream.close()
                    except Exception:
                        pass
        if job:
            kernel32.CloseHandle(wintypes.HANDLE(job))


def _child_main():
    """Child worker process main entry."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker-child", action="store_true")
    parser.add_argument("--path", type=str, required=True)
    parser.add_argument("--limits-json", type=str, required=True)
    args = parser.parse_args()

    # Handshake: wait for parent to attach Job Object
    line = sys.stdin.readline()
    if line.strip() != "PROCEED":
        sys.exit(2)

    limits_dict = json.loads(args.limits_json)
    limits = ImportLimits(**limits_dict)

    report = inspect_pdf(args.path, limits)

    report_dict = _report_to_wire(report)

    # Ensure UTF-8 output to avoid stdout encoding issues
    json_bytes = json.dumps(report_dict, ensure_ascii=False).encode("utf-8")
    sys.stdout.buffer.write(json_bytes)
    sys.stdout.buffer.flush()
    sys.exit(0)


if __name__ == "__main__":
    _child_main()
