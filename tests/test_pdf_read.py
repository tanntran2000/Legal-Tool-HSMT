"""Tests for legal_tool.pdf_read - Bounded PDF reading models, types, and contracts."""

import ctypes
from contextlib import ExitStack, nullcontext
from copy import deepcopy
from dataclasses import asdict
import tempfile
from ctypes import wintypes
import hashlib
import io
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

# Test-only portable import gate: every attempted native call is recorded.
_NATIVE_CALLS = []


class _ForbiddenNativeCall:
    def __init__(self, name):
        self.name = name

    def __call__(self, *args, **kwargs):
        _NATIVE_CALLS.append(self.name)
        raise AssertionError("Portable policy test attempted native call: " + self.name)


class _ImportOnlyBinding:
    def __init__(self):
        self.functions = {}

    def __getattr__(self, name):
        return self.functions.setdefault(name, _ForbiddenNativeCall(name))


with (patch.object(ctypes, "WinDLL", lambda *a, **k: _ImportOnlyBinding(), create=True)
      if os.name != "nt" else nullcontext()):
    from legal_tool import pdf_read
    from legal_tool.pdf_read import (
        ImportLimits,
        PageReading,
        ReadReport,
        inspect_pdf,
    )
    from legal_tool import worker
    from legal_tool.worker import inspect_bounded
    import pypdf
    from pypdf.generic import EncodedStreamObject

    # Windows kernel32 bindings for handle inspection
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetProcessHandleCount.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetProcessHandleCount.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    kernel32.GetFileAttributesW.restype = wintypes.DWORD

_TEST_RUNTIME = Path(os.environ.get(
    "CW02_TEST_RUNTIME", str(Path(tempfile.gettempdir()) / "legal-tool-cw02-tests" / str(os.getpid()))))
RUNTIME_ROOT = _TEST_RUNTIME / "r03"
R04_RUNTIME_ROOT = _TEST_RUNTIME / "r04"
CW01_RUNTIME_ROOT = _TEST_RUNTIME / "cw01"
_RUNTIME_READY = False

_CHILD_WITNESS = r"""import argparse, hashlib, json, sys
parser = argparse.ArgumentParser()
parser.add_argument('--mode', default='oversized_text')
parser.add_argument('--path', default=DEFAULT_PATH)
args = parser.parse_args()
if sys.stdin.readline().strip() != 'PROCEED': sys.exit(2)
page = dict(page_index=0, state='TEXT_EXTRACTABLE', text='OK', locator='page-1', warnings=[])
report = dict(path=args.path, page_count=1, read_state='TEXT_EXTRACTABLE', pages=[page],
              parser_version='pypdf/6.10.0', rule_version='wp01-v2-dq',
              sha256=hashlib.sha256(open(args.path,'rb').read()).hexdigest(),
              warnings=['D2;P=1;T=0;Q=0;M=0;I=0;U=0'], is_valid=True, excerpt='OK')
mode = args.mode
if mode == 'invalid_utf8_stdout':
    sys.stdout.buffer.write(json.dumps(report).encode('utf-8').replace(b'OK',b'\xff'));sys.exit(0)
if mode == 'wrong_path': report['path'] += '.wrong'
elif mode in ('wrong_parser', 'large_parser_version'): report['parser_version'] = 'X' * 10000
elif mode in ('wrong_rule', 'large_rule_version'): report['rule_version'] = 'X' * 10000
elif mode == 'malformed_sha': report['sha256'] = '0' * 63
elif mode == 'wrong_sha': report['sha256'] = '0' * 64
elif mode == 'negative_count': report['page_count'] = -1
elif mode == 'bool_count': report['page_count'] = True
elif mode == 'disordered_index': page['page_index'] = 1
elif mode in ('wrong_locator', 'large_locator'): page['locator'] = 'X' * 10000
elif mode == 'oversized_page_warning': page['warnings'] = ['W' * 4097]
elif mode == 'state_valid_inconsistency': report['read_state'] = 'LOCKED'
elif mode == 'aggregate_page_warning':
    second = dict(page_index=1,state='TEXT_EXTRACTABLE',text='OK',locator='page-2',warnings=['W'*3000])
    page['warnings'] = ['W'*3000]; report.update(page_count=2,pages=[page,second],excerpt='OK\n\nOK')
    report['warnings'] = ['D2;P=2;T=0;Q=0;M=0;I=0;U=0']
elif mode == 'page_document_state_mismatch': report['read_state'] = 'MIXED'
elif mode == 'invented_excerpt': report['excerpt'] = 'INVENTED'
elif mode == 'invalid_failure_retained_pages': report.update(is_valid=False,read_state='LIMIT')
elif mode == 'oversized_text': page['text'] = report['excerpt'] = 'T' * 20001
sys.stdout.buffer.write(json.dumps(report,ensure_ascii=True).encode('utf-8'))
"""


def _prepare_test_runtime():
    """Preregister bounded self-contained witnesses; preserve every generated file."""
    global _RUNTIME_READY
    if _RUNTIME_READY:
        return
    if _TEST_RUNTIME.exists():
        raise RuntimeError("Test runtime must be fresh; retained evidence is never reused")
    helper_names = ["r03/malformed_child.py", "r03/unicode_stderr_child.py",
                    "r03/faulty_child.py", "r03/cw02_packet_child.py",
                    "r04/r04_invalid_utf8_child.py", "r04/r04_malformed_report_child.py",
                    "cw01/cw01_malformed_child.py"]
    pdf_names = ["r03/false_count.pdf", "r03/ascii85_limit.pdf", "r03/source_race.pdf",
                 "r03/junction_target/text_unicode.pdf", "cw01/blank.pdf", "cw01/many_warnings.pdf",
                 "r04/r04_swap_test/input/text_unicode.pdf",
                 "r04/r04_swap_test/admitted_archive/text_unicode.pdf",
                 "r04/r04_swap_test/target/text_unicode.pdf",
                 *["r1_"+token+".pdf" for token in ("\ud800","\udfff","法")]]
    registration = dict(purpose="CW02 synthetic native regression witnesses", source="tests/test_pdf_read.py generators",
                        owner="CW02 test runner", retention="HOLD_UNTIL_INDEPENDENT_REVIEW_NO_CLEANUP",
                        max_total_bytes=33554432,
                        files=[dict(path=n,max_bytes=cap) for names,cap in ((helper_names,32768),(pdf_names,67108864)) for n in names],
                        junctions=["r03/junction", "r04/r04_swap_test/input"])
    _TEST_RUNTIME.mkdir(parents=True)
    (_TEST_RUNTIME / "runtime_register.json").write_text(json.dumps(registration,indent=2),encoding="utf-8")
    for directory in (RUNTIME_ROOT,R04_RUNTIME_ROOT,CW01_RUNTIME_ROOT):
        directory.mkdir()
    fixtures = Path(__file__).resolve().parent / "fixtures"
    witness = "DEFAULT_PATH = " + repr(str(fixtures / "text_unicode.pdf")) + "\n" + _CHILD_WITNESS
    for relative in ("r03/malformed_child.py", "r04/r04_malformed_report_child.py", "cw01/cw01_malformed_child.py"):
        (_TEST_RUNTIME / relative).write_text(witness,encoding="utf-8")
    (RUNTIME_ROOT / "unicode_stderr_child.py").write_text(
        "import sys,time\nif sys.stdin.readline().strip()!='PROCEED':sys.exit(2)\n"
        "sys.stderr.buffer.write(b'\\xe2\\x82\\xac'*2000);sys.stderr.buffer.flush();time.sleep(20)\n",encoding="utf-8")
    (R04_RUNTIME_ROOT / "r04_invalid_utf8_child.py").write_text(
        "import sys\nif sys.stdin.readline().strip()!='PROCEED':sys.exit(2)\n"
        "sys.stderr.buffer.write(b'\\xff'*4096);sys.stderr.buffer.flush();sys.exit(1)\n",encoding="utf-8")
    (RUNTIME_ROOT / "cw02_packet_child.py").write_text(
        "import sys\nif sys.stdin.readline().strip()!='PROCEED':sys.exit(2)\n"
        "sys.stdout.buffer.write(sys.argv[1].encode('utf-8'));sys.stdout.buffer.flush()\n",encoding="utf-8")
    for count,name in ((1,"blank.pdf"),(50,"many_warnings.pdf")):
        writer = pypdf.PdfWriter()
        for _ in range(count):writer.add_blank_page(width=72,height=72)
        with (CW01_RUNTIME_ROOT / name).open("wb") as handle:writer.write(handle)
    writer = pypdf.PdfWriter()
    for _ in range(201):writer.add_blank_page(width=72,height=72)
    buffer = io.BytesIO();writer.write(buffer)
    original = buffer.getvalue()
    if original.count(b"/Count 201") != 1:raise AssertionError("False-count witness root is ambiguous")
    (RUNTIME_ROOT / "false_count.pdf").write_bytes(original.replace(b"/Count 201",b"/Count 1  ",1))
    writer = pypdf.PdfWriter(); page = writer.add_blank_page(width=72,height=72)
    stream = EncodedStreamObject();stream._data = b"z" * 600000 + b"~>"
    stream[pypdf.generic.NameObject("/Filter")] = pypdf.generic.NameObject("/ASCII85Decode")
    page[pypdf.generic.NameObject("/Contents")] = writer._add_object(stream)
    with (RUNTIME_ROOT / "ascii85_limit.pdf").open("wb") as handle:writer.write(handle)
    if sum(p.stat().st_size for p in _TEST_RUNTIME.rglob("*") if p.is_file()) > 33554432:
        raise AssertionError("Registered runtime cap exceeded")
    _RUNTIME_READY = True



def _get_process_handle_count() -> int:
    count = wintypes.DWORD()
    if kernel32.GetProcessHandleCount(kernel32.GetCurrentProcess(), ctypes.byref(count)):
        return count.value
    return 0


class TestPdfReadTypesAndDefaults(unittest.TestCase):
    """Verifies that the PDF read data types and default limits conform to WP01 specifications."""

    def test_import_limits_defaults(self):
        """Verify default limits protect against unbounded memory and page allocation."""
        limits = ImportLimits()
        self.assertGreater(limits.max_pages, 0)
        self.assertLessEqual(limits.max_pages, 200)
        self.assertGreater(limits.max_stream_bytes, 0)
        self.assertLessEqual(limits.max_stream_bytes, 2 * 1024 * 1024)
        self.assertGreater(limits.timeout_seconds, 0)
        self.assertLessEqual(limits.timeout_seconds, 20)

    def test_page_reading_structure(self):
        """Verify PageReading attributes and contract."""
        page = PageReading(
            page_index=0,
            state="TEXT_EXTRACTABLE",
            text="Hợp đồng kinh tế",
            locator="page-1",
            warnings=[],
        )
        self.assertEqual(page.page_index, 0)
        self.assertEqual(page.state, "TEXT_EXTRACTABLE")
        self.assertEqual(page.text, "Hợp đồng kinh tế")
        self.assertEqual(page.locator, "page-1")
        self.assertEqual(page.warnings, [])


class TestPdfReadNegativeContracts(unittest.TestCase):
    """Verifies negative path contracts for nonexistent, unsupported, and corrupt files."""

    def setUp(self):
        self.fixtures_dir = Path(__file__).resolve().parent / "fixtures"

    def test_nonexistent_file_handling(self):
        """Verify missing files are handled safely without unhandled exceptions."""
        limits = ImportLimits(max_pages=10)
        missing_path = self.fixtures_dir / "nonexistent_file_99999.pdf"
        report = inspect_pdf(missing_path, limits)
        self.assertIsInstance(report, ReadReport)
        self.assertEqual(report.read_state, "CORRUPT")
        self.assertEqual(report.parser_version, "pypdf/6.10.0")
        self.assertEqual(report.rule_version, "wp01-v2-dq")
        self.assertFalse(report.is_valid)

    def test_unsupported_file_extension(self):
        """Verify non-PDF file returns UNSUPPORTED state."""
        unsupported_path = self.fixtures_dir / "unsupported.txt"
        report = inspect_pdf(unsupported_path, ImportLimits())
        self.assertIsInstance(report, ReadReport)
        self.assertEqual(report.read_state, "UNSUPPORTED")
        self.assertEqual(report.parser_version, "pypdf/6.10.0")
        self.assertEqual(report.rule_version, "wp01-v2-dq")

    def test_corrupt_pdf_file(self):
        """Verify malformed PDF payload returns CORRUPT state without crash."""
        corrupt_path = self.fixtures_dir / "corrupt.pdf"
        report = inspect_pdf(corrupt_path, ImportLimits())
        self.assertIsInstance(report, ReadReport)
        self.assertEqual(report.read_state, "CORRUPT")
        self.assertEqual(report.parser_version, "pypdf/6.10.0")
        self.assertEqual(report.rule_version, "wp01-v2-dq")
        self.assertFalse(report.is_valid)


class TestPdfReadSyntheticFixtures(unittest.TestCase):
    """Verifies parser contracts against real synthetic fixtures."""

    def setUp(self):
        self.fixtures_dir = Path(__file__).resolve().parent / "fixtures"

    def test_text_unicode_fixture(self):
        """Verify Vietnamese Unicode, keyword matching (OR/NOT/20-30), and page count."""
        pdf_path = self.fixtures_dir / "text_unicode.pdf"
        report = inspect_pdf(pdf_path, ImportLimits())
        self.assertIsInstance(report, ReadReport)
        self.assertEqual(report.read_state, "TEXT_EXTRACTABLE")
        self.assertEqual(report.page_count, 2)
        self.assertTrue(report.is_valid)
        self.assertEqual(len(report.pages), 2)
        self.assertEqual(report.pages[0].state, "TEXT_EXTRACTABLE")
        self.assertEqual(report.pages[0].locator, "page-1")
        self.assertIn("CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM", report.pages[0].text)
        self.assertIn("OR", report.pages[0].text)
        self.assertIn("NOT", report.pages[0].text)
        self.assertIn("20 đến 30", report.pages[0].text)
        self.assertEqual(report.pages[1].state, "TEXT_EXTRACTABLE")
        self.assertEqual(report.pages[1].locator, "page-2")
        self.assertIn("20-30", report.pages[1].text)

    def test_image_only_fixture(self):
        """Verify image-only bitmap PDF returns IMAGE_ONLY without invented text."""
        pdf_path = self.fixtures_dir / "image_only.pdf"
        report = inspect_pdf(pdf_path, ImportLimits())
        self.assertIsInstance(report, ReadReport)
        self.assertEqual(report.read_state, "IMAGE_ONLY")
        self.assertEqual(report.page_count, 1)
        self.assertTrue(report.is_valid)
        self.assertEqual(len(report.pages), 1)
        self.assertEqual(report.pages[0].state, "IMAGE_ONLY")
        self.assertEqual(report.pages[0].locator, "page-1")
        self.assertEqual(report.pages[0].text.strip(), "")

    def test_mixed_fixture(self):
        """Verify multi-page mixed document classification across pages."""
        pdf_path = self.fixtures_dir / "mixed.pdf"
        report = inspect_pdf(pdf_path, ImportLimits())
        self.assertIsInstance(report, ReadReport)
        self.assertEqual(report.read_state, "MIXED")
        self.assertEqual(report.page_count, 3)
        self.assertTrue(report.is_valid)
        self.assertEqual(len(report.pages), 3)
        self.assertEqual(report.pages[0].state, "MIXED")
        self.assertEqual(report.pages[1].state, "IMAGE_ONLY")
        self.assertEqual(report.pages[2].state, "UNKNOWN")

    def test_locked_fixture(self):
        """Verify encrypted PDF returns LOCKED state without attempting decryption."""
        pdf_path = self.fixtures_dir / "locked.pdf"
        report = inspect_pdf(pdf_path, ImportLimits())
        self.assertIsInstance(report, ReadReport)
        _assert_failed_read(self, report, "LOCKED")

    def test_page_limit_fixture(self):
        """Verify 201-page document triggers LIMIT state under default 200-page bound."""
        pdf_path = self.fixtures_dir / "page_limit.pdf"
        report = inspect_pdf(pdf_path, ImportLimits(max_pages=200))
        self.assertIsInstance(report, ReadReport)
        _assert_failed_read(self, report, "LIMIT")

    def test_stream_limit_fixture(self):
        """Verify decoded stream exceeding 2 MiB triggers LIMIT state."""
        pdf_path = self.fixtures_dir / "stream_limit.pdf"
        report = inspect_pdf(pdf_path, ImportLimits(max_stream_bytes=2 * 1024 * 1024))
        self.assertIsInstance(report, ReadReport)
        _assert_failed_read(self, report, "LIMIT")

    def test_expected_oracle_manifest(self):
        """Verify independent oracle manifest exists and covers all eight input fixtures."""
        oracle_path = self.fixtures_dir / "expected.json"
        self.assertTrue(oracle_path.exists())
        data = json.loads(oracle_path.read_text(encoding="utf-8"))
        self.assertEqual(data.get("oracle_version"), "wp01-v1")
        fixtures = data.get("fixtures", {})
        expected_names = [
            "text_unicode.pdf",
            "image_only.pdf",
            "mixed.pdf",
            "locked.pdf",
            "corrupt.pdf",
            "unsupported.txt",
            "page_limit.pdf",
            "stream_limit.pdf",
        ]
        for name in expected_names:
            self.assertIn(name, fixtures, f"Fixture {name} missing from expected oracle")
            self.assertIn("read_state", fixtures[name])


class TestWindowsWorkerContracts(unittest.TestCase):
    """Verifies that the isolated Windows worker process and Job Object guard operate safely."""

    def setUp(self):
        self.fixtures_dir = Path(__file__).resolve().parent / "fixtures"

    def test_bounded_worker_text_unicode(self):
        """Verify real isolated worker inspects text_unicode.pdf under active Job Object."""
        pdf_path = self.fixtures_dir / "text_unicode.pdf"
        report = inspect_bounded(pdf_path, ImportLimits())
        self.assertIsInstance(report, ReadReport)
        self.assertEqual(report.read_state, "TEXT_EXTRACTABLE")
        self.assertEqual(report.page_count, 2)
        self.assertTrue(report.is_valid)
        self.assertEqual(len(report.pages), 2)
        self.assertIn("CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM", report.pages[0].text)

    def test_bounded_worker_mixed(self):
        """Verify real isolated worker inspects mixed.pdf and reports page states."""
        pdf_path = self.fixtures_dir / "mixed.pdf"
        report = inspect_bounded(pdf_path, ImportLimits())
        self.assertIsInstance(report, ReadReport)
        self.assertEqual(report.read_state, "MIXED")
        self.assertEqual(report.page_count, 3)
        self.assertTrue(report.is_valid)

    def test_bounded_worker_small_deadline_timeout(self):
        """Verify small deadline triggers LIMIT and terminates the child process."""
        pdf_path = self.fixtures_dir / "text_unicode.pdf"
        report = inspect_bounded(pdf_path, ImportLimits(timeout_seconds=0.001))
        self.assertIsInstance(report, ReadReport)
        _assert_failed_read(self, report, "LIMIT")
        self.assertTrue(any("TIMEOUT" in w for w in report.warnings))

    def test_bounded_worker_unc_and_directory_refusal(self):
        """Verify worker refuses UNC paths and directories before running unguarded read."""
        for target in (self.fixtures_dir, r"\\invalid_server\share\file.pdf"):
            with self.subTest(path=str(target)):
                report = inspect_bounded(target, ImportLimits())
                self.assertIsInstance(report, ReadReport)
                _assert_failed_read(self, report, "CORRUPT")

    def test_bounded_worker_guard_unavailable_handling(self):
        """Verify failure to establish native Job Object guard blocks inspection."""
        pdf_path = self.fixtures_dir / "text_unicode.pdf"

        # Config refusal on invalid memory
        with self.assertRaises(ValueError):
            ImportLimits(worker_memory_mb=0)

        # Actual OS failure injection for guard-unavailable coverage
        with patch.object(worker.kernel32, "CreateJobObjectW", return_value=0):
            report = inspect_bounded(pdf_path, ImportLimits())
            self.assertIsInstance(report, ReadReport)
            _assert_failed_read(self, report, "LIMIT")
            self.assertTrue(any("LIMIT_GUARD_UNAVAILABLE" in w for w in report.warnings))


class TestR02Regressions(unittest.TestCase):
    """Targeted regression suite for the five reproduced review finding groups (F1 to F5)."""

    def setUp(self):
        self.fixtures_dir = Path(__file__).resolve().parent / "fixtures"
        _prepare_test_runtime()

    # --- F1 / P1: Bounds enforcement before materialization & limit validation ---
    def test_f1_custom_limit_validation(self):
        cases = [("max_pages",201),("max_file_bytes",20971521),("max_stream_bytes",2097153),
                 ("timeout_seconds",20.1),("worker_memory_mb",513),("max_excerpt_page_chars",2001),
                 ("max_excerpt_file_chars",100001),("max_pages",0),("max_file_bytes",0),
                 ("timeout_seconds",0),("timeout_seconds",float("nan")),("timeout_seconds",float("inf")),
                 ("max_stream_bytes",float("nan")),("worker_memory_mb",float("nan")),
                 ("max_pages",True),("worker_memory_mb",False)]
        for field,value in cases:
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):
                ImportLimits(**{field:value})

    def test_f1_late_file_size_preflight(self):
        """Verify file size limit is enforced before reading full file into memory."""
        read_calls = []
        orig_read_bytes = Path.read_bytes

        def spy_read_bytes(path_obj):
            data = orig_read_bytes(path_obj)
            read_calls.append(len(data))
            return data

        with patch.object(Path, "read_bytes", spy_read_bytes):
            report = inspect_pdf(self.fixtures_dir / "text_unicode.pdf", ImportLimits(max_file_bytes=1024))

        _assert_failed_read(self, report, "LIMIT")
        self.assertEqual(read_calls, [], "Full Path.read_bytes was called instead of preflight stat/bounded read")

    def test_f1_late_stream_cap_decompression(self):
        """Verify stream cap is enforced during bounded decompression, not unbounded get_data."""
        called_get_data = []
        orig_get_data = EncodedStreamObject.get_data

        def spy_get_data(stream, *args, **kwargs):
            val = orig_get_data(stream, *args, **kwargs)
            called_get_data.append(len(val))
            return val

        with patch.object(EncodedStreamObject, "get_data", spy_get_data):
            report = inspect_pdf(self.fixtures_dir / "stream_limit.pdf")

        _assert_failed_read(self, report, "LIMIT")
        self.assertEqual(called_get_data, [], "Unbounded EncodedStreamObject.get_data was called during stream inspection")

    def test_f1_page_tree_before_cap(self):
        """Verify page tree counting detects limit before materializing PageObjects."""
        readers = []
        orig_reader = pdf_read.PdfReader

        def spy_reader(*args, **kwargs):
            r = orig_reader(*args, **kwargs)
            readers.append(r)
            return r

        with patch.object(pdf_read, "PdfReader", spy_reader):
            report = inspect_pdf(self.fixtures_dir / "page_limit.pdf", ImportLimits(max_pages=20))

        self.assertEqual(report.read_state, "LIMIT")
        self.assertEqual(report.page_count, 201)
        self.assertFalse(report.is_valid)
        self.assertEqual(
            len(readers[0].flattened_pages),
            0,
            "Page tree was flattened and PageObjects were expanded before page limit check",
        )

    # --- F2 / P1: Stable source identity & full-path reparse refusal ---
    def test_f2_source_hash_race(self):
        """Verify PDF is parsed from single immutable byte snapshot bound to SHA256."""
        race_target = RUNTIME_ROOT / "source_race.pdf"
        before_bytes = (self.fixtures_dir / "text_unicode.pdf").read_bytes()
        after_bytes = (self.fixtures_dir / "image_only.pdf").read_bytes()
        race_target.write_bytes(before_bytes)

        orig_reader = pdf_read.PdfReader

        def swap_then_read(stream_or_path, *args, **kwargs):
            race_target.write_bytes(after_bytes)
            return orig_reader(stream_or_path, *args, **kwargs)

        try:
            with patch.object(pdf_read, "PdfReader", swap_then_read):
                report = inspect_pdf(race_target)

            self.assertEqual(report.page_count, 2)
            self.assertEqual(report.read_state, "TEXT_EXTRACTABLE")
            self.assertEqual(report.sha256, hashlib.sha256(before_bytes).hexdigest())
        finally:
            pass  # Hold this owned race witness for independent review.

    def test_f2_junction_admission(self):
        """Verify junction / reparse point path components and ancestors are rejected."""
        target_dir = RUNTIME_ROOT / "junction_target"
        junction_dir = RUNTIME_ROOT / "junction"
        target_dir.mkdir(parents=True, exist_ok=True)
        target_file = target_dir / "text_unicode.pdf"
        target_file.write_bytes((self.fixtures_dir / "text_unicode.pdf").read_bytes())

        if not junction_dir.exists():
            subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(junction_dir), str(target_dir)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

        junction_file = junction_dir / "text_unicode.pdf"

        try:
            direct = inspect_pdf(junction_file)
            _assert_failed_read(self, direct, "CORRUPT")
            self.assertTrue(any("REPARSE_POINT_REFUSED" in w for w in direct.warnings))

            native = inspect_bounded(junction_file)
            _assert_failed_read(self, native, "CORRUPT")
            self.assertTrue(any("REPARSE_POINT_REFUSED" in w for w in native.warnings))
        finally:
            pass  # Registered junction and files remain held.


    # --- F3 / P2: Shared excerpt budget & bounded parent IPC/diagnostics ---
    def test_f3_aggregate_excerpt_budget(self):
        """Verify shared excerpt budget is enforced across page texts and file excerpt."""
        limits = ImportLimits(max_excerpt_file_chars=50, max_excerpt_page_chars=2000)
        report = inspect_pdf(self.fixtures_dir / "text_unicode.pdf", limits)
        self.assertEqual(report.read_state, "TEXT_EXTRACTABLE")
        sum_pages = sum(len(p.text) for p in report.pages)
        self.assertLessEqual(sum_pages, 50, f"Sum of page text characters {sum_pages} exceeds file budget 50")
        self.assertLessEqual(len(report.excerpt), 50)
        all_warnings = report.warnings + [w for p in report.pages for w in p.warnings]
        self.assertTrue(
            any("EXCERPT_TRUNCATED" in w for w in all_warnings),
            "Missing EXCERPT_TRUNCATED warning when excerpt budget was reached",
        )

    def test_f3_uncapped_worker_stderr(self):
        """Verify worker caps child stderr to <= 4 KiB and returns LIMIT on overflow."""
        faulty_script = RUNTIME_ROOT / "faulty_child.py"
        faulty_script.write_text(
            "import sys\n"
            "line = sys.stdin.readline()\n"
            'if line.strip() != "PROCEED":\n'
            "    sys.exit(2)\n"
            'sys.stderr.write("E" * (2 * 1024 * 1024))\n'
            "sys.stderr.flush()\n"
            "sys.exit(1)\n",
            encoding="utf-8",
        )

        try:
            report = _run_test_child(self.fixtures_dir / "text_unicode.pdf", faulty_script)

            _assert_failed_read(self, report, "LIMIT")
            total_warning_bytes = _warning_bytes(report)
            self.assertLessEqual(
                total_warning_bytes,
                4096,
                f"Retained warning size {total_warning_bytes} exceeds 4096 byte cap",
            )
        finally:
            pass  # Hold this owned stderr witness for independent review.

    # --- F4 / P2: Job ownership cleanup & native handle safety ---
    def test_f4_spawn_failure_cleanup(self):
        """Verify injected spawn failure does not leak Job handles and does not escape API."""
        acquired_jobs = []
        orig_setup = worker._setup_job_object

        def setup_spy(memory):
            job = orig_setup(memory)
            if job:
                acquired_jobs.append(job)
            return job

        before = _get_process_handle_count()
        escaped_exceptions = []

        try:
            with (
                patch.object(worker, "_setup_job_object", setup_spy),
                patch.object(
                    worker.subprocess,
                    "Popen",
                    side_effect=OSError("review injected bounded spawn failure"),
                ),
            ):
                for _ in range(5):
                    try:
                        report = inspect_bounded(self.fixtures_dir / "text_unicode.pdf")
                        escaped_exceptions.append(False)
                        _assert_failed_read(self, report, "LIMIT")
                    except OSError:
                        escaped_exceptions.append(True)
            after = _get_process_handle_count()
            self.assertEqual(
                escaped_exceptions,
                [False, False, False, False, False],
                "OSError escaped inspect_bounded API instead of returning LIMIT report",
            )
            self.assertEqual(
                after - before,
                0,
                f"Handle leak detected: delta={after - before} after 5 spawn failures",
            )
        finally:
            for job in acquired_jobs:
                kernel32.CloseHandle(wintypes.HANDLE(job))

    def test_f4_malformed_memory_limit_cleanup(self):
        """Verify invalid memory limit does not leak Job handles."""
        before = _get_process_handle_count()
        try:
            try:
                limits = ImportLimits(worker_memory_mb=float("nan"))
                report = inspect_bounded(self.fixtures_dir / "text_unicode.pdf", limits)
            except (ValueError, TypeError):
                pass
        finally:
            after = _get_process_handle_count()
            self.assertEqual(
                after - before,
                0,
                f"Handle leak detected on malformed memory limit: delta={after - before}",
            )

    # --- F5 / P2: Oracle execution acceptance gate ---
    def test_f5_native_oracle_acceptance(self):
        """Keep the frozen v1 facts and independently specify fresh-v2 diagnostics."""
        oracle_path = self.fixtures_dir / "expected.json"
        frozen_oracle = oracle_path.read_bytes()
        oracle = json.loads(frozen_oracle)
        self.assertEqual(oracle["oracle_version"], "wp01-v1")
        self.assertEqual(oracle["rule_version"], "wp01-v1")
        v2_diagnostics = {
            "text_unicode.pdf": "D2;P=2;T=0;Q=0;M=0;I=0;U=0",
            "image_only.pdf": "D2;P=1;T=0;Q=0;M=0;I=1;U=0",
            "mixed.pdf": "D2;P=3;T=0;Q=0;M=1;I=1;U=1",
        }
        for name, expected in oracle["fixtures"].items():
            fixture = self.fixtures_dir / name
            original = fixture.read_bytes()
            for engine in (inspect_pdf, inspect_bounded):
                with self.subTest(fixture=name, engine=engine.__name__):
                    report = engine(fixture)
                    for field in ("read_state", "page_count", "is_valid"):
                        if field in expected:self.assertEqual(getattr(report,field),expected[field],field)
                    self.assertEqual(report.parser_version, oracle["parser_version"])
                    self.assertEqual(report.rule_version, "wp01-v2-dq")
                    warnings = [v2_diagnostics[name]] if expected["is_valid"] else expected["warnings"]
                    self.assertEqual(report.warnings, warnings)
                    expected_hash = hashlib.sha256(original).hexdigest() if fixture.suffix==".pdf" else ""
                    self.assertEqual(report.sha256, expected_hash, "captured/empty fixture identity")
                    if "pages" in expected:
                        self.assertEqual(len(report.pages), len(expected["pages"]))
                        for page, exp_page in zip(report.pages, expected["pages"]):
                            for field in ("page_index", "locator", "state"):
                                if field in exp_page:self.assertEqual(getattr(page,field),exp_page[field],field)
                            self.assertEqual(page.warnings, [])
                            for keyword in exp_page.get("expected_keywords",[]):self.assertIn(keyword,page.text)
                    self.assertEqual(fixture.read_bytes(), original)
        self.assertEqual(oracle_path.read_bytes(), frozen_oracle)


class TestR03Regressions(unittest.TestCase):
    """Targeted regression suite for the five R03 reproduced gaps (A to E)."""

    def setUp(self):
        self.fixtures_dir = Path(__file__).resolve().parent / "fixtures"
        _prepare_test_runtime()

    def test_r03_a_false_page_count_bypass(self):
        """A: Verify false declared /Count does not bypass bounded leaf traversal."""
        target_pdf = RUNTIME_ROOT / "false_count.pdf"
        self.assertTrue(target_pdf.exists())

        direct = inspect_pdf(target_pdf, ImportLimits(max_pages=20))
        _assert_failed_read(self, direct, "LIMIT")
        self.assertEqual(len(direct.pages), 0, "Direct parser materialized pages on false-count PDF")

        native = inspect_bounded(target_pdf, ImportLimits(max_pages=20))
        _assert_failed_read(self, native, "LIMIT")
        self.assertEqual(len(native.pages), 0, "Native worker returned pages on false-count PDF")

    def test_r03_b_ascii85_bounded_decode_before_cap(self):
        """B: Verify ASCII85 decoder bounds memory during decoding before stream cap."""
        target_pdf = RUNTIME_ROOT / "ascii85_limit.pdf"
        self.assertTrue(target_pdf.exists())

        decoded_lengths = []
        orig_decode = pypdf.filters.ASCII85Decode.decode

        def spy_decode(data, *args, **kwargs):
            res = orig_decode(data, *args, **kwargs)
            decoded_lengths.append(len(res))
            return res

        with patch.object(pypdf.filters.ASCII85Decode, "decode", spy_decode):
            report = inspect_pdf(target_pdf)

        _assert_failed_read(self, report, "LIMIT")
        self.assertTrue(
            all(l <= 2097152 for l in decoded_lengths),
            f"ASCII85 decoder allocated over-cap intermediate buffer: {decoded_lengths}",
        )

    def test_r03_c_oversized_child_report_rejection(self):
        """C: Verify worker strictly validates received JSON schema and text bounds."""
        child_script = RUNTIME_ROOT / "malformed_child.py"
        self.assertTrue(child_script.exists())

        report = _run_test_child(self.fixtures_dir / "text_unicode.pdf", child_script,
                                 limits=ImportLimits(max_excerpt_file_chars=50))

        self.assertEqual(report.read_state, "LIMIT", "Worker accepted child report exceeding excerpt budget")
        self.assertFalse(report.is_valid)
        self.assertLessEqual(len(report.excerpt), 50)
        self.assertTrue(
            any("CHILD_PROCESS_ERROR" in w for w in report.warnings),
            f"Expected schema/bounds validation warning, got {report.warnings}",
        )

    def test_r03_d_utf8_diagnostic_byte_cap_and_early_exit(self):
        """D: Verify stderr drain uses strict BYTE cap and terminates child on overflow."""
        child_script = RUNTIME_ROOT / "unicode_stderr_child.py"
        self.assertTrue(child_script.exists())

        start = time.monotonic()
        report = _run_test_child(self.fixtures_dir / "text_unicode.pdf", child_script)
        elapsed = time.monotonic() - start

        _assert_failed_read(self, report, "LIMIT")
        self.assertLess(elapsed, 5.0, "Worker waited for timeout instead of early kill on overflow")
        total_warning_bytes = _warning_bytes(report)
        self.assertLessEqual(
            total_warning_bytes,
            4096,
            f"Diagnostic warning bytes {total_warning_bytes} exceeds 4096 byte cap",
        )

    def test_r03_e_reparse_guard_unavailable_fails_closed(self):
        """E: Verify failure to query file attributes fails closed instead of assuming safe."""
        with patch.object(pdf_read.kernel32, "GetFileAttributesW", return_value=0xFFFFFFFF):
            report = inspect_pdf(self.fixtures_dir / "text_unicode.pdf")

        _assert_failed_read(self, report, "CORRUPT")
        self.assertTrue(
            any(
                "PATH_ADMISSION_FAILED" in w
                or "REPARSE_POINT_REFUSED" in w
                or "ADMISSION_FAILED" in w
                for w in report.warnings
            ),
            f"Expected fail-closed path admission warning, got {report.warnings}",
        )


class TestR04Regressions(unittest.TestCase):
    """Targeted regression suite for the three R04 findings (A, B, C)."""

    def setUp(self):
        self.fixtures_dir = Path(__file__).resolve().parent / "fixtures"
        _prepare_test_runtime()

    def test_r04_a_open_junction_swap_race(self):
        """A: Verify normal parent directory swapped to junction at open fails closed."""
        swap_root = R04_RUNTIME_ROOT / "r04_swap_test"
        if swap_root.exists():
            raise RuntimeError("Fresh registered swap case already exists")
        if not swap_root.resolve().is_relative_to(_TEST_RUNTIME.resolve()):
            raise RuntimeError("Swap case escaped owned runtime")
        swap_root.mkdir()

        admitted_dir = swap_root / "input"
        admitted_dir.mkdir(parents=True, exist_ok=True)
        archive_dir = swap_root / "admitted_archive"
        target_dir = swap_root / "target"
        target_dir.mkdir(parents=True, exist_ok=True)

        shutil.copy2(self.fixtures_dir / "text_unicode.pdf", admitted_dir / "text_unicode.pdf")
        shutil.copy2(self.fixtures_dir / "image_only.pdf", target_dir / "text_unicode.pdf")

        target_file = admitted_dir / "text_unicode.pdf"
        swapped = [False]
        orig_open = open
        orig_create_file = pdf_read.kernel32.CreateFileW

        def perform_swap():
            if not swapped[0]:
                swapped[0] = True
                source = str(admitted_dir).replace("'", "''")
                archive = str(archive_dir).replace("'", "''")
                target = str(target_dir).replace("'", "''")
                subprocess.run(
                    ["powershell.exe", "-NoProfile", "-Command",
                     f"Move-Item -LiteralPath '{source}' -Destination '{archive}'; "
                     f"New-Item -ItemType Junction -Path '{source}' -Target '{target}'"],
                    check=True, capture_output=True,
                )


        def hook_open(file, *args, **kwargs):
            if str(file) == str(target_file):
                perform_swap()
            return orig_open(file, *args, **kwargs)

        def hook_create_file(file, *args, **kwargs):
            if str(file) == str(target_file):
                perform_swap()
            return orig_create_file(file, *args, **kwargs)

        try:
            with patch("builtins.open", side_effect=hook_open), patch.object(
                pdf_read.kernel32, "CreateFileW", side_effect=hook_create_file
            ):
                report = inspect_pdf(target_file)

            self.assertEqual(report.read_state, "CORRUPT", "Junction-swapped input admitted without failing closed")
            self.assertFalse(report.is_valid)
            self.assertTrue(
                any(
                    "PATH_ADMISSION_FAILED" in w
                    or "REPARSE_POINT_REFUSED" in w
                    or "OPEN_FAILED" in w
                    for w in report.warnings
                ),
                f"Expected fail-closed path admission warning, got {report.warnings}",
            )
        finally:
            pass  # Registered swap evidence remains held.

    def test_r04_b_invalid_utf8_diagnostic_expansion(self):
        """B: Verify stderr invalid UTF-8 replacement bytes do not expand diagnostic beyond 4096 bytes."""
        child_script = R04_RUNTIME_ROOT / "r04_invalid_utf8_child.py"
        self.assertTrue(child_script.exists())

        report = _run_test_child(self.fixtures_dir / "text_unicode.pdf", child_script)

        _assert_failed_read(self, report, "LIMIT")
        total_warning_bytes = sum(len(w.encode("utf-8")) for w in report.warnings)
        self.assertLessEqual(
            total_warning_bytes,
            4096,
            f"Diagnostic warning bytes {total_warning_bytes} exceeds 4096 byte cap",
        )
        self.assertTrue(
            any("CHILD_PROCESS_ERROR" in w for w in report.warnings),
            f"Expected CHILD_PROCESS_ERROR in warnings, got {report.warnings}",
        )

    def test_r04_c_strict_child_report_contract(self):
        """Every original malformed packet remains a guarded native witness."""
        _assert_malformed_packets(self, R04_RUNTIME_ROOT / "r04_malformed_report_child.py",
                                 ['wrong_path', 'wrong_parser', 'wrong_rule', 'malformed_sha', 'wrong_sha', 'negative_count', 'bool_count', 'disordered_index', 'wrong_locator', 'oversized_page_warning', 'state_valid_inconsistency'])


class TestCW01Regressions(unittest.TestCase):
    """Targeted regression suite for CW01 shared publication contract."""

    def setUp(self):
        self.fixtures_dir = Path(__file__).resolve().parent / "fixtures"
        _prepare_test_runtime()

    def test_cw01_malformed_packets_rejected_and_bounded(self):
        """Every original malformed packet remains a guarded native witness."""
        _assert_malformed_packets(self, CW01_RUNTIME_ROOT / "cw01_malformed_child.py",
                                 ['large_parser_version', 'large_rule_version', 'large_locator', 'aggregate_page_warning', 'page_document_state_mismatch', 'invented_excerpt', 'invalid_failure_retained_pages', 'invalid_utf8_stdout'])

    def test_cw01_blank_and_unknown_direct_native_parity(self):
        """Verify genuine blank PDF yields UNKNOWN state with exact direct and native parity."""
        blank_pdf = CW01_RUNTIME_ROOT / "blank.pdf"
        self.assertTrue(blank_pdf.exists())

        direct = inspect_pdf(blank_pdf)
        native = inspect_bounded(blank_pdf)

        self.assertEqual(direct.read_state, "UNKNOWN")
        self.assertTrue(direct.is_valid)
        self.assertEqual(direct.page_count, 1)
        self.assertEqual(len(direct.pages), 1)
        self.assertEqual(direct.pages[0].state, "UNKNOWN")

        self.assertEqual(native.read_state, direct.read_state, "Native failed direct/native parity on blank PDF")
        self.assertEqual(native.is_valid, direct.is_valid)
        self.assertEqual(native.page_count, direct.page_count)
        self.assertEqual(len(native.pages), len(direct.pages))
        self.assertEqual(native.pages[0].state, direct.pages[0].state)
        self.assertEqual(native.sha256, direct.sha256)

    def test_cw01_global_warning_budget_direct_and_native(self):
        """Compact producer diagnostics retain the same fifty blank pages."""
        many_pdf = CW01_RUNTIME_ROOT / "many_warnings.pdf"
        self.assertTrue(many_pdf.exists())
        source_hash = hashlib.sha256(many_pdf.read_bytes()).hexdigest()
        direct, native = inspect_pdf(many_pdf), inspect_bounded(many_pdf)
        for report in (direct, native):
            self.assertTrue(report.is_valid, report.warnings)
            self.assertEqual((report.read_state, report.page_count, len(report.pages)), ("UNKNOWN", 50, 50))
            self.assertEqual(report.warnings, ["D2;P=50;T=0;Q=0;M=0;I=0;U=50"])
            self.assertEqual(report.excerpt, "")
            self.assertEqual(report.sha256, source_hash)
            self.assertEqual([p.locator for p in report.pages], [f"page-{i+1}" for i in range(50)])
            self.assertTrue(all(p.state=="UNKNOWN" and p.text=="" for p in report.pages))
            self.assertLessEqual(pdf_read.calculate_aggregate_warning_bytes(report.warnings, report.pages), 4096)
        self.assertEqual(pdf_read._report_to_wire(direct), pdf_read._report_to_wire(native))
        self.assertEqual(hashlib.sha256(many_pdf.read_bytes()).hexdigest(), source_hash)


def _assert_failed_read(test, report, state):
    test.assertEqual(report.read_state, state)
    test.assertFalse(report.is_valid)


def _run_test_child(target, script, arguments=(), limits=None):
    actual_popen = subprocess.Popen
    def launch(*args, **kwargs):
        return actual_popen([sys.executable, "-B", str(script), *arguments], **kwargs)
    with patch.object(worker.subprocess, "Popen", launch):
        return inspect_bounded(target, limits)


def _assert_malformed_packets(test, script, variants):
    test.assertTrue(script.exists())
    target = test.fixtures_dir / "text_unicode.pdf"
    for variant in variants:
        with test.subTest(variant=variant):
            report = _run_test_child(target, script, ("--mode", variant, "--path", str(target)))
            test.assertEqual(report.read_state, "LIMIT")
            test.assertFalse(report.is_valid)
            test.assertEqual((report.pages, report.excerpt), ([], ""))
            test.assertLessEqual(_warning_bytes(report), 4096)
            test.assertTrue(any("CHILD_PROCESS_ERROR" in w for w in report.warnings))


def _resource_spies(stack):
    return [stack.enter_context(patch.object(module, attr)) for module, attrs in
            ((pdf_read, ("_check_path_admission", "_read_file_snapshot", "PdfReader")),
             (worker, ("_check_path_admission", "_read_file_snapshot", "_setup_job_object")),
             (worker.subprocess, ("Popen",))) for attr in attrs]


def _warning_bytes(report):
    return len("\n".join(report.warnings).encode("utf-8"))


def _contract_packet(path, failure=False):
    page = dict(page_index=0,state="TEXT_EXTRACTABLE",text="OK",locator="page-1",warnings=[])
    return dict(path=str(path),page_count=0 if failure else 1,
                read_state="LIMIT" if failure else "TEXT_EXTRACTABLE",pages=[] if failure else [page],
                parser_version="pypdf/6.10.0",rule_version="wp01-v2-dq",sha256="a"*64,
                warnings=["TIMEOUT_LIMIT_EXCEEDED: deadline"] if failure else ["D2;P=1;T=0;Q=0;M=0;I=0;U=0"],
                is_valid=not failure,excerpt="" if failure else "OK")


def _packet_dto(packet):
    values = deepcopy(packet)
    if type(values["path"]) is str:values["path"] = Path(values["path"])
    if type(values["pages"]) is list:
        values["pages"] = [PageReading(**p) if type(p) is dict else p for p in values["pages"]]
    return ReadReport(**values)


class _ContractCase(unittest.TestCase):
    def setUp(self):
        self.path = Path(__file__).resolve().parent / "fixtures" / "text_unicode.pdf"
        self.limits = ImportLimits()

    def tearDown(self):
        if os.name != "nt":self.assertEqual(_NATIVE_CALLS, [], "Native calls were caught or attempted")

    def publish_both(self, packet, captured="a"*64):
        return [pdf_read.publish_report(self.path,self.limits,
                deepcopy(packet) if wire else _packet_dto(packet),captured,wire) for wire in (False,True)]

    def assert_rejected(self, reports):
        for report in reports:
            self.assertEqual(report.read_state,"LIMIT")
            self.assertIs(report.is_valid,False)
            self.assertEqual((report.pages,report.excerpt),([],""))
            self.assertTrue(report.warnings[0].startswith("CHILD_PROCESS_ERROR:"))
            self.assertLessEqual(_warning_bytes(report),4096)

    def assert_wire_utf8(self, report):
        try:json.dumps(pdf_read._report_to_wire(report),ensure_ascii=False).encode("utf-8")
        except UnicodeError:self.fail("Report contains text unencodable as UTF-8")

    def assert_mutations_rejected(self, cases, failure=False, page=False):
        for field,value in cases:
            packet = _contract_packet(self.path,failure)
            target = packet["pages"][0] if page else packet
            target[field] = value
            with self.subTest(location="page" if page else "report",failure=failure,
                              field=field,value_type=type(value).__name__):
                self.assert_rejected(self.publish_both(packet))

class CW02PortableContract(_ContractCase):
    """Real shared policy; import bindings never emulate native behavior."""
    def test_completed_DTO_and_wire_share_shape_and_identity(self):
        cases = [("page_count",True),("page_count",-1),("page_count",2),("page_count",201),
                 ("is_valid",1),("pages",None),("pages",[42]),("warnings",None),
                 ("parser_version","X"*10000),("rule_version","wrong"),("sha256","b"*64),
                 ("sha256",None),("sha256",""),("sha256","A"*64),("path",str(self.path)+".wrong"),
                 ("path",17),("read_state","LOCKED"),("read_state","MIXED"),("excerpt","invented")]
        self.assert_mutations_rejected(cases)
        for field,value in (("path",str(self.path)),("pages",[_contract_packet(self.path)["pages"][0]])):
            report = _packet_dto(_contract_packet(self.path));setattr(report,field,value)
            with self.subTest(DTO_container=field):
                self.assert_rejected([pdf_read.publish_report(self.path,self.limits,report,"a"*64)])

    def test_received_required_fields_are_not_repaired(self):
        for field in _contract_packet(self.path):
            packet = _contract_packet(self.path);del packet[field]
            with self.subTest(field=field):
                self.assert_rejected([pdf_read.publish_report(self.path,self.limits,packet,"a"*64,True)])
        for field in _contract_packet(self.path)["pages"][0]:
            packet = _contract_packet(self.path);del packet["pages"][0][field]
            with self.subTest(page_field=field):
                self.assert_rejected([pdf_read.publish_report(self.path,self.limits,packet,"a"*64,True)])

    def test_page_types_bounds_order_locator_and_states(self):
        cases = [("page_index",True),("page_index",1),("state","LIMIT"),("state",None),
                 ("locator","page-2"),("locator",17),("text",None),("text","T"*2001),
                 ("warnings","not-list"),("warnings",[17])]
        self.assert_mutations_rejected(cases,page=True)

    def test_failure_DTO_and_wire_do_not_repair_pages_excerpt_or_state(self):
        cases = [("read_state","UNKNOWN"),("is_valid",True),("page_count",True),("page_count",-1),
                 ("pages",[_contract_packet(self.path)["pages"][0]]),("excerpt","retained")]
        self.assert_mutations_rejected(cases,failure=True)

    def test_genuine_missing_hash_is_preserved_for_every_exact_code(self):
        for code in pdf_read.ALLOWED_MISSING_HASH_PREFIXES:
            packet = _contract_packet(self.path,True);packet.update(sha256="",warnings=[code+": witness"])
            with self.subTest(code=code):
                for result in self.publish_both(packet):
                    self.assertEqual((result.read_state,result.page_count,result.sha256),("LIMIT",0,""))
                    self.assertEqual(result.warnings,packet["warnings"])
                packet["warnings"] = [code+"X: malformed"]
                self.assert_rejected(self.publish_both(packet))

    def test_missing_hash_nonzero_or_unrecognized_diagnostics_rejected(self):
        for warnings,count in (([],0),(["CONFIG_ERRORX: forged"],0),([None],0),(["CONFIG_ERROR: witness"],1)):
            packet = _contract_packet(self.path,True);packet.update(sha256="",warnings=warnings,page_count=count)
            with self.subTest(warnings=warnings,count=count):self.assert_rejected(self.publish_both(packet))

    def test_captured_terminal_failures_keep_observed_counts_and_matching_hash(self):
        for state,count,code in (("LOCKED",0,"LOCKED_DOCUMENT"),("CORRUPT",2,"CORRUPT_DOCUMENT"),
                                 ("LIMIT",201,"PAGE_LIMIT_EXCEEDED"),("LIMIT",1,"STREAM_LIMIT_EXCEEDED")):
            packet = _contract_packet(self.path,True);packet.update(read_state=state,page_count=count,warnings=[code+": witness"])
            with self.subTest(state=state,count=count):
                for result in self.publish_both(packet):
                    self.assertEqual((result.read_state,result.page_count,result.sha256),(state,count,"a"*64))
                packet["sha256"] = "b"*64;self.assert_rejected(self.publish_both(packet))

    def test_failure_warning_types_and_utf8_are_checked_before_early_return(self):
        for warnings in ([17],[None],[{}],["\ud800"]):
            for sha in ("a"*64,""):
                packet = _contract_packet(self.path,True);packet.update(warnings=warnings,sha256=sha)
                with self.subTest(warnings=warnings,sha=sha):self.assert_rejected(self.publish_both(packet))

    def test_received_overflow_is_rejected_and_generated_overflow_retains_identity(self):
        for failure,sha in ((False,"a"*64),(True,"a"*64),(True,"")):
            packet = _contract_packet(self.path,failure)
            packet.update(sha256=sha,warnings=["TIMEOUT_LIMIT_EXCEEDED: "+"W"*4097])
            wire = pdf_read.publish_report(self.path,self.limits,packet,"a"*64,True)
            self.assert_rejected([wire])
            producer = pdf_read.publish_report(self.path,self.limits,_packet_dto(packet),"a"*64)
            self.assertEqual((producer.read_state,producer.page_count,producer.sha256),("LIMIT",packet["page_count"],sha))
            self.assertTrue(producer.warnings[0].startswith("LIMIT_DIAGNOSTIC_BUDGET:"))
            wire = {**asdict(producer),"path":str(self.path)}
            self.assertEqual(pdf_read.publish_report(self.path,self.limits,wire,"a"*64,True).warnings,producer.warnings)

    def test_warning_budget_counts_multibyte_duplicates_and_separators(self):
        packet = _contract_packet(self.path);summary = packet["warnings"][0];packet["warnings"].append("é"*1000)
        packet["pages"][0]["warnings"] = ["é"*1000,"W"*(94-len(summary.encode("utf-8"))-1)]
        self.assertEqual(len("\n".join(packet["warnings"]+packet["pages"][0]["warnings"]).encode("utf-8")),4096)
        for result in self.publish_both(packet):
            self.assertTrue(result.is_valid);self.assertEqual(result.pages[0].warnings,packet["pages"][0]["warnings"])
        packet["pages"][0]["warnings"][-1] += "W"
        self.assert_rejected([self.publish_both(packet)[1]])

    def test_surrogate_text_and_excerpt_are_rejected(self):
        for field in ("text","excerpt"):
            packet = _contract_packet(self.path)
            if field == "text":packet["pages"][0]["text"] = packet["excerpt"] = "\ud800"
            else:packet["excerpt"] = "\ud800"
            with self.subTest(field=field):self.assert_rejected(self.publish_both(packet))

    def test_generated_diagnostics_sanitize_short_and_long_surrogates(self):
        for diagnostic in ("short\ud800", "é"*3000+"\udfff"):
            result = pdf_read._build_failure_report(self.path,"LIMIT",["WORKER_EXECUTION_ERROR: "+diagnostic])
            self.assertLessEqual(_warning_bytes(result),4096)
            self.assertEqual(result.sha256,"")
            self.assertTrue(result.warnings[0].startswith("WORKER_EXECUTION_ERROR:"))

    def test_zero_unknown_and_exhausted_excerpt_text_pages_remain_valid(self):
        packets = []
        packet = _contract_packet(self.path);packet.update(pages=[],page_count=0,read_state="UNKNOWN",excerpt="",warnings=["D2;P=0;T=0;Q=0;M=0;I=0;U=0"]);packets.append(packet)
        packet = _contract_packet(self.path);packet.update(read_state="UNKNOWN",excerpt="")
        packet["pages"][0].update(state="UNKNOWN",text="");packet["warnings"]=["D2;P=1;T=0;Q=0;M=0;I=0;U=1"];packets.append(packet)
        packet = _contract_packet(self.path);packet["pages"].append(dict(page_index=1,state="TEXT_EXTRACTABLE",text="",locator="page-2",warnings=["EXCERPT_TRUNCATED"]))
        packet["page_count"] = 2;packet["warnings"]=["EXCERPT_TRUNCATED;D2;P=2;T=1;Q=0;M=0;I=0;U=0"];packets.append(packet)
        for packet in packets:
            for result in self.publish_both(packet):self.assertTrue(result.is_valid)

    def test_existing_limits_revalidated_before_any_resource(self):
        mutations = [("max_file_bytes",0),("max_pages",201),("max_stream_bytes",True),
                     ("timeout_seconds",float("nan")),("worker_memory_mb",513),
                     ("max_excerpt_page_chars",2001),("max_excerpt_file_chars",100001)]
        for name,value in mutations:
            for entry in (inspect_pdf,inspect_bounded):
                limits = ImportLimits();object.__setattr__(limits,name,value)
                with self.subTest(entry=entry.__name__,field=name), ExitStack() as stack:
                    resources = _resource_spies(stack)
                    report = entry(self.path,limits)
                    self.assertEqual((report.read_state,report.page_count,report.sha256),("LIMIT",0,""))
                    self.assertTrue(report.warnings[0].startswith("CONFIG_ERROR:"))
                    for resource in resources:resource.assert_not_called()

    def test_valid_limits_are_copied_before_capture_and_smaller_values_preserved(self):
        values = dict(max_file_bytes=2048,max_pages=7,max_stream_bytes=1024,timeout_seconds=3,
                      worker_memory_mb=64,max_excerpt_page_chars=20,max_excerpt_file_chars=40)
        for entry in (inspect_pdf,inspect_bounded):
            limits = ImportLimits(**values)
            writer = pypdf.PdfWriter();buffer = io.BytesIO();writer.write(buffer);raw = buffer.getvalue()
            def captured(path,max_bytes):
                self.assertEqual(max_bytes,2048)
                object.__setattr__(limits,"max_pages",201);object.__setattr__(limits,"worker_memory_mb",513)
                return raw,None,len(raw)
            with self.subTest(entry=entry.__name__),patch.object(pdf_read,"_check_path_admission",return_value=None), \
                 patch.object(worker,"_check_path_admission",return_value=None), \
                 patch.object(pdf_read,"_read_file_snapshot",side_effect=captured), \
                 patch.object(worker,"_read_file_snapshot",side_effect=captured), \
                 patch.object(pdf_read,"_get_page_count_bounded",return_value=(0,True)) as count, \
                 patch.object(worker,"_setup_job_object",return_value=None) as job:
                report = entry(self.path,limits)
                if entry is inspect_pdf:
                    self.assertTrue(report.is_valid);self.assertEqual(count.call_args.args[1],7)
                else:job.assert_called_once_with(64)


    def test_r1_locked_requires_matching_hash(self):
        for code in pdf_read.ALLOWED_MISSING_HASH_PREFIXES:
            packet = _contract_packet(self.path,True)
            packet.update(read_state="LOCKED",sha256="",warnings=[code+": witness"])
            for wire,report in zip((False,True),self.publish_both(packet)):
                with self.subTest(code=code,wire=wire):self.assert_rejected([report])
            packet["sha256"] = "a"*64
            for report in self.publish_both(packet):
                self.assertEqual((report.read_state,report.sha256),("LOCKED","a"*64))

    def test_r1_path_utf8_admission_and_failure_identity(self):
        for token in ("\ud800","\udfff"):
            self.path = Path("r1_"+token+".pdf")
            for wire,report in zip((False,True),self.publish_both(_contract_packet(self.path))):
                with self.subTest(token=hex(ord(token)),wire=wire):
                    self.assert_rejected([report]);self.assert_wire_utf8(report)
            with self.subTest(token=hex(ord(token)),generated=True):
                report = pdf_read._build_failure_report(self.path,"CORRUPT",["OPEN_FAILED: witness"])
                self.assertEqual((report.read_state,report.sha256,report.warnings),("CORRUPT","",["OPEN_FAILED: witness"]))
                self.assert_wire_utf8(report)
            for entry in (inspect_pdf,inspect_bounded):
                for invalid in (False,True):
                    limits = ImportLimits()
                    if invalid:object.__setattr__(limits,"max_pages",201)
                    with self.subTest(token=hex(ord(token)),entry=entry.__name__,invalid=invalid), ExitStack() as stack:
                        resources = _resource_spies(stack)
                        report = entry(self.path,limits)
                        self.assertEqual((report.read_state,report.page_count,report.sha256,report.is_valid),
                                         ("LIMIT" if invalid else "CORRUPT",0,"",False))
                        self.assertEqual((report.pages,report.excerpt),([],""))
                        self.assertTrue(report.warnings[0].startswith("CONFIG_ERROR:" if invalid else "PATH_ADMISSION_FAILED:"))
                        self.assert_wire_utf8(report)
                        for resource in resources:resource.assert_not_called()


class CW02OracleCorrection(_ContractCase):
    """ORACLE CORRECTION ONLY: old early-corrupt LIMIT oracle was incorrect."""
    def test_early_corrupt_EXPECT_CORRUPT_count0_empty_hash(self):
        packet = _contract_packet(self.path,True)
        packet.update(read_state="CORRUPT",sha256="",warnings=["PATH_NOT_FOUND: file does not exist"])
        for report in self.publish_both(packet):
            self.assertEqual((report.read_state,report.page_count,report.sha256,report.is_valid),("CORRUPT",0,"",False))
            self.assertEqual((report.pages,report.excerpt,report.warnings),([],"",packet["warnings"]))


@unittest.skipUnless(os.name == "nt", "Requires actual Windows capture and Job Object APIs")
class CW02WindowsContract(_ContractCase):
    """Guarded native JSON witnesses."""
    def controlled(self,packet):
        _prepare_test_runtime()
        return _run_test_child(self.path, RUNTIME_ROOT / "cw02_packet_child.py",
                               (json.dumps(packet, ensure_ascii=True),))

    def test_native_received_failures_warnings_surrogates_and_missing_hash(self):
        sha = hashlib.sha256(self.path.read_bytes()).hexdigest()
        for mode in ("genuine_failure","unsupported","config_prefix","warning_type","warning_overflow","surrogate_text","locked_empty_sha"):
            packet = _contract_packet(self.path,True);packet["sha256"] = ""
            if mode == "genuine_failure":packet["warnings"] = ["LIMIT_GUARD_UNAVAILABLE: unavailable"]
            elif mode == "unsupported":packet.update(read_state="UNSUPPORTED",warnings=["UNSUPPORTED_FORMAT: refused"])
            elif mode == "locked_empty_sha":packet.update(read_state="LOCKED",warnings=["PATH_NOT_FOUND: file does not exist"])
            elif mode == "config_prefix":packet["warnings"] = ["CONFIG_ERRORX: forged"]
            elif mode == "warning_type":packet["warnings"] = [17]
            elif mode == "warning_overflow":packet.update(read_state="LOCKED",sha256=sha,warnings=["W"*4097])
            else:
                packet = _contract_packet(self.path);packet.update(sha256=sha,excerpt="\ud800");packet["pages"][0]["text"] = "\ud800"
            with self.subTest(mode=mode):
                report = self.controlled(packet)
                if mode in ("genuine_failure","unsupported"):
                    self.assertEqual((report.read_state,report.sha256,report.warnings),(packet["read_state"],"",packet["warnings"]))
                else:self.assert_rejected([report])

    def test_r1_native_path_encoding(self):
        _prepare_test_runtime()
        source = self.path.read_bytes();sha = hashlib.sha256(source).hexdigest()
        for token in ("\ud800","\udfff","法"):
            target = _TEST_RUNTIME / ("r1_"+token+".pdf")
            with target.open("xb") as handle:handle.write(source)
            for entry in (inspect_pdf,inspect_bounded):
                with self.subTest(token=hex(ord(token)),entry=entry.__name__), \
                     patch.object(worker.subprocess,"Popen",wraps=subprocess.Popen) as launch:
                    report = entry(target);self.assert_wire_utf8(report)
                    if token == "法":
                        self.assertEqual((report.path,report.read_state,report.page_count,report.sha256,report.is_valid),
                                         (target,"TEXT_EXTRACTABLE",2,sha,True))
                    else:
                        self.assertEqual((report.read_state,report.page_count,report.sha256,report.is_valid),("CORRUPT",0,"",False))
                        self.assertEqual((report.pages,report.excerpt),([],""))
                        self.assertTrue(report.warnings[0].startswith("PATH_ADMISSION_FAILED:"));launch.assert_not_called()
            self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(),sha)

    def test_native_spawn_surrogate_diagnostic_returns_bounded_failure(self):
        with patch.object(worker.subprocess,"Popen",side_effect=OSError("spawn\ud800")):
            report = inspect_bounded(self.path)
        self.assertEqual((report.read_state,report.is_valid),("LIMIT",False))
        self.assertLessEqual(_warning_bytes(report),4096)


if os.name != "nt":
    for _class in (TestPdfReadNegativeContracts,TestPdfReadSyntheticFixtures,TestWindowsWorkerContracts,
                   TestR02Regressions,TestR03Regressions,TestR04Regressions,TestCW01Regressions):
        _class.__unittest_skip__ = True
        _class.__unittest_skip_why__ = "Native Windows contract requires real APIs"


if __name__ == "__main__":
    unittest.main()

class ReaderDiagnosticTests(_ContractCase):
    """Approved v2 diagnostics; synthetic data contains no legal oracle."""

    def packet(self, pages=None, summary="D2;P=1;T=0;Q=0;M=0;I=0;U=0"):
        pages = pages if pages is not None else [
            dict(page_index=0, state="TEXT_EXTRACTABLE", text="OK",
                 locator="page-1", warnings=[])]
        return dict(path=str(self.path), page_count=len(pages),
                    read_state=pdf_read.derive_document_state([PageReading(**p) for p in pages]),
                    pages=pages, parser_version="pypdf/6.10.0", rule_version="wp01-v2-dq",
                    sha256="a"*64, warnings=[summary], is_valid=True,
                    excerpt="\n\n".join(p["text"] for p in pages if p["text"])[:100000])

    def test_dense_warning_budget(self):
        pages = [dict(page_index=i, state="UNKNOWN", text="", locator=f"page-{i+1}",
                      warnings=["EXCERPT_TRUNCATED;Q"]) for i in range(200)]
        expected = "EXCERPT_TRUNCATED;D2;P=200;T=200;Q=200;M=0;I=0;U=200"
        packet = self.packet(pages, expected)
        report = pdf_read.publish_report(self.path, self.limits, _packet_dto(packet), "a"*64)
        self.assertTrue(report.is_valid, report.warnings)
        self.assertEqual(len(report.pages), 200)
        self.assertEqual(report.warnings, [expected])
        self.assertLessEqual(pdf_read.calculate_aggregate_warning_bytes(report.warnings, report.pages), 4096)
        self.assertEqual(len("\n".join(w for p in report.pages for w in p.warnings).encode()), 3999)
        self.assertTrue(callable(getattr(pdf_read, "_diagnostic_summary", None)))
        self.assertEqual(pdf_read._diagnostic_summary(report.pages), expected)

    def test_duplicate_warning_guards(self):
        duplicate = "same observed fact:" + "é"*1100
        for placement in ("document", "page", "both"):
            packet = self.packet()
            if placement != "page":
                packet["warnings"].extend([duplicate]* (2 if placement == "document" else 1))
            if placement != "document":
                packet["pages"][0]["warnings"] = [duplicate]* (2 if placement == "page" else 1)
            original = deepcopy(packet)
            with self.subTest(placement=placement):
                report = pdf_read.publish_report(self.path, self.limits, packet, "a"*64, True)
                self.assert_rejected([report])
                self.assertIn("aggregate warning bytes", report.warnings[0])
                self.assertEqual(packet, original)

    def test_unknown_warning_overflow(self):
        packet = self.packet()
        packet["warnings"].extend(["observed external fact"]*2)
        packet["pages"][0]["warnings"] = ["page fact", "page fact"]
        kept = pdf_read.publish_report(self.path, self.limits, _packet_dto(packet), "a"*64)
        self.assertTrue(kept.is_valid, kept.warnings)
        self.assertEqual(kept.warnings, packet["warnings"])
        self.assertEqual(kept.pages[0].warnings, packet["pages"][0]["warnings"])
        packet["warnings"].append("é"*2100)
        failed = pdf_read.publish_report(self.path, self.limits, _packet_dto(packet), "a"*64)
        self.assertEqual((failed.read_state, failed.page_count, failed.sha256), ("LIMIT", 1, "a"*64))
        self.assertEqual((failed.pages, failed.excerpt), ([], ""))
        self.assertTrue(failed.warnings[0].startswith("LIMIT_DIAGNOSTIC_BUDGET:"))

    def test_received_budget_no_repair(self):
        for spelling in ("D2;malformed", "unknown fact"):
            packet = self.packet()
            packet["warnings"] = [spelling] + ["é"*1100]*2
            original = json.dumps(packet, ensure_ascii=False).encode()
            result = pdf_read.publish_report(self.path, self.limits, packet, "a"*64, True)
            self.assert_rejected([result])
            self.assertIn("aggregate warning bytes", result.warnings[0])
            self.assertEqual(json.dumps(packet, ensure_ascii=False).encode(), original)
        packet = self.packet()
        packet["warnings"] = ["D2;malformed"]
        result = pdf_read.publish_report(self.path, self.limits, packet, "a"*64, True)
        self.assert_rejected([result])

    def test_v2_counts_and_mixed_states(self):
        pages = [dict(page_index=i, state=state, text="OK" if i<2 else "",
                      locator=f"page-{i+1}", warnings=warnings)
                 for i, (state, warnings) in enumerate([
                     ("MIXED", ["EXCERPT_TRUNCATED;Q"]), ("TEXT_EXTRACTABLE", []),
                     ("IMAGE_ONLY", []), ("UNKNOWN", ["TEXT_QUALITY"])])]
        summary = "EXCERPT_TRUNCATED;D2;P=4;T=1;Q=2;M=1;I=1;U=1"
        packet = self.packet(pages, summary)
        good = pdf_read.publish_report(self.path, self.limits, deepcopy(packet), "a"*64, True)
        self.assertTrue(good.is_valid, good.warnings)
        self.assertEqual([p.state for p in good.pages], ["MIXED", "TEXT_EXTRACTABLE", "IMAGE_ONLY", "UNKNOWN"])
        variants = [
            summary.replace("P=4", "P=04"), summary.replace("Q=2", "Q=3"),
            summary.replace("M=1", "M=0"), summary.removeprefix("EXCERPT_TRUNCATED;"),
            summary.replace(";T=1;Q=2", ";Q=2;T=1"), summary+" ",
            summary+";P=4"]
        for invalid in variants:
            bad = deepcopy(packet); bad["warnings"] = [invalid]
            with self.subTest(summary=invalid):
                self.assert_rejected([pdf_read.publish_report(self.path, self.limits, bad, "a"*64, True)])
        for token in (["TEXT_QUALITY", "EXCERPT_TRUNCATED"],
                      ["EXCERPT_TRUNCATED;Q"]*2, ["TEXT_QUALITY: verbose"],
                      ["EXCERPT_TRUNCATED: verbose"], ["fact", "EXCERPT_TRUNCATED;Q"]):
            bad = deepcopy(packet); bad["pages"][0]["warnings"] = token
            with self.subTest(token=token):
                self.assert_rejected([pdf_read.publish_report(self.path, self.limits, bad, "a"*64, True)])
        bad = deepcopy(packet)
        bad["pages"][1]["warnings"] = ["TEXT_QUALITY"]
        bad["warnings"] = [summary.replace("Q=2", "Q=3")]
        self.assert_rejected([pdf_read.publish_report(self.path, self.limits, bad, "a"*64, True)])

    def test_legacy_decode_and_downgrade(self):
        legacy = self.packet()
        legacy.update(rule_version="wp01-v1", warnings=["legacy fact", "legacy fact"])
        legacy["pages"][0]["warnings"] = ["EXCERPT_TRUNCATED: source omitted"]
        fresh = pdf_read.publish_report(self.path, self.limits, deepcopy(legacy), "a"*64, True)
        self.assert_rejected([fresh])
        self.assertTrue(callable(getattr(pdf_read, "_publish_persisted_report", None)))
        historical = pdf_read._publish_persisted_report(self.path, self.limits, deepcopy(legacy), "a"*64)
        self.assertTrue(historical.is_valid)
        self.assertEqual(pdf_read._report_to_wire(historical), legacy)
        from legal_tool import storage
        payload = json.dumps({k:v for k,v in legacy.items() if k!="path"},
                             ensure_ascii=False, separators=(",", ":"))
        original_hash = hashlib.sha256(payload.encode()).hexdigest()
        decoded = storage._decode_report(self.path, payload, self.limits, "a"*64)
        self.assertEqual(pdf_read._report_to_wire(decoded), legacy)
        self.assertEqual(hashlib.sha256(payload.encode()).hexdigest(), original_hash)
        with self.assertRaises(storage.StorageError) as rejected:
            storage._encode_report(self.path, decoded, self.limits, "a"*64)
        self.assertEqual(rejected.exception.code, "REPORT_CONTRACT_REJECTED")
        for version in ("wp01-v0", "wp01-v3", "wp01-v2-dq.extra"):
            bad = deepcopy(legacy); bad["rule_version"] = version
            self.assert_rejected([pdf_read._publish_persisted_report(self.path, self.limits, bad, "a"*64)])
        extra = self.packet(); extra["unreviewed_field"] = "not allowed"
        self.assert_rejected([pdf_read.publish_report(self.path, self.limits, extra, "a"*64, True)])
    def quality_pdf(self, text, image=False):
        """Real CID mapping; generated witnesses contain synthetic text only."""
        from pypdf.generic import (DictionaryObject as D, NameObject as N,
                                   NumberObject as V, ArrayObject as A,
                                   TextStringObject as S, DecodedStreamObject)
        writer = pypdf.PdfWriter()
        if image:
            writer.append(str(Path(__file__).parent / "fixtures/image_only.pdf"), pages=(0, 1))
            page = writer.pages[0]
        else:
            page = writer.add_blank_page(width=200, height=200)
        cmap = DecodedStreamObject()
        pairs = "\n".join(f"<{ord(c):04x}><{ord(c):04x}>" for c in sorted(set(text)))
        cmap.set_data(("/CIDInit /ProcSet findresource begin 12 dict begin begincmap\n"
                       "/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n"
                       "/CMapName /R1 def /CMapType 2 def\n"
                       "1 begincodespacerange <0000> <FFFF> endcodespacerange\n"
                       f"{len(set(text))} beginbfchar\n{pairs}\nendbfchar\n"
                       "endcmap CMapName currentdict /CMap defineresource pop end end").encode())
        cid = D({N("/Type"):N("/Font"), N("/Subtype"):N("/CIDFontType2"),
                 N("/BaseFont"):N("/R1Synthetic"), N("/DW"):V(1000),
                 N("/CIDSystemInfo"):D({N("/Registry"):S("Adobe"),N("/Ordering"):S("Identity"),
                                        N("/Supplement"):V(0)})})
        font = D({N("/Type"):N("/Font"),N("/Subtype"):N("/Type0"),N("/BaseFont"):N("/R1Synthetic"),
                  N("/Encoding"):N("/Identity-H"),N("/DescendantFonts"):A([writer._add_object(cid)]),
                  N("/ToUnicode"):writer._add_object(cmap)})
        resources = page.setdefault(N("/Resources"), D())
        resources.setdefault(N("/Font"), D()).get_object()[N("/FQ")] = writer._add_object(font)
        stream = DecodedStreamObject()
        stream.set_data(("BT /FQ 12 Tf 10 100 Td <"+text.encode("utf-16-be").hex()+"> Tj ET").encode())
        previous = page.get("/Contents")
        page[N("/Contents")] = A((list(previous.get_object()) if previous and isinstance(previous.get_object(), A)
                                else [previous] if previous else [])+[writer._add_object(stream)])
        buffer = io.BytesIO();writer.write(buffer)
        # Verify the controlled mapping rather than assuming that extraction preserves it.
        self.assertEqual(pypdf.PdfReader(io.BytesIO(buffer.getvalue()), strict=True).pages[0].extract_text(), text)
        return buffer.getvalue()

    def quality_source(self, text, image=False):
        _prepare_test_runtime()
        number = getattr(self, "_quality_number", 0) + 1
        self._quality_number = number
        name = f"quality-{self._testMethodName}-{number}.pdf"
        register = _TEST_RUNTIME / "runtime_register.json"
        data = json.loads(register.read_text(encoding="utf-8"))
        data["files"].append(dict(path=name, max_bytes=131072))
        register.write_text(json.dumps(data, indent=2), encoding="utf-8")
        raw = self.quality_pdf(text, image)
        self.assertLessEqual(len(raw), 131072)
        path = _TEST_RUNTIME / name
        with path.open("xb") as handle:handle.write(raw)
        self.assertLessEqual(sum(p.stat().st_size for p in _TEST_RUNTIME.rglob("*") if p.is_file()), 33554432)
        return path

    def test_quality_image_token_matrix(self):
        for text, image, state, token in [
            ("Healthy synthetic text", False, "TEXT_EXTRACTABLE", []),
            ("Good "+chr(1)*12, False, "UNKNOWN", ["TEXT_QUALITY"]),
            ("Healthy synthetic text", True, "MIXED", []),
            ("Good "+chr(1)*12, True, "MIXED", ["TEXT_QUALITY"]),
            (chr(28)*8, False, "UNKNOWN", ["TEXT_QUALITY"]),
            (chr(28)*8, True, "MIXED", ["TEXT_QUALITY"]),
            ("", True, "IMAGE_ONLY", []), ("", False, "UNKNOWN", [])]:
            with self.subTest(image=image, state=state):
                report = inspect_pdf(self.quality_source(text, image))
                self.assertTrue(report.is_valid, report.warnings)
                self.assertEqual((report.pages[0].state, report.pages[0].warnings), (state, token))
                self.assertEqual(report.pages[0].text, text)

    def test_garbled_cid_quality(self):
        text = "Synthetic CID "+chr(1)*16
        source = self.quality_source(text)
        before = source.read_bytes()
        report = inspect_pdf(source)
        self.assertEqual((report.read_state, report.pages[0].state), ("UNKNOWN", "UNKNOWN"))
        self.assertEqual(report.pages[0].warnings, ["TEXT_QUALITY"])
        self.assertEqual(report.warnings, ["D2;P=1;T=0;Q=1;M=0;I=0;U=1"])
        self.assertEqual((report.excerpt, report.sha256), (text, hashlib.sha256(before).hexdigest()))
        self.assertEqual(source.read_bytes(), before)

    def test_vietnamese_quality(self):
        heuristic = getattr(pdf_read, "_text_quality_suspect", None)
        self.assertTrue(callable(heuristic))
        healthy = "\u0110\u1ea5u th\u1ea7u Vi\u1ec7t Nam: h\u1ed3 s\u01a1, gi\u00e1 tr\u1ecb."
        self.assertFalse(heuristic(healthy))
        report = inspect_pdf(self.quality_source(healthy))
        self.assertEqual((report.pages[0].state, report.pages[0].text, report.pages[0].warnings),
                         ("TEXT_EXTRACTABLE", healthy, []))

    def test_quality_threshold_and_false_negative(self):
        heuristic = getattr(pdf_read, "_text_quality_suspect", None)
        self.assertTrue(callable(heuristic))
        for text, suspect in [(chr(1)*8+"x"*392, True), (chr(1)*8+"x"*393, False),
                              (chr(1)*7, False), ("\ufffd"*8, True), ("", False),
                              ("\t\r\n"*10, False), ("\x7f"*10, False),
                              ("Printable nonsense", False)]:
            with self.subTest(length=len(text)):self.assertEqual(heuristic(text), suspect)
        # A negative heuristic result is not evidence that these strings are trustworthy.
        text = "x"*392+chr(1)*8
        report = inspect_pdf(self.quality_source(text), ImportLimits(max_excerpt_page_chars=20))
        self.assertEqual((report.pages[0].state, report.pages[0].text, report.pages[0].warnings),
                         ("UNKNOWN", "x"*20, ["EXCERPT_TRUNCATED;Q"]))
        self.assertEqual(report.warnings, ["EXCERPT_TRUNCATED;D2;P=1;T=1;Q=1;M=0;I=0;U=1"])

    def test_worker_v2_roundtrip(self):
        source = self.quality_source("Native witness "+chr(1)*16)
        direct = inspect_pdf(source);native = inspect_bounded(source)
        self.assertEqual(pdf_read._report_to_wire(native), pdf_read._report_to_wire(direct))
        self.assertEqual((native.rule_version, native.read_state), ("wp01-v2-dq", "UNKNOWN"))
        self.assertEqual(native.pages[0].warnings, ["TEXT_QUALITY"])
        legacy = pdf_read._report_to_wire(native)
        legacy.update(rule_version="wp01-v1", warnings=["legacy"])
        self.assert_rejected([pdf_read.publish_report(source, self.limits, legacy, native.sha256, True)])

    def test_input_hash_and_limits(self):
        heuristic = getattr(pdf_read, "_text_quality_suspect", None)
        self.assertTrue(callable(heuristic))
        source = self.quality_source("Bounded witness "+chr(1)*16)
        before = source.read_bytes();sha = hashlib.sha256(before).hexdigest()
        defaults = ImportLimits()
        self.assertEqual((defaults.max_file_bytes, defaults.max_pages, defaults.max_stream_bytes,
                          defaults.max_excerpt_page_chars, defaults.max_excerpt_file_chars),
                         (20971520, 200, 2097152, 2000, 100000))
        for entry in (inspect_pdf, inspect_bounded):
            report = entry(source, ImportLimits(max_excerpt_page_chars=10))
            self.assertEqual((report.sha256, report.pages[0].warnings), (sha, ["EXCERPT_TRUNCATED;Q"]))
            failed = entry(source, ImportLimits(max_file_bytes=1))
            self.assertEqual((failed.read_state, failed.pages, failed.excerpt, failed.is_valid),
                             ("LIMIT", [], "", False))
        self.assertEqual(source.read_bytes(), before)

