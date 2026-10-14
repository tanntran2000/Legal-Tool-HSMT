"""Fail-closed CI checks, separate from the 119 product tests."""
from copy import deepcopy
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import types
import unittest
import warnings
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if importlib.util.find_spec("ci_checks") is None:
    ci = None
else:
    import ci_checks as ci


class SyntheticCase(unittest.TestCase):
    def test_ok(self):
        pass
    def test_failure(self):
        self.fail("synthetic failure")
    def test_error(self):
        raise RuntimeError("synthetic error")
    def test_skip(self):
        self.skipTest("synthetic skip")
    def test_resource_warning(self):
        warnings.warn("synthetic unclosed SQLite connection", ResourceWarning)


class TestCIGates(unittest.TestCase):
    def test_error_log_exact_portable_ids_and_legacy_subsets(self):
        methods = ('test_error_log_known_codes_ids_and_determinism',
            'test_error_log_excludes_source_paths_messages_and_secrets',
            'test_error_log_invalid_required_metadata_and_unknown_versions',
            'test_error_log_warning_scan_budget_and_utf8_output_boundaries',
            'test_error_log_page_states_quality_truncation_and_d2_summary',
            'test_error_log_token_boundaries_and_unclassified_counts',
            'test_error_log_no_side_effects_or_input_mutation',
            'test_error_log_exact_normal_and_fallback_text')
        prefix = 'tests.test_pdf_read.TestErrorLogFormatter.'
        for profile, count, old in [('windows-native', 188, 170), ('linux-portable', 34, 20)]:
            ids = ci.expected_ids(profile)
            self.assertEqual([x for x in ids if x.startswith(prefix)], [prefix+m for m in methods])
            self.assertEqual(len(ids), count)
            self.assertEqual(len([x for x in ids if not x.startswith(prefix)
                and not x.startswith('tools.standalone_display.')]), old)
            for actual in ([x for x in ids if not x.startswith(prefix)], ids+[prefix+methods[0]]):
                with self.assertRaises(ValueError):
                    ci.validate_inventory(ids, actual, [])
        self.assertEqual(ci.PORTABLE_CLASSES,
            ('TestPdfReadTypesAndDefaults', 'CW02PortableContract', 'CW02OracleCorrection'))

    def test_error_log_inventory_rejects_missing_duplicate_or_nonportable_methods(self):
        self.assertTrue(hasattr(ci, 'ERROR_LOG_METHODS'), 'formatter inventory missing')
        target = ROOT / 'tests/test_pdf_read.py'
        original = target.read_bytes()
        name = b'test_error_log_exact_normal_and_fallback_text'
        variants = [original.replace(b'class TestErrorLogFormatter', b'class OtherFormatter', 1),
                    original.replace(b'def '+name, b'def omitted_formatter_case', 1),
                    original.replace(b'def '+name, b'async def '+name, 1),
                    original.replace(b'def '+name, b'def test_nonportable_native_case', 1),
                    original.replace(b'    def '+name, b'    def '+name+b'(self):\n        pass\n\n    def '+name, 1)]
        read_bytes = Path.read_bytes
        for raw in variants:
            def read(path):
                return raw if path == target else read_bytes(path)
            with patch.object(Path, 'read_bytes', read):
                for profile in ('windows-native', 'linux-portable'):
                    with self.subTest(profile=profile), self.assertRaises(ValueError):
                        ci.expected_ids(profile)

    def test_standalone_exact_members_and_caps(self):
        prefix = 'tools/standalone_display/'
        for name, cap in [('display.py', 100000), ('tests/test_display.py', 100000), ('README.md', 4096)]:
            path = prefix + name
            self.assertIn(path, ci.ALLOWED_FILES)
            ci.validate_entry(path, '100644', b'#' + b'x' * (cap - 1))
            with self.assertRaises(ValueError):
                ci.validate_entry(path, '100644', b'#' + b'x' * cap)
        for path in [prefix + 'extra.py', prefix + 'tests/extra.py', prefix + 'other.json']:
            with self.assertRaises(ValueError):
                ci.validate_entry(path, '100644', b'{}')

    def test_standalone_fixture_cap_precedes_pin(self):
        import hashlib
        path = 'tools/standalone_display/display_data.json'
        self.assertIn(path, ci.FIXTURES)
        raw = (ROOT / path).read_bytes()
        ci.validate_entry(path, '100644', raw)
        for mode in ['120000', '160000', '100755', None]:
            with self.assertRaises(ValueError):
                ci.validate_entry(path, mode, raw)
        with self.assertRaises(ValueError):
            ci.validate_entry(path, '100644', raw.replace(b'DEMO', b'TEST', 1))
        oversized = b'x' * 32769
        with patch.dict(ci.FIXTURES, {path: hashlib.sha256(oversized).hexdigest()}):
            with self.assertRaisesRegex(ValueError, 'cap'):
                ci.validate_entry(path, '100644', oversized)

    def test_standalone_inventory_and_legacy_subsets(self):
        module = 'tools.standalone_display.tests.test_display.'
        windows = ci.expected_ids('windows-native')
        portable = ci.expected_ids('linux-portable')
        for profile, ids, old in [('windows-native', windows, 170), ('linux-portable', portable, 20)]:
            additions = [x for x in ids if x.startswith(module)]
            formatter = [x for x in ids if x.startswith('tests.test_pdf_read.TestErrorLogFormatter.')]
            self.assertTrue(additions)
            self.assertEqual(len(formatter), 8)
            self.assertEqual(len(ids) - len(additions) - len(formatter), old)
            self.assertTrue(any('.DisplayPortableContract.' in x for x in additions))
            self.assertEqual(any('.DisplayNativeUI.' in x for x in additions), profile == 'windows-native')
            for absent in [additions, additions[:1]]:
                with self.assertRaises(ValueError):
                    ci.validate_inventory(ids, [x for x in ids if x not in absent], [])

    def test_standalone_members_without_retired_bundle_cap(self):
        self.assertTrue(hasattr(ci, 'HANDOFF_CAPS'), 'six-file full-byte policy missing')
        self.assertEqual(set(ci.HANDOFF_CAPS), {'tools/standalone_display/' + p for p in
            ['display.py', 'display_data.json', 'tests/test_display.py', 'README.md']} |
            {'.github/scripts/ci_checks.py', '.github/scripts/test_ci_checks.py'})
        entries = {p: {'bytes': 1} for p in ci.HANDOFF_CAPS}
        ci.validate_handoff(entries)
        entries['.github/scripts/ci_checks.py']['bytes'] = 100001
        with self.assertRaisesRegex(ValueError, 'cap'):
            ci.validate_handoff(entries)
        entries = {p: {'bytes': cap} for p, cap in ci.HANDOFF_CAPS.items()}
        self.assertGreater(sum(row['bytes'] for row in entries.values()), 100000)
        ci.validate_handoff(entries)  # PR4's completed publication bundle is historical.
        entries.pop('tools/standalone_display/README.md')
        with self.assertRaisesRegex(ValueError, 'missing'):
            ci.validate_handoff(entries)

    def test_source_test_decimal_100000_byte_boundaries(self):
        self.assertEqual(ci.SOURCE_CAP, 100000)
        for path in sorted(ci.PYTHON_FILES):
            with self.subTest(path=path):
                try:
                    ci.validate_entry(path, '100644', b'#' + b'x' * 99999)
                except ValueError as error:
                    self.fail('100000-byte source/test must be admitted: ' + str(error))
                with self.assertRaisesRegex(ValueError, 'cap'):
                    ci.validate_entry(path, '100644', b'#' + b'x' * 100000)

    def test_direct_pdf_runner_collects_platform_inventory(self):
        collected = []
        def flatten(suite):
            for item in suite:
                if isinstance(item, unittest.TestSuite):
                    yield from flatten(item)
                else:
                    yield item.id().replace('__main__.', 'tests.test_pdf_read.', 1)
        def collect_only(program):
            collected.extend(flatten(program.test))
        sys.path.insert(0, str(ROOT))
        try:
            with patch.object(unittest.TestProgram, 'runTests', collect_only), \
                 patch.object(sys, 'argv', [str(ROOT / 'tests/test_pdf_read.py')]):
                runpy.run_path(str(ROOT / 'tests/test_pdf_read.py'), run_name='__main__')
        finally:
            sys.path.pop(0)
        profile = 'windows-native' if os.name == 'nt' else 'linux-portable'
        expected = [identity for identity in ci.expected_ids(profile)
                    if identity.startswith('tests.test_pdf_read.')]
        self.assertEqual(sorted(collected), sorted(expected))

    def setUp(self):
        self.assertIsNotNone(ci, "CI helper does not exist yet")
        self.ids = ["tests.synthetic.Case.test_one"]
        self.good = dict(schema_version=1, complete=True, profile="linux-portable",
                         collected_ids=self.ids, started_ids=self.ids,
                         successful_ids=self.ids, tests_run=1, failures=0, errors=0,
                         skips=0, expected_failures=0, unexpected_successes=0,
                         loader_errors=[], resource_warnings=[], native_calls=[])

    def test_aggregate_success(self):
        ci.validate_aggregate({n: {"result": "success"} for n in ci.REQUIRED_JOBS})

    def test_aggregate_adverse_results(self):
        for job in ci.REQUIRED_JOBS:
            for state in ["failure", "skipped", "cancelled", "missing", "", None, True]:
                with self.subTest(job=job, state=state):
                    needs = {n: {"result": "success"} for n in ci.REQUIRED_JOBS}
                    needs[job]["result"] = state
                    with self.assertRaises(ValueError):
                        ci.validate_aggregate(needs)

    def test_aggregate_missing_or_invalid_needs(self):
        good = {n: {"result": "success"} for n in ci.REQUIRED_JOBS}
        for needs in [{}, None, [], {**good, "extra": {"result": "success"}},
                      {n: good[n] for n in ci.REQUIRED_JOBS[1:]},
                      {**good, ci.REQUIRED_JOBS[0]: {}},
                      {**good, ci.REQUIRED_JOBS[0]: "success"}]:
            with self.subTest(needs=needs), self.assertRaises(ValueError):
                ci.validate_aggregate(needs)

    def test_inventory_success(self):
        ci.validate_inventory(self.ids, self.ids, [])

    def test_inventory_zero_duplicate_error_and_mismatch(self):
        for expected, actual, errors in [([], [], []), (self.ids, [], []),
                (self.ids * 2, self.ids * 2, []), (self.ids, self.ids * 2, []),
                (self.ids, ["tests.other.Case.test_wrong"], []),
                (self.ids, self.ids, ["import failed"]),
                (self.ids, [None], []), (self.ids, self.ids, None)]:
            with self.subTest(actual=actual), self.assertRaises(ValueError):
                ci.validate_inventory(expected, actual, errors)

    def test_report_success(self):
        ci.validate_report(self.good, self.ids)

    def test_report_adverse_outcomes(self):
        for field, value in [("complete", False), ("schema_version", True),
                ("tests_run", 0), ("tests_run", True), ("failures", 1),
                ("errors", 1), ("skips", 1), ("expected_failures", 1),
                ("unexpected_successes", 1), ("loader_errors", ["error"]),
                ("resource_warnings", ["unclosed SQLite"]),
                ("native_calls", ["GetFileAttributesW"]),
                ("successful_ids", []), ("started_ids", self.ids * 2),
                ("collected_ids", []), ("profile", "unknown")]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                bad = deepcopy(self.good); bad[field] = value
                ci.validate_report(bad, self.ids)

    def test_report_missing_fields(self):
        for key in self.good:
            with self.subTest(key=key), self.assertRaises(ValueError):
                bad = deepcopy(self.good); del bad[key]
                ci.validate_report(bad, self.ids)

    def test_real_unittest_result(self):
        case = SyntheticCase("test_ok")
        report = ci.execute_suite(unittest.TestSuite([case]), [case.id()],
                                  "linux-portable", io.StringIO(), [])
        ci.validate_report(report, [case.id()])
        self.assertEqual(report["successful_ids"], [case.id()])

    def test_real_fail_error_skip_warning(self):
        for method in ["test_failure", "test_error", "test_skip", "test_resource_warning"]:
            with self.subTest(method=method):
                case = SyntheticCase(method); log = io.StringIO()
                report = ci.execute_suite(unittest.TestSuite([case]), [case.id()],
                                          "linux-portable", log, [])
                with self.assertRaises(ValueError):
                    ci.validate_report(report, [case.id()])
                if method == "test_resource_warning":
                    self.assertIn("ResourceWarning", log.getvalue())
                    self.assertTrue(report["resource_warnings"])

    def test_discovery_resource_warning_rejects_real_cli_report(self):
        # Only metadata/runtime/collector are seams; executor and report validation are real.
        ids = ci.expected_ids("linux-portable")
        class NamedPass(unittest.TestCase):
            def __init__(self, identity):
                super().__init__("test_ok")
                self.identity = identity
            def id(self):
                return self.identity
            def test_ok(self):
                pass
        def collector(profile):
            self.assertEqual(profile, "linux-portable")
            warnings.warn("synthetic ResourceWarning during discovery", ResourceWarning)
            return unittest.TestSuite(NamedPass(identity) for identity in ids), ids, ids
        frozen = types.ModuleType("tests.test_pdf_read")
        frozen._NATIVE_CALLS = []
        package = types.ModuleType("tests")
        package.__path__ = []
        package.test_pdf_read = frozen
        with tempfile.TemporaryDirectory(prefix="lt-ci-discovery-") as directory:
            path = Path(directory)
            self.assertTrue(path.resolve().is_relative_to(Path(tempfile.gettempdir()).resolve()))
            with patch.object(ci, "context", return_value={"synthetic_control_only": True}), \
                 patch.object(ci, "require_test_runtime"), \
                 patch.object(ci, "collect_suite", side_effect=collector), \
                 patch.dict(sys.modules, {"tests": package, "tests.test_pdf_read": frozen}), \
                 patch.dict(os.environ, {"CI_OUTPUT_DIR": directory}, clear=True), \
                 patch.object(sys, "argv", ["ci_checks.py", "tests", "--profile", "linux-portable"]), \
                 patch.object(sys, "__stdout__", io.StringIO()), \
                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()), \
                 warnings.catch_warnings(record=True):
                warnings.simplefilter("always", ResourceWarning)
                exit_code = ci.main()
            report = ci.read_json(path / "tests.json")
            self.assertNotEqual(exit_code, 0)
            self.assertEqual(report["status"], "FAILED")
            self.assertEqual(report["tests_run"], ci.EXPECTED_COUNTS['linux-portable'])
            self.assertEqual(len(report["resource_warnings"]), 1)
            self.assertIn("during discovery", report["resource_warnings"][0])
            self.assertIn("ResourceWarning", (path / "tests.log").read_text(encoding="utf8"))
            with self.assertRaises(ValueError):
                ci.validate_report(report, ids)

    def test_source_size_and_syntax(self):
        ci.validate_entry("legal_tool/storage.py", "100644", b"x = 1\n")
        ci.validate_entry("tests/test_storage.py", "100644", b"#" + b"x" * 99999)
        with self.assertRaises(ValueError):
            ci.validate_entry("tests/test_storage.py", "100644", b"#" + b"x" * 100000)
        for path, cap in [("tests/test_preparation_listing.py", 100000), ("README.md", 2048)]:
            ci.validate_entry(path, "100644", b"#" + b"x" * (cap - 1))
            with self.assertRaises(ValueError):
                ci.validate_entry(path, "100644", b"#" + b"x" * cap)
        for raw in [b"#" + b"x" * 100000, b"invalid python ???", b"\xff"]:
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                ci.validate_entry("legal_tool/storage.py", "100644", raw)

    def test_path_and_type_policy(self):
        for path, mode in [("../secret.py", "100644"), ("/legal_tool/storage.py", "100644"),
                ("legal_tool\\storage.py", "100644"), ("runtime/app.sqlite3", "100644"),
                ("tests/fixtures/personal.pdf", "100644"),
                (".github/workflows/disabled.yml", "100644"),
                ("legal_tool/storage.py", "120000"), ("legal_tool/storage.py", "160000"),
                ("legal_tool/storage.py", "100755")]:
            with self.subTest(path=path, mode=mode), self.assertRaises(ValueError):
                ci.validate_entry(path, mode, b"x = 1\n")

    def test_dependency_policy(self):
        ci.validate_entry("requirements-wp01.txt", "100644", b"pypdf==6.10.0\r\n")
        for raw in [b"pypdf==6.9.0\n", b"pypdf==6.10.0\ncoverage\n", b""]:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                ci.validate_entry("requirements-wp01.txt", "100644", raw)

    def test_fixture_pin_independent_of_source_cap(self):
        path = "tests/fixtures/page_limit.pdf"; raw = (ROOT / path).read_bytes()
        # This fixture exceeded the historical80KiB source cap; its pin is independent.
        self.assertGreater(len(raw), 81920)
        ci.validate_entry(path, "100644", raw)
        with self.assertRaises(ValueError):
            ci.validate_entry(path, "100644", raw + b"changed")
        with self.assertRaises(ValueError):
            ci.validate_entry("tests/fixtures/expected.json", "100644", b"{}")

    def test_job_env_rejects_runner_context(self):
        good = ci.read_json(ROOT / ".github/workflows/ci.yml")
        for job in good["jobs"]:
            for expression in ["${{ runner.temp }}", "${{ runner['temp'] }}",
                               "${{ format('{0}', runner.temp) }}"]:
                bad = deepcopy(good)
                bad["jobs"][job].setdefault("env", {})["UNSUPPORTED"] = expression
                with self.assertRaisesRegex(ValueError, "runner.*job.*env"):
                    ci.validate_workflow(bad)
        # Literal text has no expression; step env supports runner per GitHub's table.
        supported = deepcopy(good)
        for job in supported["jobs"].values():
            job["env"] = {"LITERAL": "runner.temp"}
            job["steps"][0]["env"] = {"SUPPORTED": "${{ runner.temp }}"}
        ci.validate_workflow(supported)

    def test_actual_workflow(self):
        ci.validate_workflow(ci.read_json(ROOT / ".github/workflows/ci.yml"))

    def test_workflow_safety(self):
        good = ci.read_json(ROOT / ".github/workflows/ci.yml")
        variants = []
        bad = deepcopy(good); bad["on"]["pull_request"]["paths"] = ["legal_tool/**"]; variants.append(bad)
        bad = deepcopy(good); bad["on"]["pull_request"]["types"].remove("synchronize"); variants.append(bad)
        bad = deepcopy(good); bad["permissions"]["pull-requests"] = "write"; variants.append(bad)
        bad = deepcopy(good); bad["jobs"]["windows-native"]["if"] = "false"; variants.append(bad)
        bad = deepcopy(good); bad["jobs"]["linux-portable"]["continue-on-error"] = True; variants.append(bad)
        bad = deepcopy(good); bad["jobs"]["ci-required"]["if"] = "success()"; variants.append(bad)
        bad = deepcopy(good); bad["jobs"]["ci-required"]["needs"].pop(); variants.append(bad)
        bad = deepcopy(good); bad["jobs"]["scope-policy"]["steps"][1]["with"]["persist-credentials"] = True; variants.append(bad)
        bad = deepcopy(good); bad["jobs"]["scope-policy"]["steps"][1]["with"]["ref"] = "main"; variants.append(bad)
        bad = deepcopy(good); bad["jobs"]["scope-policy"]["steps"][1]["uses"] = "actions/checkout@main"; variants.append(bad)
        bad = deepcopy(good); bad["jobs"]["scope-policy"]["permissions"] = {"contents": "write"}; variants.append(bad)
        bad = deepcopy(good); bad["jobs"]["scope-policy"]["steps"].insert(-1, {"run": "echo ${{ secrets['EXAMPLE'] }}"}); variants.append(bad)
        for number, bad in enumerate(variants):
            with self.subTest(number=number), self.assertRaises(ValueError):
                ci.validate_workflow(bad)

    def test_invalid_json_and_missing_report(self):
        for raw in [b"", b"{", b'{"a":1,"a":2}', b"NaN"]:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                ci.decode_json(raw)
        with self.assertRaises(ValueError):
            ci.read_json(ROOT / "missing-ci-report.json")

    def test_aggregate_cli_rejects_bad_inputs(self):
        for needs in ["", "{", "{}", json.dumps({n: {"result": "skipped"} for n in ci.REQUIRED_JOBS})]:
            env = os.environ.copy(); env["CI_NEEDS_JSON"] = needs
            env.pop("CI_OUTPUT_DIR", None); env.pop("GITHUB_STEP_SUMMARY", None)
            result = subprocess.run([sys.executable, "-B", str(HERE / "ci_checks.py"), "aggregate"],
                                    cwd=ROOT, env=env, capture_output=True, text=True)
            with self.subTest(needs=needs):
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("PASS", result.stdout)


    def test_preparation_module_has_approved_source_cap(self):
        self.assertIn("tests/test_preparations.py", ci.ALLOWED_FILES)
        ci.validate_entry("tests/test_preparations.py", "100644", b"x = 1\n")
        ci.validate_entry("tests/test_preparations.py", "100644", b"#" + b"x" * 99999)
        with self.assertRaises(ValueError):
            ci.validate_entry("tests/test_preparations.py", "100644", b"#" + b"x" * 100000)

    def test_preparation_ids_are_required_only_in_windows_inventory(self):
        import ast
        path = ROOT / "tests/test_preparations.py"
        tree = ast.parse(path.read_bytes())
        required = {"tests.test_preparations." + cls.name + "." + method.name
                    for cls in tree.body if isinstance(cls, ast.ClassDef) and not cls.name.startswith("_")
                    for method in cls.body if isinstance(method, ast.FunctionDef) and method.name.startswith("test_")}
        self.assertTrue(required)
        windows = ci.expected_ids("windows-native")
        portable = ci.expected_ids("linux-portable")
        windows = [x for x in windows if not x.startswith('tools.standalone_display.')]
        portable = [x for x in portable if not x.startswith('tools.standalone_display.')]
        windows = [x for x in windows if not x.startswith('tests.test_pdf_read.TestErrorLogFormatter.')]
        portable = [x for x in portable if not x.startswith('tests.test_pdf_read.TestErrorLogFormatter.')]
        self.assertTrue(required <= set(windows))
        self.assertFalse(required & set(portable))
        self.assertEqual(len(windows), 138 + len(required))
        listing = {x for x in windows if x.startswith("tests.test_preparation_listing.")}
        reader = {x for x in windows if ".ReaderDiagnosticTests." in x}
        self.assertEqual(len(listing), 7)
        self.assertEqual(len(reader), 12)
        self.assertFalse((listing | reader) & set(portable))
        for missing in (listing, reader):
            with self.assertRaises(ValueError):
                ci.validate_inventory(windows, [x for x in windows if x not in missing], [])
        self.assertEqual(len(portable), 20)
        with self.assertRaises(ValueError):
            ci.validate_inventory(windows, [x for x in windows if x not in required], [])


    def test_native_bootstrap_owns_paths_and_restores_environment(self):
        self.assertTrue(callable(getattr(ci, "native_test_inputs", None)))
        keys = ("WP01_PREPARATION_TEST_RUNTIME", "WP01_PREPARATION_BEFORE_STORAGE", "CW02_TEST_RUNTIME")
        prior = {key: "prior-" + key for key in keys}
        with tempfile.TemporaryDirectory() as base, patch.dict(os.environ, {**prior, "RUNNER_TEMP": base}):
            report = {}
            with patch.object(ci, "_fetch_historical_storage", return_value=b"# unit retrieval fixture\n"):
                with ci.native_test_inputs(report):
                    owned = Path(os.environ[keys[0]]).parent
                    self.assertEqual(owned.parent, Path(base))
                    self.assertTrue(Path(os.environ[keys[0]]).is_dir())
                    self.assertEqual(Path(os.environ[keys[1]]).read_bytes(), b"# unit retrieval fixture\n")
                    self.assertFalse(Path(os.environ[keys[2]]).exists())
                    self.assertEqual(Path(os.environ[keys[2]]).parent, owned)
                self.assertFalse(owned.exists())
            self.assertEqual({key: os.environ[key] for key in keys}, prior)
            self.assertEqual(report["bootstrap_cleanup"], "complete")

    def test_historical_retrieval_rejects_wrong_hash_before_materializing(self):
        self.assertTrue(callable(getattr(ci, "_fetch_historical_storage", None)))
        response = unittest.mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.geturl.return_value = ci.HISTORICAL_STORAGE_URL
        response.read.return_value = b"x" * 48222
        opener = unittest.mock.MagicMock()
        opener.open.return_value = response
        with patch.object(ci.urllib.request, "build_opener", return_value=opener):
            with self.assertRaisesRegex(ValueError, "SHA256"):
                ci._fetch_historical_storage()
        response.read.assert_called_once_with(80 * 1024 + 1)
        opener.open.assert_called_once_with(ci.HISTORICAL_STORAGE_URL, timeout=15)

    def test_historical_retrieval_refuses_oversize_status_and_redirect(self):
        self.assertTrue(callable(getattr(ci, "_fetch_historical_storage", None)))
        for status, url, body, diagnostic in [
                (200, ci.HISTORICAL_STORAGE_URL, b"x" * (80 * 1024 + 1), "cap"),
                (503, ci.HISTORICAL_STORAGE_URL, b"", "status"),
                (200, "https://example.invalid/other", b"", "URL")]:
            response = unittest.mock.MagicMock()
            response.__enter__.return_value = response
            response.status = status
            response.geturl.return_value = url
            response.read.return_value = body
            opener = unittest.mock.MagicMock()
            opener.open.return_value = response
            with self.subTest(diagnostic=diagnostic), patch.object(ci.urllib.request, "build_opener", return_value=opener):
                with self.assertRaisesRegex(ValueError, diagnostic):
                    ci._fetch_historical_storage()
        with self.assertRaisesRegex(ValueError, "redirect"):
            ci._NoHistoricalRedirect().redirect_request(None, None, 302, "redirect", {}, "https://example.invalid/")

    def test_native_bootstrap_retrieval_failure_cleans_and_restores(self):
        self.assertTrue(callable(getattr(ci, "native_test_inputs", None)))
        keys = ("WP01_PREPARATION_TEST_RUNTIME", "WP01_PREPARATION_BEFORE_STORAGE", "CW02_TEST_RUNTIME")
        with tempfile.TemporaryDirectory() as base, patch.dict(os.environ, {"RUNNER_TEMP": base}):
            for key in keys:
                os.environ.pop(key, None)
            with patch.object(ci, "_fetch_historical_storage", side_effect=TimeoutError("synthetic retrieval timeout")):
                with self.assertRaises(TimeoutError):
                    with ci.native_test_inputs({}):
                        self.fail("Retrieval failure must prevent test execution")
            self.assertEqual(list(Path(base).iterdir()), [])
            self.assertTrue(all(key not in os.environ for key in keys))

    def test_native_bootstrap_body_failure_cleans_and_restores(self):
        self.assertTrue(callable(getattr(ci, "native_test_inputs", None)))
        with tempfile.TemporaryDirectory() as base, patch.dict(os.environ, {"RUNNER_TEMP": base}):
            before = {key: os.environ.get(key) for key in
                      ("WP01_PREPARATION_TEST_RUNTIME", "WP01_PREPARATION_BEFORE_STORAGE", "CW02_TEST_RUNTIME")}
            report = {}
            with patch.object(ci, "_fetch_historical_storage", return_value=b"# unit retrieval fixture\n"):
                with self.assertRaisesRegex(RuntimeError, "synthetic test failure"):
                    with ci.native_test_inputs(report):
                        raise RuntimeError("synthetic test failure")
            self.assertEqual(list(Path(base).iterdir()), [])
            self.assertEqual({key: os.environ.get(key) for key in before}, before)
            self.assertEqual(report["bootstrap_cleanup"], "complete")

    def test_native_bootstrap_cleanup_failure_fails_gate_and_restores(self):
        self.assertTrue(callable(getattr(ci, "native_test_inputs", None)))
        original = tempfile.TemporaryDirectory
        allocated = []
        def allocate(*args, **kwargs):
            owned = original(*args, **kwargs)
            cleanup = owned.cleanup
            allocated.append((owned, cleanup))
            owned.cleanup = lambda: (_ for _ in ()).throw(OSError("synthetic cleanup denied"))
            return owned
        with original() as base, patch.dict(os.environ, {"RUNNER_TEMP": base}):
            before = {key: os.environ.get(key) for key in
                      ("WP01_PREPARATION_TEST_RUNTIME", "WP01_PREPARATION_BEFORE_STORAGE", "CW02_TEST_RUNTIME")}
            report = {}
            try:
                with patch.object(ci.tempfile, "TemporaryDirectory", side_effect=allocate), patch.object(
                        ci, "_fetch_historical_storage", return_value=b"# unit retrieval fixture\n"):
                    with self.assertRaisesRegex(ValueError, "cleanup"):
                        with ci.native_test_inputs(report):
                            pass
                self.assertEqual({key: os.environ.get(key) for key in before}, before)
                self.assertEqual(report["bootstrap_cleanup"], "failed")
            finally:
                for owned, cleanup in allocated:
                    cleanup()


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromTestCase(TestCIGates)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestCIGates)
    if suite.countTestCases() == 0:
        raise SystemExit("ERROR: zero CI helper tests")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() and not result.skipped
                     and not result.expectedFailures and not result.unexpectedSuccesses else 1)
