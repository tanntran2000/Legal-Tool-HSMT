"""Fail-closed CI checks, separate from the 119 product tests."""
from copy import deepcopy
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
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
            self.assertEqual(report["tests_run"], 20)
            self.assertEqual(len(report["resource_warnings"]), 1)
            self.assertIn("during discovery", report["resource_warnings"][0])
            self.assertIn("ResourceWarning", (path / "tests.log").read_text(encoding="utf8"))
            with self.assertRaises(ValueError):
                ci.validate_report(report, ids)

    def test_source_size_and_syntax(self):
        ci.validate_entry("legal_tool/storage.py", "100644", b"x = 1\n")
        for raw in [b"#" + b"x" * 81920, b"invalid python ???", b"\xff"]:
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

    def test_fixture_larger_than_source_cap(self):
        path = "tests/fixtures/page_limit.pdf"; raw = (ROOT / path).read_bytes()
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


    def test_preparation_module_has_approved_32k_cap(self):
        self.assertIn("tests/test_preparations.py", ci.ALLOWED_FILES)
        ci.validate_entry("tests/test_preparations.py", "100644", b"x = 1\n")
        ci.validate_entry("tests/test_preparations.py", "100644", b"#" + b"x" * (32768 - 1))
        with self.assertRaises(ValueError):
            ci.validate_entry("tests/test_preparations.py", "100644", b"#" + b"x" * 32768)

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
        self.assertTrue(required <= set(windows))
        self.assertFalse(required & set(portable))
        self.assertEqual(len(windows), 119 + len(required))
        self.assertEqual(len(portable), 20)
        with self.assertRaises(ValueError):
            ci.validate_inventory(windows, [x for x in windows if x not in required], [])


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromTestCase(TestCIGates)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestCIGates)
    if suite.countTestCases() == 0:
        raise SystemExit("ERROR: zero CI helper tests")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() and not result.skipped
                     and not result.expectedFailures and not result.unexpectedSuccesses else 1)
