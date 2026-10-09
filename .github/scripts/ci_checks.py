"""Small, fail-closed GitHub CI gates; standard library only."""
import argparse
import ast
from contextlib import redirect_stderr, redirect_stdout
import gc
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import sqlite3
import subprocess
import sys
import sysconfig
import time
import unittest
import warnings

ROOT = Path(__file__).resolve().parents[2]
REQUIRED_JOBS = ("scope-policy", "windows-native", "linux-portable")
# Update only with approved test additions; IDs are independently derived/discovered.
EXPECTED_COUNTS = {"windows-native": 119, "linux-portable": 20}
PORTABLE_CLASSES = ("TestPdfReadTypesAndDefaults", "CW02PortableContract", "CW02OracleCorrection")
SOURCE_CAP = 80 * 1024
OUTPUT_CAP = 256 * 1024
WORKFLOW = ".github/workflows/ci.yml"
PYTHON_FILES = {
    "legal_tool/__init__.py", "legal_tool/pdf_read.py", "legal_tool/storage.py", "legal_tool/worker.py",
    "tests/__init__.py", "tests/fixture_factory.py", "tests/test_pdf_read.py", "tests/test_storage.py",
    ".github/scripts/ci_checks.py", ".github/scripts/test_ci_checks.py",
}
FIXTURES = {
    "tests/fixtures/corrupt.pdf": "b3da49d3483747ad476e2f461dfbbb72516203e2e0947ddefed90f50d8deb5d6",
    "tests/fixtures/expected.json": "5f12210bcd4934f0af26da4d763e9f104112ad96cc761c1d10391b6569d300ba",
    "tests/fixtures/image_only.pdf": "3553a18e977e37d5ae313d12f4141d2bda836942090d0be0146e4311c7389b19",
    "tests/fixtures/locked.pdf": "97e42fc247914c2f427df22849b288db9668832779334d91ce9793e1a06a5402",
    "tests/fixtures/mixed.pdf": "9092429334740349ac78337db74a64b994580e66225229065301a0859c726fdf",
    "tests/fixtures/page_limit.pdf": "55a839118a8f0e9d09f968502df0f6d8745df5cc128a6e4e5f6fa81b6f1c347a",
    "tests/fixtures/stream_limit.pdf": "ea8ebfb5447d31c44bdf59552b9464ed68d26d59c54f53e426885ae71134e82b",
    "tests/fixtures/text_unicode.pdf": "f8fab60581b6954744122fb34a2f3e371f607030c985b856baa865160e7465fd",
    "tests/fixtures/unsupported.txt": "d1e0d082cd811c10affadcf9bad2d5b00c1748a09fd9284f0076cc20e2233bdc",
}
ALLOWED_FILES = PYTHON_FILES | set(FIXTURES) | {WORKFLOW, "README.md", ".gitignore", "requirements-wp01.txt"}
ACTIONS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",  # v7.0.1
    "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",  # v7.0.0
    "actions/upload-artifact": "cf430e030ddbb5b0abf93d22962f4752f3646cd9",  # v7.0.2
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def decode_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result
    def invalid_constant(value):
        raise ValueError("invalid JSON constant: " + value)
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_constant)
    except (TypeError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid JSON: " + str(error)) from error


def read_json(path):
    try:
        raw = Path(path).read_bytes()
    except OSError as error:
        raise ValueError("missing/unreadable report: " + str(path)) from error
    require(len(raw) <= OUTPUT_CAP, "JSON report exceeds output cap")
    return decode_json(raw)


def validate_inventory(expected_ids, discovered_ids, loader_errors):
    require(type(loader_errors) is list and not loader_errors, "test discovery errors")
    for label, ids in [("expected", expected_ids), ("discovered", discovered_ids)]:
        require(type(ids) is list and len(ids) > 0, label + " test inventory is zero/invalid")
        require(all(type(i) is str and i and not any(c in i for c in "\r\n\0") for i in ids),
                label + " test IDs invalid")
        require(len(set(ids)) == len(ids), label + " duplicate test IDs")
    require(set(expected_ids) == set(discovered_ids), "test ID inventory mismatch")


def validate_report(report, expected_ids):
    required = {"schema_version", "complete", "profile", "collected_ids", "started_ids", "successful_ids",
                "tests_run", "failures", "errors", "skips", "expected_failures", "unexpected_successes",
                "loader_errors", "resource_warnings", "native_calls"}
    require(type(report) is dict and required <= report.keys(), "missing/invalid test report fields")
    require(type(report["schema_version"]) is int and report["schema_version"] == 1, "invalid report schema")
    require(report["complete"] is True, "incomplete test report")
    require(report["profile"] in EXPECTED_COUNTS, "invalid test profile")
    validate_inventory(expected_ids, report["collected_ids"], report["loader_errors"])
    validate_inventory(expected_ids, report["started_ids"], [])
    validate_inventory(expected_ids, report["successful_ids"], [])
    require(type(report["tests_run"]) is int and report["tests_run"] == len(expected_ids), "invalid tests-run count")
    for field in ["failures", "errors", "skips", "expected_failures", "unexpected_successes"]:
        require(type(report[field]) is int and report[field] == 0, "adverse unittest outcome: " + field)
    require(type(report["resource_warnings"]) is list and not report["resource_warnings"], "ResourceWarning recorded")
    require(type(report["native_calls"]) is list and not report["native_calls"], "forbidden native attempt recorded")


def validate_aggregate(needs):
    require(type(needs) is dict and set(needs) == set(REQUIRED_JOBS), "missing/extra mandatory job result")
    for name in REQUIRED_JOBS:
        require(type(needs[name]) is dict and needs[name].get("result") == "success",
                "mandatory job did not succeed: " + name)


def validate_entry(path, mode, raw):
    require(type(path) is str and path in ALLOWED_FILES and "\\" not in path
            and not PurePosixPath(path).is_absolute() and ".." not in PurePosixPath(path).parts,
            "path outside approved source/CI/synthetic-fixture policy: " + str(path))
    require(mode == "100644", "unsupported file type/mode: " + path)
    if path in FIXTURES:
        require(hashlib.sha256(raw).hexdigest() == FIXTURES[path], "synthetic fixture/oracle identity changed: " + path)
        return  # The approved 87,408-byte PDF is not Python source; do not apply its source cap.
    require(len(raw) <= SOURCE_CAP, "source/test/config exceeds 80KiB: " + path)
    try:
        text = raw.decode("utf8")
        if path in PYTHON_FILES:
            compile(text, path, "exec", dont_inherit=True)
        elif path == "requirements-wp01.txt":
            require(text.splitlines() == ["pypdf==6.10.0"], "dependency must remain only pypdf==6.10.0")
        elif path == WORKFLOW:
            validate_workflow(decode_json(raw))
    except (UnicodeError, SyntaxError) as error:
        raise ValueError("UTF8/syntax error in " + path + ": " + str(error)) from error


def validate_workflow(workflow):
    require(type(workflow) is dict, "workflow must be an object")
    require(workflow.get("on") == {"pull_request": {"types": ["opened", "synchronize", "reopened", "ready_for_review"]}},
            "required unfiltered PR triggers changed")
    require(workflow.get("permissions") == {"contents": "read"}, "workflow permissions changed")
    concurrency = workflow.get("concurrency", {})
    require(type(concurrency) is dict and concurrency.get("group") == "${{ github.workflow }}-${{ github.event.pull_request.number }}"
            and concurrency.get("cancel-in-progress") is True, "bounded PR concurrency missing")
    jobs = workflow.get("jobs")
    require(type(jobs) is dict and set(jobs) == set(REQUIRED_JOBS) | {"ci-required"}, "required jobs changed")
    def visit(value):
        if type(value) is dict:
            require("continue-on-error" not in value, "continue-on-error is forbidden")
            require("secrets" not in value, "secret access is forbidden")
            for child in value.values():
                visit(child)
        elif type(value) is list:
            for child in value:
                visit(child)
        elif type(value) is str:
            require(re.search(r"\bsecrets\s*(?:\.|\[)", value) is None, "secret expressions forbidden")
    visit(workflow)
    for name, job in jobs.items():
        require(type(job) is dict and job.get("name") == name, "stable check name required")
        require("permissions" not in job, "job-level permission overrides forbidden")
        for value in job.get("env", {}).values():
            if type(value) is str:
                for expression in re.findall(r"\$\{\{(.*?)\}\}", value, flags=re.S):
                    expression = re.sub(r"'(?:''|[^'])*'", "''", expression)
                    require(re.search(r"(?<![\w.])runner\b", expression) is None,
                            "runner context unavailable in job-level env")
        require(job.get("runs-on") == ("windows-2025" if name == "windows-native" else "ubuntu-24.04"), "runner changed")
        timeout = job.get("timeout-minutes")
        require(type(timeout) is int and 1 <= timeout <= 15, "bounded job timeout required")
        if name == "ci-required":
            require(job.get("if") == "${{ always() }}" and job.get("needs") == list(REQUIRED_JOBS), "aggregate must always require all gates")
        else:
            require("if" not in job and "needs" not in job, "mandatory gate may not be conditionally skipped")
        steps = job.get("steps")
        require(type(steps) is list and len(steps) > 0, "workflow steps missing")
        checkout = setup = gate = False
        for step in steps:
            require(type(step) is dict, "invalid workflow step")
            if "uses" in step:
                action, separator, sha = step["uses"].partition("@")
                require(separator and ACTIONS.get(action) == sha, "official full action SHA required")
                values = step.get("with", {})
                if action == "actions/checkout":
                    checkout = True
                    require(values.get("persist-credentials") is False
                            and values.get("ref") == "${{ github.event.pull_request.head.sha }}"
                            and values.get("repository") == "${{ github.event.pull_request.head.repo.full_name }}", "exact PR head/no credentials required")
                if action == "actions/setup-python":
                    setup = True
                    require(values.get("python-version") == "3.13.16" and values.get("architecture") == "x64", "CI Python pin changed")
            command = step.get("run", "")
            require(type(command) is str, "invalid run command")
            expected = "scope" if name == "scope-policy" else "aggregate" if name == "ci-required" else "tests --profile " + name
            if command == "python -X utf8 -B .github/scripts/ci_checks.py " + expected:
                require("if" not in step, "gate command may not be conditionally skipped")
                gate = True
        require(checkout and setup and gate, "checkout/setup/mandatory gate command missing")


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started_ids = []
        self.successful_ids = []
    def startTest(self, test):
        self.started_ids.append(test.id())
        super().startTest(test)
    def addSuccess(self, test):
        self.successful_ids.append(test.id())
        super().addSuccess(test)


def execute_suite(suite, expected_ids, profile, stream, native_calls, discovery_warnings=()):
    validate_inventory(expected_ids, expected_ids, [])
    with warnings.catch_warnings(record=True) as observed:
        warnings.simplefilter("always", ResourceWarning)
        result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=RecordedResult).run(suite)
        gc.collect()  # Make unclosed SQLite ResourceWarnings visible before verdict.
    resources = []
    for warning in [*discovery_warnings, *observed]:
        message = "%s:%s: %s: %s" % (warning.filename, warning.lineno, warning.category.__name__, warning.message)
        stream.write(message + "\n")
        if issubclass(warning.category, ResourceWarning):
            resources.append(message)
    return dict(schema_version=1, complete=True, profile=profile, collected_ids=expected_ids,
                started_ids=result.started_ids, successful_ids=result.successful_ids,
                tests_run=result.testsRun, failures=len(result.failures), errors=len(result.errors),
                skips=len(result.skipped), expected_failures=len(result.expectedFailures),
                unexpected_successes=len(result.unexpectedSuccesses), loader_errors=[],
                resource_warnings=resources, native_calls=list(native_calls))


def git(*args):
    return subprocess.check_output(["git", "-c", "core.autocrlf=false", *args], cwd=ROOT, timeout=30)


def context():
    head = git("rev-parse", "HEAD").decode().strip()
    requested = os.environ.get("CI_HEAD_SHA", head)
    base = os.environ.get("CI_BASE_SHA", "LOCAL_NOT_PROVIDED")
    require(re.fullmatch(r"[0-9a-f]{40}", requested) is not None and head == requested, "checkout differs from exact PR head")
    if os.environ.get("GITHUB_ACTIONS") == "true":
        require("CI_HEAD_SHA" in os.environ and re.fullmatch(r"[0-9a-f]{40}", base) is not None, "PR head/base metadata missing")
    try:
        parser = importlib.metadata.version("pypdf")
    except importlib.metadata.PackageNotFoundError:
        parser = "NOT_INSTALLED"
    return dict(head_sha=head, base_sha=base, requested_head_sha=requested, python=platform.python_version(),
                pypdf=parser, sqlite=sqlite3.sqlite_version, os=platform.platform(), architecture=platform.machine(),
                free_threaded=bool(sysconfig.get_config_var("Py_GIL_DISABLED")), run_id=os.environ.get("GITHUB_RUN_ID", "LOCAL"))


def require_test_runtime(profile):
    require(sys.version_info[:3] == (3, 13, 16), "CI requires Python3.13.16; do not change local interpreter")
    require(platform.machine().lower() in {"amd64", "x86_64"}, "CI requires x64")
    require(not sysconfig.get_config_var("Py_GIL_DISABLED")
            and getattr(sys, "_is_gil_enabled", lambda: True)(), "standard GIL Python required")
    require(importlib.metadata.version("pypdf") == "6.10.0", "CI requires pypdf6.10.0")
    require((os.name == "nt") if profile == "windows-native" else (sys.platform.startswith("linux") and os.name == "posix"), "wrong test platform")


def expected_ids(profile):
    ids = []
    filenames = ["tests/test_pdf_read.py"] + (["tests/test_storage.py"] if profile == "windows-native" else [])
    for filename in filenames:
        tree = ast.parse((ROOT / filename).read_bytes())
        module = filename[:-3].replace("/", ".")
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
                if profile == "linux-portable" and node.name not in PORTABLE_CLASSES:
                    continue
                ids.extend(module + "." + node.name + "." + method.name for method in node.body
                           if isinstance(method, ast.FunctionDef) and method.name.startswith("test_"))
    require(len(ids) == EXPECTED_COUNTS[profile], "approved expected test count changed; review EXPECTED_COUNTS update")
    return ids


def collect_suite(profile):
    sys.path.insert(0, str(ROOT))
    loader = unittest.TestLoader()
    suite = (loader.discover(str(ROOT / "tests"), top_level_dir=str(ROOT)) if profile == "windows-native"
             else loader.loadTestsFromNames(["tests.test_pdf_read." + name for name in PORTABLE_CLASSES]))
    def flatten(value):
        for case in value:
            if isinstance(case, unittest.TestSuite):
                yield from flatten(case)
            else:
                yield case.id()
    ids = list(flatten(suite))
    expected = expected_ids(profile)
    validate_inventory(expected, ids, loader.errors)
    return suite, expected, ids


def scope():
    entries = {}
    for row in git("ls-files", "--stage", "-z").split(b"\0"):
        if not row:
            continue
        meta, path = row.split(b"\t", 1)
        mode, oid, stage = meta.decode().split()
        path = path.decode("utf8")
        require(stage == "0" and path not in entries, "unmerged/duplicate source index")
        target = ROOT / path
        require(not target.is_symlink() and target.resolve().is_relative_to(ROOT.resolve()), "source path escapes checkout")
        raw = target.read_bytes()
        validate_entry(path, mode, raw)
        require(git("cat-file", "blob", oid) == raw, "working bytes differ from staged blob: " + path)
        entries[path] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), git_blob=oid)
    require(set(entries) == ALLOWED_FILES, "missing/extra policy-controlled file")
    return {"entries": entries, "source_cap_bytes": SOURCE_CAP, "fixture_policy": "nine pinned synthetic members; separate from source cap"}


class BoundedLog:
    def __init__(self, path):
        self.file = path.open("w", encoding="utf8", newline="\n")
        self.bytes = 0
    def write(self, text):
        self.bytes += len(text.encode("utf8", errors="replace"))
        require(self.bytes <= OUTPUT_CAP, "CI log exceeds cap")
        self.file.write(text)
        sys.__stdout__.write(text)
    def flush(self):
        self.file.flush()
        sys.__stdout__.flush()
    def close(self):
        self.file.close()


def summarize(report):
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with Path(target).open("a", encoding="utf8") as out:
            out.write("\n### " + report["command"] + ": " + report["status"] + "\n\n")
            out.write("```json\n" + json.dumps(report, ensure_ascii=True, indent=2) + "\n```\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["context", "scope", "tests", "aggregate", "validate-report", "collect"])
    parser.add_argument("--profile", choices=list(EXPECTED_COUNTS), default="windows-native")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    report = {"command": args.command, "status": "INCOMPLETE", "complete": False}
    directory = Path(os.environ["CI_OUTPUT_DIR"]) if "CI_OUTPUT_DIR" in os.environ else None
    if directory:
        directory.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    exit_code = 1
    try:
        if args.command == "aggregate":
            needs = decode_json(os.environ.get("CI_NEEDS_JSON", ""))
            validate_aggregate(needs)
            report["needs"] = needs
        report["environment"] = context()
        if args.command == "scope":
            report.update(scope())
        elif args.command == "tests":
            require(directory is not None, "test output directory is required")
            require_test_runtime(args.profile)
            with warnings.catch_warnings(record=True) as discovery_warnings:
                warnings.simplefilter("always", ResourceWarning)
                try:
                    suite, expected, ids = collect_suite(args.profile)
                    from tests import test_pdf_read as frozen
                    require(type(frozen._NATIVE_CALLS) is list and not frozen._NATIVE_CALLS, "native call occurred during discovery")
                    if args.profile == "windows-native":
                        import ctypes
                        require(isinstance(frozen.kernel32, ctypes.WinDLL), "real Windows API bindings required")
                    log = BoundedLog(directory / "tests.log")
                    try:
                        with redirect_stdout(log), redirect_stderr(log):
                            result = execute_suite(suite, ids, args.profile, log, frozen._NATIVE_CALLS, discovery_warnings)
                        report.update(result)
                        validate_report(report, expected)
                    finally:
                        log.close()
                except BaseException:
                    # Discovery can fail before the report/log exists; warnings must stay visible.
                    for warning in discovery_warnings:
                        sys.stderr.write(warnings.formatwarning(warning.message, warning.category, warning.filename, warning.lineno))
                    raise
        elif args.command == "validate-report":
            require(args.report is not None, "report path required")
            result = read_json(args.report)
            require(result.get("profile") == args.profile, "report profile mismatch")
            validate_report(result, expected_ids(args.profile))
        elif args.command == "collect":
            _, expected, ids = collect_suite(args.profile)
            report.update(profile=args.profile, collected_ids=ids, expected_ids=expected, tests_executed=0)
        report.update(status="RECORDED" if args.command in {"context", "collect"} else "PASS", complete=True)
        exit_code = 0
    except Exception as error:
        report.update(status="FAILED", diagnostic=str(error))
        print("ERROR: " + str(error), file=sys.stderr)
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - start, 6)
        raw = (json.dumps(report, ensure_ascii=True, indent=2) + "\n").encode()
        require(len(raw) <= OUTPUT_CAP, "CI report exceeds cap")
        if directory:
            path = directory / (args.command + ".json")
            path.write_bytes(raw)
            # Readback must be valid before a successful verdict can leave the process.
            stored = read_json(path)
            require(stored == report, "report readback differs")
        summarize(report)
    print(json.dumps({"command": args.command, "status": report["status"], "head_sha": report.get("environment", {}).get("head_sha"), "report": str(directory) if directory else "console"}))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
