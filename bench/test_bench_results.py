import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("bench_results", ROOT / "scripts/bench_results.py")
bench_results = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = bench_results
SPEC.loader.exec_module(bench_results)


class BenchResultsTest(unittest.TestCase):
    def setUp(self):
        self.current = bench_results.validate(bench_results.load_json(ROOT / "bench/fixtures/current.json"))
        self.baseline = bench_results.validate(bench_results.load_json(ROOT / "bench/fixtures/baseline.json"))

    def test_locked_boundaries_and_missing_row(self):
        rows = bench_results.compare_rows(self.current, self.baseline, None)
        by_name = {row.name: row for row in rows}
        self.assertEqual(by_name["micro/noise"].classification, "noise")
        self.assertEqual(by_name["micro/boundary"].classification, "notable")
        self.assertEqual(by_name["wall/changed"].classification, "changed")
        self.assertEqual(by_name["node/missing"].classification, "unclassified")
        self.assertEqual(by_name["node/missing"].reason, "missing baseline row")

    def test_no_baseline(self):
        rows = bench_results.compare_rows(self.current, None, None)
        self.assertTrue(all(row.classification == "unclassified" for row in rows))
        self.assertTrue(all(row.reason == "no baseline" for row in rows))

    def test_incompatible_ir_does_not_affect_wall_clock(self):
        rows = bench_results.compare_rows(self.current, self.baseline, "incompatible Ir pins: Valgrind differs")
        self.assertTrue(all(row.classification == "unclassified" for row in rows if row.tier == "rust-micro"))
        self.assertEqual(next(row for row in rows if row.tier == "rust-wall").classification, "changed")

    def test_ir_compatibility_checks_each_git_pin(self):
        changes = {
            "Cargo.lock": ("Cargo.lock", "lock changed\n", "Cargo.lock differs"),
            "missing manifest": ("bench/pins.json", None, "pin manifest unavailable"),
            **{
                key: ("bench/pins.json", {key: "changed"}, f"{label} differs")
                for key, label in bench_results.IR_PINS.items()
            },
        }
        for name, (path, change, expected) in changes.items():
            with self.subTest(pin=name), tempfile.TemporaryDirectory() as directory:
                repository = Path(directory)
                subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
                subprocess.run(["git", "config", "user.email", "bench@example.invalid"], cwd=repository, check=True)
                subprocess.run(["git", "config", "user.name", "Bench Test"], cwd=repository, check=True)
                (repository / "bench").mkdir()
                (repository / "Cargo.lock").write_text("lock\n")
                pins = {key: "same" for key in bench_results.IR_PINS}
                (repository / "bench/pins.json").write_text(json.dumps(pins))
                subprocess.run(["git", "add", "."], cwd=repository, check=True)
                subprocess.run(["git", "commit", "-qm", "baseline"], cwd=repository, check=True)
                baseline = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository, text=True).strip()
                previous = Path.cwd()
                try:
                    os.chdir(repository)
                    self.assertEqual(bench_results.ir_compatible(baseline, baseline), (True, None))
                finally:
                    os.chdir(previous)
                if change is None:
                    (repository / path).unlink()
                elif isinstance(change, str):
                    (repository / path).write_text(change)
                else:
                    pins.update(change)
                    (repository / path).write_text(json.dumps(pins))
                subprocess.run(["git", "add", "."], cwd=repository, check=True)
                subprocess.run(["git", "commit", "-qm", "current"], cwd=repository, check=True)
                current = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository, text=True).strip()
                previous = Path.cwd()
                try:
                    os.chdir(repository)
                    compatible, reason = bench_results.ir_compatible(baseline, current)
                finally:
                    os.chdir(previous)
                self.assertFalse(compatible)
                self.assertIn(expected, reason)

    def test_missing_current_row_is_unclassified(self):
        current = {**self.current, "rows": self.current["rows"][:-1]}
        baseline = {**self.baseline, "rows": [*self.baseline["rows"], self.current["rows"][-1]]}
        row = next(row for row in bench_results.compare_rows(current, baseline, None) if row.name == "node/missing")
        self.assertIsNone(row.current)
        self.assertEqual(row.classification, "unclassified")
        self.assertEqual(row.reason, "missing current row")

    def test_merge_writes_valid_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            output = Path(directory) / "results.json"
            first.write_text(json.dumps({"schema_version": 1, "git_sha": "sha", "rows": self.current["rows"][:2]}))
            second.write_text(json.dumps({"schema_version": 1, "git_sha": "sha", "rows": self.current["rows"][2:]}))
            bench_results.merge([first, second], output, None)
            merged = bench_results.validate(json.loads(output.read_text()))
            self.assertEqual(len(merged["rows"]), 4)

    def test_fixture_compare_cli_writes_locked_markdown(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "comparison.md"
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/bench_results.py"),
                    "compare",
                    "--current",
                    str(ROOT / "bench/fixtures/current.json"),
                    "--baseline",
                    str(ROOT / "bench/fixtures/baseline.json"),
                    "--output",
                    str(output),
                    "--baseline-label",
                    "v0.4.11",
                ],
                check=True,
            )
            markdown = output.read_text()
            self.assertIn("Baseline: `v0.4.11 (baseline)`", markdown)
            self.assertIn("| rust-micro | 1 | 0 | 1 | 0 |", markdown)
            self.assertIn("unclassified (missing baseline row)", markdown)

    def test_zero_baseline_is_unclassified(self):
        baseline = {**self.baseline, "rows": [{**self.baseline["rows"][0], "value": 0}]}
        current = {**self.current, "rows": [self.current["rows"][0]]}
        row = bench_results.compare_rows(current, baseline, None)[0]
        self.assertEqual(row.classification, "unclassified")
        self.assertEqual(row.reason, "zero baseline")

    def test_criterion_collector_requires_fresh_complete_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "criterion"
            marker = Path(directory) / "started"
            output = Path(directory) / "results.json"
            stale = root / "removed/benchmark/new/estimates.json"
            stale.parent.mkdir(parents=True)
            stale.write_text(json.dumps({"median": {"point_estimate": 1}}))
            marker.touch()
            marker_time = marker.stat().st_mtime_ns
            os.utime(stale, ns=(marker_time, marker_time))
            for name in bench_results.EXPECTED_CRITERION:
                estimate = root.joinpath(*name.split("/"), "new", "estimates.json")
                estimate.parent.mkdir(parents=True)
                estimate.write_text(json.dumps({"median": {"point_estimate": 10}}))
                estimate.with_name("benchmark.json").write_text(json.dumps({"full_id": name}))
            bench_results.collect_criterion(root, output, "sha", marker)
            self.assertEqual(len(json.loads(output.read_text())["rows"]), len(bench_results.EXPECTED_CRITERION))

            missing = next(iter(bench_results.EXPECTED_CRITERION))
            root.joinpath(*missing.split("/"), "new", "estimates.json").unlink()
            with self.assertRaisesRegex(bench_results.BenchError, "row set mismatch"):
                bench_results.collect_criterion(root, output, "sha", marker)

    def test_gungraun_collector_reads_tagged_integer_metrics(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "gungraun"
            marker = Path(directory) / "started"
            output = Path(directory) / "results.json"
            marker.touch()
            for identifier in bench_results.GUNGRAUN_NAMES:
                summary = root / identifier / "summary.json"
                summary.parent.mkdir(parents=True)
                summary.write_text(
                    json.dumps(
                        {
                            "id": identifier,
                            "profiles": [
                                {
                                    "tool": "Callgrind",
                                    "summaries": {
                                        "total": {
                                            "summary": {
                                                "Callgrind": {
                                                    "Ir": {"metrics": {"Left": {"Int": 42}}}
                                                }
                                            }
                                        }
                                    },
                                }
                            ],
                        }
                    )
                )
            bench_results.collect_gungraun(root, output, "sha", marker)
            rows = json.loads(output.read_text())["rows"]
            self.assertEqual(len(rows), len(bench_results.GUNGRAUN_NAMES))
            self.assertTrue(all(row["value"] == 42 for row in rows))

    def test_renderer_has_locked_layout(self):
        rows = bench_results.compare_rows(self.current, self.baseline, None)
        markdown = bench_results.render(self.baseline, rows)
        self.assertIn("Baseline: `baseline`", markdown)
        self.assertIn("| tier | noise | changed | notable | unclassified |", markdown)
        self.assertNotIn("`micro/noise`", markdown)

    def test_renderer_escapes_benchmark_names(self):
        current = {**self.current, "rows": [{**self.current["rows"][0], "name": "bad\\|`name\rrow\nnext"}]}
        rows = bench_results.compare_rows(current, None, None)
        markdown = bench_results.render(None, rows)
        self.assertIn("`bad&#92;&#124;&#96;name<br>row<br>next`", markdown)


if __name__ == "__main__":
    unittest.main()
