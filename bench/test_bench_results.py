import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("bench_results", ROOT / "scripts/bench_results.py")
bench_results = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = bench_results
SPEC.loader.exec_module(bench_results)


def backdate(marker):
    """Move a run marker one second back so files written next are strictly newer on coarse-mtime filesystems."""
    past = marker.stat().st_mtime_ns - 1_000_000_000
    os.utime(marker, ns=(past, past))


class BenchResultsTest(unittest.TestCase):
    def setUp(self):
        self.current = bench_results.validate(bench_results.load_json(ROOT / "bench/fixtures/current.json"))
        self.baseline = bench_results.validate(bench_results.load_json(ROOT / "bench/fixtures/baseline.json"))

    def test_locked_boundaries_and_missing_row(self):
        rows = bench_results.compare_rows(self.current, self.baseline, None)
        by_name = {row.name: row for row in rows}
        self.assertEqual(by_name["micro/noise"].classification, "noise")
        self.assertEqual(by_name["micro/boundary"].classification, "notable")
        self.assertEqual(by_name["wall/changed"].classification, "informational")
        self.assertEqual(by_name["wall/changed"].direction, "regressed")
        self.assertEqual(by_name["node/missing"].classification, "unclassified")
        self.assertEqual(by_name["node/missing"].reason, "missing baseline row")

    def compare_one(self, metric, baseline, current, ir_reason=None):
        def document(value):
            return {"schema_version": 1, "git_sha": "sha", "rows": [{"tier": "rust-wall", "name": "bench", "metric": metric, "value": value}]}

        return bench_results.compare_rows(document(current), document(baseline), ir_reason)[0]

    def test_higher_is_better_metric_reverses_direction(self):
        faster = self.compare_one("mb_per_s", 100, 150)
        self.assertEqual((faster.classification, faster.direction), ("informational", "improved"))
        slower = self.compare_one("mb_per_s", 100, 50)
        self.assertEqual(slower.direction, "regressed")

    def test_classified_allocation_metric_uses_bands(self):
        row = self.compare_one("allocs_per_msg", 100, 103)
        self.assertEqual((row.classification, row.direction), ("notable", "regressed"))
        self.assertEqual(self.compare_one("bytes_allocated_per_msg", 1000, 985).classification, "changed")

    def test_informational_metrics_are_never_classified(self):
        for metric in ("wakeups_per_s", "cpu_ms_per_s", "allocs_per_mb", "rtt_us_p99"):
            with self.subTest(metric=metric):
                row = self.compare_one(metric, 100, 200)
                self.assertEqual(row.classification, "informational")

    def test_ir_pin_mismatch_only_unclassifies_ir_rows(self):
        reason = "incompatible Ir pins: Cargo.lock differs"
        self.assertEqual(self.compare_one("Ir", 100, 103, reason).reason, reason)
        self.assertEqual(self.compare_one("allocs_per_msg", 100, 103, reason).classification, "notable")

    def test_no_baseline(self):
        rows = bench_results.compare_rows(self.current, None, None)
        self.assertTrue(all(row.classification == "unclassified" for row in rows))
        self.assertTrue(all(row.reason == "no baseline" for row in rows))

    def test_incompatible_ir_keeps_wall_clock_informational(self):
        rows = bench_results.compare_rows(self.current, self.baseline, "incompatible Ir pins: Valgrind differs")
        self.assertTrue(all(row.classification == "unclassified" for row in rows if row.tier == "rust-micro"))
        self.assertEqual(
            next(row for row in rows if row.tier == "rust-wall").classification,
            "informational",
        )

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

    def test_merge_accepts_registered_metrics_and_rejects_unregistered(self):
        rows = [
            {"tier": "rust-wall", "name": "throughput/tcp", "metric": "mb_per_s", "value": 950.5},
            {"tier": "rust-wall", "name": "throughput/tcp", "metric": "allocs_per_mb", "value": 12},
            {"tier": "rust-micro", "name": "pubsub/forward_8", "metric": "allocs_per_msg", "value": 3},
        ]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "rows.json"
            output = Path(directory) / "results.json"
            source.write_text(json.dumps({"schema_version": 1, "git_sha": "sha", "rows": rows}))
            bench_results.merge([source], output, None)
            self.assertEqual(len(json.loads(output.read_text())["rows"]), 3)
        with self.assertRaisesRegex(bench_results.BenchError, "unknown metric 'furlongs'"):
            bench_results.validate({"schema_version": 1, "git_sha": "sha", "rows": [{**rows[0], "metric": "furlongs"}]})

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
            self.assertIn("| rust-micro | 1 | 0 | 1 | 0 | 0 |", markdown)
            self.assertIn("| rust-wall | 0 | 0 | 0 | 1 | 0 |", markdown)
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
            backdate(marker)
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

    def test_custom_collector_merges_fresh_registered_rows(self):
        expected = {
            ("rust-wall", "throughput/tcp", "mb_per_s"),
            ("rust-wall", "throughput/tcp", "allocs_per_mb"),
            ("rust-micro", "pubsub/forward_8", "allocs_per_msg"),
        }
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(bench_results, "EXPECTED_CUSTOM", expected):
            root = Path(directory) / "custom"
            marker = Path(directory) / "started"
            output = Path(directory) / "results.json"
            root.mkdir()
            stale = root / "removed.json"
            stale.write_text(json.dumps([{"tier": "rust-wall", "name": "removed", "metric": "mb_per_s", "value": 1}]))
            marker.touch()
            backdate(marker)
            marker_time = marker.stat().st_mtime_ns
            os.utime(stale, ns=(marker_time, marker_time))
            (root / "throughput.json").write_text(json.dumps([
                {"tier": "rust-wall", "name": "throughput/tcp", "metric": "mb_per_s", "value": 950.5},
                {"tier": "rust-wall", "name": "throughput/tcp", "metric": "allocs_per_mb", "value": 12},
            ]))
            forward = root / "forward.json"
            forward.write_text(json.dumps([{"tier": "rust-micro", "name": "pubsub/forward_8", "metric": "allocs_per_msg", "value": 3}]))
            bench_results.collect_custom(root, output, "sha", marker)
            rows = json.loads(output.read_text())["rows"]
            self.assertEqual({(row["tier"], row["name"], row["metric"]) for row in rows}, expected)

            forward.unlink()
            with self.assertRaisesRegex(bench_results.BenchError, "row set mismatch"):
                bench_results.collect_custom(root, output, "sha", marker)

    def test_gungraun_collector_reads_tagged_integer_metrics(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "gungraun"
            marker = Path(directory) / "started"
            output = Path(directory) / "results.json"
            marker.touch()
            backdate(marker)
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
        self.assertIn(
            "| tier | noise | changed | notable | informational | unclassified |",
            markdown,
        )
        self.assertNotIn("`micro/noise`", markdown)

    def test_v1_baseline_compares_new_metric_rows_as_missing(self):
        extra = {"tier": "rust-wall", "name": "wall/changed", "metric": "mb_per_s", "value": 900}
        current = {**self.current, "rows": [*self.current["rows"], extra]}
        rows = {(row.name, row.metric): row for row in bench_results.compare_rows(current, self.baseline, None)}
        self.assertEqual(rows["wall/changed", "median_ns"].classification, "informational")
        self.assertAlmostEqual(rows["wall/changed", "median_ns"].delta, 20.0)
        self.assertEqual(rows["wall/changed", "mb_per_s"].reason, "missing baseline row")
        markdown = bench_results.render(self.baseline, list(rows.values()))
        self.assertIn("| `wall/changed` | `median_ns` | 100 | 120 | +20.00% | informational | regressed |", markdown)
        self.assertIn("| `wall/changed` | `mb_per_s` | — | 900 |", markdown)

    def test_renderer_escapes_benchmark_names(self):
        current = {**self.current, "rows": [{**self.current["rows"][0], "name": "bad\\|`name\rrow\nnext"}]}
        rows = bench_results.compare_rows(current, None, None)
        markdown = bench_results.render(None, rows)
        self.assertIn("`bad&#92;&#124;&#96;name<br>row<br>next`", markdown)


if __name__ == "__main__":
    unittest.main()
