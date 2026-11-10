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


REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def package(name, version, dependencies=(), external=False):
    """One `Cargo.lock` package entry; `external` gives it a registry source."""
    lines = ["", "[[package]]", f'name = "{name}"', f'version = "{version}"']
    if external:
        lines.append(f'source = "{REGISTRY}"')
    if dependencies:
        lines += ["dependencies = [", *(f' "{dependency}",' for dependency in dependencies), "]"]
    return "\n".join(lines) + "\n"


# A workspace crate depending on one external crate through another.
LOCK = "version = 4\n" + package("minip2p-core", "0.10.5", ["aead"]) + package("aead", "0.6.1", ["inout"], external=True) + package(
    "inout", "0.2.0", external=True
)


class BenchResultsTest(unittest.TestCase):
    def setUp(self):
        self.base = bench_results.validate(bench_results.load_json(ROOT / "bench/fixtures/base.json"))
        self.head = bench_results.validate(bench_results.load_json(ROOT / "bench/fixtures/head.json"), strict=False)

    def compare_one(self, metric, base, head, tier="rust-micro", name="bench"):
        def document(value):
            return {"schema_version": 1, "git_sha": "sha", "rows": [{"tier": tier, "name": name, "metric": metric, "value": value}]}

        return bench_results.compare_rows(document(base), document(head))[0]

    def test_ab_rows_match_by_key_and_tolerate_unknown_metrics(self):
        rows = {(row.name, row.metric): row for row in bench_results.compare_rows(self.base, self.head)}
        classes = {key: (row.classification, row.direction) for key, row in rows.items()}
        self.assertEqual(classes, {
            ("micro/negligible", "Ir"): ("negligible", ""),
            ("micro/regressed", "Ir"): ("notable", "regressed"),
            ("wall/slower", "median_ns"): ("informational", ""),
            ("wall/slower", "furlongs"): ("new", ""),
            ("wall/removed", "median_ns"): ("removed", ""),
            ("node/new", "median_ns"): ("new", ""),
        })
        self.assertAlmostEqual(rows["wall/slower", "median_ns"].delta, 50.0)
        self.assertIsNone(rows["wall/removed", "median_ns"].head)

    def test_only_deterministic_metrics_are_labeled(self):
        def labels(metric, base, head, tier="rust-micro"):
            row = self.compare_one(metric, base, head, tier=tier)
            return row.classification, row.direction

        self.assertEqual(labels("Ir", 1000, 1015), ("changed", "regressed"))
        self.assertEqual(labels("allocs_per_msg", 100, 103), ("notable", "regressed"))
        self.assertEqual(labels("bytes_allocated_per_msg", 1000, 985), ("changed", "improved"))
        self.assertEqual(labels("Ir", 0, 5), ("notable", "regressed"))
        for metric in ("median_ns", "mb_per_s", "allocs_per_mb", "wakeups_per_s", "rtt_us_p99", "furlongs"):
            with self.subTest(metric=metric):
                self.assertEqual(labels(metric, 100, 200, tier="rust-wall"), ("informational", ""))

    def test_unstrict_validation_still_rejects_malformed_rows(self):
        row = {"tier": "rust-next", "name": "bench", "metric": "furlongs", "value": 1}
        bench_results.validate({"schema_version": 1, "git_sha": "sha", "rows": [row]}, strict=False)
        for bad in ({"metric": ""}, {"value": -1}, {"tier": None}):
            with self.subTest(bad=bad), self.assertRaises(bench_results.BenchError):
                bench_results.validate({"schema_version": 1, "git_sha": "sha", "rows": [{**row, **bad}]}, strict=False)

    def test_compare_cli_sections(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "comparison.md"
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/bench_results.py"),
                    "compare",
                    "--base", str(ROOT / "bench/fixtures/base.json"),
                    "--head", str(ROOT / "bench/fixtures/head.json"),
                    "--base-ref", "main",
                    "--run-url", "https://run",
                    "--output", str(output),
                ],
                check=True,
            )
            markdown = output.read_text()
        self.assertIn("- Head: `head` ([run](https://run))", markdown)
        self.assertIn("- Base: `base`, the merge-base with `main`, measured in the same run.", markdown)
        self.assertNotIn("[!NOTE]", markdown)
        changed, negligible, informational = markdown.split("<details>")
        self.assertIn("| `rust-micro` | `micro/regressed` | `Ir` | 1,000 | 1,020 | +2.00% | notable | regressed |", changed)
        self.assertIn("| `rust-wall` | `wall/removed` | `median_ns` | 10 | — | — | removed |", changed)
        self.assertIn("`node/new`", changed)
        self.assertIn("Negligible (1)", negligible)
        self.assertIn("`micro/negligible`", negligible)
        self.assertIn("Informational (1)", informational)
        self.assertIn("| `rust-wall` | `wall/slower` | `median_ns` | 100 | 150 | +50.00% |\n", informational)

    def test_ir_pins_note(self):
        def tree(root, lock=LOCK, pins=None):
            (root / "bench").mkdir(parents=True)
            (root / "Cargo.lock").write_text(lock)
            (root / "bench/targets").write_text("ir minip2p-core - multiaddr_ir\n")
            if pins is not False:
                (root / "bench/pins.json").write_text(json.dumps({key: "same" for key in bench_results.IR_PINS} | (pins or {})))
            return root

        changes = {
            "same": ({}, None),
            "toolchain": ({"pins": {"rust": "changed"}}, "Rust toolchain differs between base and head"),
            "two pins": ({"pins": {"rust": "x", "valgrind": "y"}}, "Rust toolchain, Valgrind version differ between base and head"),
            "lock": ({"lock": LOCK.replace('"0.6.1"', '"0.6.2"')}, "`Cargo.lock` differs between base and head for the IR benches"),
            "missing": ({"pins": False}, "could not compare base and head (`cannot read bench/pins.json`)"),
        }
        for name, (change, expected) in changes.items():
            with self.subTest(change=name), tempfile.TemporaryDirectory() as directory:
                base = tree(Path(directory) / "base")
                head = tree(Path(directory) / "head", **change)
                self.assertEqual(bench_results.ir_pins_note(base, head), expected)
        rows = bench_results.compare_rows(self.base, self.head)
        markdown = bench_results.render(self.base, self.head, rows, pins_note="Rust toolchain differs between base and head")
        self.assertIn("> [!NOTE]\n> Ir pins: Rust toolchain differs between base and head, so `Ir` deltas may include that change.", markdown)
        self.assertIn("notable | regressed", markdown)

    def test_lock_comparison_covers_only_the_ir_benches_graph(self):
        def reachable(lock):
            return bench_results.reachable_lock(lock.encode(), {"minip2p-core"})

        self.assertEqual(reachable(LOCK), reachable(LOCK.replace('"0.10.5"', '"0.10.6"')))
        self.assertNotEqual(reachable(LOCK), reachable(LOCK.replace('"0.6.1"', '"0.6.2"')))
        self.assertNotEqual(reachable(LOCK), reachable(LOCK.replace('"0.2.0"', '"0.2.1"')))
        example_dependency = LOCK + package("mimalloc", "0.1.52", external=True) + package("relay-example", "0.10.5", ["mimalloc"])
        self.assertEqual(reachable(LOCK), reachable(example_dependency))

    def test_lock_comparison_resolves_duplicate_versions(self):
        two_versions = (
            package("minip2p-core", "0.10.5", ["aead 0.6.1"])
            + package("aead", "0.6.1", external=True)
            + package("aead", "0.5.0", external=True)
        )
        entries = bench_results.reachable_lock(two_versions.encode(), {"minip2p-core"})
        self.assertIn(("aead", "0.6.1", REGISTRY), {entry[0] for entry in entries})
        self.assertNotIn(("aead", "0.5.0", REGISTRY), {entry[0] for entry in entries})
        with self.assertRaisesRegex(bench_results.BenchError, "matches 2 packages"):
            bench_results.reachable_lock(two_versions.replace('"aead 0.6.1"', '"aead"').encode(), {"minip2p-core"})

    def test_merge_writes_valid_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            output = Path(directory) / "results.json"
            first.write_text(json.dumps({"schema_version": 1, "git_sha": "sha", "rows": self.base["rows"][:2]}))
            second.write_text(json.dumps({"schema_version": 1, "git_sha": "sha", "rows": self.base["rows"][2:]}))
            bench_results.merge([first, second], output, None)
            merged = bench_results.validate(json.loads(output.read_text()))
            self.assertEqual(len(merged["rows"]), len(self.base["rows"]))

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
        for metric in ("furlongs", []):
            with self.subTest(metric=metric), self.assertRaisesRegex(bench_results.BenchError, "unknown metric"):
                bench_results.validate({"schema_version": 1, "git_sha": "sha", "rows": [{**rows[0], "metric": metric}]})

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

    def test_renderer_escapes_benchmark_names(self):
        head = {**self.head, "rows": [{**self.head["rows"][0], "name": "bad\\|`name\rrow\nnext"}]}
        markdown = bench_results.render(self.base, head, bench_results.compare_rows(self.base, head))
        self.assertIn("`bad&#92;&#124;&#96;name<br>row<br>next`", markdown)


if __name__ == "__main__":
    unittest.main()
