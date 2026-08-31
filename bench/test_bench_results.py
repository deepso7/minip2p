import importlib.util
import json
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

    def test_renderer_has_locked_layout(self):
        rows = bench_results.compare_rows(self.current, self.baseline, None)
        markdown = bench_results.render(self.current, self.baseline, rows, True)
        self.assertIn("Baseline: `baseline`", markdown)
        self.assertIn("Baseline is stale", markdown)
        self.assertIn("| tier | noise | changed | notable | unclassified |", markdown)
        self.assertNotIn("`micro/noise`", markdown)


if __name__ == "__main__":
    unittest.main()
