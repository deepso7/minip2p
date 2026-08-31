#!/usr/bin/env python3
"""Normalize benchmark output and compare schema-version-1 result files."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 1
TIERS = ("rust-micro", "rust-wall", "node-ffi")
METRICS = {"rust-micro": "Ir", "rust-wall": "median_ns", "node-ffi": "median_ns"}
EXPECTED_CRITERION = {
    "multiaddr/parse_text", "multiaddr/encode_binary", "multiaddr/decode_binary",
    "yamux/64KiB/session_send_and_drain", "yamux/64KiB/session_receive_and_drain",
    "peer_book_128_peers_16_addrs/tick_active", "peer_book_128_peers_16_addrs/tick_expire",
    "peer_book_128_peers_16_addrs/next_timeout", "pubsub/floodsub_publish_32x60KiB",
    "relay_handle_event_same_now_128_pending_hops",
    "quic/idle_poll/1", "quic/idle_poll/64", "quic/idle_poll/256", "quic/idle_poll/512",
    "tcp/readiness_poll/1", "tcp/readiness_poll/64", "tcp/readiness_poll/256", "tcp/readiness_poll/512",
    "e2e/tcp/setup", "e2e/tcp/ping", "e2e/tcp/echo_64b", "e2e/tcp/echo_64b_crossed_4x4",
    "e2e/tcp/transfer_1mib", "e2e/quic/setup", "e2e/quic/ping", "e2e/quic/echo_64b",
    "e2e/quic/echo_64b_crossed_4x4", "e2e/quic/transfer_1mib",
}


class BenchError(ValueError):
    """Invalid benchmark input."""


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise BenchError(f"cannot read {path}: {error}") from error


def validate(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or document.get("schema_version") != SCHEMA_VERSION:
        raise BenchError("results must use schema_version 1")
    if not isinstance(document.get("git_sha"), str) or not document["git_sha"]:
        raise BenchError("results require a non-empty git_sha")
    rows = document.get("rows")
    if not isinstance(rows, list):
        raise BenchError("results require a rows array")
    seen: set[tuple[str, str, str]] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise BenchError(f"row {index} must be an object")
        tier, name, metric, value = (row.get(key) for key in ("tier", "name", "metric", "value"))
        if tier not in TIERS:
            raise BenchError(f"row {index} has unknown tier {tier!r}")
        if not isinstance(name, str) or not name:
            raise BenchError(f"row {index} requires a non-empty name")
        if metric != METRICS[tier]:
            raise BenchError(f"row {index} must use metric {METRICS[tier]!r}")
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise BenchError(f"row {index} requires a finite non-negative value")
        key = (tier, name, metric)
        if key in seen:
            raise BenchError(f"duplicate row: {'/'.join(key)}")
        seen.add(key)
    return document


def write_results(git_sha: str, rows: Iterable[dict[str, Any]], output: Path) -> None:
    document = validate({"schema_version": SCHEMA_VERSION, "git_sha": git_sha, "rows": list(rows)})
    document["rows"].sort(key=lambda row: (TIERS.index(row["tier"]), row["name"], row["metric"]))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2) + "\n")


def merge(inputs: list[Path], output: Path, git_sha: str | None) -> None:
    documents = [validate(load_json(path)) for path in inputs]
    shas = {document["git_sha"] for document in documents}
    if git_sha is None:
        if len(shas) != 1:
            raise BenchError("input files have different git_sha values")
        git_sha = shas.pop()
    elif any(sha != git_sha for sha in shas):
        raise BenchError("an input git_sha does not match --git-sha")
    write_results(git_sha, (row for document in documents for row in document["rows"]), output)


def collect_criterion(root: Path, output: Path, git_sha: str, since: Path) -> None:
    try:
        started_at = since.stat().st_mtime_ns
    except OSError as error:
        raise BenchError(f"cannot read Criterion run marker {since}: {error}") from error
    rows = []
    for estimate in root.glob("**/new/estimates.json"):
        if estimate.stat().st_mtime_ns < started_at:
            continue
        relative = estimate.relative_to(root)
        name = "/".join(relative.parts[:-2])
        point = load_json(estimate).get("median", {}).get("point_estimate")
        if point is None:
            raise BenchError(f"missing median.point_estimate in {estimate}")
        rows.append({"tier": "rust-wall", "name": name, "metric": "median_ns", "value": point})
    names = {row["name"] for row in rows}
    if names != EXPECTED_CRITERION:
        missing = sorted(EXPECTED_CRITERION - names)
        unexpected = sorted(names - EXPECTED_CRITERION)
        raise BenchError(f"Criterion row set mismatch; missing={missing}, unexpected={unexpected}")
    write_results(git_sha, rows, output)


def collect_vitest(report: Path, output: Path, git_sha: str) -> None:
    rows = []
    for file in load_json(report).get("files", []):
        for group in file.get("groups", []):
            for benchmark in group.get("benchmarks", []):
                median_ms = benchmark.get("median")
                name = benchmark.get("name")
                if not isinstance(name, str) or not isinstance(median_ms, (int, float)):
                    raise BenchError(f"invalid Vitest benchmark in {report}")
                rows.append({"tier": "node-ffi", "name": name, "metric": "median_ns", "value": median_ms * 1_000_000})
    if not rows:
        raise BenchError(f"no Vitest benchmarks found in {report}")
    write_results(git_sha, rows, output)


def collect_gungraun(root: Path, output: Path, git_sha: str) -> None:
    name_map = {
        "parse_text": "multiaddr/parse_text",
        "encode_binary": "multiaddr/encode_binary",
        "decode_binary": "multiaddr/decode_binary",
        "session_send_and_drain": "yamux/64KiB/session_send_and_drain",
        "session_receive_and_drain": "yamux/64KiB/session_receive_and_drain",
        "tick_active": "peer_book_128_peers_16_addrs/tick_active",
        "tick_expire": "peer_book_128_peers_16_addrs/tick_expire",
        "next_timeout": "peer_book_128_peers_16_addrs/next_timeout",
        "floodsub_publish_32x60_kib": "pubsub/floodsub_publish_32x60KiB",
        "relay_handle_event_same_now_128_pending_hops": "relay_handle_event_same_now_128_pending_hops",
    }
    rows = []
    for path in root.glob("**/summary.json"):
        summary = load_json(path)
        identifier = summary.get("id") or summary.get("function_name")
        name = name_map.get(identifier)
        if name is None:
            continue
        ir = None
        for profile in summary.get("profiles", []):
            if profile.get("tool") != "Callgrind":
                continue
            metric = profile["summaries"]["total"]["summary"]["Callgrind"]["Ir"]["metrics"]
            ir = metric.get("Left", metric.get("Both", [None])[0])
        if not isinstance(ir, (int, float)):
            raise BenchError(f"missing Callgrind Ir in {path}")
        rows.append({"tier": "rust-micro", "name": name, "metric": "Ir", "value": ir})
    if len(rows) != 10:
        raise BenchError(f"expected 10 Gungraun summaries under {root}, found {len(rows)}")
    write_results(git_sha, rows, output)


def git_bytes(tree: str, path: str) -> bytes:
    result = subprocess.run(
        ["git", "show", f"{tree}:{path}"], capture_output=True, check=False
    )
    if result.returncode:
        raise BenchError(f"cannot read {path} at {tree}")
    return result.stdout


def ir_compatible(baseline_tree: str, current_tree: str) -> tuple[bool, str | None]:
    """Compare the five pins that make instruction counts comparable."""
    checks = (
        ("Cargo.lock", "Cargo.lock", True),
        ("Rust toolchain", "bench/pins.json", False),
    )
    for label, path, use_hash in checks:
        before = git_bytes(baseline_tree, path)
        after = git_bytes(current_tree, path)
        if use_hash:
            before = hashlib.sha256(before).digest()
            after = hashlib.sha256(after).digest()
        if before != after:
            return False, f"incompatible Ir pins: {label} differs"
    return True, None


@dataclass(frozen=True)
class ComparedRow:
    tier: str
    name: str
    metric: str
    baseline: float | int | None
    current: float | int | None
    delta: float | None
    classification: str
    direction: str
    reason: str | None = None


def compare_rows(
    current: dict[str, Any], baseline: dict[str, Any] | None, ir_reason: str | None
) -> list[ComparedRow]:
    old = {} if baseline is None else {
        (row["tier"], row["name"], row["metric"]): row["value"] for row in baseline["rows"]
    }
    compared = []
    for row in current["rows"]:
        key = (row["tier"], row["name"], row["metric"])
        reason = "no baseline" if baseline is None else None
        if reason is None and row["tier"] == "rust-micro" and ir_reason:
            reason = ir_reason
        if reason is None and key not in old:
            reason = "missing baseline row"
        baseline_value = old.get(key)
        if reason is not None:
            compared.append(ComparedRow(*key, baseline_value, row["value"], None, "unclassified", "", reason))
            continue
        if baseline_value == 0:
            compared.append(ComparedRow(*key, baseline_value, row["value"], None, "unclassified", "", "zero baseline"))
            continue
        delta = (row["value"] - baseline_value) / baseline_value * 100
        magnitude = abs(delta)
        changed, notable = (1.0, 2.0) if row["tier"] == "rust-micro" else (20.0, 30.0)
        classification = "notable" if magnitude >= notable else "changed" if magnitude >= changed else "noise"
        direction = "improved" if delta < 0 else "regressed" if delta > 0 else ""
        compared.append(ComparedRow(*key, baseline_value, row["value"], delta, classification, direction))
    current_keys = {(row["tier"], row["name"], row["metric"]) for row in current["rows"]}
    for key, baseline_value in old.items():
        if key not in current_keys:
            compared.append(ComparedRow(*key, baseline_value, None, None, "unclassified", "", "missing current row"))
    compared.sort(key=lambda row: (TIERS.index(row.tier), row.name, row.metric))
    return compared


def display_value(value: float | int | None) -> str:
    if value is None:
        return "—"
    if isinstance(value, int) or value.is_integer():
        return f"{int(value):,}"
    return f"{value:,.2f}"


def render(
    current: dict[str, Any], baseline: dict[str, Any] | None, rows: list[ComparedRow], stale: bool
) -> str:
    baseline_sha = "none" if baseline is None else baseline["git_sha"]
    lines = ["<!-- bench-comment -->", "## Benchmark comparison", "", f"Baseline: `{baseline_sha}`"]
    if stale:
        lines += ["", "> Baseline is stale: it is not this pull request's merge base."]
    lines += ["", "| tier | noise | changed | notable | unclassified |", "| --- | ---: | ---: | ---: | ---: |"]
    for tier in TIERS:
        tier_rows = [row for row in rows if row.tier == tier]
        counts = {name: sum(row.classification == name for row in tier_rows) for name in ("noise", "changed", "notable", "unclassified")}
        lines.append(f"| {tier} | {counts['noise']} | {counts['changed']} | {counts['notable']} | {counts['unclassified']} |")
    for tier in TIERS:
        visible = [row for row in rows if row.tier == tier and row.classification != "noise"]
        if not visible:
            continue
        lines += ["", f"### {tier}", "", "| benchmark | baseline | current | Δ% | class | direction |", "| --- | ---: | ---: | ---: | --- | --- |"]
        for row in visible:
            delta = "—" if row.delta is None else f"{row.delta:+.2f}%"
            classification = row.classification if row.reason is None else f"{row.classification} ({row.reason})"
            lines.append(f"| `{row.name}` | {display_value(row.baseline)} | {display_value(row.current)} | {delta} | {classification} | {row.direction} |")
    return "\n".join(lines) + "\n"


def command_compare(args: argparse.Namespace) -> None:
    current = validate(load_json(args.current))
    baseline = None if args.baseline is None else validate(load_json(args.baseline))
    ir_reason = args.ir_reason
    if baseline is not None and ir_reason is None and args.check_ir_pins:
        compatible, ir_reason = ir_compatible(args.baseline_tree or baseline["git_sha"], args.current_tree or current["git_sha"])
        if compatible:
            ir_reason = None
    rows = compare_rows(current, baseline, ir_reason)
    args.output.write_text(render(current, baseline, rows, args.stale))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    merge_parser = commands.add_parser("merge")
    merge_parser.add_argument("inputs", nargs="+", type=Path)
    merge_parser.add_argument("--output", type=Path, required=True)
    merge_parser.add_argument("--git-sha")
    merge_parser.set_defaults(run=lambda args: merge(args.inputs, args.output, args.git_sha))
    criterion_parser = commands.add_parser("criterion")
    criterion_parser.add_argument("--root", type=Path, default=Path("target/criterion"))
    criterion_parser.add_argument("--output", type=Path, required=True)
    criterion_parser.add_argument("--git-sha", required=True)
    criterion_parser.add_argument("--since", type=Path, required=True)
    criterion_parser.set_defaults(run=lambda args: collect_criterion(args.root, args.output, args.git_sha, args.since))
    start_parser = commands.add_parser("start")
    start_parser.add_argument("--output", type=Path, required=True)
    start_parser.set_defaults(run=lambda args: (args.output.parent.mkdir(parents=True, exist_ok=True), args.output.touch()))
    vitest_parser = commands.add_parser("vitest")
    vitest_parser.add_argument("--report", type=Path, required=True)
    vitest_parser.add_argument("--output", type=Path, required=True)
    vitest_parser.add_argument("--git-sha", required=True)
    vitest_parser.set_defaults(run=lambda args: collect_vitest(args.report, args.output, args.git_sha))
    gungraun_parser = commands.add_parser("gungraun")
    gungraun_parser.add_argument("--root", type=Path, default=Path("target/gungraun"))
    gungraun_parser.add_argument("--output", type=Path, required=True)
    gungraun_parser.add_argument("--git-sha", required=True)
    gungraun_parser.set_defaults(run=lambda args: collect_gungraun(args.root, args.output, args.git_sha))
    compare_parser = commands.add_parser("compare")
    compare_parser.add_argument("--current", type=Path, required=True)
    compare_parser.add_argument("--baseline", type=Path)
    compare_parser.add_argument("--output", type=Path, required=True)
    compare_parser.add_argument("--stale", action="store_true")
    compare_parser.add_argument("--check-ir-pins", action="store_true")
    compare_parser.add_argument("--baseline-tree")
    compare_parser.add_argument("--current-tree")
    compare_parser.add_argument("--ir-reason", help=argparse.SUPPRESS)
    compare_parser.set_defaults(run=command_compare)
    return root


def main() -> int:
    try:
        args = parser().parse_args()
        args.run(args)
        return 0
    except BenchError as error:
        print(f"bench-results: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
