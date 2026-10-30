#!/usr/bin/env python3
"""Normalize benchmark output and compare schema-version-1 result files."""

from __future__ import annotations

import argparse
import json
import math
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, NamedTuple

SCHEMA_VERSION = 1
TIERS = ("rust-micro", "rust-wall", "node-ffi")


class Metric(NamedTuple):
    higher_is_better: bool


# Fixed registry: every row's metric must be listed here. Any tier may use any metric.
METRICS = {
    "Ir": Metric(higher_is_better=False),
    "median_ns": Metric(higher_is_better=False),
    "mb_per_s": Metric(higher_is_better=True),
    "wakeups_per_s": Metric(higher_is_better=False),
    "cpu_ms_per_s": Metric(higher_is_better=False),
    "allocs_per_mb": Metric(higher_is_better=False),
    "bytes_allocated_per_mb": Metric(higher_is_better=False),
    "datagrams_per_mb": Metric(higher_is_better=False),
    "avg_datagram_bytes": Metric(higher_is_better=True),
    "datagrams_per_receive_call": Metric(higher_is_better=True),
    "allocs_per_msg": Metric(higher_is_better=False),
    "bytes_allocated_per_msg": Metric(higher_is_better=False),
    "rtt_us_p50": Metric(higher_is_better=False),
    "rtt_us_p99": Metric(higher_is_better=False),
}
# Classification bands as (metric, tier or None for any, name prefix,
# (changed %, notable %)); the first matching entry wins. A row under `changed`
# is noise. Rows that match no entry are informational: their change is shown
# without a direction. Wall-clock bands sit above the run-to-run noise measured
# on code-identical runs on the bench instance (p90 / max absolute change).
BANDS = (
    # Deterministic: instruction counts, and allocations of isolated agent
    # operations with fixed inputs.
    ("Ir", None, "", (1.0, 2.0)),
    ("allocs_per_msg", None, "", (1.0, 2.0)),
    ("bytes_allocated_per_msg", None, "", (1.0, 2.0)),
    # Endpoint e2e (p90 1.3%, max 4.9%) and Node FFI (p90 2%, max 4.8%).
    ("median_ns", "rust-wall", "e2e/", (5.0, 10.0)),
    ("median_ns", "node-ffi", "", (5.0, 10.0)),
    # Criterion micro benches (p90 4%, outliers to 40%).
    ("median_ns", "rust-wall", "", (10.0, 20.0)),
    # Throughput (p90 5.4%, max 5.8%).
    ("mb_per_s", None, "", (5.0, 10.0)),
    # Application ping latency under load (p90 3%, swings ~22-37 µs).
    ("rtt_us_p50", None, "", (15.0, 30.0)),
    # Idle wakeups are near-deterministic; a change means a new timer.
    ("wakeups_per_s", None, "", (10.0, 20.0)),
    # Allocations and datagrams over real transports depend on scheduling, read
    # chunking and congestion control (p90 1.6%, max 10%).
    *((metric, None, "", (15.0, 30.0)) for metric in (
        "allocs_per_mb", "bytes_allocated_per_mb", "datagrams_per_mb",
        "avg_datagram_bytes", "datagrams_per_receive_call",
    )),
    # rtt_us_p99 (p90 49%) and idle cpu_ms_per_s (~0.005 ms/s of timer noise)
    # stay informational.
)
EXPECTED_CRITERION = {
    "multiaddr/parse_text", "multiaddr/encode_binary", "multiaddr/decode_binary",
    "yamux/64KiB/session_send_and_drain", "yamux/64KiB/session_receive_and_drain",
    "yamux/256KiB/queued_send_16KiB_window_updates", "yamux/1024_streams/sparse_send_8_streams",
    "peer_book_128_peers_16_addrs/tick_active", "peer_book_128_peers_16_addrs/tick_expire",
    "peer_book_128_peers_16_addrs/next_deadline",
    "pubsub/gossipsub_publish_32x60KiB",
    "pubsub/gossipsub_forward_1KiB/8", "pubsub/gossipsub_forward_1KiB/32",
    "pubsub/gossipsub_forward_1KiB/128", "pubsub/gossipsub_heartbeat_1000_peers_100_topics",
    "relay_handle_event_same_now_128_pending_hops",
    "quic/idle_poll/1", "quic/idle_poll/64", "quic/idle_poll/256", "quic/idle_poll/512",
    *{
        f"tcp/{group}/{count}"
        for group in ("readiness_poll", "readiness_poll_sparse", "transport_poll_idle", "transport_poll_sparse")
        for count in (1, 64, 256, 512)
    },
    "e2e/tcp/setup", "e2e/tcp/ping", "e2e/tcp/echo_64b", "e2e/tcp/echo_64b_crossed_4x4",
    "e2e/tcp/transfer_1mib", "e2e/quic/setup", "e2e/quic/ping", "e2e/quic/echo_64b",
    "e2e/quic/echo_64b_crossed_4x4", "e2e/quic/transfer_1mib",
}
GUNGRAUN_NAMES = {
    "parse_text": "multiaddr/parse_text",
    "encode_binary": "multiaddr/encode_binary",
    "decode_binary": "multiaddr/decode_binary",
    "session_send_and_drain": "yamux/64KiB/session_send_and_drain",
    "session_receive_and_drain": "yamux/64KiB/session_receive_and_drain",
    "queued_send_16kib_window_updates": "yamux/256KiB/queued_send_16KiB_window_updates",
    "sparse_send_8_of_1024_streams": "yamux/1024_streams/sparse_send_8_streams",
    "tick_active": "peer_book_128_peers_16_addrs/tick_active",
    "tick_expire": "peer_book_128_peers_16_addrs/tick_expire",
    "next_deadline": "peer_book_128_peers_16_addrs/next_deadline",
    "gossipsub_publish_32x60_kib": "pubsub/gossipsub_publish_32x60KiB",
    "gossipsub_forward_1_kib_8": "pubsub/gossipsub_forward_1KiB/8",
    "gossipsub_forward_1_kib_32": "pubsub/gossipsub_forward_1KiB/32",
    "gossipsub_forward_1_kib_128": "pubsub/gossipsub_forward_1KiB/128",
    "gossipsub_heartbeat_1000_peers_100_topics": "pubsub/gossipsub_heartbeat_1000_peers_100_topics",
    "relay_handle_event_same_now_128_pending_hops": "relay_handle_event_same_now_128_pending_hops",
    **{
        f"relay_{size}_{case}": f"relay_server_{size}/{case}"
        for size in ("100", "1k", "10k")
        for case in (
            "next_deadline",
            "tick_idle",
            "tick_expire_100",
            "reserve_new_peer",
            "connect_new_peer",
            "hop_admission",
            "close_connection_100_circuits",
            "close_destination_connection",
            "reset_holding_full_tails",
        )
    },
}
# Benchmarks renamed since the last release, old name suffix -> new, so a
# release baseline still lines up with the current rows. Drop entries once a
# release carries the new names.
RENAMED_SUFFIXES = {"/next_timeout": "/next_deadline"}
EXPECTED_VITEST = {"sdk_drain_flood", "sdk_stream_transfer", "raw_drain_events", "connected_peers_sync"}
# Rows a bench measures itself (for example throughput or allocations), keyed by
# (tier, name, metric). Each such bench writes a JSON array of rows into the
# `custom` collector's root; list every row it emits here.
EXPECTED_CUSTOM: set[tuple[str, str, str]] = {
    *{
        ("rust-wall", f"endpoint_idle/{variant}", metric)
        for variant in ("quic_only", "quic_dual_stack", "full", "full_no_mdns")
        for metric in ("wakeups_per_s", "cpu_ms_per_s")
    },
    *{
        ("rust-wall", f"endpoint_throughput/{case}", metric)
        for case in ("tcp", "quic", "relayed")
        for metric in ("mb_per_s", "allocs_per_mb", "bytes_allocated_per_mb")
    },
    *{
        ("rust-wall", f"endpoint_throughput/{case}/{endpoint}/{direction}", metric)
        for case, endpoints in (("quic", ("client", "target")), ("relayed", ("client", "target", "relay")))
        for endpoint in endpoints
        for direction in ("sent", "received")
        for metric in ("datagrams_per_mb", "avg_datagram_bytes")
    },
    *{
        ("rust-wall", f"endpoint_throughput/{case}/{endpoint}/received", "datagrams_per_receive_call")
        for case, endpoints in (("quic", ("client", "target")), ("relayed", ("client", "target", "relay")))
        for endpoint in endpoints
    },
    *{("rust-wall", f"endpoint_rtt/{case}/100m_100ms", "mb_per_s") for case in ("quic", "tcp")},
    *{
        ("rust-wall", f"endpoint_ping_load/{load}/{transport}", metric)
        for load in ("idle", "relay", "pubsub")
        for transport in ("tcp", "quic")
        for metric in ("rtt_us_p50", "rtt_us_p99")
    },
    *{
        ("rust-micro", f"pubsub/gossipsub_forward_1KiB/{n}", metric)
        for n in (8, 32, 128)
        for metric in ("allocs_per_msg", "bytes_allocated_per_msg")
    },
}
IR_PINS = {
    "rust": "Rust toolchain",
    "profile": "optimization profile",
    "gungraun": "Gungraun version",
    "valgrind": "Valgrind version",
    "valgrind_sha256": "Valgrind archive digest",
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
        if not isinstance(metric, str) or metric not in METRICS:
            raise BenchError(f"row {index} has unknown metric {metric!r}")
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
        if estimate.stat().st_mtime_ns <= started_at:
            continue
        name = load_json(estimate.with_name("benchmark.json")).get("full_id")
        if not isinstance(name, str) or not name:
            raise BenchError(f"missing full_id in {estimate.with_name('benchmark.json')}")
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
    document = load_json(report)
    if document.get("success") is not True:
        raise BenchError(f"Vitest benchmark run did not succeed: {report}")
    rows = []
    for file in document.get("testResults", []):
        for assertion in file.get("assertionResults", []):
            for benchmark in assertion.get("benchmarks", []):
                for task in benchmark.get("tasks", []):
                    median_ms = task.get("latency", {}).get("p50")
                    name = task.get("name")
                    if not isinstance(name, str) or isinstance(median_ms, bool) or not isinstance(median_ms, (int, float)):
                        raise BenchError(f"invalid Vitest benchmark in {report}")
                    rows.append({"tier": "node-ffi", "name": name, "metric": "median_ns", "value": median_ms * 1_000_000})
    names = {row["name"] for row in rows}
    if names != EXPECTED_VITEST or len(rows) != len(EXPECTED_VITEST):
        missing = sorted(EXPECTED_VITEST - names)
        unexpected = sorted(names - EXPECTED_VITEST)
        raise BenchError(f"Vitest row set mismatch; missing={missing}, unexpected={unexpected}")
    write_results(git_sha, rows, output)


def collect_gungraun(root: Path, output: Path, git_sha: str, since: Path) -> None:
    try:
        started_at = since.stat().st_mtime_ns
    except OSError as error:
        raise BenchError(f"cannot read Gungraun run marker {since}: {error}") from error
    rows = []
    for path in root.glob("**/summary.json"):
        if path.stat().st_mtime_ns <= started_at:
            continue
        summary = load_json(path)
        identifier = summary.get("id") or summary.get("function_name")
        name = GUNGRAUN_NAMES.get(identifier)
        if name is None:
            raise BenchError(f"unexpected Gungraun benchmark {identifier!r} in {path}")
        ir = None
        for profile in summary.get("profiles", []):
            if profile.get("tool") != "Callgrind":
                continue
            metric = profile["summaries"]["total"]["summary"]["Callgrind"]["Ir"]["metrics"]
            ir = metric.get("Left")
            if ir is None:
                both = metric.get("Both") or []
                ir = both[0] if both else None
            if isinstance(ir, dict):
                ir = ir.get("Int")
        if not isinstance(ir, (int, float)):
            raise BenchError(f"missing Callgrind Ir in {path}")
        rows.append({"tier": "rust-micro", "name": name, "metric": "Ir", "value": ir})
    names = {row["name"] for row in rows}
    expected = set(GUNGRAUN_NAMES.values())
    if names != expected or len(rows) != len(expected):
        missing = sorted(expected - names)
        unexpected = sorted(names - expected)
        raise BenchError(f"Gungraun row set mismatch; missing={missing}, unexpected={unexpected}")
    write_results(git_sha, rows, output)


def collect_custom(root: Path, output: Path, git_sha: str, since: Path) -> None:
    """Merge the row arrays that benches wrote into `root` after `since`, requiring exactly `EXPECTED_CUSTOM`."""
    try:
        started_at = since.stat().st_mtime_ns
    except OSError as error:
        raise BenchError(f"cannot read custom run marker {since}: {error}") from error
    rows = []
    for path in sorted(root.glob("*.json")):
        if path.stat().st_mtime_ns <= started_at:
            continue
        document = load_json(path)
        if not isinstance(document, list):
            raise BenchError(f"custom rows file must hold a JSON array: {path}")
        rows.extend(document)
    validate({"schema_version": SCHEMA_VERSION, "git_sha": git_sha, "rows": rows})
    keys = {(row["tier"], row["name"], row["metric"]) for row in rows}
    if keys != EXPECTED_CUSTOM:
        missing = sorted(EXPECTED_CUSTOM - keys)
        unexpected = sorted(keys - EXPECTED_CUSTOM)
        raise BenchError(f"custom row set mismatch; missing={missing}, unexpected={unexpected}")
    write_results(git_sha, rows, output)


def git_bytes(tree: str, path: str) -> bytes:
    result = subprocess.run(
        ["git", "show", f"{tree}:{path}"], capture_output=True, check=False
    )
    if result.returncode:
        raise BenchError(f"cannot read {path} at {tree}")
    return result.stdout


def lock_without_workspace_versions(lock: bytes) -> str:
    """`Cargo.lock` with the version of every path package (an entry without a
    `source`, i.e. a workspace crate) blanked, so a release's version bump does
    not make instruction counts incomparable. External packages stay exact."""
    blocks = lock.decode().split("\n[[package]]\n")
    return "\n[[package]]\n".join(
        block if "\nsource = " in block else re.sub(r'^version = ".*"$', "version = _", block, flags=re.M)
        for block in blocks
    )


def ir_compatible(baseline_tree: str, current_tree: str) -> tuple[bool, str | None]:
    """Compare the five pins that make instruction counts comparable."""
    if lock_without_workspace_versions(git_bytes(baseline_tree, "Cargo.lock")) != lock_without_workspace_versions(
        git_bytes(current_tree, "Cargo.lock")
    ):
        return False, "incompatible Ir pins: Cargo.lock differs"
    try:
        before_bytes = git_bytes(baseline_tree, "bench/pins.json")
        after_bytes = git_bytes(current_tree, "bench/pins.json")
    except BenchError:
        return False, "incompatible Ir pins: pin manifest unavailable"
    try:
        before = json.loads(before_bytes)
        after = json.loads(after_bytes)
    except json.JSONDecodeError as error:
        raise BenchError(f"invalid bench/pins.json: {error}") from error
    for key, label in IR_PINS.items():
        if before.get(key) != after.get(key):
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


def current_name(name: str) -> str:
    """A baseline benchmark name under its current name (see `RENAMED_SUFFIXES`)."""
    for old, new in RENAMED_SUFFIXES.items():
        if name.endswith(old):
            return name[: -len(old)] + new
    return name


def band(tier: str, name: str, metric: str) -> tuple[float, float] | None:
    """The row's (changed, notable) band from `BANDS`, or None when informational."""
    for band_metric, band_tier, prefix, thresholds in BANDS:
        if band_metric == metric and band_tier in (None, tier) and name.startswith(prefix):
            return thresholds
    return None


def compare_rows(
    current: dict[str, Any], baseline: dict[str, Any] | None, ir_reason: str | None
) -> list[ComparedRow]:
    old = {} if baseline is None else {
        (row["tier"], current_name(row["name"]), row["metric"]): row["value"]
        for row in baseline["rows"]
    }
    compared = []
    for row in current["rows"]:
        key = (row["tier"], row["name"], row["metric"])
        reason = "no baseline" if baseline is None else None
        if reason is None and row["metric"] == "Ir" and ir_reason:
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
        thresholds = band(*key)
        if thresholds is None:
            compared.append(ComparedRow(*key, baseline_value, row["value"], delta, "informational", ""))
            continue
        better = -delta if METRICS[row["metric"]].higher_is_better else delta
        direction = "improved" if better < 0 else "regressed" if better > 0 else ""
        changed, notable = thresholds
        magnitude = abs(delta)
        classification = "notable" if magnitude >= notable else "changed" if magnitude >= changed else "noise"
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


def markdown_code(value: str) -> str:
    """Render an untrusted value inside a Markdown table code span."""
    value = (
        value.replace("\\", "&#92;")
        .replace("|", "&#124;")
        .replace("\r\n", "<br>")
        .replace("\r", "<br>")
        .replace("\n", "<br>")
        .replace("`", "&#96;")
    )
    return f"`{value}`"


# Unclassified rows that stay in the top table: rows only one side has.
UNMATCHED = ("missing baseline row", "missing current row")


def row_table(rows: list[ComparedRow], with_reason: bool) -> list[str]:
    lines = ["| tier | benchmark | metric | baseline | current | Δ% | class | direction |", "| --- | --- | --- | ---: | ---: | ---: | --- | --- |"]
    for row in rows:
        delta = "—" if row.delta is None else f"{row.delta:+.2f}%"
        classification = row.classification if row.reason is None or not with_reason else f"{row.classification} ({row.reason})"
        lines.append(f"| {row.tier} | {markdown_code(row.name)} | `{row.metric}` | {display_value(row.baseline)} | {display_value(row.current)} | {delta} | {classification} | {row.direction} |")
    return lines


def render(
    baseline: dict[str, Any] | None,
    rows: list[ComparedRow],
    baseline_label: str | None = None,
    head_sha: str | None = None,
    run_url: str | None = None,
    latest_release: str | None = None,
) -> str:
    """The sticky PR comment: rows beyond their band and unmatched rows up top,
    every other row in a collapsed block, shared unclassified reasons once."""
    lines = ["<!-- bench-comment -->", "## Benchmark comparison", ""]
    head = "unknown" if head_sha is None else head_sha[:12]
    lines.append(f"- Head: {markdown_code(head)}" + ("" if run_url is None else f" ([run]({run_url}))"))
    if baseline is None:
        lines.append("- Baseline: none")
    else:
        sha = baseline["git_sha"][:12]
        name = sha if baseline_label is None else f"{baseline_label} ({sha})"
        lines.append(f"- Baseline: {markdown_code(name)}, the latest release rather than the PR base, so changes already on `main` show up too.")
        if latest_release and baseline_label and latest_release != baseline_label:
            lines += ["", f"> [!WARNING]\n> The baseline is stale: the latest release is {markdown_code(latest_release)}, which has no stored baseline."]
    classifications = ("noise", "changed", "notable", "informational", "unclassified")
    lines += ["", "| tier | noise | changed | notable | informational | unclassified |", "| --- | ---: | ---: | ---: | ---: | ---: |"]
    for tier in TIERS:
        tier_rows = [row for row in rows if row.tier == tier]
        counts = {name: sum(row.classification == name for row in tier_rows) for name in classifications}
        lines.append(f"| {tier} | {counts['noise']} | {counts['changed']} | {counts['notable']} | {counts['informational']} | {counts['unclassified']} |")
    beyond = [row.classification in ("changed", "notable") or row.reason in UNMATCHED for row in rows]
    top = [row for row, up in zip(rows, beyond) if up]
    rest = [row for row, up in zip(rows, beyond) if not up]
    reasons: dict[str, int] = {}
    for row in rest:
        if row.reason is not None:
            reasons[row.reason] = reasons.get(row.reason, 0) + 1
    lines += ["", "### Beyond the noise band", ""]
    lines += row_table(top, with_reason=True) if top else ["None."]
    if reasons:
        lines += ["", *(f"- {count} rows unclassified: {reason}" for reason, count in reasons.items())]
    if rest:
        lines += ["", f"<details><summary>Other rows ({len(rest)})</summary>", "", *row_table(rest, with_reason=False), "", "</details>"]
    return "\n".join(lines) + "\n"


def command_compare(args: argparse.Namespace) -> None:
    current = validate(load_json(args.current))
    baseline = None if args.baseline is None else validate(load_json(args.baseline))
    ir_reason = None
    if baseline is not None and args.check_ir_pins:
        compatible, ir_reason = ir_compatible(args.baseline_tree or baseline["git_sha"], args.current_tree or current["git_sha"])
        if compatible:
            ir_reason = None
    rows = compare_rows(current, baseline, ir_reason)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render(baseline, rows, args.baseline_label, current["git_sha"], args.run_url, args.latest_release))


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
    gungraun_parser.add_argument("--since", type=Path, required=True)
    gungraun_parser.set_defaults(run=lambda args: collect_gungraun(args.root, args.output, args.git_sha, args.since))
    custom_parser = commands.add_parser("custom")
    custom_parser.add_argument("--root", type=Path, default=Path("target/bench-results/custom"))
    custom_parser.add_argument("--output", type=Path, required=True)
    custom_parser.add_argument("--git-sha", required=True)
    custom_parser.add_argument("--since", type=Path, required=True)
    custom_parser.set_defaults(run=lambda args: collect_custom(args.root, args.output, args.git_sha, args.since))
    compare_parser = commands.add_parser("compare")
    compare_parser.add_argument("--current", type=Path, required=True)
    compare_parser.add_argument("--baseline", type=Path)
    compare_parser.add_argument("--output", type=Path, required=True)
    compare_parser.add_argument("--check-ir-pins", action="store_true")
    compare_parser.add_argument("--baseline-tree")
    compare_parser.add_argument("--baseline-label")
    compare_parser.add_argument("--current-tree")
    compare_parser.add_argument("--run-url")
    compare_parser.add_argument("--latest-release", help="the repository's latest release, to flag a stale baseline")
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
