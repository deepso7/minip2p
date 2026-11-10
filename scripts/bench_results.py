#!/usr/bin/env python3
"""Normalize benchmark output, and compare a head result with its base's from the same run."""

from __future__ import annotations

import argparse
import json
import math
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 1
TIERS = ("rust-micro", "rust-wall", "node-ffi")


# Fixed registry: every row's metric must be listed here. Any tier may use any metric.
METRICS = {
    "Ir",
    "median_ns",
    "mb_per_s",
    "wakeups_per_s",
    "cpu_ms_per_s",
    "allocs_per_mb",
    "bytes_allocated_per_mb",
    "datagrams_per_mb",
    "avg_datagram_bytes",
    "datagrams_per_receive_call",
    "allocs_per_msg",
    "bytes_allocated_per_msg",
    "rtt_us_p50",
    "rtt_us_p99",
}
# Changed/notable thresholds (%) of the deterministic metrics, all lower is
# better: instruction counts, and allocations of isolated agent operations
# with fixed inputs (`router_allocs` asserts two runs agree). A
# comparison labels only these rows; every other metric (wall clock,
# throughput, latency, allocations over real transports) is informational,
# since code-identical runs on the bench instance move it by tens of percent.
BANDS = {
    "Ir": (1.0, 2.0),
    "allocs_per_msg": (1.0, 2.0),
    "bytes_allocated_per_msg": (1.0, 2.0),
}
EXPECTED_CRITERION = {
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


def validate(document: Any, strict: bool = True) -> dict[str, Any]:
    """Check a result document. `strict` also requires every tier and metric
    to be registered; a comparison reads the measured side's rows unstrictly,
    since a PR may add tiers or metrics this checkout does not know yet."""
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
        if not isinstance(tier, str) or not tier or (strict and tier not in TIERS):
            raise BenchError(f"row {index} has unknown tier {tier!r}")
        if not isinstance(name, str) or not name:
            raise BenchError(f"row {index} requires a non-empty name")
        if not isinstance(metric, str) or not metric or (strict and metric not in METRICS):
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


def ir_seeds(targets: bytes) -> set[str]:
    """The packages of the `ir` lines in `bench/targets`."""
    return {fields[1] for line in targets.decode().splitlines() if (fields := line.split()) and fields[0] == "ir"}


def reachable_lock(lock: bytes, seeds: set[str]) -> set[tuple]:
    """The `Cargo.lock` entries reachable from `seeds` by any dependency edge,
    each as (identity, checksum, dependency identities), so a change outside the
    IR benches' graph (an example's or a binding's dependency) does not make
    instruction counts incomparable. Edges carry no feature, kind or target, so
    this is a superset of what the benches build. A path package (no `source`,
    a workspace crate) is identified by name alone, so a release's version bump
    does not count as a change; external packages keep version and source."""
    try:
        packages = tomllib.loads(lock.decode()).get("package", [])
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise BenchError(f"invalid Cargo.lock: {error}") from error

    def identity(package: dict[str, Any]) -> tuple:
        source = package.get("source")
        return (package["name"], None, None) if source is None else (package["name"], package["version"], source)

    by_name: dict[str, list[dict[str, Any]]] = {}
    for package in packages:
        by_name.setdefault(package["name"], []).append(package)

    # A dependency is written `name`, `name version` or `name version (source)`.
    def resolve(reference: str) -> dict[str, Any]:
        name, _, rest = reference.partition(" ")
        version, _, source = rest.partition(" ")
        matches = [
            package
            for package in by_name.get(name, [])
            if (not version or package["version"] == version) and (not source or f"({package.get('source')})" == source)
        ]
        if len(matches) != 1:
            raise BenchError(f"Cargo.lock dependency {reference!r} matches {len(matches)} packages")
        return matches[0]

    entries = set()
    pending = []
    for seed in seeds:
        if seed not in by_name:
            raise BenchError(f"Cargo.lock has no package {seed}")
        pending += by_name[seed]
    seen: set[tuple] = set()
    while pending:
        package = pending.pop()
        key = identity(package)
        if key in seen:
            continue
        seen.add(key)
        dependencies = [resolve(reference) for reference in package.get("dependencies", [])]
        entries.add((key, package.get("checksum"), tuple(sorted(identity(dependency) for dependency in dependencies))))
        pending += dependencies
    return entries


def ir_pins_note(base_source: Path, head_source: Path) -> str | None:
    """Why the two source trees' instruction counts are not like for like, or
    None: `bench/pins.json` or the IR benches' part of `Cargo.lock` differs.
    The comparison still classifies the Ir rows and shows this as a note."""

    def read(source: Path, path: str) -> bytes:
        try:
            return (source / path).read_bytes()
        except OSError as error:
            raise BenchError(f"cannot read {path}") from error

    try:
        # The head's IR benches: the base may not have a new one yet.
        seeds = ir_seeds(read(head_source, "bench/targets"))
        if reachable_lock(read(base_source, "Cargo.lock"), seeds) != reachable_lock(read(head_source, "Cargo.lock"), seeds):
            return "`Cargo.lock` differs between base and head for the IR benches"
        before = json.loads(read(base_source, "bench/pins.json"))
        after = json.loads(read(head_source, "bench/pins.json"))
    except (BenchError, json.JSONDecodeError) as error:
        return f"could not compare base and head ({markdown_code(str(error))})"
    changed = [label for key, label in IR_PINS.items() if before.get(key) != after.get(key)]
    if not changed:
        return None
    return f"{', '.join(changed)} {'differs' if len(changed) == 1 else 'differ'} between base and head"


@dataclass(frozen=True)
class ComparedRow:
    tier: str
    name: str
    metric: str
    base: float | int | None
    head: float | int | None
    delta: float | None
    # `notable`, `changed` or `negligible` for a banded row; `informational`
    # for every other row both sides have; `new` or `removed` otherwise.
    classification: str
    direction: str = ""


def tier_order(tier: str) -> int:
    return TIERS.index(tier) if tier in TIERS else len(TIERS)


def compare_rows(base: dict[str, Any], head: dict[str, Any]) -> list[ComparedRow]:
    """Head's rows against base's, matched by (tier, name, metric). Only
    metrics in `BANDS` get a class and direction."""
    before = {(row["tier"], row["name"], row["metric"]): row["value"] for row in base["rows"]}
    after = {(row["tier"], row["name"], row["metric"]): row["value"] for row in head["rows"]}
    compared = []
    for key in before.keys() | after.keys():
        old, new = before.get(key), after.get(key)
        if old is None or new is None:
            compared.append(ComparedRow(*key, old, new, None, "new" if old is None else "removed"))
            continue
        delta = None if old == 0 else (new - old) / old * 100
        thresholds = BANDS.get(key[2])
        if thresholds is None:
            compared.append(ComparedRow(*key, old, new, delta, "informational"))
            continue
        direction = "regressed" if new > old else "improved"
        changed, notable = thresholds
        # A zero base has no percentage; any change from it is notable.
        magnitude = abs(delta) if delta is not None else 0.0 if new == old else math.inf
        classification = "notable" if magnitude >= notable else "changed" if magnitude >= changed else "negligible"
        compared.append(ComparedRow(*key, old, new, delta, classification, "" if classification == "negligible" else direction))
    compared.sort(key=lambda row: (tier_order(row.tier), row.name, row.metric))
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


def row_table(rows: list[ComparedRow], labeled: bool) -> list[str]:
    header = "| tier | benchmark | metric | base | head | Δ% |"
    rule = "| --- | --- | --- | ---: | ---: | ---: |"
    if labeled:
        header += " class | direction |"
        rule += " --- | --- |"
    lines = [header, rule]
    for row in rows:
        delta = "—" if row.delta is None else f"{row.delta:+.2f}%"
        line = f"| {markdown_code(row.tier)} | {markdown_code(row.name)} | {markdown_code(row.metric)} | {display_value(row.base)} | {display_value(row.head)} | {delta} |"
        lines.append(line + (f" {row.classification} | {row.direction} |" if labeled else ""))
    return lines


def details(summary: str, rows: list[ComparedRow], labeled: bool) -> list[str]:
    return ["", f"<details><summary>{summary} ({len(rows)})</summary>", "", *row_table(rows, labeled), "", "</details>"] if rows else []


def render(
    base: dict[str, Any],
    head: dict[str, Any],
    rows: list[ComparedRow],
    base_ref: str | None = None,
    run_url: str | None = None,
    pins_note: str | None = None,
) -> str:
    """The sticky PR comment: changed deterministic rows and rows only one side
    has up top, negligible and informational rows collapsed below."""
    lines = ["<!-- bench-comment -->", "## Benchmark comparison", ""]
    lines.append(f"- Head: {markdown_code(head['git_sha'][:12])}" + ("" if run_url is None else f" ([run]({run_url}))"))
    merge_base = "" if base_ref is None else f", the merge-base with {markdown_code(base_ref)}"
    lines.append(f"- Base: {markdown_code(base['git_sha'][:12])}{merge_base}, measured in the same run.")
    lines.append(f"- Only {', '.join(f'`{metric}`' for metric in BANDS)} rows are classified; wall-clock and other timing rows are informational.")
    if pins_note:
        lines += ["", f"> [!NOTE]\n> Ir pins: {pins_note}, so `Ir` deltas may include that change."]
    top = [row for row in rows if row.classification in ("notable", "changed", "new", "removed")]
    lines += ["", "### Changed", ""]
    lines += row_table(top, labeled=True) if top else ["None."]
    lines += details("Negligible", [row for row in rows if row.classification == "negligible"], labeled=False)
    lines += details("Informational", [row for row in rows if row.classification == "informational"], labeled=False)
    return "\n".join(lines) + "\n"


def command_compare(args: argparse.Namespace) -> None:
    base = validate(load_json(args.base), strict=False)
    head = validate(load_json(args.head), strict=False)
    pins_note = None
    if args.base_source is not None and args.head_source is not None:
        pins_note = ir_pins_note(args.base_source, args.head_source)
    rows = compare_rows(base, head)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render(base, head, rows, args.base_ref, args.run_url, pins_note))


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
    compare_parser = commands.add_parser("compare", help="compare a head result with its base's from the same run")
    compare_parser.add_argument("--base", type=Path, required=True)
    compare_parser.add_argument("--head", type=Path, required=True)
    compare_parser.add_argument("--output", type=Path, required=True)
    compare_parser.add_argument("--base-source", type=Path, help="the base's source tree, to note differing Ir pins")
    compare_parser.add_argument("--head-source", type=Path, help="the head's source tree, to note differing Ir pins")
    compare_parser.add_argument("--base-ref", help="the branch whose merge-base is the base")
    compare_parser.add_argument("--run-url")
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
