# PR benchmarking pipeline for minip2p

> **Status:** Historical design record. The AWS implementation supersedes the
> workflow design below. It runs all tiers sequentially in one isolated Fargate
> task, has a 90-minute job limit, requires approval through the `aws-bench`
> environment, and uses `pull_request_target` only to run trusted workflow and
> infrastructure code. The pull request source is compiled inside Docker.
> Stable releases, rather than pushes to `main`, publish baselines. Manual runs
> always measure the default branch. A tier failure rejects the whole result.
> See [the AWS runner README](../../infra/bench/README.md) and
> [the workflow](../../.github/workflows/bench.yml) for the current contract.
>
> This document remains the locked pre-implementation specification validated
> by the [Map: PR benchmarking pipeline spec](https://github.com/deepso7/minip2p/issues/125).
>
> **Research:**
> [measurement methodology](https://github.com/deepso7/minip2p/blob/research/bench-methodology/docs/research/bench-measurement-methodology.md),
> [CI mechanics](https://github.com/deepso7/minip2p/blob/research/bench-ci-mechanics/docs/research/bench-ci-mechanics.md).

## Goal and boundaries

Ship a homegrown GitHub Actions pipeline that runs the three benchmark tiers on
every pull request targeting `main`, compares each row against a stored baseline
from `main`, and posts one sticky PR comment. Results stay informational. They
never fail the check or gate merges.

CodSpeed and Bencher are out. React Native and mobile binding benches are out.
Threshold merge gates may return later once real runs show a noise history; they
are not part of this plan.

The comparison model is PR vs a stored `main` baseline on a different hosted
runner. Same-job merge-base reruns were considered and rejected.

## Tiers

Three parallel jobs in `bench.yml`. A failing tier does not drop the others'
rows from the comment.

| Tier | Job | Metric | Harness | Classification bands |
| --- | --- | --- | --- | --- |
| `rust-micro` | Gungraun Callgrind `Ir` | Instruction count | Gungraun + `gungraun-runner` + Valgrind via `gungraun/setup-gungraun` | noise `< 1%`, changed `>= 1%` and `< 2%`, notable `>= 2%` |
| `rust-wall` | Criterion wall-clock | Median latency | Criterion | noise `< 20%`, changed `>= 20%` and `< 30%`, notable `>= 30%` |
| `node-ffi` | Vitest Bench / Tinybench | Median latency | Vitest Bench under `bindings/ts/node` | same wall-clock bands as `rust-wall` |

A value exactly on a boundary enters the higher category. Bands are symmetric
for improvements and regressions. Direction is labeled `improved` or
`regressed`; unclassified rows leave direction blank.

Reports may show throughput derived from latency. Throughput never drives
classification.

### Runtime budget

Each tier job targets ≤15 minutes including build, with `timeout-minutes: 25`.
Workflow wall-clock is the slowest job. Trim Criterion/Tinybench sample settings
only if a tier breaches the 15-minute target under cached builds.

### Environment pins (all three jobs)

| Pin | Value |
| --- | --- |
| Runner | `ubuntu-latest` |
| Rust | `1.98.0` via `dtolnay/rust-toolchain` (bench jobs only) |
| Node (`node-ffi`) | `24` via `actions/setup-node` |
| Gungraun + `gungraun-runner` | `0.19.4` |
| Valgrind | `3.27.1` |
| Target | `x86_64-unknown-linux-gnu` (linux-x64 hosted runner) |

No extra hardening in v1 (no CPU affinity, no ASLR tweaks). Build and measure
in release / Criterion release mode. Pin strings live in the workflow YAML (and
Cargo where relevant). Do not embed runner image id, Node version, rustc string,
or other pin metadata in `results.json`.

## Portfolio

### `rust-micro` (Gungraun)

A 1:1 mirror of the ten existing deterministic Criterion cases. Criterion suites
stay for local wall-clock; Gungraun targets are separate `[[bench]] harness =
false` entries that coexist with them. Setup must sit outside the measured body
so it is excluded from the instruction count.

| Suite | Cases |
| --- | --- |
| `multiaddr` | `parse_text`, `encode_binary`, `decode_binary` |
| `yamux` / 64 KiB | `session_send_and_drain`, `session_receive_and_drain` |
| `peer_book_128_peers_16_addrs` | `tick_active`, `tick_expire`, `next_timeout` |
| `pubsub` | `floodsub_publish_32x60KiB` |
| `relay_server_event` | `relay_handle_event_same_now_128_pending_hops` |

Secure-mux handshake and wire-codec decode benches are deliberate follow-ups,
not part of this plan.

### `rust-wall` (Criterion)

**Socket sweeps (existing).** Keep full COUNTS = `[1, 64, 256, 512]` curves:

- `minip2p-quic` `idle_poll`
- `minip2p-tcp` `readiness_poll`

**Endpoint e2e (new).** Public `Endpoint` API, two endpoints in one process on
loopback. TCP and QUIC are separate rows. TCP exercises secure-mux (Noise +
Yamux). QUIC exercises TLS + quiche streams, not Noise + Yamux.

| Scenario | Measurement | Connection state | Scale |
| --- | --- | --- | --- |
| Setup | `dial` → `PeerReady` | Cold each sample | Single connection |
| Ping | `ping` → `PingRttMeasured` / `wait_ping_rtt` | Warm | Single connection |
| Echo | 64-byte app-protocol stream round-trip | Warm | Single stream, plus one crossed multi bench |
| Transfer | 1 MiB app-protocol stream round-trip | Warm | Single connection, single stream |

Crossed multi applies only to the 64-byte echo: N=4 connections × 4 streams (16
in flight). One Criterion sample is wall time until every echo in the batch
completes. Topology is one listener and one dialer; multi-conn means N dials to
the same listener `PeerAddr`.

Timer boundaries:

- Setup: start before `dial`; stop at first `PeerReady` for that peer.
- Ping: start before `ping`; stop when `PingRttMeasured` arrives.
- Echo (including crossed): start before opening the batch of streams; stop when
  the last echo payload is received.
- Transfer: start before `open_stream` / first send; stop when the full 1 MiB
  echo is received.

Out of the e2e suite: sustained throughput as a timed scenario, multi-conn or
multi-stream variants of setup/ping/1 MiB transfer, and separate processes for
listener and dialer.

### `node-ffi` (Vitest Bench)

Measures FFI hot-path wall-clock latency against its own stored baseline. It
does not compute a Rust↔Node binding-overhead delta. End-to-end path latency
stays on the Rust e2e tier.

- Platform: linux-x64 only (same as `bindings.yml` / ADR 0004).
- Surface: `Minip2p` SDK, with one exception for raw `NodeEndpoint.drainEvents`.
- Transport for peer setup: TCP loopback only. No QUIC matrix in this tier.
- Not in this tier: e2e mirror (setup / ping / echo / transfer), paired overhead
  columns, multi-arch PR baselines.

| Row | Surface | Setup | Measurement |
| --- | --- | --- | --- |
| SDK drain flood | `Minip2p` | Two endpoints, TCP loopback, pubsub (or equivalent) burst | Wall time to drain-to-empty after the burst |
| Raw `drainEvents` | `NodeEndpoint` | Same peer setup | Wall time of `drainEvents(limit)` loop until empty |
| Sync call | `Minip2p` / native | Endpoint up | `connectedPeers()` × N median latency |

## Baseline storage and lifecycle

Home is a public `bench-data` branch.

- Each successful write stores `<main-sha>.json`.
- `latest` is a pointer file whose contents are that SHA. Readers load `latest`,
  then `<sha>.json`.
- Every push to `main` (no path filter) that finishes a fully successful bench
  run updates the branch. Failed or partial runs write nothing.
- Keep every `<sha>.json` forever.
- One normalized `results.json` covers all three tiers. Tier is a field on each
  row, not a separate file.

### PR compare

Always compare against `latest`. The sticky comment prints the baseline SHA and
a stale note when that SHA is not the PR's merge-base.

### No baseline / incompatible pins

- No baseline yet: still post current numbers; every row is `unclassified` with
  reason `no baseline`.
- Instruction-count incompatibility: Rust toolchain, `Cargo.lock` hash,
  optimization profile, Gungraun version, or Valgrind version differs between
  baseline tree and PR tree. Detect at compare time from git (workflow pin
  strings at the two SHAs + `Cargo.lock` hash). Do not read pin fields from the
  result file.
- On incompatibility, Ir rows are `unclassified` (show current value and reason;
  do not call it improved or regressed). The next successful main write replaces
  `latest`. Wall-clock tiers still classify whenever a baseline exists; bands
  absorb host noise. Node version is not part of the incompatibility set.
- New benchmarks without a matching baseline row are `unclassified`.

### `results.json` shape

Minimal contract implementers must preserve. Field names may gain optional
extensions, but compare/report must understand this shape:

```json
{
  "schema_version": 1,
  "git_sha": "<sha that produced these numbers>",
  "rows": [
    {
      "tier": "rust-micro",
      "name": "multiaddr/parse_text",
      "metric": "Ir",
      "value": 1234567
    },
    {
      "tier": "rust-wall",
      "name": "e2e/tcp/ping",
      "metric": "median_ns",
      "value": 89012
    },
    {
      "tier": "node-ffi",
      "name": "sdk_drain_flood",
      "metric": "median_ns",
      "value": 4567
    }
  ]
}
```

`name` is a stable row id. Changing a name orphans the baseline row and forces
`unclassified` until main catches up.

## Workflows

`ci.yml` stays unchanged. Bench collection and sticky commenting are separate
workflows.

### `bench.yml`

Triggers:

- `pull_request` targeting `main`: every PR, no path filters, no opt-in label.
- `push` to `main`: every push, no path filters.

Workflow-level `permissions: contents: read`. Concurrency group
`bench-${{ github.ref }}` with `cancel-in-progress` for pull requests only
(match `ci.yml` / `bindings.yml`).

Jobs:

1. **`rust-micro`**, **`rust-wall`**, **`node-ffi`** (PR and main). Run in
   parallel. Each uploads its own artifact slice of `results.json` rows (or a
   partial file the merge step concatenates).
2. **`baseline`** (push-to-main only). Needs job-level `contents: write`, its own
   non-ref concurrency group `bench-baseline`, and rebase-retry push. Merges the
   three tier artifacts into one `results.json`, commits `<sha>.json` + updates
   `latest` on `bench-data`.
3. **`compare`** (PR only). Fetches `bench-data` with a plain read (works for
   forks), classifies rows, renders `comparison.md` embedding the baseline SHA
   and stale note, uploads `comparison.md` plus the PR number as an artifact.
   Does not comment.

### `bench-comment.yml`

`on: workflow_run` of Bench, `types: [completed]`. Permissions: `actions: read`,
`pull-requests: write`.

Gate on successful download and validation of the compare artifact (see failure
rules below). Download by `run-id` into `runner.temp`. Treat the artifact as
untrusted input: PR number must be an integer, and the PR's `head.sha` must
match `workflow_run.head_sha` (defeats PR-number spoofing). Upsert one sticky
comment via a `<!-- bench-comment -->` marker with `gh api` PATCH/POST, body
passed as a file. No third-party comment action.

Fork and same-repo PRs take the same path. Do not use `pull_request_target` for
benches: that would build and execute PR code in a privileged context.
`workflow_run` runs the default-branch workflow file on the default branch and
never checks out PR code.

Bootstrap caveat: `bench-comment.yml` only triggers once its file exists on
`main`. The PR that introduces it cannot exercise the comment half end to end.

### Sticky comment layout

- One sticky comment, upserted in place.
- Per-tier summary counts (noise / changed / notable / unclassified).
- Row tables only for changed, notable, and unclassified rows. Tiers that are
  all noise still show summary counts and omit the table.
- Delta columns: benchmark · baseline · current · Δ% · class · direction
  (`improved` / `regressed`; blank when unclassified).

### Failures, timeouts, cancels

- Bench failure or timeout: the comment workflow still runs and upserts a sticky
  banner (with a link to the run) above the last successful comparison. It does
  not clear that comparison.
- Cancelled runs, including concurrency cancellation of a superseded PR run,
  leave the sticky comment untouched.
- Benchmark outcomes never gate merges.

## Local commands

- `just bench` covers all wall-clock suites: the five existing Criterion micros
  (local wall-clock), both socket sweeps (including `tcp/readiness_poll`), and
  the new e2e suite. Align local runs with the PR `rust-wall` tier.
- `just bench-ir` runs the Gungraun tier only, so the Valgrind prerequisite stays
  out of the default recipe.

## Decision index

| Topic | Ticket |
| --- | --- |
| Measurement methodology | [Research: measurement methodology for stored-baseline benchmarking](https://github.com/deepso7/minip2p/issues/126) |
| CI mechanics | [Research: PR-comment and baseline-storage mechanics for a homegrown bench workflow](https://github.com/deepso7/minip2p/issues/127) |
| Metric and noise policy | [Decide: benchmark metric and noise policy per tier](https://github.com/deepso7/minip2p/issues/128) |
| Baseline lifecycle | [Decide: baseline storage and update lifecycle](https://github.com/deepso7/minip2p/issues/129) |
| E2E scenarios | [Decide: end-to-end Rust benchmark scenarios](https://github.com/deepso7/minip2p/issues/130) |
| Node FFI tier | [Decide: Node FFI overhead tier design](https://github.com/deepso7/minip2p/issues/131) |
| Triggers and report | [Decide: workflow triggers and PR report format](https://github.com/deepso7/minip2p/issues/132) |
| Portfolio and budget | [Decide: micro-benchmark portfolio and PR runtime budget](https://github.com/deepso7/minip2p/issues/134) |
| Runner pins | [Decide: benchmark runner and environment pinning](https://github.com/deepso7/minip2p/issues/135) |
| Spec home and handoff | [Decide: spec location and implementation handoff](https://github.com/deepso7/minip2p/issues/136) |

## One-PR implementation sequence

Land the whole pipeline in a single PR against this plan. Suggested landing
order inside that PR (or stacked commits):

1. **Gungraun mirrors.** Add the ten `rust-micro` benches as
   `harness = false` targets alongside existing Criterion suites. Keep setup out
   of the measured body. Wire `just bench-ir`.
2. **Endpoint e2e Criterion suite.** TCP and QUIC rows for setup, ping, 64 B
   echo (+ 4×4 crossed), and 1 MiB transfer under the public `Endpoint` API.
   Extend `just bench` to include `tcp/readiness_poll` and the new e2e suite.
3. **`node-ffi` Vitest Bench suite.** Three rows under `bindings/ts/node`
   (SDK drain flood, raw `drainEvents`, `connectedPeers` sync) on TCP loopback.
4. **Normalize + compare.** Shared `results.json` writer/merger, classification
   against bands, Ir incompatibility detection from git pins + `Cargo.lock`
   hash, `comparison.md` renderer.
5. **`bench.yml`.** Three parallel tier jobs, main-only `baseline` job writing
   `bench-data` (`<sha>.json` + `latest`), PR-only `compare` artifact upload.
   Pins as locked above. Create empty `bench-data` branch (or first main push
   after merge creates it).
6. **`bench-comment.yml`.** `workflow_run` sticky upsert with artifact
   validation, failure/timeout banner, cancel-no-op. Merge this file to `main`
   before expecting comment tests from follow-up PRs.
7. **Docs touch.** Point `justfile` comments / relevant READMEs at this plan and
   the local `just bench` / `just bench-ir` split. No ADR and no Blume user-docs
   page for this effort.

### Completion gate

On the implementation PR:

- `just fmt`, `just test`, `just clippy`, and binding checks that already cover
  Node.
- Manual dry-run notes: Gungraun smoke on linux-x64, Criterion e2e smoke, Vitest
  Bench smoke, and (after merge of the workflow files) one follow-up PR that
  proves the sticky comment path.

This map does not open GitHub implementation issues. Open those from this plan
later if the work needs splitting.

## Completion

This specification is complete when no behavior above is left to inference for
an implementer, every deliberate exclusion is listed, and the one-PR sequence
covers workflows, baseline branch, all three tiers, compare/report, and `just`
targets.
