# PR benches against the merge-base, measured in the same run

Supersedes the comparison model of [the PR benchmarking plan](../plans/pr-benchmarking-pipeline.md), which compared a PR with a stored baseline and rejected same-job merge-base reruns. Runs on ADR 0025's instance kept that model, comparing the head with the newest release's stored result, and their PR comments were close to random:

- The baseline was measured days or weeks earlier, maybe on another host, so everything merged to `main` since the release was attributed to the PR.
- Wall clock is noisy on the shared-tenancy instance: code-identical runs 20 minutes apart moved rows by 40–128%, well past the bands.
- `Ir` rows went unclassified whenever the IR benches' slice of `Cargo.lock` or `bench/pins.json` differed from the release's (28 of 47 PR comments), and that also switched off the rule that ignored a Criterion row whose `Ir` twin was flat, so noisy wall rows were flagged.
- The `compare` job ran the PR head's own `bench_results.py`, so a PR could change its own bands.

`Ir` (Callgrind instruction counts) is deterministic: the same build gave the same count on all 49 rows.

## Decision

- **A PR run measures its head and its merge-base with the base branch in the same job, on the same instance.** Each side is built into its own image from its own tree and validated by its own harness and registries inside its container. `Ir` runs once per side. The wall, custom and Node tiers alternate which side goes first, so drift on the host hits both alike. A dispatch with `base` set does the same for `ref` (the default branch when empty).
- **Only deterministic metrics are classified:** `Ir`, and the per-message allocation counts of isolated agent operations (`allocs_per_msg`, `bytes_allocated_per_msg` from `router_allocs`, which asserts two runs agree), with 1%/2% changed/notable bands. Smaller changes go in a collapsed "negligible" section.
- **Every other row is informational:** wall clock, throughput, RTT, latency, FFI, datagram and allocation-over-transport rows show base, head and Δ% in a collapsed table, with no class or direction.
- **Rows match by (tier, name, metric).** A row only one side has shows as new or removed. Differing `Ir` pins no longer unclassify rows; the comment adds a note.
- **The comparator runs from the trusted base checkout** and reads head's rows without requiring its metrics or tiers to be registered.
- **The Criterion twins of the `Ir` benches are gone** (`multiaddr`, `data_path`, `peer_book`, `publish`, `router`, `relay_server_event`). Their `Ir` rows answer the same question deterministically, and once wall clock is informational the twins add only noise. `quic idle_poll`, `tcp readiness_poll` and `endpoint_e2e` stay.
- **Releases still record `<sha>.json` on `bench-data`** as trend history. PR runs no longer read it.

## Rejected alternatives

- **Stored baselines with wider wall bands, or more samples.** Neither fixes attribution of `main`'s changes, and bands wide enough for this host flag nothing.
- **Flagging wall rows from repeated A/B rounds.** It doubles or triples the run for a signal that still moves tens of percent; a `rounds` knob can come later if wall rows need it.
- **A dedicated or bare-metal host.** It costs much more than the on-demand runner of ADR 0025.

## Consequences

- A PR run builds two images and measures twice: about 30 minutes of measuring instead of about 14, inside the 90-minute job limit. Both images exist at once, so a run needs more free disk.
- Interleaving is per tier, not per bench target: the base side runs its own `scripts/run-benches.sh`, which only knows whole passes.
- Wall-clock regressions are no longer called out. They are still visible in the informational table and, over releases, on `bench-data`.

## Addendum: quick wall-clock benches on A/B runs

Once wall-clock rows stopped gating anything, measuring them in full on both sides cost most of a PR run: each side's `wall` pass took 7–8 minutes on the instance. `scripts/run-bench-container.sh` now sets `MINIP2P_BENCH_QUICK=1` for A/B runs only and passes it into both containers; the benches read it themselves, since the base side runs its own `scripts/run-benches.sh`, which would not know a new flag. Criterion runs 10 samples over 1 s without plots, `endpoint_idle` measures a 4 s window, `endpoint_rtt` times one transfer per case and `endpoint_ping_load` takes 100 samples; every row stays a rate, median or percentile. Locally this cut a `wall` pass from about 499 s to about 209 s, so a PR run should spend about 9 minutes less measuring. Release and baseline runs measure in full. A base tree from before the knob ignores it, so the first PR after it compares a full base with a quick head, which is acceptable for informational rows.
