# Measurement methodology for stored-baseline benchmarking

Research for [Research: measurement methodology for stored-baseline benchmarking](https://github.com/deepso7/minip2p/issues/126), part of the PR benchmarking pipeline map ([#125](https://github.com/deepso7/minip2p/issues/125)). Claims are pinned to:

- Gungraun (the renamed iai-callgrind, see below) [repo](https://github.com/gungraun/gungraun) and [guide](https://gungraun.github.io/gungraun/latest/html/) at release 0.19.4;
- valgrind manuals for [callgrind](https://valgrind.org/docs/manual/cl-manual.html), [cachegrind](https://valgrind.org/docs/manual/cg-manual.html), and the [core](https://valgrind.org/docs/manual/manual-core.html);
- the [criterion book](https://bheisler.github.io/criterion.rs/book/) and [docs.rs](https://docs.rs/criterion/latest/criterion/struct.Criterion.html);
- [GitHub-hosted runner docs](https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners) and the [runner-images Ubuntu 24.04 software list](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md);
- [rustc-perf](https://github.com/rust-lang/rustc-perf) (collector README, comparison-analysis, deployment docs), [github-action-benchmark](https://github.com/benchmark-action/github-action-benchmark), and [rustls ci-bench](https://github.com/rustls/rustls/blob/main/ci-bench/README.md);
- [vitest benchmark config](https://vitest.dev/config/benchmark), [tinybench](https://github.com/tinylibs/tinybench), [node:perf_hooks](https://nodejs.org/api/perf_hooks.html);
- minip2p at [`219eaa5`](https://github.com/deepso7/minip2p/tree/219eaa54ceb31d13d55873ad46c8c4dd97f1eeb6) (the 7 criterion suites run by `just bench`).

> **Naming note:** iai-callgrind has been renamed to **Gungraun** (org `gungraun/gungraun`; the crate ships a "Migrating from Iai-Callgrind to Gungraun" guide, and the old `iai-callgrind.github.io` book URLs now 404). Mechanics are unchanged, but the pipeline should target `gungraun`/`gungraun-runner` directly. ([README](https://github.com/gungraun/gungraun), [guide TOC](https://raw.githubusercontent.com/gungraun/gungraun/main/docs/src/SUMMARY.md))

## Decision (recommendation)

Split the pipeline by determinism, not by crate:

1. **Rust micro-bench tier (the 5 sans-I/O suites)** — `multiaddr`, `yamux/data_path`, `discovery/peer_book`, `pubsub/fanout`, `relay-server/relay_server_event`: add Gungraun bench targets and compare **callgrind instruction counts (Ir)** against a stored JSON baseline from main. Instruction counts are the only metric that transfers across GitHub-hosted VMs; these five benches are pure in-memory state machines with fixed seeds, exactly the shape callgrind measures deterministically. Existing criterion targets stay for local wall-clock work; the two coexist as separate `[[bench]]` targets.
2. **Rust socket/end-to-end tier** — `quic/idle_poll`, `tcp/readiness_poll`, and future end-to-end benches: **instruction counting cannot cover these as written** (details in §1.4). Keep criterion wall-clock, store baselines as artifacts, and report deltas informationally with a wide flag threshold (≥ 30%, sized above the documented ±10–20% hosted-runner amplitude). Reworking the poll benches against the sans-I/O seams (`TcpProvider`, in-memory clock/entropy) would move them into tier 1 later, but that is bench surgery, not pipeline config.
3. **Node FFI tier**: vitest bench (tinybench under the hood) with its built-in `--outputJson` / `--compare` stored-baseline flow. **No machine-independent metric exists for Node** — perf_hooks exposes no hardware counters, and JIT code generation makes instruction-count determinism unverifiable. Same wide informational thresholds as tier 2.

### Recommendation matrix

| Tier | Metric | Harness | Expected noise floor | Suggested flag threshold |
| --- | --- | --- | --- | --- |
| Rust micro (5 sans-I/O suites) | Instructions (Ir); Estimated Cycles as secondary color only | Gungraun `[[bench]] harness = false` targets beside criterion; `gungraun-runner` + valgrind via `gungraun/setup-gungraun@v1`; `--save-summary=json` artifacts as the stored baseline | Near-zero: "highly reproducible; for some programs perfectly reproducible" ([cachegrind manual](https://valgrind.org/docs/manual/cg-manual.html)); "repeatable to 7 or more significant digits" ([Gungraun](https://gungraun.github.io/gungraun/latest/html/comparison/criterion.html)); small perturbations from code layout/ASLR remain | 1–2% on Ir |
| Rust socket / end-to-end (`idle_poll`, `readiness_poll`, future E2E) | Wall-clock (mean ns/iter) | criterion as-is; baseline via `--save-baseline` + artifact storage (or exported estimates; `critcmp` reads undocumented internals and "can break at any point" — [README](https://github.com/BurntSushi/critcmp)) | ±10–20% on hosted runners, worse with I/O ([github-action-benchmark README](https://github.com/benchmark-action/github-action-benchmark)) | ≥ 30%, informational only |
| Node FFI (new; napi-rs binding) | Wall-clock (tinybench latency mean/p50) | vitest bench with `--outputJson` on main, `--compare` on PRs ([vitest config](https://vitest.dev/config/benchmark)) | Same ±10–20% band; no deterministic option exists | ≥ 30%, informational only |

## 1. Instruction counting (Gungraun / callgrind)

### 1.1 What it measures and how machine-independent it is

- Callgrind records instruction counts and call relationships; cache simulation (`--cache-sim=yes`) and branch prediction are optional simulations layered on top ([callgrind manual](https://valgrind.org/docs/manual/cl-manual.html)). Gungraun reports Instructions, L1/LL/RAM hits, total read+write, and Estimated Cycles, the last being derived from the cache simulation, not measured ([output format](https://gungraun.github.io/gungraun/latest/html/benchmarks/library_benchmarks/configuration/output_format.html)). The README cautions that estimated cycles "merely correlates to wall-clock times but is not a replacement" ([README](https://github.com/gungraun/gungraun)).
- Valgrind's own docs: wall-time has "high variability" while "instruction counts are highly reproducible; for some programs they are perfectly reproducible" — but results are sensitive to binary/shared-library size changes and ASLR, so "don't expect perfectly repeatable results if your program changes at all" ([cachegrind manual](https://valgrind.org/docs/manual/cg-manual.html)). Cross-machine comparability assumes the same compiled binary; a compiler bump changes the instruction stream itself, so **the stored baseline must be regenerated whenever the toolchain or lockfile changes**.
- rustc-perf concurs: instruction counts still have "some non-determinism and natural variation," and cachegrind-style results are "almost deterministic" ([collector README](https://github.com/rust-lang/rustc-perf/blob/master/collector/README.md)). Gungraun claims measurements are "accurate … even in virtualized CI environments" and comparable between systems ([comparison](https://gungraun.github.io/gungraun/latest/html/comparison/criterion.html)).

### 1.2 Setup cost and CI overhead

- Valgrind is **not preinstalled** on `ubuntu-24.04` runners ([runner-images list](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md)); install via apt or the first-party `gungraun/setup-gungraun@v1` action, which also installs a `gungraun-runner` version-matched to the library crate — a hard requirement, mismatches abort the run ([installation](https://gungraun.github.io/gungraun/latest/html/installation/gungraun.html), [CI page](https://gungraun.github.io/gungraun/latest/html/installation/ci.html)). Valgrind ≥ 3.20 required; no Windows.
- Slowdown: no single documented callgrind factor exists; valgrind documents a 4x floor with no instrumentation and roughly 2x more for cache/branch simulation ([core manual](https://valgrind.org/docs/manual/manual-core.html), [callgrind manual](https://valgrind.org/docs/manual/cl-manual.html)). Each bench runs **once** instead of criterion's ~100-sample loop, so total CI time is usually competitive ([comparison](https://gungraun.github.io/gungraun/latest/html/comparison/criterion.html)).

### 1.3 Baselines, JSON output, and coexistence with criterion

- Criterion-compatible baseline CLI: `--save-baseline`, `--baseline`, `--load-baseline` ([baselines](https://gungraun.github.io/gungraun/latest/html/cli_and_env/baselines.html)); `--output-format=json` and `--save-summary=json` write versioned per-bench `summary.json` files under `target/gungraun` — the natural stored-baseline format for a PR-comment pipeline ([machine-readable output](https://gungraun.github.io/gungraun/latest/html/cli_and_env/output/machine_readable.html)).
- Opt-in regression limits (`--callgrind-limits='ir=5%'`, exit code 3 on breach) exist for a future gating phase; for the informational-only pipeline, parse the JSON instead ([regressions](https://gungraun.github.io/gungraun/latest/html/regressions.html)).
- Coexistence: each Gungraun bench is its own `[[bench]]` target with `harness = false`; the Gungraun docs themselves recommend keeping wall-clock benches (criterion) alongside for local use — it **supplements** criterion, it does not replace it ([quickstart](https://gungraun.github.io/gungraun/latest/html/benchmarks/library_benchmarks/quickstart.html), [comparison](https://gungraun.github.io/gungraun/latest/html/comparison/criterion.html)).

### 1.4 Hard limits — and whether the two socket benches fit

Valgrind runs real programs making real syscalls (rustls's ci-bench runs a client and server as separate child processes doing piped I/O under callgrind in CI — [rustls ci-bench README](https://github.com/rustls/rustls/blob/main/ci-bench/README.md)), but it serializes threads onto one CPU and warps scheduling ([core manual §2.8](https://valgrind.org/docs/manual/manual-core.html)), and it counts only user-space instructions — kernel work and blocked time are invisible ([cachegrind manual](https://valgrind.org/docs/manual/cg-manual.html)).

Against this repo's two socket benches (both single-process, loopback):

- **`transports/tcp/benches/readiness_poll.rs`**: the measured routine writes one byte per peer stream and then busy-loops `provider.poll(...)` until all bytes arrive. The number of poll iterations — and therefore the instruction count — depends on when the kernel makes the sockets readable, which is timing- and scheduler-dependent. Under valgrind's serialized, rescheduled execution this is worse, not better. **Ir for this bench is nondeterministic by construction.**
- **`transports/quic/benches/idle_poll.rs`**: the measured iteration (a single `poll()` over idle connections) is nearly deterministic, but setup performs up to 512 real QUIC handshakes under a hard 20-second wall-clock `SETUP_TIMEOUT`. At callgrind's ≥ 4–8x slowdown, setup will trip its own timeout before measurement starts.
- Gungraun's default toggle covers only the benchmark function; getting deterministic coverage of I/O-driven code requires client requests or fragile `--toggle-collect` setups ([threads & subprocesses](https://gungraun.github.io/gungraun/latest/html/benchmarks/library_benchmarks/threads_and_subprocesses.html)).

Conclusion: **the two poll benches stay wall-clock unless reworked.** The rustls precedent shows socket-shaped code *can* be instruction-counted when the harness is built for it (readiness driven deterministically, no wall-clock timeouts); minip2p's sans-I/O seams (`TcpProvider`, `Clock`) make such a rework feasible, but it is out of scope for the pipeline spec.

## 2. Wall-clock on GitHub-hosted runners

- Standard public-repo runners are 4-vCPU Azure VMs; no CPU pinning, no CPU-model or performance-stability guarantees ([GitHub docs](https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners)).
- The only first-party variance figure found: github-action-benchmark documents "the amplitude of the benchmarks is about +- 10~20%" on hosted runners, larger with network/file I/O, and its default alert threshold is 200% precisely to sit above that ([README](https://github.com/benchmark-action/github-action-benchmark)).
- For contrast, rustc-perf gets stable timing only on dedicated bare metal: HyperThreading and Turbo Boost off, `performance` governor, ASLR and swap disabled ([deployment.md](https://github.com/rust-lang/rustc-perf/blob/master/docs/deployment.md)). rustls similarly states a laptop is "too noisy" and ~1% wall-time resolution needs a tuned bare-metal server ([ci-bench README](https://github.com/rustls/rustls/blob/main/ci-bench/README.md)).
- Criterion's defaults (noise_threshold 1%, significance_level 5%, bootstrapped t-test — [analysis](https://bheisler.github.io/criterion.rs/book/analysis.html), [docs.rs](https://docs.rs/criterion/latest/criterion/struct.Criterion.html)) are tuned for quiet machines, an order of magnitude below hosted-runner noise. Its `--save-baseline`/`--baseline`/`--load-baseline` flags support the stored-baseline flow directly ([command-line options](https://bheisler.github.io/criterion.rs/book/user_guide/command_line_options.html)).
- Credible cross-VM posture: deltas under ~20–30% are indistinguishable from noise; flag at ≥ 30% and never gate. Longer measurement windows and higher sample counts reduce within-run variance but cannot remove between-VM variance (different hardware generations).

## 3. Prior art

- **rustc-perf**: instructions are the default metric "because it has the least variation"; benchmarks with high instruction variance get flagged with a "?" ([collector README](https://github.com/rust-lang/rustc-perf/blob/master/collector/README.md)). Significance is historical, not fixed: a delta is significant when it exceeds Q3 + 3×IQR of that benchmark's historical deltas ([comparison-analysis.md](https://github.com/rust-lang/rustc-perf/blob/master/docs/comparison-analysis.md)). Once the pipeline accumulates history, this is the model to grow toward.
- **github-action-benchmark**: stores history as JSON on gh-pages (or an external JSON path + cache); ratio-based alerts; its Rust ingestion is the nightly libtest stdout format, **not** criterion — criterion/Gungraun numbers would go through its `customSmallerIsBetter` JSON format ([README](https://github.com/benchmark-action/github-action-benchmark), [rust example](https://github.com/benchmark-action/github-action-benchmark/blob/master/examples/rust/README.md)). Given the homegrown constraint, its main value is validating the "JSON on a branch + threshold + PR comment" shape.
- **rustls ci-bench**: the closest match to this repo — callgrind instruction counting with `--collect-atstart=no` plus client requests, multi-process piped I/O under callgrind in CI, a `compare` subcommand emitting GitHub-flavored markdown, and significance judged "based on historic data"; wall-time kept as a separate non-CI mode ([README](https://github.com/rustls/rustls/blob/main/ci-bench/README.md)).

## 4. Node FFI tier

- **vitest bench** (experimental) runs benches via tinybench and has first-class stored-baseline support: `--outputJson main.json` on main, `--compare main.json` on the PR ([vitest config](https://vitest.dev/config/benchmark), [features](https://vitest.dev/guide/features.html)).
- **tinybench** reports latency/throughput mean, p50, MAD, relative margin of error, and sample counts, timed via `performance.now()`/`process.hrtime` — all wall-clock ([README](https://github.com/tinylibs/tinybench)).
- **node:perf_hooks** offers monotonic timing, `timerify`, event-loop-delay histograms, and even histogram comparison stats (Welch/KS/Mann-Whitney), but **no hardware counters** ([Node docs](https://nodejs.org/api/perf_hooks.html)).
- **No machine-independent option exists.** Running node under callgrind is technically possible, but cachegrind's documented sensitivity to code layout applies to JIT-generated code, and V8's tiered compilation is runtime-feedback-driven; no primary source quantifying V8 instruction-count determinism under callgrind was found, so treat it as unusable rather than merely unproven. Linux perf counters would additionally need `perf_event_paranoid` relaxation ([rustc-perf collector README](https://github.com/rust-lang/rustc-perf/blob/master/collector/README.md)).

## Unverified points

- The Estimated Cycles weighting formula (commonly quoted as L1 + 5×LL + 35×RAM) was not confirmed from a primary source.
- No single documented "callgrind = Nx slowdown" figure exists; the 4x/2x components above are the closest first-party numbers.
- No primary-source quantification of V8 JIT non-determinism under callgrind.
