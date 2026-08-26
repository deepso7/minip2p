---
name: pr-review
description: >-
  Orchestrated high-depth PR review for minip2p: planner + parallel micro-agents
  (State/Parse/Security/Flow/Verify/Quality), then merge with confidence gating.
  Small diffs stay single-pass. Use for /pr-review, /pr-review ultra, or
  orchestrated multi-agent PR review.
disable-model-invocation: true
---

# PR review (orchestrated)

## Goal

Beat single-pass review on recall via **planner → specialized micro-agents → merge**. This skill is the orchestration layer only. Small diffs skip the fan-out (see downgrade).

Host-portable: any agent that can spawn parallel sub-agents can run it — no host-specific Task/Bugbot wiring. Domain hunts and tools stay **minip2p-tuned** (`cargo`/`just`/`no_std`/fuzz, AGENTS.md, Endpoint/Swarm layering).

## Ownership (do not drift)

| File | Owns |
| --- | --- |
| This `SKILL.md` | Diff source, output format, specialist selection, fan-out, merge, modes, small-diff downgrade |
| `reference.md` | Shared constraints (severity scale, confidence gate, line-number rule, tool rules, finding schema) + specialist charters |

## Severity

The P0–P3 scale and the confidence gate are defined once, in `reference.md`'s shared constraints. Read them before planning; the output and merge below use those definitions.

## Output

1. `**N issues found** across X files` (or no issues)
2. Table: Severity | Location (`file:line`) | Finding
3. Each finding: `P{N}: <what breaks + who is hurt>. <fix direction>.`
4. **Copy block** — after the table, one fenced `text` block the user can paste into an agent:

```text
Check if these issues are valid — if so, understand the root cause of each and fix them. If appropriate, use sub-agents to investigate and fix each issue separately.

<file name="path/to/file.rs">
<violation number="1" location="path/to/file.rs:LINE">
P{N}: …finding text…
</violation>
</file>
```

Group violations by file. Keep the whole copy block in one fence so it copies in one shot. If nothing survives, say `**No issues found** across X files` and emit **no** copy block. Do **not** add undeclared sections.

## Diff source

- Default: `git diff origin/main...HEAD` (+ dirty tree if present)
- **Untracked files never appear in any `git diff`** — run `git status --porcelain`, and treat untracked non-ignored files as fully added. Skipping this silently drops whole new modules from the review
- Do **not** read GitHub bot/human review comments unless asked to compare

**Arg grammar** (optional tokens after `/pr-review`):

```text
/pr-review [ultra] [worktree <path>] [base <sha|ref>]
```

- `worktree <path>` — review that checkout instead of the current workspace
- `base <sha|ref>` — diff `base...HEAD` (default `origin/main`)
- Flags and key/value tokens may appear in either order; unknown tokens → ask once, do not guess

## Tools (keep few)

Orchestrator: read files, search, `git show`/`git diff`, focused tests (`cargo test -p …`). No sprawling toolkits.

Specialists are **read-only** — no `cargo`/`just`. Verify alone may run one focused `cargo test -p <crate>`; parallel cargo invocations contend on the same `target/` lock and stall. Specialist tool rules live in `reference.md`'s shared constraints.

## Pipeline

### 1. Planner (you)

From the diff only:

1. List changed paths and a one-line blast radius (what can break) — map paths to crates/transports (`crates/`, `transports/`, `fuzz/`, `bindings/`)
2. Note symbols/APIs whose **callers outside the diff** must be checked (out-of-diff)
3. Decide **small-diff downgrade** vs fan-out (below)
4. If fan-out: pick specialists; emit a short plan; launch them **in one parallel wave** (same turn — never serialize waves)
5. If downgrade: say you downgraded, then review yourself (no specialists)

**Small-diff downgrade** (normal mode only; `ultra` always fans out)

Treat as small when **all** of:

- Net diff size ≲ **200 lines** of non-import/non-fmt code (added+removed; skip pure `use`/import churn and rustfmt-only whitespace)
- Touches **≤ 2 crates/packages** (a crate root + its `tests/` still counts as one)
- No new protocol wire surface, no CI/`just`/`no_std`/fuzz matrix edits, no security-sensitive authz/key paths

Then: **do not spawn specialists**. Apply `reference.md`'s severity bar + the charter hunt lenses yourself in one pass. Still honor Output / confidence ≥ 0.8 / untracked files. Say explicitly that you downgraded.

Borderline or risky small diffs (lifecycle state machines, parsers, relay/NAT, FFI locks): fan out anyway, or the user can pass `ultra`.

**Specialist selection** (when not downgraded)

- Default on nontrivial PRs: State, Parse, Security, Flow, Verify — drop a charter specialist only if its charter has zero touch surface
- **Quality**: run when the diff touches tests (`**/tests/**`, `#[cfg(test)]` modules, or new/changed `#[test]`) **or** adds/changes internal helpers, wrapper types, or doc/README/AGENTS blocks that assert contracts; otherwise skip
- Never drop Verify solely because Quality is running — they own different failure modes

### 2. Micro-agents (parallel)

Use the host’s parallel sub-agent mechanism. Specialists inherit the parent model unless the user names one.

Each specialist gets: worktree path, exact `base...HEAD`, changed-file list (including untracked/added files), planner blast-radius notes, the mode (normal/ultra), and **only its charter** (see `reference.md`).

Paste `reference.md`’s shared constraints (severity bar, confidence gate, line-number rule, finding schema) into every specialist prompt verbatim, or they will invent their own P0–P3 scale.

Every **charter** finding **must** be structured:

```json
{"reasoning":"…","severity":"P0|P1|P2|P3","confidence":0.0-1.0,"path":"file","line":123,"finding":"what breaks + who is hurt. fix hint."}
```

For Quality, “who is hurt” may be _reviewers/maintainers misled by false confidence_ or _future regressions the test cannot catch_.

Charters:

| Agent | Owns |
| --- | --- |
| **State** | Invariants, lifecycle, close/reset/retry, event ordering, post-close behavior |
| **Parse** | Lengths, encodings, fixtures/goldens, validate-before-side-effects |
| **Security** | Untrusted peers/input, authz, spoofing, expensive work before reject |
| **Flow** | Spins, starvation, deadlines, unbounded/superlinear buffers, error-path leaks |
| **Verify** | _Missing_ tests for new failure modes; CI/just/`no_std`/fuzz gaps; README/doc lies; AGENTS.md policy |
| **Quality** | _Hollow_ proof and LLM-shaped test/docs padding; internal no-policy wrappers — not intentional public/layer boundaries |

### 3. Merge (you)

After a downgrade, skip specialist merge — publish from your single pass (still confirm every P0/P1 against `file:line`).

After fan-out:

1. Collect all findings that pass the confidence gate (`reference.md` shared constraints)
2. Dedupe near-duplicates (same root cause → keep highest severity / clearest). Prefer Verify for “test missing”; prefer Quality for “test present but hollow/duplicate”; a test that **cannot pass as written** is a P0 defect, not a Quality finding
3. Drop nits / pure style even if a specialist emitted them — including Quality naming taste or “sounds like an LLM” without an artifact. **Quality floor:** a finding that names a specific `file:line` artifact and states what bug or regression it would fail to catch is **not** a nit — keep it
4. Apply the `reference.md` allowlist:
   - **Test-shaped** entries (white-box event/agent-queue injection, timeout-driven integration outcomes, feature-matrix twins): drop the finding **unless** the new test is strictly weaker than in-file peers covering the same claim
   - **Boundary / one-line public API** entries: drop unconditionally — those are intentional layer boundaries, not “weaker peers”
5. **Confirm before publishing.** Specialist confidence is self-reported and uncalibrated — for every surviving P0/P1, open the cited `file:line` yourself and re-derive the failure story from the code, not from the agent summary. Drop what you cannot reproduce; fix the line number if it drifted. Do the same for any P2 two agents describe differently
6. Optional: run focused `cargo test -p <touched>` once; fold hard evidence in
7. Output **exactly** per the Output section above. Include Quality findings when they survive. Do not fix code unless asked

## Modes

- **normal** (default): small-diff downgrade when the bar matches; otherwise defect specialists + Quality when its selection rule matches. Specialists go out-of-diff only to confirm or refute a suspected in-diff finding
- **ultra**: always fan out (no small-diff downgrade), one wave — after finishing its in-diff hunks, each specialist additionally sweeps every symbol on the planner's out-of-diff list against **its own** charter, suspicion or not. No separate caller-sweep agent; use when user says ultra or PR is large/risky

## Examples

```text
/pr-review
/pr-review ultra
/pr-review worktree /path/to/wt base <sha>
/pr-review ultra base origin/main
```
