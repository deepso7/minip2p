---
name: pr-review
description: >-
  Orchestrated high-depth PR review: planner + parallel micro-agents
  (State/Parse/Security/Flow/Verify/Quality), then merge with confidence
  gating. Use for /pr-review, /pr-review ultra, or orchestrated
  multi-agent PR review (not the single-agent rule alone).
disable-model-invocation: true
---

# PR review (orchestrated)

## Goal

Beat single-pass review on recall via **planner → specialized micro-agents → merge**. This skill is the orchestration layer only.

## Ownership (do not drift)

| File | Owns |
| --- | --- |
| `.cursor/rules/pr-review.mdc` | Severity bar + **output format** (summary, table, per-finding lines, copy block). Do not invent extra output sections here. |
| `.cursor/skills/pr-review/reference.md` | Specialist charters (hunt / do-not-hunt / allowlists) |
| This `SKILL.md` | Diff source, specialist selection, fan-out, merge, modes |

Quality policy lives in `reference.md`. The `.mdc` stays generic for standalone / Bugbot use — do not duplicate Quality bullets into the rule.

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

Orchestrator: read files, `rg`/search, `git show`/`git diff`, focused tests (`cargo test -p …`). No sprawling toolkits.

Specialists are **read-only** — no `cargo`/`just`. Verify alone may run one focused `cargo test -p <crate>`; parallel cargo invocations contend on the same `target/` lock and stall.

## Pipeline

### 1. Planner (you)

From the diff only:

1. List changed paths and a one-line blast radius (what can break)
2. Note symbols/APIs whose **callers outside the diff** must be checked (out-of-diff)
3. Pick which specialists to run (see selection rules below)
4. Emit a short plan; then launch specialists **in parallel** (separate subagents / Task calls)

**Specialist selection**

- Default on nontrivial PRs: State, Parse, Security, Flow, Verify — drop one only if its charter has zero touch surface
- **Quality**: run when the diff touches tests (`**/tests/**`, `#[cfg(test)]` modules, or new/changed `#[test]`) **or** adds/changes internal helpers, wrapper types, or doc/README blocks that assert contracts; otherwise skip
- Never drop Verify solely because Quality is running — they own different failure modes

### 2. Micro-agents (parallel)

Specialists inherit the parent model — omit `model` on Task unless the user names one.

Each specialist gets: worktree path, exact `base...HEAD`, changed-file list (including untracked/added files), planner blast-radius notes, and **only its charter** (see `reference.md`).

Specialists receive only this skill’s pasted charter — they do not auto-load `pr-review.mdc`. Paste `reference.md`’s shared constraints (severity bar, confidence gate, line-number rule) into every specialist prompt, or they will invent their own P0–P3 scale.

Every finding **must** be structured:

```json
{"reasoning":"…","severity":"P0|P1|P2|P3","confidence":0.0-1.0,"path":"file","line":123,"finding":"what breaks + who is hurt. fix hint."}
```

For Quality, “who is hurt” may be *reviewers/maintainers misled by false confidence* or *future regressions the test cannot catch*.

Charters:

| Agent | Owns |
| --- | --- |
| **State** | Invariants, lifecycle, close/reset/retry, event ordering, post-close behavior |
| **Parse** | Lengths, encodings, fixtures/goldens, validate-before-side-effects |
| **Security** | Untrusted peers/input, authz, spoofing, expensive work before reject |
| **Flow** | Spins, starvation, deadlines, unbounded/superlinear buffers, error-path leaks |
| **Verify** | *Missing* tests for new failure modes; CI/just/`no_std`/fuzz gaps; README/doc lies; AGENTS.md policy |
| **Quality** | *Hollow* proof and LLM-shaped test/docs padding; internal no-policy wrappers — not intentional public/layer facades |

Specialists must: stay in charter; read every in-diff hunk relevant to that charter before following out-of-diff callers; not stop after one hit; confidence &lt; 0.8 → omit. Charters partition **failure modes, not files** — two specialists reading the same file is expected, and the merge dedupes.

### 3. Merge (you)

1. Collect all findings with confidence ≥ 0.8
2. Dedupe near-duplicates (same root cause → keep highest severity / clearest). Prefer Verify for “test missing”; prefer Quality for “test present but hollow/duplicate”; a test that **cannot pass as written** is a P0 defect, not a Quality finding
3. Drop nits / pure style even if a specialist emitted them — including Quality naming taste or “sounds like an LLM” without an artifact. **Quality floor:** a finding that names a specific `file:line` artifact and states what bug or regression it would fail to catch is **not** a nit — keep it
4. Apply the `reference.md` allowlist:
   - **Test-shaped** entries (white-box queue injection, timeout-driven integration outcomes, feature-matrix twins): drop the finding **unless** the new test is strictly weaker than in-file peers covering the same claim
   - **Facade / one-line public API** entries: drop unconditionally — those are intentional layer boundaries, not “weaker peers”
5. **Confirm before publishing.** Specialist confidence is self-reported and uncalibrated — for every surviving P0/P1, open the cited `file:line` yourself and re-derive the failure story from the code, not from the specialist's summary. Drop what you cannot reproduce; fix the line number if it drifted. Do the same for any P2 two specialists describe differently
6. Optional: run focused `cargo test -p <touched>` once; fold hard evidence in
7. Output **exactly** per `.cursor/rules/pr-review.mdc` Output section (summary line, table, per-finding evidence, copy block). Include Quality findings in the table and copy block when they survive. If nothing survives, say `**No issues found** across X files` and emit **no** copy block. Do **not** add undeclared sections (no separate severity-count block)
8. Do not fix code unless asked

## Modes

- **normal** (default): defect specialists + Quality when its selection rule matches; thorough but time-bounded
- **ultra**: same agents, one wave — each specialist extends **its own** charter with an out-of-diff pass over the planner's symbol list *after* finishing its in-diff hunks. No second launch, no generic caller-sweep agent; use when user says ultra or PR is large/risky

## Examples

```text
/pr-review
/pr-review ultra
/pr-review worktree /path/to/wt base <sha>
/pr-review ultra base origin/main
```
