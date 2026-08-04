---
name: pr-review
description: >-
  Orchestrated high-depth PR review: planner + parallel micro-agents
  (State/Parse/Security/Flow/Verify/Quality) + Bugbot, then merge with
  confidence gating. Use for /pr-review, /pr-review ultra, or orchestrated
  multi-agent PR review (not the single-agent rule alone).
disable-model-invocation: true
---

# PR review (orchestrated)

## Goal

Beat single-pass review on recall via **planner → specialized micro-agents + Bugbot → merge**. This skill is the orchestration layer only. Bugbot is a complementary hunter (different heuristics), not a replacement for any charter specialist.

## Ownership (do not drift)

| File | Owns |
| --- | --- |
| `.cursor/rules/pr-review.mdc` | Severity bar + **output format** (summary, table, per-finding lines, copy block). Do not invent extra output sections here. |
| `.cursor/skills/pr-review/reference.md` | Specialist charters (hunt / do-not-hunt / allowlists) |
| This `SKILL.md` | Diff source, specialist selection, Bugbot fan-out, merge, modes |

Quality policy lives in `reference.md`. The `.mdc` stays generic for standalone / Bugbot use — do not duplicate Quality bullets into the rule.

## Diff source

- Default: `git diff origin/main...HEAD` (+ dirty tree if present)
- **Untracked files never appear in any `git diff`** — run `git status --porcelain`, and treat untracked non-ignored files as fully added. Skipping this silently drops whole new modules from the review
- Do **not** read GitHub bot/human review comments unless asked to compare

**Arg grammar** (optional tokens after `/pr-review`):

```text
/pr-review [ultra] [no-bugbot] [worktree <path>] [base <sha|ref>]
```

- `worktree <path>` — review that checkout instead of the current workspace
- `base <sha|ref>` — diff `base...HEAD` (default `origin/main`)
- `no-bugbot` — skip the Bugbot Task (specialists only)
- Flags and key/value tokens may appear in either order; unknown tokens → ask once, do not guess

## Tools (keep few)

Orchestrator: read files, `rg`/search, `git show`/`git diff`, focused tests (`cargo test -p …`). No sprawling toolkits.

Specialists are **read-only** — no `cargo`/`just`. Verify alone may run one focused `cargo test -p <crate>`; parallel cargo invocations contend on the same `target/` lock and stall.

## Pipeline

### 1. Planner (you)

From the diff only:

1. List changed paths and a one-line blast radius (what can break)
2. Note symbols/APIs whose **callers outside the diff** must be checked (out-of-diff)
3. Pick which specialists to run (see selection rules below); include Bugbot unless `no-bugbot` or the diff is empty
4. Emit a short plan; then launch specialists **and Bugbot in one parallel wave** (separate subagents / Task calls in the same message)

**Specialist selection**

- Default on nontrivial PRs: State, Parse, Security, Flow, Verify — drop one only if its charter has zero touch surface
- **Quality**: run when the diff touches tests (`**/tests/**`, `#[cfg(test)]` modules, or new/changed `#[test]`) **or** adds/changes internal helpers, wrapper types, or doc/README blocks that assert contracts; otherwise skip
- **Bugbot**: default on for nontrivial PRs (same bar as defect specialists). Skip only when `no-bugbot`, the diff is empty, or there is nothing to review
- Never drop Verify solely because Quality is running — they own different failure modes
- Never drop charter specialists solely because Bugbot is running — Bugbot overlaps failure modes on purpose; merge dedupes

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
| **Quality** | *Hollow* proof and LLM-shaped test/docs padding; internal no-policy wrappers — not intentional public/layer boundaries |
| **Bugbot** | Complementary general bug hunt (own heuristics). Not a charter replacement — see launch rules below |

Specialists must: stay in charter; read every in-diff hunk relevant to that charter before following out-of-diff callers; not stop after one hit; confidence &lt; 0.8 → omit. Charters partition **failure modes, not files** — two specialists reading the same file is expected, and the merge dedupes.

#### Bugbot launch (same wave)

Launch **exactly one** `bugbot` Task alongside the specialists (unless skipped):

- `description: "Bugbot"`
- `subagent_type: "bugbot"`
- `run_in_background: true` when Multitask Mode applies or other specialists in the wave are backgrounded; otherwise `false` is fine for a solo Bugbot-only wave (should not happen in this skill)
- Do **not** precompute the Bugbot diff — the subagent computes it from the repo path
- Prompt shape (exact):

```text
Full Repository Path: <absolute worktree / repo path>
Diff: branch changes
Base Branch: <include only when /pr-review base <ref> was given and <ref> is not the repo default>
Custom Instructions:
Match pr-review severity: P0 hangs/panics/definitively wrong results or broken tests/fixtures; P1 correctness/security likely to hit users/peers; P2 contract/lifecycle/resource bugs or clear untested holes; P3 maintainability/portability with a real failure mode. Confidence bar: omit anything you would rate below ~0.8. No style/formatting/import nits — every finding needs a concrete failure story (what breaks + who is hurt). Prefer actionable file:line locations.
```

- Default `Diff: branch changes` (committed + staged + unstaged vs merge-base). If the user explicitly asked to review only uncommitted/dirty changes, use `Diff: uncommitted changes` instead and omit `Base Branch`
- If Bugbot fails (bad invocation, empty diff metadata, etc.): retry **once** per the review-bugbot rules (fix prompt shape; last-resort `Diff: natural language` + `Change Description` from the planner’s changed-file list). If it still fails, **continue merge with specialist findings only** — do not invent a final-output section about the failure
- **Untracked-only paths**: Bugbot’s git-based diff may miss them. Specialists still cover files the planner listed as untracked/added; do not expect Bugbot findings there

### 3. Merge (you)

1. Collect all findings with confidence ≥ 0.8. For Bugbot rows with no confidence field, treat as provisional 0.85 so they enter the pool — they still go through confirm (step 5)
2. Normalize Bugbot severities into `P0`–`P3` when labels differ; if unlabeled, default `P2` unless the text clearly implies hang/panic/wrong-results (`P0`) or user-facing correctness/security (`P1`). Map path/line from Bugbot’s Location column into the same `{path,line,finding}` shape
3. Dedupe near-duplicates (same root cause → keep highest severity / clearest). Prefer Verify for “test missing”; prefer Quality for “test present but hollow/duplicate”; a test that **cannot pass as written** is a P0 defect, not a Quality finding. When Bugbot and a charter specialist agree, keep the clearer write-up (usually the specialist’s failure story) at the higher severity
4. Drop nits / pure style even if a specialist or Bugbot emitted them — including Quality naming taste or “sounds like an LLM” without an artifact. **Quality floor:** a finding that names a specific `file:line` artifact and states what bug or regression it would fail to catch is **not** a nit — keep it
5. Apply the `reference.md` allowlist:
   - **Test-shaped** entries (white-box queue injection, timeout-driven integration outcomes, feature-matrix twins): drop the finding **unless** the new test is strictly weaker than in-file peers covering the same claim
   - **One-line public API** entries: drop unconditionally — those are intentional layer boundaries, not “weaker peers”
6. **Confirm before publishing.** Specialist/Bugbot confidence is self-reported and uncalibrated — for every surviving P0/P1, open the cited `file:line` yourself and re-derive the failure story from the code, not from the agent summary. Drop what you cannot reproduce; fix the line number if it drifted. Do the same for any P2 two agents describe differently
7. Optional: run focused `cargo test -p <touched>` once; fold hard evidence in
8. Output **exactly** per `.cursor/rules/pr-review.mdc` Output section (summary line, table, per-finding evidence, copy block). Include Quality and surviving Bugbot findings in the table and copy block. If nothing survives, say `**No issues found** across X files` and emit **no** copy block. Do **not** add undeclared sections (no separate severity-count block, no “Bugbot vs specialists” split)
9. Do not fix code unless asked

## Modes

- **normal** (default): defect specialists + Bugbot + Quality when its selection rule matches; thorough but time-bounded
- **ultra**: same agents (including Bugbot), one wave — each charter specialist extends **its own** charter with an out-of-diff pass over the planner's symbol list *after* finishing its in-diff hunks. Bugbot stays single-shot (no second launch). No generic caller-sweep agent; use when user says ultra or PR is large/risky

## Examples

```text
/pr-review
/pr-review ultra
/pr-review no-bugbot
/pr-review worktree /path/to/wt base <sha>
/pr-review ultra base origin/main
```
