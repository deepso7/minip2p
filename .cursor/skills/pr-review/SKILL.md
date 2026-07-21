---
name: pr-review
description: >-
  Orchestrated high-depth PR review: planner + parallel micro-agents, then
  merge with confidence gating. Use when the user asks for /pr-review or an
  orchestrated multi-agent PR review (not the single-agent rule alone).
disable-model-invocation: true
---

# PR review (orchestrated)

## Goal

Beat single-pass review on recall via **planner → specialized micro-agents → merge**. Keep severity/output bar from `.cursor/rules/pr-review.mdc`. Do **not** replace that rule — this skill is the orchestration layer.

## Diff source

- Default: `git diff $(git merge-base HEAD origin/main)...HEAD` (+ dirty tree if present)
- Or user-specified worktree / `base...head`
- Do **not** read GitHub bot/human review comments unless asked to compare

## Tools (keep few)

Allowed: read files, `rg`/search, `git show`/`git diff`, focused tests (`cargo test -p …`). No sprawling toolkits.

## Pipeline

### 1. Planner (you)

From the diff only:

1. List changed paths and a one-line blast radius (what can break)
2. Note symbols/APIs whose **callers outside the diff** must be checked (out-of-diff)
3. Pick which specialists to run (default: all five below on nontrivial PRs; drop Editorial-only if zero docs)
4. Emit a short plan; then launch specialists **in parallel** (separate subagents / Task calls)

### 2. Micro-agents (parallel)

Specialists inherit the parent model — omit `model` on Task unless the user names one.

Each specialist gets: worktree path, exact `base...head`, changed-file list, planner blast-radius notes, and **only its charter** (see `reference.md`).

Every finding **must** be structured:

```json
{"reasoning":"…","severity":"P0|P1|P2|P3","confidence":0.0-1.0,"path":"file","line":123,"finding":"what breaks + who is hurt. fix hint."}
```

Charters:

| Agent | Owns |
|---|---|
| **State** | Invariants, lifecycle, close/reset/retry, event ordering, post-close behavior |
| **Parse** | Lengths, encodings, fixtures/goldens, validate-before-side-effects |
| **Security** | Untrusted peers/input, authz, spoofing, expensive work before reject |
| **Flow** | Spins, starvation, deadlines, unbounded/superlinear buffers, error-path leaks |
| **Verify** | Tests/CI/fuzz/`no_std` gaps, README/doc lies, AGENTS.md policy on touched code |

Specialists must: stay in charter; read out-of-diff callers when the planner flagged symbols; not stop after one hit; confidence &lt; 0.8 → omit.

### 3. Merge (you)

1. Collect all findings with confidence ≥ 0.8
2. Dedupe near-duplicates (same root cause → keep highest severity / clearest)
3. Drop nits / pure style even if a specialist emitted them
4. Optional: run focused `cargo test -p <touched>` once; fold hard evidence in
5. Output per `pr-review.mdc`: summary line, table, short evidence per finding, severity counts, and one Cubic-style **copy block** (single fenced `text` with `<file>` / `<violation>` prompts grouped by file) so the user can paste into an agent
6. Do not fix code unless asked

## Modes

- **normal** (default): all specialists, thorough but time-bounded
- **ultra**: same agents + explicit out-of-diff pass on every public/changed symbol the planner listed; prefer deeper reads over skimming; use when user says ultra or PR is large/risky

## Examples

```text
/pr-review
/pr-review ultra
/pr-review worktree /path/to/wt base <sha>
```
