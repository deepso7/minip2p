---
name: delete-comment
description: Sweep implementation comments out of the repo, turning decisions into ADRs and excuses into issues.
disable-model-invocation: true
---

Implementation comments are banned in this repo (`AGENTS.md`, Coding preferences). `scripts/check-comments.py` finds them and holds a per-file ratchet in `scripts/comment-baseline.json`; CI fails if any file gains a comment. This skill drives the count down.

The argument, if any, is the paths to sweep. Without one, sweep everything `scripts/check-comments.py --list` still reports.

## 1. Plan the sweep

Branch off `main` first. Run `python3 scripts/check-comments.py --list <paths>` and count lines per crate or top-level directory. Partition into disjoint groups of roughly 600 comment lines each: one large crate alone, small crates together. Under ~300 lines in total, do it yourself with one group.

## 2. Fan out

Make a scratch dir `OUT` outside the repo (e.g. `/tmp/delete-comment`). Spawn one subagent per group, all in one message so they run concurrently, each with the prompt:

> Follow the brief in `.agents/skills/delete-comment/SWEEP-BRIEF.md` exactly. AGENT=<name>. OUT=<OUT>. Your paths: <paths>

Give the scripts group the extra instruction that a script header that is the only usage doc moves into `scripts/README.md`, not an ADR. Wait for every agent before step 3.

Done when every agent has reported and `--list <paths>` prints only the comments agents flagged as unsure.

## 3. Consolidate decisions into ADRs

Read every `OUT/*/adr/*.md`. Merge drafts that record the same decision across groups, drop any that only restate an existing ADR, and apply `amend-NNNN.md` drafts to their ADR. Number the rest after the highest in `docs/adr/` and move them there. Check each against `ADR-FORMAT.md`'s bar: a draft that fails it is a lost tautology, not an ADR; drop it.

## 4. File excuses as issues

Read every `OUT/*/issues.md`, merge duplicates, and check each against open issues (`docs/agents/issue-tracker.md`). File each with `gh issue create`, label `needs-triage`, body from the draft (keep the quoted comment and file reference).

## 5. Verify and lock in

```bash
cargo fmt --all && cargo fmt --manifest-path fuzz/Cargo.toml
pnpm format    # when TS or JS changed
python3 scripts/check-comments.py --update
just dev
just clippy full
```

Review `git diff --stat` and spot-check the diff for anything that is not a comment deletion, a minimal rename, or an ADR. Fix any failure before opening the PR.

## 6. Report

Open a PR (the `pr` skill writes its body) listing: comment lines removed per group and by category, the new ADRs, the issues filed, and the comment lines the baseline still allows.
