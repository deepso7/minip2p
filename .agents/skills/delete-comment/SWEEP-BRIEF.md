# Comment sweep brief

You are one of several agents sweeping implementation comments out of this repo. The lead gave you `AGENT` (a short name), `OUT` (a scratch directory) and your paths.

Read `AGENTS.md` first, and skim `GLOSSARY.md` and the titles in `docs/adr/` (read any ADR that touches your area).

## Scope

Only the files under your paths. Other agents edit other paths in the same checkout at the same time: never touch a file outside yours. Don't switch branches, commit, push, or file issues.

List every comment in your scope with:

    python3 scripts/check-comments.py --list <path> [<path> ...]

That prints `file:line: text` for every implementation comment: `//` and `/* */` in Rust/TS/JS, `#` in shell/Python. It already excludes rustdoc (`///`, `//!`), JSDoc `/** */`, Python docstrings and tool directives (`SAFETY:`, `oxlint-disable`, `@ts-expect-error`, `noqa`, `shellcheck`). Leave those alone. A multi-line comment is one comment; judge it as a whole.

## Classify each comment

- **Tautology**: repeats what the code already says (names, types, the next line's obvious effect), section dividers, banners.
- **Stale**: refers to code, behaviour, history, PR/issue numbers, or plans that no longer match the code. Check the code before calling it stale.
- **Excuse**: covers for a hacky, incomplete or knowingly wrong implementation ("for now", "hack", "workaround", "TODO", "temporary", "good enough", "we don't handle X", silent fallbacks, duplicated logic justified by a comment). The comment lets a shortcut stand.
- **Decision Record**: documents an important, non-obvious decision a future reader would otherwise "fix": a protocol or spec requirement, an invariant, an ordering constraint, a security or resource-bound reason, interop with another implementation, a rejected alternative. Be honest, but don't inflate a trivial "why" into a decision.

## Act

- **Tautology / Stale**: delete the comment.
- **Excuse**: delete the comment and append an issue draft to `$OUT/$AGENT/issues.md`: one `## <title>` per issue saying what is hacky, where (`path:line` in the original file), what a proper fix looks like, and the deleted comment quoted. Merge excuses with one root cause into one issue.
- **Decision Record**: delete the comment and record the decision in `$OUT/$AGENT/adr/<slug>.md`, in the format of `.agents/skills/domain-modeling/ADR-FORMAT.md` and the tone of `docs/adr/`: `# <short title of the decision>`, then a paragraph or short bullet list saying what was decided and why, naming the code it governs (crate, type, function; no line numbers). One ADR per coherent decision or tight cluster of related decisions in one component, not one per comment. If an existing ADR already records the decision, delete the comment; only if it adds a real detail, draft `$OUT/$AGENT/adr/amend-<NNNN>.md` instead.
- **Tests**: a comment narrating the scenario is usually tautology; one stating a non-obvious protocol fact the test relies on is a decision record. If deleting it leaves a test unreadable, rename a variable or the test instead, minimally.

Deletion mechanics: remove whole-line comments entirely, leaving at most one blank line where they sat. For a trailing comment, remove the comment and the whitespace before it. Never change behaviour. Don't touch comments inside string literals or generated files. Don't build or run tests: other agents share the target dir, and the lead runs fmt, clippy and tests at the end.

Done means `python3 scripts/check-comments.py --list <your paths>` prints nothing, apart from any comment you are genuinely unsure about.

## Report back

Keep it short:
- counts per category and comment lines removed
- ADR draft files and issue titles
- anything left in place, and why
