# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

- **`CONTEXT.md`** at the repo root.
- **`docs/adr/`** — read ADRs that touch the area you're about to work in.

If either does not exist, **proceed silently**. Don't flag its absence or suggest creating it upfront. The `/domain-modeling` skill creates domain docs lazily when terms or decisions are actually resolved.

## File structure

This repo uses a single-context layout:

```
/
├── CONTEXT.md
├── docs/adr/
└── crates/, transports/, bindings/, docs/
```

## Use the glossary's vocabulary

When your output names a domain concept, use the term as defined in `CONTEXT.md`. Don't drift to synonyms the glossary explicitly avoids.

If the concept you need isn't in the glossary yet, reconsider whether you're inventing language the project doesn't use; if it is a real gap, note it for `/domain-modeling`.

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than silently overriding.
