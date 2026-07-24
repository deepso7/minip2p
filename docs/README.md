# minip2p documentation

The user-facing site is built with [Blume](https://useblume.dev/). Content
lives in `md/`; `.blume/` and `dist/` are generated and must not be edited.

## Requirements

- Node.js 22.13 or newer
- pnpm 11.10.0

## Work locally

```bash
pnpm install --frozen-lockfile
pnpm dev
```

Run the complete docs check before opening a pull request:

```bash
pnpm check
```

This runs Blume's project diagnostics, production build, and link validation.
From the repository root, the same check is available as:

```bash
just docs-site
```

The Rust programs under `snippets/` back the main copy-paste examples. Keep
their corresponding MDX code blocks in sync and compile both fixtures after
changing an API example.
