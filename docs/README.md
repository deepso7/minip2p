# minip2p documentation

The user-facing site is built with [Blume](https://useblume.dev/). Content lives in `md/`; `.blume/` and `dist/` are generated and must not be edited.

The landing page at `/` lives in `pages/index.astro`. The documentation starts at `/intro`, in `md/intro.mdx`.

Blume emits `js-yaml` imports into its generated runtime. The root `js-yaml` dependency keeps those imports on Blume's v5 API when the workspace also installs v4 for Astro.

## Requirements

- Node.js 24.20 or newer
- pnpm 12.5.1

## Work locally

Run from the repository root:

```bash
pnpm install --frozen-lockfile
pnpm docs:dev
```

Run the complete docs check before opening a pull request:

```bash
pnpm docs:check
```

This runs Blume's project diagnostics, an isolated production build (safe alongside `pnpm docs:dev`), and link validation. From the repository root, the same check is available as:

```bash
just docs-site
```

The Rust programs under `snippets/` back the main copy-paste examples. Keep their corresponding MDX code blocks in sync and compile both fixtures after changing an example:

```bash
cargo check --manifest-path docs/snippets/quickstart/Cargo.toml
cargo check --manifest-path docs/snippets/custom-stream/Cargo.toml
```
