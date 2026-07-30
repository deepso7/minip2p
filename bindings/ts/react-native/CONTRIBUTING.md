# Contributing

This package is part of the `bindings/ts` pnpm workspace and includes an Expo SDK 56 development-build example.

## Setup

Use the Node.js version in `bindings/ts/.nvmrc`, then install from the TypeScript workspace root:

```sh
corepack enable
pnpm install --frozen-lockfile
```

Expo Go cannot load the native library. Generate native projects and use a development build:

```sh
pnpm example prebuild
pnpm example android
pnpm example ios
```

The example's native directories are reproducible outputs and are not committed.

## Binding generation

Run generation whenever `crates/ffi` or the UniFFI/ubrn version set changes:

```sh
pnpm rn:ios
pnpm rn:android
```

Generated files under `src/generated`, `cpp/generated`, `android`, and `ios` are committed and must not be edited directly. Android `.so` files and the iOS XCFramework are ignored build products.

The Android build expects SDK 36 and NDK `28.2.13676358`. The generation script clears an unrelated `LIBCLANG_PATH`, because a host Xtensa toolchain must not leak into BoringSSL's Android build. The iOS script sets the deployment target before Rust and BoringSSL compilation.

## Checks

```sh
pnpm typecheck
pnpm lint
pnpm build
```

`pnpm lint` checks formatting and lint rules with Ultracite, Oxlint, and Oxfmt. Run `pnpm format` to apply formatting and safe lint fixes.

Before submitting generated changes, start from a clean checkout, install with `--frozen-lockfile`, regenerate, and confirm the entire Git worktree remains clean.

Keep pull requests focused and update this README whenever build or lifecycle contracts change.
