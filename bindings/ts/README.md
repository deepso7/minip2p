# minip2p TypeScript

TypeScript bindings for [minip2p](https://minip2p.com).

| Package | Purpose |
| --- | --- |
| [`@minip2p/core`](./core) | Platform-neutral SDK, types, events, and backend contract |
| [`@minip2p/react-native`](./react-native) | Published React Native adapter with Android and iOS libraries |
| [`@minip2p/node`](./node) | Node.js adapter over the napi-rs binding shell |
| [`@minip2p/web`](./web) | Browser adapter over the wasm-bindgen shell, dialing over WebTransport |

The platform binary packages live in [`node-platforms`](./node-platforms). The Expo application lives in [`examples/react-native`](../../examples/react-native), the browser page in [`examples/web`](../../examples/web).

Platform adapters implement `@minip2p/core/backend` and re-export the public SDK types. The Node and web shells hand values over in the same serde shape, so both run `@minip2p/core/serde-backend`'s `SerdeBackend` over their native endpoint. See [FEATURES.md](./FEATURES.md) for the Rust-to-TypeScript capability map.

Run from the repository root. Docs and bindings share one pnpm workspace and lockfile.

```sh
pnpm install --frozen-lockfile
pnpm typecheck
pnpm --filter @minip2p/node native:build
pnpm test          # also builds the web wasm: needs wasm32 and wasm-bindgen-cli
pnpm lint
pnpm build
pnpm --filter @minip2p/web test:e2e   # browsers via Playwright
```
