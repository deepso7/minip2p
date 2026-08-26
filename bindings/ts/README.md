# minip2p TypeScript

TypeScript bindings for [minip2p](https://minip2p.com).

| Package | Purpose |
| --- | --- |
| [`@minip2p/core`](./core) | Platform-neutral SDK, types, events, and backend contract |
| [`@minip2p/react-native`](./react-native) | Published React Native adapter with Android and iOS libraries |
| [`@minip2p/node`](./node) | Node.js adapter over the napi-rs binding shell |

Platform adapters implement `@minip2p/core/backend` and re-export the public SDK types. See [FEATURES.md](./FEATURES.md) for the Rust-to-TypeScript capability map.

```sh
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm lint
pnpm build
```
