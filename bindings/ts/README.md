# minip2p TypeScript

The TypeScript workspace is a pnpm monorepo orchestrated by Turborepo.

| Package | Purpose |
| --- | --- |
| [`@minip2p/core`](./core) | Platform-neutral SDK, public types, errors, event delivery, and native backend contract |
| [`react-native-minip2p`](./react-native) | React Native TurboModule backend and Expo development app |
| [`@minip2p/node`](./node) | Node.js adapter scaffold; the napi-rs backend is the next implementation slice |

Platform packages implement the backend contract from `@minip2p/core` and re-export the same SDK-facing types. Platform-neutral behavior belongs in `core`; native loading, generated bindings, and FFI error conversion belong in the platform adapter.

```sh
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm lint
pnpm build
```

Future TypeScript-hosted targets such as WASM belong beside the current adapters at `bindings/ts/wasm`. Bindings for other language ecosystems remain top-level siblings, such as `bindings/python`, `bindings/swift`, and `bindings/kotlin`.
