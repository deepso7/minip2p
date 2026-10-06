# minip2p-nodejs

Thin [napi-rs](https://napi.rs/) binding shell over `minip2p-ffi-core`. The `@minip2p/node` package owns the TypeScript adapter and builds this crate into its native addon.

The shell translates napi values and forwards synchronous commands to `minip2p-ffi-core`. Events and snapshots are not converted by hand: `minip2p-ffi-core`'s `serde` feature derives the one JavaScript shape (`{ tag, inner }` events, camelCase fields, omitted `None`s, bytes as `Buffer`, variant-name strings for enums, lossless `u64`s), and the shell hands each value to napi-rs's serde serializer. `ts_return_type` names the matching TypeScript types in the generated declarations. A strong `ThreadsafeFunction` acts as the event doorbell; the TypeScript adapter drains the core's bounded carry on the Node.js thread. The shell does not own sockets, driver lifecycle policy, or another event queue.

Every `FfiError` is thrown as a JS `Error` with the formatted message, a `code` set to the variant name (for example `Backpressure`), and a `detail` property for variants that carry one. The TypeScript adapter maps `code` to the typed SDK errors.

Build the linux addon from `bindings/ts/node` with:

```bash
pnpm native:build
```
