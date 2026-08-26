# minip2p-nodejs

Thin [napi-rs](https://napi.rs/) binding shell over `minip2p-ffi-core`.
The `@minip2p/node` package owns the TypeScript adapter and builds this crate
into its native addon.

The shell translates napi values and forwards synchronous commands to
`minip2p-ffi-core`. A strong `ThreadsafeFunction` acts as the event doorbell;
the TypeScript adapter drains the core's bounded carry on the Node.js thread.
The shell does not own sockets, driver lifecycle policy, or another event
queue.

Build the linux addon from `bindings/ts/node` with:

```bash
pnpm native:build
```
