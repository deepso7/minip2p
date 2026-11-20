# `@minip2p/web` pumping, trap recovery and wasm loading

The browser host (`bindings/ts/web/src/sdk.ts`, `wasm.ts`) drives the caller-driven `WebEndpoint` itself. Its rules:

- **Every command schedules a pump.** Any SDK call may queue work in Rust (a dial, a write), so `webBackend`'s `call` hook runs `pump.schedule()` in a `finally` after each one. `Pump` coalesces schedules into one microtask burst of up to `PUMP_ROUNDS` polls. If the endpoint is still busy after that, it re-arms with a zero-delay timer so the page gets to run between bursts.
- **A failing pump stops silently.** If `poll` throws, the endpoint has already failed and its owner (`WasmCalls`'s `onFail`) has reported it, so `Pump` just stops.
- **A trapped instance is cleaned up from TypeScript.** After a `WebAssembly.RuntimeError` the wasm instance can neither close its WebTransport sessions nor be freed. `onFail` stops the pump, calls `JsIo.dispose()` to close the browser sessions directly, and fails the backend.
- **Release frees after drain.** Once the endpoint is closed and its final events are drained, `release` stops the pump and frees the wasm object. Freeing drops its doorbell and its `JsIo`, so a timer armed by the last pump never touches the freed endpoint.
- **Promised wasm sources are awaited before `init`.** wasm-bindgen only fetches a string or URL that is passed to it directly, so `instantiate` awaits a `Promise<InitInput>` before handing it to `init`.
