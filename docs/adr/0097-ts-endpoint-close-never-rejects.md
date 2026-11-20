# TS endpoint close never rejects and is not an event

`Minip2p.close` and the backends' close (`CloseOnce` in `core/src/backend.ts`, `SerdeBackend`, the React Native adapter) follow one contract:

- **`EndpointClosed` resolves `close`, it is never dispatched.** Backends turn it into the `BackendClosed` report; `#dispatchNative` ignores it. Once close is requested, the serde and React Native backends drop every other drained event, since the SDK has stopped listening.
- **Close never rejects and always releases.** Without a started driver, native releases the endpoint at once and the report is `Drained`. If native fails to stop (a wasm trap or native panic), no `EndpointClosed` will come, so the report is `Failed`, and `release` still runs; a failing `release` does not replace the report.
- **Native close goes first.** `Minip2p.close` asks native to close before anything that can call back into the SDK runs, so a re-entrant `close` from a handler gets the same promise.
- **Close notification is outside the event queue.** Handlers of the close report run after the queue is closed and cannot break the close.
