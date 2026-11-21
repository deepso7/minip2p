# TS adapters normalize native events into one SDK shape

The Node/wasm serde backend (`SerdeBackend`, `normalizeEvent` in `core/src/serde-backend.ts`) and the React Native adapter (`react-native/src/adapter.ts`) convert native events into the shared `P2pEvent` shape. The generated UniFFI event and the SDK event share one shape (the `minip2p-ffi-core` derives) once integers and enums are converted. The conversion rules:

- **Connection IDs are mapped** to public, JS-safe numbers, since native ones span the full u64 range. A released public ID is never reused.
- **Connect IDs are not mapped.** They round-trip into native calls, and native allocates them well inside the safe integer range.
- **Stream IDs are public per connection.** A record without a connection (an endpoint error, say) cannot name a public stream, so its `streamId` is dropped.
- **QUIC stop and close codes stay `bigint`** (`errorCode`, `code`): they are 62-bit varints the remote picks, so narrowing to `number` would lose them.
- **A fieldless variant arrives without `inner`** in both runtimes (e.g. `MdnsRecovered`); the raw event types and `sdkEvent` model that rather than inventing an empty `inner`.
- Serde shells hand bytes over as `Uint8Array`, not `ArrayBuffer`. The shared adapter contract (`test-fixtures`) feeds deliberately loose, partly malformed events to check that the adapters reject or tolerate them.
- Config fields range-checked natively (e.g. `quic.timeThreshold`) are passed through unchecked by `config.ts`, because the native error already names the field.
