# `bytes::Bytes` is the shared stream payload type

Stream payloads are `Vec<u8>` at every boundary (`TransportEvent`, `SwarmEvent`, `EndpointEvent`, `send_stream`), so any layer that keeps a payload or sends it to several places copies it: relay forwarding and NAT straggler injection clone each chunk, and gossipsub copies its shared frame once per recipient when it builds `SendStream` (#249). Payloads become `bytes::Bytes`, re-exported as `minip2p_core::Bytes` and depended on with `default-features = false`, so fan-out and relaying clone a handle instead of the bytes.

`Bytes` is `Send + Sync`, slices in O(1) without copying, and needs only `alloc` and atomic CAS, which `thumbv7em-none-eabi` has. `Bytes::from(Vec<u8>)` takes over the vector's allocation, so a decrypted Noise frame or a QUIC read becomes a payload without another copy. `Vec::from(Bytes)` hands the allocation back when the handle is unique, which is the common case at the binding boundary. `bytes` keeps its `unsafe` inside its own crate; `forbid(unsafe_code)` still holds for ours. It is already in the lockfile through quiche and uniffi.

We rejected a minimal `Arc<[u8]>` plus range type: building an `Arc<[u8]>` from a `Vec` copies the bytes, so every received chunk would pay a copy the shared type exists to remove, and `Arc<Vec<u8>>` avoids that only at the cost of a second indirection and reimplementing what `bytes` already does. We rejected an `Rc`-based type because the std and FFI drivers move the endpoint across threads. We rejected a newtype over `Bytes`: it would only forward methods, and the re-export already keeps the dependency declared in one place.

## Consequences

- Pubsub's `SharedFrame` (`Arc` under `std`, `Rc` otherwise) is replaced by `Bytes`, so the `no_std` build no longer uses `Rc` there.
- The `Transport`, swarm and endpoint `send_stream` take `Bytes`; the application-facing endpoint method accepts `impl Into<Bytes>`, so `Vec<u8>` and static slices keep working. A write that does not fully fit hands back its unsent tail as a slice of the same `Bytes`, without a copy (ADR 0012).
- Slicing can pin the whole source allocation, so a layer that retains a slice shorter than half its payload's original length copies it (ADR 0012).
- FFI types keep `Vec<u8>`; ffi-core converts at the boundary. The copies into and out of JavaScript, and QUIC's copy out of its reusable read buffer, remain.
- Targets without atomic CAS (for example `thumbv6m`) would need `bytes`'s `extra-platforms` feature. None is supported today.
- Wire decoders keep borrowing `&[u8]`; only stream payloads change type.
