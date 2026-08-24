# minip2p

A minimal libp2p implementation in Rust with sans-I/O cores, transport adapters, and foreign-runtime bindings.

## Language

### Bindings

**FFI core**:
The binding-agnostic embedding layer (`minip2p-ffi-core`): the detached driver thread, event flattening, and endpoint lifecycle that every binding shell builds on.

**Binding shell**:
A thin crate adapting the FFI core to one foreign toolchain — UniFFI for React Native (`minip2p-ffi`), napi-rs for Node (`minip2p-nodejs`). Shells hold no driver or lifecycle logic of their own.
_Avoid_: wrapper

**Backend contract**:
The synchronous `Minip2pBackend` interface in `@minip2p/core` that each JS binding implements; the TypeScript-facing seam shared by React Native and Node.
