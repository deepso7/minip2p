# PyO3 for the Python bindings

The Python SDK needs a native binding over `minip2p-ffi-core`, whose doorbell rings from a Rust thread and whose `wait_stopped` blocks until that thread exits. We chose a hand-written **PyO3** binding shell (`crates/python`, `minip2p-python`, `publish = false`, `pyo3` pinned exactly), packaged by maturin as `abi3-py311` wheels, over reusing `crates/ffi`'s UniFFI Python output and over BoltFFI. Full comparison: [docs/research/python-binding-mechanisms.md](../research/python-binding-mechanisms.md).

## Considered Options

- **PyO3 + maturin** (chosen): the shell releases the GIL exactly where it says so, modules are marked free-threading-safe by default, maturin handles abi3/manylinux/musllinux wheels and cross builds, and PyO3's macros compile under the workspace `forbid(unsafe_code)` unchanged.
- **UniFFI Python (reuse `crates/ffi`)**: zero new Rust and ctypes releases the GIL by default, but it extends the mobile-only `uniffi =0.31.2` pin to Python (the coupling ADR 0001 and 0002 kept off Node), and ctypes lowers `bytes` through a per-byte Python loop.
- **BoltFFI Python**: its generated extension never releases the GIL, so a Python thread in `wait_stopped` deadlocks against a pending doorbell callback until the timeout; it also re-enables the GIL on free-threaded builds and its packer has no cross-compilation, manylinux, or abi3 support.

## Consequences

- `wait_stopped` (and any future blocking call) must run inside `Python::detach`; a regression test proves `wait_stopped` returns while a doorbell callback is pending. Forgetting `detach` recreates the interpreter-wide stall.
- The Python SDK is two layers in one distribution: a private `minip2p._native` shell of one-line forwards over the FFI core, and a pure-Python, asyncio-first `minip2p` package that owns the drain loop, typed errors, and SDK ergonomics mirroring the TypeScript SDK. The shell holds no lifecycle logic (ADR 0002).
- Events cross as a PyO3 complex enum so ffi-core drift fails to compile; the hand-written `_native.pyi` is checked against the built module by `stubtest` in CI.
- Free-threaded wheels wait for `abi3t` (Python 3.15); until then 3.14t users build from source.
