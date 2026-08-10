# minip2p-circuit

`minip2p-circuit` turns an already-negotiated relay bridge stream into a
regular minip2p `Transport` connection. It is fully Sans-I/O: the upgrade runs
in a [`minip2p-secure-mux`](../secure-mux) session driven over the bridge, while
the wrapped transport remains responsible for actual I/O. This crate contributes
the bridge plumbing on top of that session: circuit identifiers, bridge
lifecycle, and arbitration against direct connections.

The wrapper assigns circuit connections IDs in the `CIRCUIT` namespace, leaving
wrapped transport IDs unchanged. Callers adopt HOP/STOP bridge streams with
`CircuitTransport::adopt_bridge` and then use the ordinary `Transport` API.

Fresh Noise key material comes from a
[`minip2p_platform::EntropySource`](../platform) — the one entropy seam every
minip2p transport draws from, so a single adapter over a board's RNG serves a
`CircuitTransport` and a `TcpTransport` at once. Default features add
`CircuitTransport::new_os`, which uses the platform crate's `StdEntropy`.
Disable default features for `no_std + alloc` and pass an `EntropySource`
explicitly.

A custom source must fill the whole output with cryptographically unpredictable
bytes. If its backend fails, return an `EntropyError` rather than substitute
predictable bytes:

```rust,ignore
use minip2p_platform::{EntropyError, EntropySource};

struct PlatformEntropy;

impl EntropySource for PlatformEntropy {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        platform_rng_fill(output)
            .map_err(|_| EntropyError::failed("platform RNG unavailable"))
    }
}
```
