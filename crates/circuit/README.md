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

Default features enable OS entropy. Disable default features for
`no_std + alloc` and provide an `EntropySource` explicitly.

A custom source must fill the entire destination with cryptographically
unpredictable bytes. If its backend fails, return `EntropyError::new(...)`
rather than substitute predictable bytes:

```rust,ignore
use minip2p_circuit::{EntropyError, EntropySource};

struct PlatformEntropy;

impl EntropySource for PlatformEntropy {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        platform_rng_fill(destination)
            .map_err(|_| EntropyError::new("platform RNG unavailable"))
    }
}
```
