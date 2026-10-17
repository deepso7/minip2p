# minip2p-circuit

`minip2p-circuit` turns an already-negotiated relay bridge stream into a regular minip2p `Transport` connection. It is fully Sans-I/O: the upgrade runs in a [`minip2p-secure-mux`](../secure-mux) session driven over the bridge, while the wrapped transport remains responsible for actual I/O. This crate contributes the bridge plumbing on top of that session: circuit identifiers, bridge lifecycle, and arbitration against direct connections.

The wrapper assigns circuit connections IDs in the `CIRCUIT` namespace, leaving wrapped transport IDs unchanged. Callers adopt HOP/STOP bridge streams with `CircuitTransport::adopt_bridge` and then use the ordinary `Transport` API.

The circuit consumes its bridge's bytes as its own session takes them and acknowledges them on the bridge at once; end-to-end receive credit is the circuit's own Yamux session's to give, so a reader on a circuit stream that never acknowledges stalls the far sender exactly as it would over TCP (ADR 0012). A circuit that ends while its streams still hold delivered, unacknowledged bytes stays an unsettled connection: `ack_stream` and `reset_stream` still settle those streams after `Closed`, and `CircuitTransport::circuit_slots` counts it, alongside active circuits, until they do. Hosts admit new circuits against that count (the NAT agent's `max_circuits`).

## Memory budget

Each `CircuitTransport` has a circuit memory budget (ADR 0021), set with `CircuitLimits` through `CircuitTransport::with_limits`, which also carries the circuits' `YamuxConfig`; `CircuitTransport::new` uses `CircuitLimits::default()`. The budget caps the circuits' retained payload: queued sends (counted twice for slice pinning), receive windows, decoder backlogs and output backlogs. A circuit's bridge stream is charged to the wrapped transport's own budget.

- **Fixed part:** `CircuitLimits::connection_reservation_bytes()` = `SecureMuxSession::fixed_reservation_bytes(&yamux)` (twice Yamux's total send cap, the session's write queue, its decoders and the control replies a peer may provoke) + one Noise message (`NOISE_WIRE_FRAME`) the bridge may hold refused as Full. Reserved from the claim or adoption until teardown drops the session.
- **Per stream:** `CircuitLimits::stream_reservation_bytes()` = the Yamux receive window, from open or admission until the stream settles, also after its circuit ended.

What does not fit is refused, never queued: `open_stream` fails with `ResourceExhausted { resource: "circuit memory budget" }` and an inbound stream is reset. A host reserves a circuit's fixed part ahead of time with `claim_circuit` (or `hold_circuit_claims`, which the NAT agent drives) before it accepts a STOP or sends a HOP CONNECT, and adopts with `BridgeAdoption::claimed` to carry the claim into the circuit; a failed or repeated adoption releases it. An unclaimed adoption reserves for itself, failing with `AdoptError::BudgetExhausted`, and an `unsent_prefix` longer than one Noise message is `AdoptError::PrefixTooLong`. The defaults (2,432 KiB windows, 960 MiB) admit 68 circuits with one stream each: 11.64 MiB fixed plus the window is 14 MiB. `CircuitLimits::validate` (run by `with_limits`) rejects a budget that cannot fit one circuit and one stream with `InvalidLimit`. `memory_reserved()` reports what is reserved now.

A full bridge is backpressure, not a fault (ADR 0012). When the wrapped transport answers a bridge write with `Full`, the circuit keeps that one unsent tail and stops pulling from its session until the bridge's `StreamWritable`; stream writes on the circuit then fill its Yamux send caps and return `TransportError::Full` themselves.

Fresh Noise key material comes from a [`minip2p_core::platform::EntropySource`](../core/README.md#platform-contracts) — the one entropy seam every minip2p transport draws from, so a single adapter over a board's RNG serves a `CircuitTransport` and a `TcpTransport` at once. Default features add `CircuitTransport::new_os`, which uses `minip2p_core::platform::StdEntropy`. Disable default features for `no_std + alloc` and pass an `EntropySource` explicitly.

A custom source must fill the whole output with cryptographically unpredictable bytes. If its backend fails, return an `EntropyError` rather than substitute predictable bytes:

```rust,ignore
use minip2p_core::platform::{EntropyError, EntropySource};

struct PlatformEntropy;

impl EntropySource for PlatformEntropy {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        platform_rng_fill(output)
            .map_err(|_| EntropyError::failed("platform RNG unavailable"))
    }
}
```
