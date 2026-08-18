# minip2p-relay

Sans-IO state machines for the libp2p Circuit Relay v2 wire protocols. `no_std` + `alloc` compatible.

Circuit Relay v2 lets a peer behind NAT advertise a relay as its public rendezvous point (`HOP.RESERVE`), and lets another peer connect through that relay to the reserved peer (`HOP.CONNECT` + `STOP.CONNECT`). This crate implements both client and relay-side per-stream roles. See the spec at <https://github.com/libp2p/specs/tree/master/relay>.

## Scope

This crate owns protobuf messages, protocol IDs, status encoding, the 8 KiB control-frame boundary, and the state of one HOP or STOP stream. It does **not** implement:

- Reservation tables, clocks, admission or refusal policy.
- Circuit forwarding, byte accounting, or whole-service lifecycle state.
- Automatic relay discovery. Callers supply the relay multiaddr.

Those service responsibilities belong above these reusable wire machines.

## State machines

- **`HopReservation`** -- drives `HOP.RESERVE` against a relay to obtain a reservation (peer B's "listen" side). Produces `ReservationOutcome::Accepted { reservation, limit }` or `Refused { status, reason }`.
- **`HopConnect`** -- drives `HOP.CONNECT` against a relay to open a circuit to another reserved peer (peer A's "dial" side). Produces `ConnectOutcome::Bridged` with the stream now acting as a bidirectional byte pipe.
- **`StopResponder`** -- responds to an incoming `STOP.CONNECT` from the relay (peer B's "accept incoming circuit" side). Accept or reject the request; on accept, subsequent bytes flow through the same stream as the relayed data.
- **`HopResponder`** -- accepts one inbound `HOP.RESERVE` or `HOP.CONNECT`, exposes the decoded request for an explicit service decision, and emits the resulting status/close/reset actions.
- **`StopInitiator`** -- sends one outbound `STOP.CONNECT`, preserves the destination's exact status, and maps terminal outcomes back to a HOP status with `StopInitiatorOutcome::hop_status`.

Each machine is driven through `SansIoProtocol`: feed its role-specific inputs and drain outputs until idle. A valid request is always emitted before outputs caused by its decision. Bytes pipelined behind an accepted HOP request or STOP response are retained and emitted as bridge data only after the final `STATUS:OK` frame.

Relay-side malformed handling is deterministic. A complete, well-framed message with a wrong kind or missing/invalid required field receives `UNEXPECTED_MESSAGE` or `MALFORMED_MESSAGE`, followed by a local write close. Invalid varint framing, declarations over the limit, and locally constructed responses that cannot fit request a stream reset. Remote close/reset inputs leave the machines in deterministic terminal states; `StopInitiatorOutcome` maps pre-accept closure/reset to `CONNECTION_FAILED`.

## Protocol IDs

- `HOP_PROTOCOL_ID = "/libp2p/circuit/relay/0.2.0/hop"`
- `STOP_PROTOCOL_ID = "/libp2p/circuit/relay/0.2.0/stop"`
- `MAX_MESSAGE_SIZE = 8192` (8 KiB)

The 8 KiB maximum applies to every relay control frame, with an exactly 8 KiB payload accepted. This deliberately differs from rust-libp2p's 4 KiB relay codec limit. Coalesced application payload after a complete handshake frame is not part of the control-frame size.

## Usage (reservation)

```rust
use minip2p_core::SansIoProtocol;
use minip2p_relay::{HopReservation, HopReservationInput, HopReservationOutput};

let mut reservation = HopReservation::new();

while let Some(output) = reservation.poll_output() {
    match output {
        HopReservationOutput::Outbound(bytes) => send_to_relay(bytes),
        HopReservationOutput::Outcome(outcome) => handle(outcome),
    }
}

// Feed incoming bytes:
// reservation.handle_input(HopReservationInput::Data(data))?;
```

`HopConnect`, `StopResponder`, `HopResponder`, and `StopInitiator` follow the same input/output drain-loop shape. Relay hosts execute `Outbound`, `CloseWrite`, and `Reset` outputs against the owned stream and retain `BridgeData` for circuit forwarding.

## no_std

Disable default features:

```toml
[dependencies]
minip2p-relay = { path = "crates/relay", default-features = false }
```

## Integration

The state machines are transport-agnostic; in practice they ride on top of a `minip2p-swarm` user protocol (see `swarm.add_protocol(HOP_PROTOCOL_ID)` + `Stream*` events). A Sans-I/O end-to-end test that exercises the full reservation + connect + stop + DCUtR flow lives at `crates/swarm/tests/relay_holepunch_flow.rs`.
