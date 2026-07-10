# minip2p-relay

Sans-IO state machines for the libp2p Circuit Relay v2 **client** protocols. `no_std` + `alloc` compatible.

Circuit Relay v2 lets a peer behind NAT advertise a relay as its public rendezvous point (`HOP.RESERVE`), and lets another peer connect through that relay to the reserved peer (`HOP.CONNECT` + `STOP.CONNECT`). This crate implements the client side of all three roles. See the spec at <https://github.com/libp2p/specs/tree/master/relay>.

## Scope

Client-side only. This crate does **not** implement:

- The relay server itself (HOP responder, STOP initiator).
- Connection limits, accounting, or refusal policies.
- Automatic relay discovery. Callers supply the relay multiaddr.

Interop goal for this crate is bridging two minip2p peers through a third-party libp2p relay; the relay server is the only party that needs to speak HOP as a responder.

## State machines

- **`HopReservation`** -- drives `HOP.RESERVE` against a relay to obtain a reservation (peer B's "listen" side). Produces `ReservationOutcome::Accepted { reservation, limit }` or `Refused { status, reason }`.
- **`HopConnect`** -- drives `HOP.CONNECT` against a relay to open a circuit to another reserved peer (peer A's "dial" side). Produces `ConnectOutcome::Bridged` with the stream now acting as a bidirectional byte pipe.
- **`StopResponder`** -- responds to an incoming `STOP.CONNECT` from the relay (peer B's "accept incoming circuit" side). Accept or reject the request; on accept, subsequent bytes flow through the same stream as the relayed data.

Each machine is driven through `SansIoProtocol`: feed role-specific inputs (`HopReservationInput`, `HopConnectInput`, `StopResponderInput`) and drain role-specific outputs until idle. Bytes that arrive pipelined after the initial `STATUS:OK` reply are emitted as bridge-data outputs on the connect/stop side so the caller can feed them into an upper-layer stream without a second poll round.

## Protocol IDs

- `HOP_PROTOCOL_ID = "/libp2p/circuit/relay/0.2.0/hop"`
- `STOP_PROTOCOL_ID = "/libp2p/circuit/relay/0.2.0/stop"`
- `MAX_MESSAGE_SIZE = 8192`

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

`HopConnect` and `StopResponder` follow the same input / output / drain-loop shape.

## no_std

Disable default features:

```toml
[dependencies]
minip2p-relay = { path = "crates/relay", default-features = false }
```

## Integration

The state machines are transport-agnostic; in practice they ride on top of a `minip2p-swarm` user protocol (see `swarm.add_user_protocol(HOP_PROTOCOL_ID)` + `UserStream*` events). A Sans-I/O end-to-end test that exercises the full reservation + connect + stop + DCUtR flow lives at `crates/swarm/tests/relay_holepunch_flow.rs`.
