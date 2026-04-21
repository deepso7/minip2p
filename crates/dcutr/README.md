# minip2p-dcutr

Sans-IO state machines for DCUtR (Direct Connection Upgrade through Relay). `no_std` + `alloc` compatible.

DCUtR is the libp2p protocol that coordinates UDP hole punching between two peers that are already connected via a relay circuit. The two peers exchange their observed addresses and a synchronized "go now" signal over the relayed stream; each side then dials the other directly, racing the NAT pinholes open. See the spec at <https://github.com/libp2p/specs/blob/master/relay/DCUtR.md>.

## Scope

This crate implements the message state machines only. It does **not**:

- Open the underlying relayed stream (that is the relay + swarm layer's job).
- Send UDP packets or dial transports.
- Measure RTT (the caller passes timestamps in).

## State machines

- **`DcutrInitiator`** -- the peer that initiates the upgrade after being connected via relay. Sends `CONNECT`, waits for the remote `CONNECT`, records its own RTT, then issues `SYNC` and emits `InitiatorOutcome::DialNow { remote_addrs, remote_addr_bytes, rtt_ms }`.
- **`DcutrResponder`** -- the remote peer. Receives the initiator's `CONNECT`, emits `ResponderEvent::ConnectReceived { remote_addrs, remote_addr_bytes }`, replies with its own `CONNECT`, then emits `ResponderEvent::SyncReceived` when the initiator's `SYNC` arrives. The caller kicks off the hole-punch bombardment on `SyncReceived`.

Both machines accept `&[Multiaddr]` at construction time and automatically serialize them to the wire using multicodec-binary encoding (via `Multiaddr::to_bytes()` in `minip2p-core`). Incoming `obs_addrs` are decoded the same way; entries that fail to parse are dropped silently but remain available as raw bytes in `remote_addr_bytes` for diagnostics.

Each machine accepts raw bytes via `on_data(&[u8])` and exposes pending outbound bytes via `take_outbound()`. The wire format is length-prefixed protobuf `HolePunch` messages; the frame helpers (`encode_frame`, `decode_frame`, `FrameDecode`) are re-exported from the crate root.

## Protocol ID

- `DCUTR_PROTOCOL_ID = "/libp2p/dcutr"`
- `MAX_MESSAGE_SIZE = 4096`

## Usage sketch

```rust
use minip2p_core::Multiaddr;
use minip2p_dcutr::{DcutrInitiator, InitiatorOutcome};

let mut initiator = DcutrInitiator::new(&our_observed_addrs); // &[Multiaddr]
let out = initiator.take_outbound(); // send these bytes on the negotiated stream

// Feed incoming bytes + measured RTT:
// initiator.on_data(&data, rtt_ms)?;
// if let Some(InitiatorOutcome::DialNow { remote_addrs, rtt_ms, .. }) = initiator.outcome() {
//     // dial each remote Multiaddr directly, wait rtt_ms for a connection,
//     // fall back to relayed ping if none succeeds.
// }
```

The timing rules (wait `rtt / 2` on the responder side before blasting UDP, etc.) live in the caller -- see `holepunch-plan.md` for the CLI's approach.

## no_std

Disable default features:

```toml
[dependencies]
minip2p-dcutr = { path = "crates/dcutr", default-features = false }
```

## Integration

The state machines typically run over a stream that was originally a relay circuit bridge. In minip2p that is exposed as a user protocol on the swarm (`swarm.add_user_protocol(DCUTR_PROTOCOL_ID)` + `UserStream*` events). The end-to-end pure-state-machine flow is exercised by `crates/swarm/tests/relay_holepunch_flow.rs`.
