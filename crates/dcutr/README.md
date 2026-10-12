# minip2p-dcutr

Sans-IO state machines for DCUtR (Direct Connection Upgrade through Relay). `no_std` + `alloc` compatible.

DCUtR is the libp2p protocol that coordinates UDP hole punching between two peers that are already connected via a relay circuit. The two peers exchange their observed addresses and a synchronized "go now" signal over the relayed stream; each side then dials the other directly, racing the NAT pinholes open. See the spec at <https://github.com/libp2p/specs/blob/master/relay/DCUtR.md>.

## Scope

This crate implements the message state machines only. Protobuf field framing for `HolePunch` uses the shared vocabulary in `minip2p-core`; semantic validation and contextual `DcutrMessageError` / `DcutrError` values stay here. It does **not**:

- Open the underlying relayed stream (that is the relay + swarm layer's job).
- Send UDP packets or dial transports.
- Measure RTT (the caller passes timestamps in).

## State machines

- **`DcutrInitiator`** -- the peer that initiates the upgrade after being connected via relay. Sends `CONNECT`, waits for the remote `CONNECT`, records its own RTT, then issues `SYNC` and emits `InitiatorOutcome::DialNow { remote_addrs, remote_addr_bytes, rtt_ms }`.
- **`DcutrResponder`** -- the remote peer. Receives the initiator's `CONNECT`, emits `ResponderEvent::ConnectReceived { remote_addrs, remote_addr_bytes }`, replies with its own `CONNECT`, then emits `ResponderEvent::SyncReceived` when the initiator's `SYNC` arrives. The caller kicks off the hole-punch bombardment on `SyncReceived`.

Both machines accept `&[Multiaddr]` at construction time and automatically serialize them to the wire using multicodec-binary encoding (via `Multiaddr::to_bytes()` in `minip2p-core`). Incoming `obs_addrs` are decoded the same way; entries that fail to parse are dropped silently but remain available as raw bytes in `remote_addr_bytes` for diagnostics.

Each machine takes inputs through methods named for what they do (`on_data`, `send_sync`, `on_remote_write_closed`); after construction and after every input, drain `poll_output` until it returns `None`. Both constructors return `Result`: addresses that would not fit one 4 KiB frame are refused with `DcutrError::MessageTooLarge` before anything is queued. The receive buffer is a `minip2p_core::FrameExchange`, so a frame declaring more than the maximum is refused from its header. Bytes coalesced behind the initiator's CONNECT reply, or behind the responder's SYNC, belong to the application and are returned once by `take_trailing_data` after the exchange completes. The wire format is length-prefixed protobuf `HolePunch` messages; the frame helpers (`encode_frame`, `decode_frame`, `FrameDecode`) are re-exported from the crate root.

## Protocol ID

- `DCUTR_PROTOCOL_ID = "/libp2p/dcutr"`
- `MAX_MESSAGE_SIZE = 4096`

## Usage sketch

```rust
use minip2p_core::Multiaddr;
use minip2p_dcutr::{DcutrInitiator, DcutrInitiatorOutput, InitiatorOutcome};

let mut initiator = DcutrInitiator::new(&our_observed_addrs)?; // &[Multiaddr]

while let Some(output) = initiator.poll_output() {
    match output {
        DcutrInitiatorOutput::Outbound(bytes) => send_on_relay_stream(bytes),
        DcutrInitiatorOutput::Outcome(InitiatorOutcome::DialNow { remote_addrs, rtt_ms, .. }) => {
            // Dial each remote Multiaddr directly, wait rtt_ms for a connection,
            // then queue SYNC once the simultaneous dial attempt starts.
            initiator.send_sync()?;
        }
    }
}

// Feed incoming bytes + measured relay RTT:
// initiator.on_data(&data, rtt_ms)?;
```

The timing rules (wait `rtt / 2` on the responder side before blasting UDP, etc.) live in the caller.

## no_std

Disable default features:

```toml
[dependencies]
minip2p-dcutr = { path = "crates/dcutr", default-features = false }
```

## Integration

The state machines typically run over a stream that was originally a relay circuit bridge. In minip2p that is exposed as a user protocol on the swarm (register it with `SwarmBuilder::protocol(DCUTR_PROTOCOL_ID)` and drive it from `Stream*` events). The end-to-end pure-state-machine flow is exercised by `crates/swarm/tests/relay_holepunch_flow.rs`.
