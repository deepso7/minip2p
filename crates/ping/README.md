# minip2p-ping

Sans-IO state machine for the `/ipfs/ping/1.0.0` protocol. `no_std` + `alloc` compatible.

Ping measures round-trip latency by sending a 32-byte payload and waiting for the remote peer to echo it back verbatim.

## Features

- Dialer sends ping, listener echoes -- both handled by the same `PingProtocol` instance.
- Fragmentation-safe: buffers partial payloads on both inbound and outbound paths.
- Configurable request timeout with `PingConfig`.
- RTT measurement via caller-provided timestamps (no internal clock dependency).
- `PingInput` values for stream lifecycle, payload, and tick inputs.
- `PingOutput` values wrapping host actions (`Send`, `CloseStreamWrite`, `ResetStream`) and protocol events (`RttMeasured`, `Timeout`, `ProtocolViolation`, etc.).
- Per-peer state tracking with inbound stream limits.

## Usage

```rust
use minip2p_core::PeerId;
use minip2p_core::SansIoProtocol;
use minip2p_ping::{PingConfig, PingInput, PingOutput, PingProtocol, PING_PAYLOAD_LEN};
use minip2p_transport::StreamId;

let mut ping = PingProtocol::new(PingConfig::default());

// After protocol negotiation succeeds on a stream, register it:
// ping.handle_input(PingInput::RegisterOutboundStream { peer_id, stream_id })?;
// ping.handle_input(PingInput::RegisterInboundStream { peer_id, stream_id })?;

// Send a ping (caller provides the payload and current timestamp):
// ping.handle_input(PingInput::SendPing { peer_id, payload, now_ms })?;

// Feed incoming stream data:
// ping.handle_input(PingInput::StreamData { peer_id, stream_id, data, now_ms })?;

// Check for timeouts periodically:
// ping.handle_input(PingInput::Tick { now_ms })?;

// Drain outputs:
// while let Some(output) = ping.poll_output() {
//     match output {
//         PingOutput::Action(action) => execute(action),
//         PingOutput::Event(event) => handle(event),
//     }
// }
// assert!(ping.is_idle());
```

## Protocol

- Protocol ID: `/ipfs/ping/1.0.0`
- Payload: exactly 32 bytes
- The dialer writes a 32-byte payload, the listener reads it and echoes it back unchanged.
- Either side can half-close or reset the stream to end the ping session.

## no_std

Disable default features:

```toml
[dependencies]
minip2p-ping = { path = "crates/ping", default-features = false }
```

## Scope

This crate implements the ping protocol state machine only. It does not open streams, send bytes over the network, or negotiate protocols. The host is responsible for feeding `PingInput` values into `PingProtocol`, executing `PingOutput::Action` commands against the transport, and draining outputs until `SansIoProtocol::is_idle()` returns `true`.
