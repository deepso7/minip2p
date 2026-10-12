# minip2p-ping

Sans-IO state machine for the `/ipfs/ping/1.0.0` protocol. `no_std` + `alloc` compatible.

Ping measures round-trip latency by sending a 32-byte payload and waiting for the remote peer to echo it back verbatim.

## Features

- Dialer sends ping, listener echoes -- both handled by the same `PingProtocol` instance.
- Fragmentation-safe: buffers partial payloads on both inbound and outbound paths.
- Configurable request timeout with `PingConfig`.
- RTT measurement via caller-provided timestamps (no internal clock dependency).
- Methods for stream lifecycle, payload, and tick inputs (`register_outbound_stream`, `register_inbound_stream`, `send_ping`, `on_stream_data`, `on_tick`, ...).
- `PingOutput` values wrapping host actions (`Send`, `CloseStreamWrite`, `ResetStream`) and protocol events (`RttMeasured`, `Timeout`, `ProtocolViolation`, etc.).
- Per-peer state tracking with inbound stream limits.

## Usage

```rust
use minip2p_core::PeerId;
use minip2p_ping::{PingConfig, PingOutput, PingProtocol, PING_PAYLOAD_LEN};
use minip2p_transport::StreamId;

let mut ping = PingProtocol::new(PingConfig::default());

// After protocol negotiation succeeds on a stream, register it:
// ping.register_outbound_stream(peer_id, stream_id)?;
// ping.register_inbound_stream(peer_id, stream_id);

// Send a ping (caller provides the payload and current timestamp):
// ping.send_ping(&peer_id, &payload, now_ms)?;

// Feed incoming stream data:
// ping.on_stream_data(&peer_id, stream_id, &data, now_ms);

// Check for timeouts periodically:
// ping.on_tick(now_ms);

// After every input, drain outputs until `None`:
// while let Some(output) = ping.poll_output() {
//     match output {
//         PingOutput::Action(action) => execute(action),
//         PingOutput::Event(event) => handle(event),
//     }
// }
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

This crate implements the ping protocol state machine only. It does not open streams, send bytes over the network, or negotiate protocols. The host is responsible for feeding stream events into `PingProtocol`, executing `PingOutput::Action` commands against the transport, and draining `poll_output` until it returns `None`.
