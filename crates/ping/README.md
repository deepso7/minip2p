# minip2p-ping

Sans-IO state machine for the `/ipfs/ping/1.0.0` protocol. `no_std` + `alloc` compatible.

Ping measures round-trip latency by sending a 32-byte payload and waiting for the remote peer to echo it back verbatim.

## Features

- Dialer sends ping, listener echoes -- both handled by the same `PingProtocol` instance.
- Fragmentation-safe: buffers partial payloads on both inbound and outbound paths.
- Configurable request timeout with `PingConfig`.
- RTT measurement via caller-provided timestamps (no internal clock dependency).
- `PingAction` commands (`Send`, `CloseStreamWrite`, `ResetStream`) for the host to execute.
- `PingEvent` notifications (`RttMeasured`, `Timeout`, `ProtocolViolation`, etc.).
- Per-peer state tracking with inbound stream limits.

## Usage

```rust
use minip2p_ping::{PingProtocol, PingConfig, PingAction, PingEvent, PING_PAYLOAD_LEN};
use minip2p_transport::StreamId;
use minip2p_core::PeerId;

let mut ping = PingProtocol::new(PingConfig::default());

// After protocol negotiation succeeds on a stream, register it:
// ping.register_outbound_stream(&peer_id, stream_id);
// ping.register_inbound_stream(&peer_id, stream_id);

// Send a ping (caller provides the payload and current timestamp):
// let actions = ping.send_ping(&peer_id, payload, now_ms)?;

// Feed incoming stream data:
// let actions = ping.on_stream_data(&peer_id, stream_id, &data, now_ms);

// Check for timeouts periodically:
// let actions = ping.on_tick(now_ms);

// Drain events:
// let events = ping.poll_events();
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

This crate implements the ping protocol state machine only. It does not open streams, send bytes over the network, or negotiate protocols. The host is responsible for wiring `PingAction` commands to the transport and feeding transport events back into `PingProtocol`.
