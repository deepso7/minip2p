# minip2p-identify

Sans-IO state machine for the `/ipfs/id/1.0.0` identify protocol. `no_std` + `alloc` compatible.

Identify is the libp2p handshake that lets two peers exchange their supported protocols, listen addresses, agent version, and observed addresses after a connection is established. It is a prerequisite for relay reservations, hole-punch coordination, and most protocol-discovery flows.

## Features

- Single `IdentifyProtocol` instance handles both roles on the same peer:
  - **Responder** (listener side): sends our identify message and closes the write half.
  - **Initiator** (dialer side): reads the remote's identify message and surfaces it as an event.
- Per-peer state tracking with multi-stream support.
- Protobuf encode/decode for `IdentifyMessage` (field-number order on encode, any-order accept on decode; unknown fields with known wire types are silently skipped).
- 8 KiB inbound message size cap.
- Peer-id migration support for swarms that discover the real `PeerId` after connection establishment.
- `IdentifyAction` commands (`Send`, `CloseStreamWrite`) for the host to execute.
- `IdentifyEvent` notifications (`Received`, `Error`).

## Usage

```rust
use minip2p_core::{Multiaddr, PeerId};
use minip2p_identify::{IdentifyConfig, IdentifyProtocol};
use minip2p_transport::StreamId;

let config = IdentifyConfig {
    protocol_version: "minip2p/0.1.0".into(),
    agent_version: "my-app/0.1.0".into(),
    protocols: vec!["/ipfs/ping/1.0.0".into()],
    public_key: vec![/* protobuf PublicKey */],
};
let mut identify = IdentifyProtocol::new(config);

// After multistream-select negotiates /ipfs/id/1.0.0:
//   - inbound stream (we respond):
//     let actions = identify.register_outbound_stream(
//         peer_id,
//         stream_id,
//         Some(remote_addr),   // observed_addr
//         &listen_addrs,       // from the transport
//     )?;
//   - outbound stream (we receive the remote's info):
//     identify.register_inbound_stream(peer_id, stream_id);

// Feed stream data / lifecycle events:
// identify.on_stream_data(peer_id, stream_id, data);
// let actions = identify.on_stream_remote_write_closed(peer_id, stream_id);
// identify.on_stream_closed(peer_id, stream_id);

// Drain events and run actions through the host/transport:
// let events = identify.poll_events();
```

`observed_addr` should be the transport address we observed the remote dialing us from. Pass `None` when the information is not available.

`listen_addrs` is the set of multiaddrs we're currently listening on. Typically the swarm driver snapshots this from the transport's `local_addresses()` on each `poll()` tick and passes it through — so the advertised set always reflects what we're actually bound to, with no caller ceremony required.

## Protocol

- Protocol ID: `/ipfs/id/1.0.0`
- Wire format: a varint length prefix followed by a protobuf-encoded `Identify` message, then the responder half-closes its write side.
- Fields: `publicKey`, `listenAddrs` (repeated, multicodec-binary), `protocols` (repeated), `observedAddr` (multicodec-binary), `protocolVersion`, `agentVersion`.

## no_std

Disable default features:

```toml
[dependencies]
minip2p-identify = { path = "crates/identify", default-features = false }
```

## Scope

This crate implements the identify protocol state machine only. It does not open streams, perform multistream-select, or serialize multiaddrs. The host is responsible for driving negotiation, plumbing `IdentifyAction` commands to the transport, and feeding transport events back into `IdentifyProtocol`.
