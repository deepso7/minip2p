# minip2p-autonat

Sans-IO state machines for libp2p AutoNAT v1 reachability probes. `no_std` + `alloc` compatible.

AutoNAT answers whether a peer's advertised addresses are actually dialable by another libp2p peer. It is different from STUN: it validates the real libp2p dial path rather than only discovering what address a third-party UDP server observed.

## Scope

This crate implements message framing, encoding/decoding, and the client/server probe state machines. It does **not**:

- Open streams.
- Dial candidate addresses.
- Read clocks or schedule retries.
- Decide relay policy.

Runtime adapters or applications perform dial-back attempts and feed the result back into the server state machine.

## Protocol ID

- `AUTONAT_PROTOCOL_ID = "/libp2p/autonat/1.0.0"`

## Usage Sketch

```rust
use minip2p_autonat::{AutoNatClient, AutoNatServer, Reachability};

let mut client = AutoNatClient::new(&our_peer_id, &candidate_addrs);
let outbound = client.take_outbound(); // send on an outbound AutoNAT stream

let mut server = AutoNatServer::new();
server.on_data(&outbound)?;
if let Some(request) = server.request() {
    // Runtime dials request.addrs for request.peer_id, then responds:
    server.respond_public(&request.addrs);
}
```

## no_std

Disable default features:

```toml
[dependencies]
minip2p-autonat = { path = "crates/autonat", default-features = false }
```
