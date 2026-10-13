# minip2p-autonat

Sans-IO state machines for libp2p AutoNAT v1 reachability probes. `no_std` + `alloc` compatible.

AutoNAT answers whether a peer's advertised addresses are actually dialable by another libp2p peer. It is different from STUN: it validates the real libp2p dial path rather than only discovering what address a third-party UDP server observed.

## Scope

This crate implements message framing, encoding/decoding, and the client/server probe state machines. Protobuf field framing uses the shared vocabulary in `minip2p-core`; invalid field numbers surface as `AutoNatError::Wire`; semantic validation and contextual `AutoNatError` values stay here. It does **not**:

- Open streams.
- Dial candidate addresses.
- Read clocks or schedule retries.
- Decide relay policy.

Runtime adapters or applications perform dial-back attempts and feed the result back into the server state machine.

## Protocol ID

- `AUTONAT_PROTOCOL_ID = "/libp2p/autonat/1.0.0"`

## Usage Sketch

Each machine takes inputs through methods named for what they do (`on_data`, `on_remote_write_closed`, `respond_public`, `respond_error`) and exposes `poll_output`. After construction and after every input, drain `poll_output` until it returns `None` before waiting on the stream again.

```rust
use minip2p_autonat::{AutoNatClient, AutoNatClientOutput, AutoNatServer, AutoNatServerOutput};

let mut client = AutoNatClient::new(&our_peer_id, &candidate_addrs);
let mut server = AutoNatServer::new();

while let Some(AutoNatClientOutput::Outbound(bytes)) = client.poll_output() {
    send_to_server(bytes);
}

server.on_data(&bytes_from_client)?;
while let Some(output) = server.poll_output() {
    match output {
        AutoNatServerOutput::Request(request) => {
            // Runtime dials request.addrs for request.peer_id, then responds:
            server.respond_public(&request.addrs);
        }
        AutoNatServerOutput::Outbound(bytes) => send_to_client(bytes),
    }
}
```

## Client outcomes

The client remembers exactly which addresses its request carried (after trimming to one frame). An `OK` response is `Reachability::Public` only for the requested addresses it names, matched exactly or with a trailing `/p2p/<our peer id>`; unrelated or malformed addresses are dropped, and an `OK` naming none of them is `Unknown`. `E_DIAL_ERROR` is `Private`. `E_DIAL_REFUSED` (often rate limiting), `E_BAD_REQUEST` and `E_INTERNAL_ERROR` are `Unknown`: they say nothing about our reachability. Aggregating outcomes across servers is the caller's policy; `minip2p-nat` requires a quorum of distinct servers.

## Size limits

Messages carry at most 8192 payload bytes. The declared length is checked from the frame header, so a message at exactly the maximum is accepted — including one that arrives with pipelined bytes behind it — while bytes that could never complete a legal frame are refused before they are buffered. Outgoing messages respect the same limit, so neither side puts a frame on the wire that the other is required to refuse: a DIAL request or DIAL_RESPONSE carries the given addresses in order, skipping any that would not fit, and a response's status text is cut to `MAX_STATUS_TEXT` (1024) bytes.

## no_std

Disable default features:

```toml
[dependencies]
minip2p-autonat = { path = "crates/autonat", default-features = false }
```
