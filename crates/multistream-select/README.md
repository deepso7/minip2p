# minip2p-multistream-select

Sans-IO state machine for the `/multistream/1.0.0` protocol negotiation. `no_std` + `alloc` compatible.

This crate implements the [multistream-select](https://github.com/multiformats/multistream-select) handshake used by libp2p to agree on a protocol for a newly opened stream.

## Features

- Varint-length-prefixed wire format (spec-compliant framing).
- Dialer and listener roles.
- Incremental `MultistreamInput::Data` handling for chunked/partial input.
- `MultistreamOutput` events for outbound data, negotiation result, and errors.
- Typed `MultistreamError` with actionable context.
- Zero-copy decoding where possible.

## Wire format

Each message is framed as:

```
<uvarint: length of payload + newline> <payload> <\n>
```

## Usage

Negotiate a protocol between a dialer and listener:

```rust
use minip2p_core::SansIoProtocol;
use minip2p_multistream_select::{
    MultistreamInput, MultistreamOutput, MultistreamSelect, MULTISTREAM_PROTOCOL_ID,
};

// Dialer side
let mut dialer = MultistreamSelect::dialer("/ipfs/ping/1.0.0");
dialer.handle_input(MultistreamInput::Start)?; // queues multistream header

// Listener side
let mut listener = MultistreamSelect::listener(["/ipfs/ping/1.0.0".to_string()]);
listener.handle_input(MultistreamInput::Start)?; // queues multistream header

// Feed received bytes into each side:
// dialer.handle_input(MultistreamInput::Data(bytes_from_listener))?;
// listener.handle_input(MultistreamInput::Data(bytes_from_dialer))?;
//
// Drain outputs and check for MultistreamOutput::Negotiated { protocol }
// to know when negotiation succeeds, or MultistreamOutput::NotAvailable
// if the listener does not support the requested protocol.
// while let Some(output) = dialer.poll_output() {
//     handle(output);
// }
```

## no_std

Disable default features:

```toml
[dependencies]
minip2p-multistream-select = { path = "crates/multistream-select", default-features = false }
```

## Scope

This crate handles single-protocol negotiation only. It does not implement `ls` or multi-protocol fallback. Concrete transport integration (feeding stream bytes in, sending outbound data out) is the caller's responsibility.
