# minip2p-stun

Sans-IO STUN Binding client helpers. `no_std` compatible.

This crate implements only STUN wire messages needed for UDP mapping discovery:

- Build RFC5389 Binding Requests.
- Parse Binding Success Responses.
- Decode `XOR-MAPPED-ADDRESS` and legacy `MAPPED-ADDRESS` attributes.

It does not own sockets, resolve DNS, choose STUN servers, retry, or read clocks.
Runtime adapters provide those pieces and feed packets into `BindingClient`.

## Usage

```rust
use minip2p_stun::BindingClient;

let transaction_id = [7u8; 12];
let client = BindingClient::new(transaction_id);
let request = client.binding_request();

// Runtime sends `request` to a STUN server and feeds replies back:
// if let Some(mapped) = client.parse_response(&packet)? {
//     // advertise `mapped` as a UDP candidate
// }
```

## no_std

Disable default features:

```toml
[dependencies]
minip2p-stun = { path = "crates/stun", default-features = false }
```
