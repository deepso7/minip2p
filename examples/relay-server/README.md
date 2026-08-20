# Relay-server host

Run a Circuit Relay v2 server on QUIC and TCP with production defaults:

```bash
cargo run -p minip2p-relay-server-example
```

The application path represented by that default is deliberately small:

```rust
let endpoint = Endpoint::builder()
    .relay_server()
    .bind_quic_dual_stack()?;
```

The example binds both transports on `0.0.0.0:4001`, prints dialable addresses
with its peer identity, and renders typed reservation/circuit lifecycle events,
directional byte totals, denial statuses, close causes, and operational errors.
Type `pause` or `resume` on stdin to change admission without removing HOP from
Identify or terminating existing reservations and circuits.

For a stable public identity and explicit advertised addresses:

```bash
cargo run -p minip2p-relay-server-example -- \
  --key var/relay.ed25519 \
  --announce /dns4/relay.example.com/tcp/4001 \
  --announce /dns4/relay.example.com/udp/4001/quic-v1
```

The key file is created owner-only on Unix and never overwritten. Configuration
and address errors are reported before transport binding where possible. Run
with `--help` for capacity, duration, byte, pending-control, timeout, and fixed
peer/IP token-bucket flags. A rate flag accepts `CAPACITY/REFILL_MS` or `off`.
Zero circuit duration/bytes mean unlimited; zero capacities deny new work.

Explicit announce addresses are trusted operator input and take precedence over
AutoNAT-confirmed direct addresses and concrete listeners. Wildcards, circuit
addresses, unsupported shapes, and conflicting `/p2p` identities are rejected.
