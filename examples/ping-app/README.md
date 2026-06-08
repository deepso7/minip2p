# minip2p-ping-app

Small app-facing example for the top-level `minip2p` facade.

It creates two loopback QUIC endpoints, listens on one, dials it from the
other, waits for Identify to mark the peer ready, sends one ping, and prints
the measured RTT.

```bash
cargo run -p minip2p-ping-app
```

The example keeps the tiny two-endpoint poll loop local. Real applications
usually have their own runtime loop and can poll one endpoint at a time with
`Endpoint::poll`, `Endpoint::next_event`, or the lower-level `SwarmCore`
Sans-I/O API.
