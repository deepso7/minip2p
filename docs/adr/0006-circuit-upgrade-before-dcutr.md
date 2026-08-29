# Circuit upgrade before DCUtR

A Circuit Relay v2 bridge is upgraded with Noise and Yamux into a Relayed path before any DCUtR. Hole punching is `/libp2p/dcutr` on that connection, matching Circuit Relay v2, DCUtR, rust-libp2p, and go-libp2p. `force_relay` only skips direct dials and the punch; it does not change the circuit handshake.

We rejected keeping DCUtR on the raw bridge as a Noise barrier (current default) and rejected skipping DCUtR only when `force_relay` is set. The first never Relayed-interop with rust-libp2p or go-libp2p. The second is #116: Node Relayed tests set `forceRelay`, rust `.relay()` does not, so one side starts Noise while the other still parses HolePunch.

## Consequences

- `Path::Relayed` is available as soon as the circuit connection is established, even if punching never runs or fails.
- Existing NAT tests that promote only after SYNC, and any in-tree work that still completes DCUtR on the unpromoted bridge, are wrong under this decision.
