# Connections before their peer identity is known

Some transports (mutual-TLS QUIC) report `Connected` before `PeerIdentityVerified`. The swarm does not wait to run its protocols:

- `SwarmState` gives such a connection a synthetic placeholder `PeerId` (`ensure_peer_id_for_conn`) so the ping and Identify handlers can run, but emits no `ConnectionEstablished` until the real identity arrives.
- On `PeerIdentityVerified`, `upgrade_connection_identity` moves everything gathered under the placeholder (ping and Identify state, the running ping attempt, peer info, buffered events) to the verified peer, since it belongs to this connection. The ping attempt moves before the ping outputs are drained, so the drain does not mistake it for one that lost its stream. The verified connection is then the newest and is handed over exactly as on `Connected`, subject to the connection race.
- `PeerIdentityVerified` also refreshes the recorded remote transport address (the source of Identify's `observedAddr`), which the transport may report more accurately there than on `Connected`.
- A placeholder connection that closes was never announced, so it gets no `ConnectionClosed`: `discard_placeholder` drops its protocol state and every queued event naming it, acknowledging any dropped `StreamData`. Established peers are never discarded this way.
