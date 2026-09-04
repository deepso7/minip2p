# minip2p-secure-mux

Sans-I/O secure, multiplexed session over an ordered byte stream. `no_std` + `alloc` compatible.

Drives the libp2p upgrade stack that every stream-oriented transport needs:

```text
ordered byte stream
  -> multistream-select  (/noise)
  -> Noise XX            (authenticates the remote peer)
  -> multistream-select  (/yamux/1.0.0, encrypted)
  -> Yamux               (libp2p substreams)
```

Relay circuits and TCP connections differ only in what the byte stream *is* — a relayed stream through a third peer, or a socket — so both drive this one component rather than each carrying its own copy of the state machine.

## Usage

The session owns no socket, no clock, and no executor. Feed it bytes read from the underlying stream, then drain outputs and write every `Write` back to that stream. After the upgrade, `poll(now)` / `next_deadline()` drive Yamux keepalive from the host's time sample:

```rust
use minip2p_secure_mux::{SecureMuxSession, SessionConfig, SessionOutput, SessionRole, YamuxConfig};

let mut session = SecureMuxSession::new(SessionConfig {
    role: SessionRole::Initiator,
    identity,
    static_secret,
    ephemeral_secret,
    expected_peer: Some(remote_peer),
    yamux: YamuxConfig::default(),
});

session.start()?;

loop {
    while let Some(output) = session.poll_output() {
        match output {
            SessionOutput::Write(bytes) => stream.write_all(&bytes)?,
            SessionOutput::Established { peer } => { /* connection policy */ }
            SessionOutput::IncomingStream { stream } => { /* accept substream */ }
            SessionOutput::StreamData { stream, data } => { /* deliver */ }
            SessionOutput::StreamRemoteWriteClosed { stream } => { /* half close */ }
            SessionOutput::StreamClosed { stream } => { /* forget */ }
        }
    }
    session.handle_input(stream.read()?)?;
}
```

Substreams are driven with `open_stream`, `send`, `close_stream_write`, and `reset_stream`; each queues outbound bytes as further `Write` outputs.

## Policy stays with the caller

`SessionOutput::Established` reports that the upgrade finished and the remote identity is cryptographically verified. It deliberately does **not** decide whether the connection should be kept.

That matters because hosts differ: one races a direct dial against a relayed one and drops the loser, another de-duplicates connections per peer, an embedded node may accept whatever arrives. The session reports the verified peer and lets the caller apply its own rule, tearing the session down if it loses. `Established` is ordered ahead of any substream output, so a caller always sees the peer before it has to decide anything about a stream.

Peer *verification* is not policy and is not optional: set `expected_peer` and Noise fails the handshake if the remote proves a different identity.

## Errors

- `SessionError::Protocol` is fatal — tear the connection down.
- `SessionError::GoAway` is fatal too, but the remote ended the session deliberately: a `code` of 0 is an orderly shutdown, so a caller that surfaces failures to its host should close quietly rather than report an error the remote never made. Every open substream goes with it, so drain outputs after the error to collect a `StreamClosed` for each.
- `SessionError::NotEstablished` means a substream operation ran before the upgrade completed. The session is untouched and still mid-upgrade; from `go_away` it means there is nothing to shut down, so just drop the underlying stream.
- `SessionError::UnknownStream` means the id does not name a substream of this session. Ids are rejected rather than truncated, so a fabricated one can never alias onto somebody else's substream. The session stays usable.
- `SessionError::Yamux` is passed through so callers can distinguish a full send buffer (retry later) from a fatal failure.

## no_std

Disable default features:

```toml
[dependencies]
minip2p-secure-mux = { path = "crates/secure-mux", default-features = false }
```

## License

MIT

## Throwaway stream experiment

On `prototype/stream-dx`, the `prototype_*` methods support the real TCP experiment for issue #149. Pull receive credit advances only when the caller reads. The option defaults off. This is an open-stream experiment; cancellation, reset, FIN cleanup, and the full Endpoint readiness contract remain unfinished. See [the experiment report](../minip2p/prototypes/stream-dx/TCP_RESULTS.md).
