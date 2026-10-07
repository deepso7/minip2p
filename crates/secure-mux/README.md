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

Relay circuits and TCP connections differ only in what the byte stream _is_ — a relayed stream through a third peer, or a socket — so both drive this one component rather than each carrying its own copy of the state machine.

## Usage

The session owns no socket, no clock, and no executor. Feed it bytes read from the underlying stream, drain its events with `poll_output`, and pull bytes to write with `poll_write` -- but only while the stream below has room. Once the session is up, each `poll_write` frames and encrypts the next Yamux frame on demand, so a downstream that stops taking bytes stops the session from producing them (ADR 0012). After the upgrade, `poll(now)` / `next_deadline()` drive Yamux keepalive from the host's time sample:

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
    while stream.has_room() {
        let Some(bytes) = session.poll_write()? else { break };
        stream.write(&bytes)?;
    }
    while let Some(output) = session.poll_output() {
        match output {
            SessionOutput::Established { peer, .. } => { /* connection policy */ }
            SessionOutput::IncomingStream { stream } => { /* accept substream */ }
            SessionOutput::StreamData { stream, data } => { /* deliver */ }
            SessionOutput::StreamRemoteWriteClosed { stream } => { /* half close */ }
            SessionOutput::StreamClosed { stream } => { /* forget */ }
            SessionOutput::StreamWritable { stream } => { /* resend a held tail */ }
        }
    }
    session.handle_input(stream.read()?)?;
}
```

Substreams are driven with `open_stream`, `send`, `close_stream_write`, and `reset_stream`; their frames come out of later `poll_write` calls. `send` takes a `Bytes` payload and accepts as much as the substream's Yamux send caps allow; the rest comes back as `YamuxError::Full` carrying the exact unsent suffix, and `StreamWritable` follows once the substream can queue again. Received data and events never wait behind outbound frames, and control replies a peer provokes without reading them are bounded by `YamuxConfig::max_pending_control`.

## Policy stays with the caller

`SessionOutput::Established` reports that the upgrade finished and the remote identity is cryptographically verified. It also carries the final Noise handshake hash, which both ends of the session share, so a host can name the connection identically on either side (the TCP transport uses it as its `ConnectionToken`). It deliberately does **not** decide whether the connection should be kept.

That matters because hosts differ: one races a direct dial against a relayed one and drops the loser, another de-duplicates connections per peer, an embedded node may accept whatever arrives. The session reports the verified peer and lets the caller apply its own rule, tearing the session down if it loses. `Established` is ordered ahead of any substream output, so a caller always sees the peer before it has to decide anything about a stream.

Peer _verification_ is not policy and is not optional: set `expected_peer` and Noise fails the handshake if the remote proves a different identity.

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
