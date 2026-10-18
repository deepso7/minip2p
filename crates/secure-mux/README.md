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

The Noise and Yamux state machines the session drives are public modules of their own, `noise` and `yamux`, for hosts and tests that need them directly; see [Noise](#noise) and [Yamux](#yamux) below.

Relay circuits and TCP connections differ only in what the byte stream _is_ — a relayed stream through a third peer, or a socket — so both drive this one component rather than each carrying its own copy of the state machine.

## Usage

The session owns no socket, no clock, and no executor. Feed it bytes read from the underlying stream, drain its events with `poll_output`, and pull bytes to write with `poll_write` -- but only while the stream below has room. Once the session is up, each `poll_write` frames and encrypts the next Yamux frame on demand, so a downstream that stops taking bytes stops the session from producing them (ADR 0012). After the upgrade, `poll(now)` / `next_deadline()` drive Yamux keepalive from the host's time sample; keep polling on the deadline even while the stream below is full, since a ping that cannot leave is how a backed-up connection to a dead peer is caught:

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
        stream.write_all(&bytes)?;
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

Input is fed to the decoders in batches of at most `MAX_INPUT_BATCH` (64 KiB), so a large read cannot grow them further.

Substreams are driven with `open_stream`, `send`, `close_stream_write`, `reset_stream`, and `set_control_stream` (which lets a substream queue into Yamux's control reserve); their frames come out of later `poll_write` calls. `send` takes a `Bytes` payload and accepts as much as the substream's Yamux send caps allow; the rest comes back as `YamuxError::Full` carrying the exact unsent suffix, and `StreamWritable` follows once the substream can queue again. Received data and events never wait behind outbound frames, and control replies a peer provokes without reading them are bounded by `YamuxConfig::max_pending_control`. Before Yamux is up, the same holds for negotiation and handshake replies: a session holding more than 64 KiB of them unread fails the upgrade.

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
- `SessionError::close_reason` maps a session-ending error to the connection's `ConnectionCloseReason`: a GoAway is `Remote { code }`, a keepalive timeout (`YamuxError::KeepaliveTimeout`) is `TimedOut`, anything else is `Error`.

## Noise

`minip2p_secure_mux::noise` is a small, caller-driven implementation of libp2p's Noise security protocol. It implements `Noise_XX_25519_ChaChaPoly_SHA256`, including libp2p identity binding, cryptographic peer-ID verification, and the two-byte libp2p framing used for both handshake and transport messages.

The module is Sans-I/O and supports `no_std + alloc`. Callers provide fresh X25519 static and ephemeral secrets for every session, feed received bytes into the state machine, and write the emitted outbound bytes using their own I/O adapter. It does not own randomness, sockets, clocks, or timers.

Handshake payload field framing uses the shared protobuf vocabulary in `minip2p-core`. Invalid field numbers are rejected by the shared decoder as `NoiseError::Wire`. Identity-binding rules, duplicate-field checks, and contextual `NoiseError` values stay in this module.

Transport plaintext is automatically segmented at 65,519 bytes so every encrypted message, including its 16-byte authentication tag, fits the 65,535 byte wire-frame limit. Each segment is copied once into its outbound frame and encrypted there; received frames are decrypted in place, and a received buffer holding exactly one frame is reused rather than reallocated.

Once the handshake completes, `NoiseSession::handshake_hash` returns the final handshake hash `h`. Both ends compute the same value, so it names the session on either side (channel binding, in Noise terms).

Interoperability fixtures and how to regenerate them are described in [`tests/fixtures/noise`](tests/fixtures/noise/README.md).

## Yamux

`minip2p_secure_mux::yamux` is a small, caller-driven, Sans-I/O implementation of the libp2p Yamux stream multiplexer (`/yamux/1.0.0`). It runs with `no_std + alloc` and leaves sockets, clocks, and task scheduling to its caller. Keepalive follows go-yamux: a session that has received no frame for 30 seconds queues a ping (outbound traffic does not postpone it), which must be pulled with `poll_frame` within 10 seconds and acknowledged with its nonce within 10 seconds after that. Missing either bound fails the session with `YamuxError::KeepaliveTimeout`. The host drives it with `YamuxSession::poll` time samples; the session never reads a clock.

The session bounds inbound frame lengths, stream count, per-stream queued sends, aggregate queued sends, and peer-provoked control replies (`max_pending_control`, which also covers resets of peer-opened streams: a peer can open streams without bound). `send` takes a `Bytes` payload and accepts as much as the send caps allow, whatever the remote window; the rest comes back as `YamuxError::Full` with the exact unsent suffix, and `YamuxOutput::Writable` fires once the stream can queue at least half of the smaller of its stream cap and the total cap it may fill again (a control stream needs at most half a non-zero reserve). `control_stream_reserve` (256 KiB of the 4 MiB total cap) is kept for streams marked with `set_control`, so application streams cannot starve the swarm's negotiation, ping and Identify streams. Accepted bytes count against the caps until the host pulls a frame carrying them with `poll_frame`, so a host that pulls only while its socket has room keeps ciphertext bounded too. Events (`poll_event`) and frames (`poll_frame`) leave separately, so inbound data never waits behind outbound frames. The session tracks which streams owe a window update or have a frame to pull, so `poll_frame` and `has_frames` never scan idle streams; data frames rotate round-robin across sendable streams. A partly framed payload stays a slice of the caller's buffer until its tail is shorter than half of it, so queued sends hold at most twice the capped bytes, provided each payload owns its allocation: a `Bytes` slice of a larger buffer keeps that whole buffer alive while queued. Receive credit is read-driven (ADR 0012): a stream's window update goes out only for bytes its reader acknowledged with `ack`, so a stream holds at most `receive_window` unacknowledged bytes and a reader that never acknowledges stalls its sender. A stream that closes with unacknowledged bytes stays unsettled and keeps its slot against `max_streams` until they are acknowledged or a local `reset` abandons them, so stream churn cannot grow retained data past `max_streams` × `receive_window`; input never has to stop. The counts outlive the session: after a GoAway or a protocol failure, `unsettled_streams` lists them for the host to take over, and `ack` and `reset` still settle them. Acknowledging more than a stream's unacknowledged bytes is `YamuxError::AckExceedsDelivered`.

Clients allocate odd stream IDs and servers allocate even stream IDs. The default `receive_window` is the specification's 256 KiB (`DEFAULT_RECEIVE_WINDOW`). A host may raise it for long, fat paths; a stream still starts from the 256 KiB credit, and the difference is granted with its first window update.

The interoperability fixture is described in [`tests/fixtures/yamux`](tests/fixtures/yamux/README.md). The `data_path` and `data_path_ir` benches measure the Yamux session's send and receive paths.

## no_std

Disable default features:

```toml
[dependencies]
minip2p-secure-mux = { path = "crates/secure-mux", default-features = false }
```

## License

MIT
