//! Drives two sessions against each other over an in-memory byte stream.
//!
//! This is the property the circuit transport relies on and that a TCP
//! transport will rely on next: two `SecureMuxSession`s wired back to back
//! complete the whole upgrade and carry substream traffic, with no socket,
//! clock, or executor anywhere.

use minip2p_identity::{Ed25519Keypair, PeerId};
use minip2p_platform::{Deadline, Now};
use minip2p_secure_mux::{
    KEEPALIVE_INTERVAL_MS, SecureMuxSession, SessionConfig, SessionError, SessionOutput,
    SessionRole, YamuxConfig,
};
use minip2p_transport::StreamId;

fn session(
    role: SessionRole,
    identity: Ed25519Keypair,
    expected: Option<&Ed25519Keypair>,
) -> SecureMuxSession {
    session_with(role, identity, expected, YamuxConfig::default())
}

fn session_with(
    role: SessionRole,
    identity: Ed25519Keypair,
    expected: Option<&Ed25519Keypair>,
    yamux: YamuxConfig,
) -> SecureMuxSession {
    let seed = match role {
        SessionRole::Initiator => 1u8,
        SessionRole::Responder => 2,
    };
    SecureMuxSession::new(SessionConfig {
        role,
        identity,
        static_secret: [seed; 32],
        ephemeral_secret: [seed.wrapping_add(0x10); 32],
        expected_peer: expected.map(|keypair| keypair.peer_id()),
        yamux,
    })
}

/// Pumps writes between the two sides until neither produces more, collecting
/// every non-write output per side.
fn exchange(
    a: &mut SecureMuxSession,
    b: &mut SecureMuxSession,
) -> (Vec<SessionOutput>, Vec<SessionOutput>) {
    let mut a_events = Vec::new();
    let mut b_events = Vec::new();

    for _ in 0..64 {
        let mut moved = false;

        while let Some(output) = a.poll_output() {
            match output {
                SessionOutput::Write(bytes) => {
                    moved = true;
                    b.handle_input(bytes).expect("peer accepts bytes");
                }
                other => a_events.push(other),
            }
        }
        while let Some(output) = b.poll_output() {
            match output {
                SessionOutput::Write(bytes) => {
                    moved = true;
                    a.handle_input(bytes).expect("peer accepts bytes");
                }
                other => b_events.push(other),
            }
        }

        if !moved {
            break;
        }
    }

    (a_events, b_events)
}

fn established_peer(events: &[SessionOutput]) -> Option<&PeerId> {
    events.iter().find_map(|event| match event {
        SessionOutput::Established { peer } => Some(peer),
        _ => None,
    })
}

fn stream_payloads(events: &[SessionOutput]) -> Vec<&[u8]> {
    events
        .iter()
        .filter_map(|event| match event {
            SessionOutput::StreamData { data, .. } => Some(data.as_slice()),
            _ => None,
        })
        .collect()
}

fn upgraded_pair() -> (SecureMuxSession, SecureMuxSession, PeerId, PeerId) {
    let dialer_key = Ed25519Keypair::generate();
    let listener_key = Ed25519Keypair::generate();
    let (dialer_peer, listener_peer) = (dialer_key.peer_id(), listener_key.peer_id());

    let mut dialer = session(SessionRole::Initiator, dialer_key, Some(&listener_key));
    let mut listener = session(SessionRole::Responder, listener_key, None);
    dialer.start().expect("initiator starts");
    listener.start().expect("responder starts");
    let _ = exchange(&mut dialer, &mut listener);

    (dialer, listener, dialer_peer, listener_peer)
}

#[test]
fn two_sessions_complete_the_upgrade_and_authenticate_each_other() {
    let dialer_key = Ed25519Keypair::generate();
    let listener_key = Ed25519Keypair::generate();
    let (dialer_peer, listener_peer) = (dialer_key.peer_id(), listener_key.peer_id());

    let mut dialer = session(SessionRole::Initiator, dialer_key, Some(&listener_key));
    let mut listener = session(SessionRole::Responder, listener_key, None);

    dialer.start().expect("initiator starts");
    listener.start().expect("responder starts");

    let (dialer_events, listener_events) = exchange(&mut dialer, &mut listener);

    assert!(dialer.is_established(), "dialer must finish the upgrade");
    assert!(
        listener.is_established(),
        "listener must finish the upgrade"
    );

    // Each side learns the other's real identity, not its own.
    assert_eq!(established_peer(&dialer_events), Some(&listener_peer));
    assert_eq!(established_peer(&listener_events), Some(&dialer_peer));
    assert_eq!(dialer.peer(), Some(&listener_peer));
    assert_eq!(listener.peer(), Some(&dialer_peer));
}

/// Feeds every write `from` has queued to `to` as one input, so `to` decrypts
/// the whole batch in a single `handle_input`.
fn flush_batched(from: &mut SecureMuxSession, to: &mut SecureMuxSession) -> Vec<SessionOutput> {
    let mut batch = Vec::new();
    let mut events = Vec::new();
    while let Some(output) = from.poll_output() {
        match output {
            SessionOutput::Write(bytes) => batch.extend_from_slice(&bytes),
            other => events.push(other),
        }
    }
    if !batch.is_empty() {
        to.handle_input(batch).expect("peer accepts the batch");
    }
    events
}

/// Drains everything `session` has queued, concatenating the writes in order
/// and discarding the rest.
fn take_writes(session: &mut SecureMuxSession) -> Vec<u8> {
    let mut batch = Vec::new();
    while let Some(output) = session.poll_output() {
        if let SessionOutput::Write(bytes) = output {
            batch.extend_from_slice(&bytes);
        }
    }
    batch
}

/// Drives the upgrade one-sidedly until the listener is up, leaving its own
/// replies unread by the dialer.
///
/// That asymmetry is the point: the listener can then act as an established
/// peer while the dialer still has its Yamux confirmation queued, so whatever
/// the listener sends next arrives packed with that confirmation in a single
/// batch.
fn drive_until_listener_established(
    dialer: &mut SecureMuxSession,
    listener: &mut SecureMuxSession,
) {
    for _ in 0..32 {
        let _ = flush_batched(dialer, listener);
        if listener.is_established() {
            break;
        }
        // The listener's reply is needed for the dialer to make progress.
        let batch = take_writes(listener);
        if batch.is_empty() {
            break;
        }
        dialer.handle_input(batch).expect("dialer accepts");
    }
    assert!(listener.is_established(), "listener must finish first");
}

#[test]
fn established_is_reported_before_any_stream_output() {
    let dialer_key = Ed25519Keypair::generate();
    let listener_key = Ed25519Keypair::generate();
    let mut dialer = session(SessionRole::Initiator, dialer_key, Some(&listener_key));
    let mut listener = session(SessionRole::Responder, listener_key, None);
    dialer.start().expect("start");
    listener.start().expect("start");

    drive_until_listener_established(&mut dialer, &mut listener);

    // Now the listener opens a substream and sends before the dialer has read
    // its Yamux confirmation, so the dialer decrypts the confirmation and the
    // frames in one batch -- the pipelined path.
    let stream = listener.open_stream().expect("open substream");
    listener.send(stream, b"pipelined".to_vec()).expect("send");

    let dialer_events = {
        let batch = take_writes(&mut listener);
        dialer
            .handle_input(batch)
            .expect("dialer accepts the batch");
        let mut events = Vec::new();
        while let Some(output) = dialer.poll_output() {
            if !matches!(output, SessionOutput::Write(_)) {
                events.push(output);
            }
        }
        events
    };

    // The batch really did carry both, or this test proves nothing.
    let established = dialer_events
        .iter()
        .position(|event| matches!(event, SessionOutput::Established { .. }))
        .expect("dialer established in this batch");
    let first_stream = dialer_events
        .iter()
        .position(|event| {
            matches!(
                event,
                SessionOutput::IncomingStream { .. } | SessionOutput::StreamData { .. }
            )
        })
        .expect("pipelined stream output in the same batch");

    // A caller applying connection policy on `Established` must see it before
    // it has to decide anything about a stream.
    assert!(
        established < first_stream,
        "Established must precede stream output: {dialer_events:?}"
    );
    assert_eq!(
        stream_payloads(&dialer_events),
        vec![b"pipelined".as_slice()]
    );
}

#[test]
fn substreams_carry_data_in_both_directions() {
    let (mut dialer, mut listener, _, _) = upgraded_pair();

    let stream = dialer.open_stream().expect("open substream");
    dialer
        .send(stream, b"ping".to_vec())
        .expect("send on substream");
    let (_, listener_events) = exchange(&mut dialer, &mut listener);

    let incoming: Vec<StreamId> = listener_events
        .iter()
        .filter_map(|event| match event {
            SessionOutput::IncomingStream { stream } => Some(*stream),
            _ => None,
        })
        .collect();
    assert_eq!(incoming.len(), 1, "listener must see one substream");
    assert_eq!(stream_payloads(&listener_events), vec![b"ping".as_slice()]);

    // ...and back the other way on the same substream.
    listener
        .send(incoming[0], b"pong".to_vec())
        .expect("reply on substream");
    let (dialer_events, _) = exchange(&mut dialer, &mut listener);
    assert_eq!(stream_payloads(&dialer_events), vec![b"pong".as_slice()]);
}

#[test]
fn half_close_and_reset_reach_the_remote() {
    let (mut dialer, mut listener, _, _) = upgraded_pair();

    let stream = dialer.open_stream().expect("open substream");
    dialer.send(stream, b"data".to_vec()).expect("send");
    dialer.close_stream_write(stream).expect("half close");
    let (_, listener_events) = exchange(&mut dialer, &mut listener);

    assert!(
        listener_events
            .iter()
            .any(|event| matches!(event, SessionOutput::StreamRemoteWriteClosed { .. })),
        "half close must surface remotely: {listener_events:?}"
    );

    let second = dialer.open_stream().expect("open second substream");
    dialer.reset_stream(second).expect("reset");
    let (_, listener_events) = exchange(&mut dialer, &mut listener);
    assert!(
        listener_events
            .iter()
            .any(|event| matches!(event, SessionOutput::StreamClosed { .. })),
        "reset must close the substream remotely: {listener_events:?}"
    );
}

#[test]
fn go_away_closes_local_substreams_and_ends_the_remote_session() {
    let (mut dialer, mut listener, _, _) = upgraded_pair();
    let stream = dialer.open_stream().expect("open substream");
    let (_, listener_events) = exchange(&mut dialer, &mut listener);
    assert!(
        listener_events.iter().any(|event| matches!(
            event,
            SessionOutput::IncomingStream { stream: incoming } if *incoming == stream
        )),
        "the substream must be live before the shutdown: {listener_events:?}"
    );

    dialer
        .go_away(0)
        .expect("an established session shuts down");

    let mut wire = Vec::new();
    let mut local = Vec::new();
    while let Some(output) = dialer.poll_output() {
        match output {
            SessionOutput::Write(bytes) => wire.extend_from_slice(&bytes),
            other => local.push(other),
        }
    }
    assert_eq!(
        local,
        vec![SessionOutput::StreamClosed { stream }],
        "shutting down must close every open substream"
    );
    assert!(!wire.is_empty(), "the GoAway frame must reach the wire");

    // The remote learns this was an orderly end, not a protocol fault, so it
    // can close quietly rather than report a failure the dialer never made.
    let result = listener.handle_input(wire);
    assert!(
        matches!(result, Err(SessionError::GoAway { code: 0 })),
        "an orderly shutdown must be reported as such: {result:?}"
    );
    assert!(!listener.is_established());
}

#[test]
fn a_remote_go_away_closes_the_substreams_it_takes_down() {
    let (mut dialer, mut listener, _, _) = upgraded_pair();
    dialer.open_stream().expect("open substream");
    let (_, listener_events) = exchange(&mut dialer, &mut listener);
    let inbound = listener_events
        .iter()
        .find_map(|event| match event {
            SessionOutput::IncomingStream { stream } => Some(*stream),
            _ => None,
        })
        .expect("the substream must be live before the shutdown");

    dialer
        .go_away(0)
        .expect("an established session shuts down");
    let result = listener.handle_input(take_writes(&mut dialer));
    assert!(
        matches!(result, Err(SessionError::GoAway { code: 0 })),
        "the remote shutdown must still be reported: {result:?}"
    );

    // A remote shutdown ends the substreams exactly as a local one does, so a
    // caller draining outputs after the error still learns to forget them
    // rather than leaking a substream it will never hear about again.
    let mut events = Vec::new();
    while let Some(output) = listener.poll_output() {
        if !matches!(output, SessionOutput::Write(_)) {
            events.push(output);
        }
    }
    assert_eq!(
        events,
        vec![SessionOutput::StreamClosed { stream: inbound }],
        "the ended substream must surface as closed"
    );
}

#[test]
fn a_mismatched_expected_peer_fails_the_handshake() {
    let dialer_key = Ed25519Keypair::generate();
    let listener_key = Ed25519Keypair::generate();
    let impostor = Ed25519Keypair::generate();

    // The dialer demands a peer the listener cannot prove it is.
    let mut dialer = session(SessionRole::Initiator, dialer_key, Some(&impostor));
    let mut listener = session(SessionRole::Responder, listener_key, None);
    dialer.start().expect("start");
    listener.start().expect("start");

    let mut failed = false;
    for _ in 0..64 {
        let mut moved = false;
        while let Some(output) = dialer.poll_output() {
            if let SessionOutput::Write(bytes) = output {
                moved = true;
                listener
                    .handle_input(bytes)
                    .expect("responder accepts the initiator's first handshake message");
            }
        }
        while let Some(output) = listener.poll_output() {
            if let SessionOutput::Write(bytes) = output {
                moved = true;
                if dialer.handle_input(bytes).is_err() {
                    failed = true;
                }
            }
        }
        if failed || !moved {
            break;
        }
    }

    assert!(failed, "the dialer must reject the wrong identity");
    assert!(!dialer.is_established());
}

#[test]
fn stream_operations_before_the_upgrade_are_rejected() {
    let dialer_key = Ed25519Keypair::generate();
    let listener_key = Ed25519Keypair::generate();
    let listener_peer = listener_key.peer_id();
    let mut dialer = session(SessionRole::Initiator, dialer_key, Some(&listener_key));
    let mut listener = session(SessionRole::Responder, listener_key, None);

    assert!(matches!(
        dialer.open_stream(),
        Err(SessionError::NotEstablished)
    ));
    assert!(matches!(
        dialer.send(StreamId::new(1), b"x".to_vec()),
        Err(SessionError::NotEstablished)
    ));
    assert!(matches!(
        dialer.close_stream_write(StreamId::new(1)),
        Err(SessionError::NotEstablished)
    ));
    assert!(matches!(
        dialer.reset_stream(StreamId::new(1)),
        Err(SessionError::NotEstablished)
    ));
    assert!(matches!(
        dialer.go_away(0),
        Err(SessionError::NotEstablished)
    ));
    assert!(!dialer.is_established());
    assert_eq!(dialer.peer(), None);

    // Rejecting an early call must not consume the session: it is still
    // mid-upgrade and has to be able to finish.
    dialer.start().expect("start after rejected calls");
    listener.start().expect("start");
    let _ = exchange(&mut dialer, &mut listener);
    assert!(
        dialer.is_established(),
        "a rejected early call must leave the session usable"
    );
    assert_eq!(dialer.peer(), Some(&listener_peer));
}

#[test]
fn out_of_range_stream_ids_are_rejected_rather_than_truncated() {
    let (mut dialer, _listener, _, _) = upgraded_pair();
    let stream = dialer.open_stream().expect("open substream");

    // Congruent to a live stream modulo 2^32: truncation would alias onto it
    // and operate on somebody else's substream.
    let aliased = StreamId::new(stream.as_u64() + (1u64 << 32));
    assert!(matches!(
        dialer.send(aliased, b"x".to_vec()),
        Err(SessionError::UnknownStream { .. })
    ));
    assert!(matches!(
        dialer.reset_stream(aliased),
        Err(SessionError::UnknownStream { .. })
    ));

    // The real stream still works, so the rejection cost nothing.
    dialer.send(stream, b"ok".to_vec()).expect("real stream");
}

#[test]
fn a_session_that_fails_mid_batch_is_dead_and_stays_dead() {
    // One batch can carry the Yamux confirmation and pipelined frames. If a
    // frame is fatal, `handle_input` must report it and the session must be
    // unusable afterwards rather than half-alive.
    let dialer_key = Ed25519Keypair::generate();
    let listener_key = Ed25519Keypair::generate();

    // The dialer refuses frames larger than 64 bytes; the listener, on default
    // limits, will pipeline a much larger one.
    let strict = YamuxConfig {
        max_frame_len: 64,
        ..YamuxConfig::default()
    };
    let mut dialer = session_with(
        SessionRole::Initiator,
        dialer_key,
        Some(&listener_key),
        strict,
    );
    let mut listener = session(SessionRole::Responder, listener_key, None);
    dialer.start().expect("start");
    listener.start().expect("start");

    // Drive until the listener is up, leaving its confirmation unread.
    drive_until_listener_established(&mut dialer, &mut listener);

    let stream = listener.open_stream().expect("open substream");
    listener
        .send(stream, vec![0u8; 4096])
        .expect("queue an oversized frame");

    let result = dialer.handle_input(take_writes(&mut listener));

    assert!(
        matches!(result, Err(SessionError::Protocol(_))),
        "an oversized frame must fail the session: {result:?}"
    );
    assert!(
        !dialer.is_established(),
        "a failed session is not established"
    );

    // The phase was consumed, so every later call fails rather than operating
    // on a half-torn-down session.
    assert!(dialer.handle_input(b"more".to_vec()).is_err());
    let _ = dialer.open_stream().unwrap_err();
}

#[test]
fn quiet_established_session_emits_a_keepalive_ping() {
    let (mut dialer, mut listener, _, _) = upgraded_pair();

    dialer.poll(Now::from_millis(0)).expect("stamp dialer");
    listener.poll(Now::from_millis(0)).expect("stamp listener");
    assert_eq!(
        dialer.next_deadline(),
        Some(Deadline::from_millis(KEEPALIVE_INTERVAL_MS))
    );
    assert!(take_writes(&mut dialer).is_empty(), "nothing is due at t=0");

    dialer
        .poll(Now::from_millis(KEEPALIVE_INTERVAL_MS))
        .expect("keepalive is due");
    let ping = take_writes(&mut dialer);
    assert!(
        !ping.is_empty(),
        "a quiet session must emit ciphertext for the yamux ping"
    );

    listener
        .handle_input(ping)
        .expect("listener accepts the ping");
    let pong = take_writes(&mut listener);
    assert!(
        !pong.is_empty(),
        "the listener already answers pings; that write is the pong"
    );

    let events = {
        dialer.handle_input(pong).expect("dialer accepts the pong");
        let mut events = Vec::new();
        while let Some(output) = dialer.poll_output() {
            events.push(output);
        }
        events
    };
    assert!(
        events.is_empty(),
        "a keepalive pong is session traffic, not a substream event: {events:?}"
    );
}
