//! Drives two sessions against each other over an in-memory byte stream.
//!
//! This is the property the circuit transport relies on and that a TCP
//! transport will rely on next: two `SecureMuxSession`s wired back to back
//! complete the whole upgrade and carry substream traffic, with no socket,
//! clock, or executor anywhere.

use minip2p_identity::{Ed25519Keypair, PeerId};
use minip2p_secure_mux::{
    SecureMuxSession, SessionConfig, SessionError, SessionOutput, SessionRole, YamuxConfig,
};
use minip2p_transport::StreamId;

fn session(
    role: SessionRole,
    identity: Ed25519Keypair,
    expected: Option<&Ed25519Keypair>,
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
        yamux: YamuxConfig::default(),
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

#[test]
fn established_is_reported_before_any_stream_output() {
    let (_dialer, _listener, _, _) = upgraded_pair();

    let dialer_key = Ed25519Keypair::generate();
    let listener_key = Ed25519Keypair::generate();
    let mut dialer = session(SessionRole::Initiator, dialer_key, Some(&listener_key));
    let mut listener = session(SessionRole::Responder, listener_key, None);
    dialer.start().expect("start");
    listener.start().expect("start");
    let (_, listener_events) = exchange(&mut dialer, &mut listener);

    // A caller applying connection policy on `Established` must see it before
    // it has to decide anything about a stream.
    let established = listener_events
        .iter()
        .position(|event| matches!(event, SessionOutput::Established { .. }))
        .expect("listener established");
    if let Some(first_other) = listener_events
        .iter()
        .position(|event| !matches!(event, SessionOutput::Established { .. }))
    {
        assert!(established < first_other, "Established must come first");
    }
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
                let _ = listener.handle_input(bytes);
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
    let mut dialer = session(SessionRole::Initiator, dialer_key, Some(&listener_key));

    assert!(matches!(
        dialer.open_stream(),
        Err(SessionError::NotEstablished)
    ));
    assert!(matches!(
        dialer.send(StreamId::new(1), b"x".to_vec()),
        Err(SessionError::NotEstablished)
    ));
    assert!(!dialer.is_established());
    assert_eq!(dialer.peer(), None);
}
