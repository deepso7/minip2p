//! Two peers that dial each other at once must settle on the same connection,
//! and a peer whose old connection died silently must still get back in.

#![cfg(feature = "quic")]

use std::time::{Duration, Instant};

use minip2p::{Ed25519Keypair, Endpoint, EndpointEvent, PeerId};

#[path = "../../../tests/support/endpoint.rs"]
mod endpoint_support;
use endpoint_support::NextEvent;

const QUIC: &str = "/ip4/127.0.0.1/udp/0/quic-v1";
/// Failure backstop, not a budget the test has to fit in.
const BACKSTOP: Duration = Duration::from_secs(10);
/// Comfortably past the swarm's 5 s `SIMULTANEOUS_DIAL_WINDOW_MS`.
const PAST_TIE_BREAK_WINDOW: Duration = Duration::from_millis(5_500);

fn bind(listen: &str, key: Ed25519Keypair) -> Endpoint {
    Endpoint::builder()
        .identity(key)
        .listen_on(listen)
        .expect("listen address")
        .bind()
        .expect("bind loopback")
}

/// Polls `endpoint` once and appends what it surfaced to `events`.
fn drive(endpoint: &mut Endpoint, events: &mut Vec<EndpointEvent>) {
    if let Some(event) = endpoint
        .next_event(Duration::from_millis(5))
        .expect("drive endpoint")
    {
        events.push(event);
    }
}

fn pinged(events: &[EndpointEvent], peer: &PeerId) -> bool {
    events.iter().any(
        |event| matches!(event, EndpointEvent::PingRttMeasured { peer_id, .. } if peer_id == peer),
    )
}

/// A and B `connect` to each other in the same tick, then ping both ways.
///
/// Each side registers its own dial first, so without the tie-break each
/// would replace it with the other's dial and close the one the other kept.
/// `ephemeral_dial_ports` is true when a dial leaves from a port other than
/// the listener's (TCP), so the kept connection's addresses show who dialed.
fn simultaneous_connect_keeps_one_shared_connection(listen: &str, ephemeral_dial_ports: bool) {
    let mut a = bind(listen, Ed25519Keypair::generate());
    let mut b = bind(listen, Ed25519Keypair::generate());
    let a_addr = a.listen().expect("a listens");
    let b_addr = b.listen().expect("b listens");
    let (a_peer, b_peer) = (a.peer_id().clone(), b.peer_id().clone());

    a.connect(&b_addr).expect("a connects");
    b.connect(&a_addr).expect("b connects");

    let (mut a_events, mut b_events) = (Vec::new(), Vec::new());
    let deadline = Instant::now() + BACKSTOP;
    while !a.is_peer_ready(&b_peer) || !b.is_peer_ready(&a_peer) {
        assert!(
            Instant::now() < deadline,
            "peers never both ready: a={a_events:?} b={b_events:?}"
        );
        drive(&mut a, &mut a_events);
        drive(&mut b, &mut b_events);
    }

    // A loser closed by the other side surfaces while the pings run.
    a.ping(&b_peer).expect("a pings");
    b.ping(&a_peer).expect("b pings");
    while !pinged(&a_events, &b_peer) || !pinged(&b_events, &a_peer) {
        assert!(
            Instant::now() < deadline,
            "pings never answered: a={a_events:?} b={b_events:?}"
        );
        drive(&mut a, &mut a_events);
        drive(&mut b, &mut b_events);
    }

    for (events, peer) in [(&a_events, &b_peer), (&b_events, &a_peer)] {
        assert!(
            !events.iter().any(|event| matches!(
                event,
                EndpointEvent::ConnectionClosed { peer_id, .. } if peer_id == peer
            )),
            "the peer must never disconnect: {events:?}"
        );
        // A losing dial completes as DialFailed, which the `connect` the
        // winner already settled absorbs.
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, EndpointEvent::DialFailed { .. })),
            "a settled connect must not surface its losing dial: {events:?}"
        );
    }
    assert!(a.is_peer_ready(&b_peer) && b.is_peer_ready(&a_peer));
    assert_eq!(a.connected_peers(), std::slice::from_ref(&b_peer));
    assert_eq!(b.connected_peers(), std::slice::from_ref(&a_peer));

    // Both keep the lower peer's dial: its remote end is the higher peer's
    // listener, while the higher peer sees it from the lower one's dial port.
    let (lower, higher, higher_addr, lower_addr, higher_peer, lower_peer) = if a_peer < b_peer {
        (&a, &b, &b_addr, &a_addr, &b_peer, &a_peer)
    } else {
        (&b, &a, &a_addr, &b_addr, &a_peer, &b_peer)
    };
    let kept_at_lower = lower.connection_id(higher_peer).expect("lower connected");
    assert_eq!(
        lower.connection_remote_addr(kept_at_lower),
        Some(higher_addr.transport()),
        "the lower peer keeps its own dial"
    );
    if ephemeral_dial_ports {
        let kept_at_higher = higher.connection_id(lower_peer).expect("higher connected");
        assert_ne!(
            higher.connection_remote_addr(kept_at_higher),
            Some(lower_addr.transport()),
            "the higher peer keeps the lower peer's dial, not its own"
        );
    }
}

#[test]
fn simultaneous_quic_connect_keeps_one_shared_connection() {
    simultaneous_connect_keeps_one_shared_connection(QUIC, false);
}

#[cfg(feature = "tcp")]
#[test]
fn simultaneous_tcp_connect_keeps_one_shared_connection() {
    simultaneous_connect_keeps_one_shared_connection("/ip4/127.0.0.1/tcp/0", true);
}

/// A dials B and B dies without closing. A new B with the same identity dials
/// A after the tie-break window, and must replace the dead connection even
/// when A is the lower peer, whose own dial would win a simultaneous dial.
fn reconnect_after_silent_death(a_is_lower: bool) {
    let (a_key, b_key) = loop {
        let (a_key, b_key) = (Ed25519Keypair::generate(), Ed25519Keypair::generate());
        if (a_key.peer_id() < b_key.peer_id()) == a_is_lower {
            break (a_key, b_key);
        }
    };
    let mut a = bind(QUIC, a_key);
    let a_addr = a.listen().expect("a listens");
    let mut b = bind(QUIC, b_key.clone());
    let b_addr = b.listen().expect("b listens");
    let (a_peer, b_peer) = (a.peer_id().clone(), b.peer_id().clone());

    a.connect(&b_addr).expect("a connects");
    let mut ignored = Vec::new();
    let deadline = Instant::now() + BACKSTOP;
    while !a.is_peer_ready(&b_peer) || !b.is_peer_ready(&a_peer) {
        assert!(Instant::now() < deadline, "first connection never ready");
        drive(&mut a, &mut ignored);
        drive(&mut b, &mut ignored);
    }
    let dead = a.connection_id(&b_peer).expect("a connected");

    // No close reaches A: its connection to B only times out much later.
    #[expect(
        clippy::mem_forget,
        reason = "dropping the endpoint would close its connections"
    )]
    std::mem::forget(b);
    let window_end = Instant::now() + PAST_TIE_BREAK_WINDOW;
    while Instant::now() < window_end {
        drive(&mut a, &mut ignored);
    }
    assert_eq!(
        a.connection_id(&b_peer),
        Some(dead),
        "still holds the dead one"
    );

    let mut b = bind(QUIC, b_key);
    b.connect(&a_addr).expect("new b connects");
    let mut a_events = Vec::new();
    let deadline = Instant::now() + BACKSTOP;
    while !b.is_peer_ready(&a_peer)
        || !a.is_peer_ready(&b_peer)
        || a.connection_id(&b_peer) == Some(dead)
    {
        assert!(
            Instant::now() < deadline,
            "new b never got in: a={a_events:?}"
        );
        drive(&mut a, &mut a_events);
        drive(&mut b, &mut ignored);
    }
    assert!(
        a_events.iter().any(|event| matches!(
            event,
            EndpointEvent::ConnectionReplaced { peer_id, old, .. } if *peer_id == b_peer && *old == dead
        )),
        "a replaces the dead connection: {a_events:?}"
    );
}

#[test]
fn reconnect_after_silent_death_replaces_when_survivor_is_lower() {
    reconnect_after_silent_death(true);
}

#[test]
fn reconnect_after_silent_death_replaces_when_survivor_is_higher() {
    reconnect_after_silent_death(false);
}
