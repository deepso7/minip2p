//! Listener must reclaim per-peer state well under the default 30s QUIC idle
//! timeout after a dialer is dropped or `close`d without `disconnect`.

#![cfg(feature = "quic")]

use std::sync::mpsc::{self, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use minip2p::{Ed25519Keypair, Endpoint, EndpointEvent, PeerId};

#[path = "../../../tests/support/endpoint.rs"]
mod endpoint_support;
use endpoint_support::NextEvent;

const CHURN_ROUNDS: usize = 50;
/// Failure backstop for the reclaim wait, not a budget it has to fit in.
///
/// These tests prove reclamation does not wait for the QUIC idle timeout (30s
/// by default), so the cap only has to stay well under that; the loop ends the
/// moment reclamation is observable, however long the box took to get there.
const RECLAIM_BACKSTOP: Duration = Duration::from_secs(5);
/// Failure backstop for a driver thread whose stop signal never arrives.
const DRIVER_BACKSTOP: Duration = Duration::from_secs(30);

fn wait_peer_ready(
    listener: &mut Endpoint,
    dialer: &mut Endpoint,
    listener_peer: &PeerId,
    dialer_peer: &PeerId,
) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !listener.is_peer_ready(dialer_peer) || !dialer.is_peer_ready(listener_peer) {
        assert!(Instant::now() < deadline, "peer ready timed out");
        let _ = listener
            .next_event(Duration::from_millis(10))
            .expect("drive listener toward ready");
        let _ = dialer
            .next_event(Duration::from_millis(10))
            .expect("drive dialer toward ready");
    }
}

fn ping_until_rtt(listener: &mut Endpoint, dialer: &mut Endpoint, listener_peer: &PeerId) {
    dialer.ping(listener_peer).expect("queue ping");
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        assert!(Instant::now() < deadline, "ping rtt timed out");
        match dialer
            .next_event(Duration::from_millis(10))
            .expect("drive dialer ping")
        {
            Some(EndpointEvent::PingRttMeasured { peer_id, .. }) if peer_id == *listener_peer => {
                return;
            }
            _ => {}
        }
        let _ = listener
            .next_event(Duration::from_millis(10))
            .expect("drive listener ping");
    }
}

fn assert_listener_reclaimed(listener: &mut Endpoint, dialer_peer: &PeerId, round: usize) {
    let backstop = Instant::now() + RECLAIM_BACKSTOP;
    while Instant::now() < backstop
        && (!listener.connected_peers().is_empty() || listener.peer_info(dialer_peer).is_some())
    {
        let _ = listener
            .next_event(Duration::from_millis(10))
            .expect("drive listener reclaim");
    }

    assert!(
        listener.connected_peers().is_empty(),
        "round {round}: listener still tracks connected peers {:?} after {RECLAIM_BACKSTOP:?}",
        listener.connected_peers()
    );
    assert!(
        listener.peer_info(dialer_peer).is_none(),
        "round {round}: listener retained identify state for {dialer_peer} after {RECLAIM_BACKSTOP:?}"
    );
}

/// A peer driven on its own thread so the endpoint under test can block.
struct Driver {
    stop: Sender<()>,
    handle: JoinHandle<Endpoint>,
}

impl Driver {
    /// Stops the thread and returns the endpoint it was driving.
    fn stop(self) -> Endpoint {
        // A send error means the thread already left on its backstop, which
        // the join below reports as the panic it is.
        match self.stop.send(()) {
            Ok(()) | Err(_) => {}
        }
        self.handle.join().expect("driver thread")
    }
}

/// Drives `endpoint` on its own thread until [`Driver::stop`].
///
/// Returns once the thread is running, so a `close()` that races it cannot
/// start draining before the peer is able to answer. The thread runs for as
/// long as the test needs it to; `DRIVER_BACKSTOP` is only there to end a
/// thread whose stop signal was lost.
fn spawn_driver(mut endpoint: Endpoint, what: &'static str) -> Driver {
    let (stop, stopped) = mpsc::channel();
    let (started, running) = mpsc::channel();
    let handle = thread::spawn(move || {
        started.send(()).expect("the test waits for this thread");
        let backstop = Instant::now() + DRIVER_BACKSTOP;
        while stopped.try_recv().is_err() {
            assert!(
                Instant::now() < backstop,
                "{what}: stop signal never arrived"
            );
            let _ = endpoint.next_event(Duration::from_millis(10)).expect(what);
        }
        endpoint
    });
    running.recv().expect("driver thread starts");
    Driver { stop, handle }
}

fn bind_loopback() -> Endpoint {
    Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind loopback")
}

#[test]
fn listener_reclaims_state_after_dialer_drop_without_disconnect() {
    let mut listener = bind_loopback();
    let listener_addr = listener.listen().expect("listener listens");
    let listener_peer = listener.peer_id().clone();

    for round in 0..CHURN_ROUNDS {
        let mut dialer = bind_loopback();
        let dialer_peer = dialer.peer_id().clone();
        dialer.connect(&listener_addr).expect("connect to listener");

        wait_peer_ready(&mut listener, &mut dialer, &listener_peer, &dialer_peer);
        ping_until_rtt(&mut listener, &mut dialer, &listener_peer);

        drop(dialer);

        assert_listener_reclaimed(&mut listener, &dialer_peer, round);
    }
}

#[test]
fn listener_reclaims_state_after_dialer_close() {
    let mut listener = bind_loopback();
    let listener_addr = listener.listen().expect("listener listens");
    let listener_peer = listener.peer_id().clone();

    let mut dialer = bind_loopback();
    let dialer_peer = dialer.peer_id().clone();
    dialer.connect(&listener_addr).expect("connect to listener");
    wait_peer_ready(&mut listener, &mut dialer, &listener_peer, &dialer_peer);
    ping_until_rtt(&mut listener, &mut dialer, &listener_peer);

    // Drive the listener so QUIC close can complete; otherwise Drop would
    // be the only path that notifies the peer.
    let remote = spawn_driver(listener, "drive listener during close");

    let events = dialer.close().expect("close flushes disconnects");
    let mut listener = remote.stop();

    assert!(
        events.iter().any(|event| matches!(
            event,
            EndpointEvent::ConnectionClosed { peer_id, .. } if peer_id == &listener_peer
        )),
        "close must surface ConnectionClosed rather than relying on Drop: {events:?}"
    );
    assert_listener_reclaimed(&mut listener, &dialer_peer, 0);
}

#[test]
fn listener_reclaims_state_after_dialer_drop_during_handshake() {
    let mut listener = bind_loopback();
    let listener_addr = listener.listen().expect("listener listens");

    let mut dialer = bind_loopback();
    let dialer_peer = dialer.peer_id().clone();
    dialer.connect(&listener_addr).expect("connect to listener");

    // Do not wait for Identify; the connection may still be handshaking.
    for _ in 0..8 {
        let _ = listener
            .next_event(Duration::from_millis(10))
            .expect("drive listener handshake");
        let _ = dialer
            .next_event(Duration::from_millis(10))
            .expect("drive dialer handshake");
    }

    drop(dialer);
    assert_listener_reclaimed(&mut listener, &dialer_peer, 0);
}

#[test]
fn close_drains_replacement_connection() {
    let mut listener = bind_loopback();
    let listener_addr = listener.listen().expect("listener listens");
    let listener_peer = listener.peer_id().clone();

    let dialer_key = Ed25519Keypair::generate();
    let mut dialer = Endpoint::builder()
        .identity(dialer_key.clone())
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind first dialer");
    let dialer_peer = dialer.peer_id().clone();
    dialer.connect(&listener_addr).expect("connect to listener");
    wait_peer_ready(&mut listener, &mut dialer, &listener_peer, &dialer_peer);

    // Queue a same-peer handshake without polling the listener, so close()
    // is the first drive that can supersede and establish the replacement.
    let mut replacement = Endpoint::builder()
        .identity(dialer_key)
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind replacement dialer");
    replacement
        .connect(&listener_addr)
        .expect("reconnect to listener");
    for _ in 0..8 {
        let _ = replacement
            .next_event(Duration::from_millis(10))
            .expect("send replacement handshake");
    }

    let remote = spawn_driver(replacement, "drive replacement during close");

    let events = listener.close().expect("close drains replacements");
    let _replacement = remote.stop();

    let established: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            EndpointEvent::ConnectionEstablished { peer_id, conn_id }
                if peer_id == &dialer_peer =>
            {
                Some(*conn_id)
            }
            _ => None,
        })
        .collect();
    assert!(
        !established.is_empty(),
        "close must observe the replacement ConnectionEstablished: {events:?}"
    );
    for conn_id in established {
        assert!(
            events.iter().any(|event| matches!(
                event,
                EndpointEvent::ConnectionClosed { peer_id, conn_id: closed, .. }
                    if peer_id == &dialer_peer && *closed == conn_id
            )),
            "close must drain the replacement {conn_id:?}: {events:?}"
        );
    }
}

#[test]
fn close_drains_pending_replacement_handshake() {
    let mut listener = bind_loopback();
    let listener_addr = listener.listen().expect("listener listens");
    let listener_peer = listener.peer_id().clone();

    let dialer_key = Ed25519Keypair::generate();
    let mut dialer = Endpoint::builder()
        .identity(dialer_key.clone())
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind first dialer");
    let dialer_peer = dialer.peer_id().clone();
    dialer.connect(&listener_addr).expect("connect to listener");
    wait_peer_ready(&mut listener, &mut dialer, &listener_peer, &dialer_peer);

    let mut replacement = Endpoint::builder()
        .identity(dialer_key)
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind replacement dialer");
    replacement
        .connect(&listener_addr)
        .expect("reconnect to listener");
    for _ in 0..4 {
        let _ = replacement
            .next_event(Duration::from_millis(10))
            .expect("send replacement initial");
    }
    // Accept the Initial without waiting for Connected; close() must keep
    // polling after the superseded peer leaves connected_peers.
    let _ = listener
        .next_event(Duration::from_millis(10))
        .expect("accept replacement initial");

    let remote = spawn_driver(replacement, "drive replacement during close");

    let events = listener.close().expect("close drains pending replacement");
    let _replacement = remote.stop();

    let established: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            EndpointEvent::ConnectionEstablished { peer_id, conn_id }
                if peer_id == &dialer_peer =>
            {
                Some(*conn_id)
            }
            _ => None,
        })
        .collect();
    assert!(
        !established.is_empty(),
        "close must observe the pending replacement ConnectionEstablished: {events:?}"
    );
    for conn_id in established {
        assert!(
            events.iter().any(|event| matches!(
                event,
                EndpointEvent::ConnectionClosed { peer_id, conn_id: closed, .. }
                    if peer_id == &dialer_peer && *closed == conn_id
            )),
            "close must drain the pending replacement {conn_id:?}: {events:?}"
        );
    }
}
