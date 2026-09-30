//! How the connection honours quiche's pacing send times (`SendInfo::at`).
//!
//! The adapter's default CUBIC never paces, so these servers run quiche's
//! BBR2, whose packets past its unpaced initial burst come back from `send`
//! with a send time in the future.

use std::time::{Duration, Instant};

use super::*;
use crate::stream_send_tests::{RawPeer, accept, listening_server, now};

/// A server connected to a raw peer, with a 64 KiB burst queued on a fresh
/// stream and polled until a paced packet is held.
fn paced_burst() -> (QuicTransport, RawPeer, ConnectionId, StreamId) {
    let mut server = listening_server(30_000);
    let config = &mut server.quiche_config;
    config.set_cc_algorithm(quiche::CongestionControlAlgorithm::Bbr2Gcongestion);
    // Room for the whole burst, so pacing rather than the window limits it.
    config.set_initial_congestion_window_packets(100);
    let (peer, id) = accept(&mut server, &mut [], |_| {});

    let stream = server.open_stream(id).expect("open stream");
    server
        .send_stream(id, stream, vec![7; 64 * 1024])
        .expect("send");
    let start = Instant::now();
    while server.connections[&id].paced_packet().is_none() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "a burst past the unpaced allowance must be held"
        );
        server.poll(now()).expect("poll");
    }
    (server, peer, id, stream)
}

/// Receives one datagram on the peer's socket without handing it to quiche.
fn recv_raw(peer: &RawPeer) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 65535];
    match peer.socket.recv_from(&mut buf) {
        Ok((len, _)) => {
            buf.truncate(len);
            Some(buf)
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => None,
        Err(error) => panic!("peer recv: {error}"),
    }
}

#[test]
fn a_held_packet_waits_for_its_send_time_and_sets_the_deadline() {
    let (mut server, peer, id, _) = paced_burst();
    // quiche's real pacing gaps are microseconds on loopback; push this one
    // out far enough to observe without racing the clock.
    let at = Instant::now() + Duration::from_millis(20);
    server
        .connections
        .get_mut(&id)
        .expect("connection")
        .repace_held_packet(at);
    while recv_raw(&peer).is_some() {}

    let polled_at = now();
    server.poll(polled_at).expect("poll");
    assert_eq!(
        recv_raw(&peer),
        None,
        "nothing leaves before the held packet"
    );

    let deadline = server.next_deadline().expect("a held packet is work");
    assert!(
        !deadline.is_expired_at(polled_at),
        "a packet not yet due must not demand an immediate poll"
    );
    assert!(
        deadline <= polled_at.deadline_after(20),
        "the held packet's send time must bound the deadline"
    );
}

#[test]
fn held_packets_leave_in_order_and_never_early() {
    let (mut server, peer, id, stream) = paced_burst();
    let (held, at) = server.connections[&id]
        .paced_packet()
        .map(|(bytes, at)| (bytes.to_vec(), at))
        .expect("held packet");
    // Discard the unpaced burst so the next datagram is whatever leaves next.
    while recv_raw(&peer).is_some() {}

    // More output while the packet is held must queue behind it.
    server
        .send_stream(id, stream, vec![8; 16 * 1024])
        .expect("send more");
    let start = Instant::now();
    let first = loop {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "held packet never sent"
        );
        server.poll(now()).expect("poll");
        if let Some(datagram) = recv_raw(&peer) {
            break datagram;
        }
    };
    assert!(Instant::now() >= at, "a paced packet left early");
    assert_eq!(first, held, "the held packet must be the first to leave");
}
