//! How an established connection answers a receive batch: one drain and flush
//! after the batch, not one per datagram.
//!
//! quiche has no delayed-ACK timer, so every flush after an ack-eliciting
//! packet sends an ACK, and every flush squeezed into a sliver of free
//! congestion window sends an undersized packet. Deferring the flush to the
//! end of the batch must still acknowledge promptly: within the poll that
//! received the packets.

use std::time::{Duration, Instant};

use super::*;
use crate::stream_send_tests::{RawPeer, accept, listening_server, now};

/// Datagrams waiting on the peer's socket, discarded unread.
fn discard_raw(peer: &RawPeer) -> usize {
    let mut buf = [0u8; 65535];
    let mut count = 0;
    while peer.socket.recv_from(&mut buf).is_ok() {
        count += 1;
    }
    count
}

/// Whether a datagram is waiting on the peer's socket, leaving it there.
fn datagram_waiting(peer: &RawPeer) -> bool {
    peer.socket.peek_from(&mut [0u8; 1]).is_ok()
}

/// Hands every datagram waiting on the peer's socket to quiche and services
/// its timers, returning how many datagrams arrived.
fn receive_all(peer: &mut RawPeer) -> usize {
    let mut buf = [0u8; 65535];
    let local = peer.socket.local_addr().expect("peer addr");
    let mut count = 0;
    while let Ok((len, from)) = peer.socket.recv_from(&mut buf) {
        count += 1;
        let packet = buf.get_mut(..len).expect("received length fits");
        // A packet quiche rejects is simply lost, as on a real network.
        match peer.conn.recv(packet, quiche::RecvInfo { from, to: local }) {
            Ok(_) | Err(_) => {}
        }
    }
    if peer.conn.timeout().is_some_and(|timeout| timeout.is_zero()) {
        peer.conn.on_timeout();
    }
    count
}

/// Sends the peer's output over a path that drops every tenth packet and
/// swaps each remaining pair, returning how many packets survived the drop.
/// `generated` counts every packet quiche produced, across calls.
fn lossy_flush(peer: &mut RawPeer, generated: &mut usize) -> usize {
    let mut out = [0u8; 1350];
    let mut packets = Vec::new();
    while let Ok((len, info)) = peer.conn.send(&mut out) {
        *generated += 1;
        if !generated.is_multiple_of(10) {
            packets.push((out.get(..len).expect("sent length fits").to_vec(), info.to));
        }
    }
    let count = packets.len();
    for pair in packets.chunks_mut(2) {
        pair.reverse();
        for (packet, to) in pair.iter() {
            peer.socket.send_to(packet, *to).expect("peer send");
        }
    }
    count
}

/// Connects a raw peer and lets the handshake's trailing traffic settle, so
/// the next datagram the peer sees answers what the test sends.
fn settled_pair() -> (QuicTransport, RawPeer, ConnectionId) {
    let mut server = listening_server(30_000);
    let (mut peer, id) = accept(&mut server, &mut [], |_| {});
    for _ in 0..5 {
        std::thread::sleep(Duration::from_millis(2));
        peer.pump();
        server.poll(now()).expect("poll");
    }
    std::thread::sleep(Duration::from_millis(2));
    discard_raw(&peer);
    (server, peer, id)
}

/// Datagrams in a [`send_burst`].
const BURST: usize = 16;

/// Sends [`BURST`] small writes on stream 0, each as its own ack-eliciting
/// datagram, and waits for loopback to deliver them.
fn send_burst(peer: &mut RawPeer) {
    for byte in 0..BURST as u8 {
        peer.conn
            .stream_send(0, &[byte; 100], false)
            .expect("peer write");
        let mut out = [0u8; 1350];
        while let Ok((len, info)) = peer.conn.send(&mut out) {
            let packet = out.get(..len).expect("sent length fits");
            peer.socket.send_to(packet, info.to).expect("peer send");
        }
    }
    std::thread::sleep(Duration::from_millis(20));
}

#[test]
fn a_receive_batch_is_acknowledged_by_one_flush_within_the_same_poll() {
    let (mut server, mut peer, _) = settled_pair();

    send_burst(&mut peer);

    let events = server.poll(now()).expect("poll");
    let data: usize = events
        .iter()
        .map(|event| match event {
            TransportEvent::StreamData { data, .. } => data.len(),
            _ => 0,
        })
        .sum();
    assert_eq!(data, BURST * 100, "the whole burst is read");

    let replies = discard_raw(&peer);
    assert!(
        replies >= 1,
        "the batch must be acknowledged within the poll that received it"
    );
    assert!(
        replies <= 2,
        "an established connection flushes once per batch, not per datagram; \
         {replies} datagrams answered {BURST}"
    );
}

#[test]
fn sustained_one_way_load_recovers_from_loss_and_reordering_with_batched_acks() {
    let (mut server, mut peer, _) = settled_pair();

    const TOTAL: usize = 1 << 20;
    let payload: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();
    let mut written = 0;
    let mut fin_written = false;
    let mut received = Vec::with_capacity(TOTAL);
    let mut fin_received = false;
    let (mut generated, mut peer_sent, mut server_sent) = (0, 0, 0);
    let mut unacknowledged_polls = 0;

    let start = Instant::now();
    while !fin_received {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "transfer stalled at {} of {TOTAL} bytes",
            received.len()
        );
        server_sent += receive_all(&mut peer);
        if written < TOTAL {
            let rest = payload.get(written..).expect("written stays in bounds");
            written += peer.conn.stream_send(0, rest, false).unwrap_or(0);
        } else if !fin_written {
            fin_written = peer.conn.stream_send(0, &[], true).is_ok();
        }
        peer_sent += lossy_flush(&mut peer, &mut generated);

        std::thread::sleep(Duration::from_millis(1));
        let mut read_data = false;
        for event in server.poll(now()).expect("poll") {
            match event {
                TransportEvent::StreamData {
                    id,
                    stream_id,
                    data,
                } => {
                    read_data = true;
                    received.extend_from_slice(&data);
                    // A reader that keeps up acknowledges what it read.
                    server.ack_stream(id, stream_id, data.len()).expect("ack");
                }
                TransportEvent::StreamRemoteWriteClosed { .. } => fin_received = true,
                _ => {}
            }
        }
        // Loopback delivers at once, so an ACK sent by the poll is waiting.
        if read_data && !datagram_waiting(&peer) {
            unacknowledged_polls += 1;
        }
    }

    assert!(
        received == payload,
        "the payload arrives whole and in order"
    );
    assert_eq!(
        unacknowledged_polls, 0,
        "every poll that read data must acknowledge it before returning"
    );
    assert!(
        server_sent * 2 < peer_sent,
        "acknowledgements must be batched: the server sent {server_sent} datagrams \
         for the peer's {peer_sent}"
    );
}

#[test]
fn an_occasional_request_is_read_acknowledged_and_answered_within_one_poll() {
    let (mut server, mut peer, id) = settled_pair();

    peer.conn
        .stream_send(0, b"request", false)
        .expect("peer write");
    peer.pump();
    std::thread::sleep(Duration::from_millis(5));

    let events = server.poll(now()).expect("poll");
    assert!(
        events.iter().any(|event| matches!(
            event,
            TransportEvent::StreamData { data, .. } if data[..] == b"request"[..]
        )),
        "one poll reads the request: {events:?}"
    );
    assert!(
        datagram_waiting(&peer),
        "the poll that read the request acknowledges it"
    );

    server
        .send_stream(id, StreamId::new(0), Bytes::from_static(b"reply"))
        .expect("reply");
    std::thread::sleep(Duration::from_millis(2));
    peer.pump();
    assert_eq!(
        peer.read(0),
        (b"reply".to_vec(), false),
        "the reply leaves with the write, without another poll"
    );
}

#[cfg(feature = "diagnostics")]
#[test]
fn diagnostics_count_the_batch_and_the_datagrams_that_left() {
    let (mut server, mut peer, id) = settled_pair();
    let identity = server.local_peer_id();
    let connection_before = server.connection_diagnostics(id).expect("live connection");
    let sockets_before = crate::datagram_counters(&identity);

    send_burst(&mut peer);
    server.poll(now()).expect("poll");

    let connection = server.connection_diagnostics(id).expect("live connection");
    assert_eq!(
        connection.datagrams_received - connection_before.datagrams_received,
        BURST as u64
    );
    assert_eq!(
        connection.receive_flushes, connection_before.receive_flushes,
        "an established connection never flushes while receiving"
    );
    let sockets = crate::datagram_counters(&identity).since(&sockets_before);
    assert_eq!(sockets.received, BURST as u64);
    assert_eq!(sockets.sent, discard_raw(&peer) as u64);
}
