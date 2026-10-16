//! How an established connection answers a receive batch: one service after
//! the batch, not one per datagram, and the batch acknowledged by it.

use std::time::{Duration, Instant};

use super::*;
use crate::test_peer::{RawPeer, accept, now, server_with_idle_timeout};

/// How long the peer's socket must stay empty before [`discard_raw`] stops.
/// Some loopbacks (macOS) deliver a datagram a little after it was sent.
const QUIET: Duration = Duration::from_millis(30);

/// Datagrams arriving on the peer's socket until it has been quiet for
/// [`QUIET`], discarded unread. Leaves the socket non-blocking.
fn discard_raw(peer: &RawPeer) -> usize {
    let mut buf = [0u8; 65535];
    let mut count = 0;
    peer.socket.set_nonblocking(false).expect("blocking");
    peer.socket
        .set_read_timeout(Some(QUIET))
        .expect("read timeout");
    while peer.socket.recv_from(&mut buf).is_ok() {
        count += 1;
    }
    peer.socket.set_nonblocking(true).expect("non-blocking");
    count
}

/// Sends the peer's output over a path that drops every tenth packet and
/// swaps each remaining pair, returning how many packets survived the drop.
/// `generated` counts every packet the engine produced, across calls.
fn lossy_flush(peer: &mut RawPeer, generated: &mut usize) -> usize {
    let mut packets = Vec::new();
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let Some(transmit) = peer.conn().poll_transmit(Instant::now(), 1, &mut buf) else {
            break;
        };
        *generated += 1;
        if !generated.is_multiple_of(10) {
            packets.push((buf[..transmit.size].to_vec(), transmit.destination));
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
fn settled_pair() -> (QuicTransport, RawPeer, ConnectionId, u64) {
    let mut server = server_with_idle_timeout(30_000);
    let (mut peer, id) = accept(&mut server, &mut [], |_| {});
    let stream = peer.open();
    for _ in 0..5 {
        std::thread::sleep(Duration::from_millis(2));
        peer.pump();
        server.poll(now()).expect("poll");
    }
    std::thread::sleep(Duration::from_millis(2));
    discard_raw(&peer);
    (server, peer, id, stream)
}

/// Datagrams in a [`send_burst`].
const BURST: usize = 16;

/// Sends [`BURST`] small writes, each as its own ack-eliciting datagram, and
/// waits for loopback to deliver them.
fn send_burst(peer: &mut RawPeer, stream: u64) {
    for byte in 0..BURST as u8 {
        assert_eq!(peer.write(stream, &[byte; 100]), 100);
        peer.service();
    }
    std::thread::sleep(Duration::from_millis(20));
}

#[test]
fn a_receive_batch_is_acknowledged_by_one_service_within_the_same_poll() {
    let (mut server, mut peer, _, stream) = settled_pair();

    send_burst(&mut peer, stream);

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
        "a connection is serviced once per batch, not per datagram; \
         {replies} datagrams answered {BURST}"
    );
}

#[test]
fn sustained_one_way_load_recovers_from_loss_and_reordering_with_batched_acks() {
    let (mut server, mut peer, _, stream) = settled_pair();

    const TOTAL: usize = 1 << 20;
    let payload: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();
    let mut written = 0;
    let mut fin_written = false;
    let mut received = Vec::with_capacity(TOTAL);
    let mut fin_received = false;
    let (mut generated, mut peer_sent, mut server_sent) = (0, 0, 0);

    let start = Instant::now();
    while !fin_received {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "transfer stalled at {} of {TOTAL} bytes",
            received.len()
        );
        server_sent += peer.receive();
        peer.run_engine();
        if written < TOTAL {
            written += peer.write(stream, &payload[written..]);
        } else if !fin_written {
            peer.finish(stream);
            fin_written = true;
        }
        peer_sent += lossy_flush(&mut peer, &mut generated);

        std::thread::sleep(Duration::from_millis(1));
        for event in server.poll(now()).expect("poll") {
            match event {
                TransportEvent::StreamData {
                    id,
                    stream_id,
                    data,
                } => {
                    received.extend_from_slice(&data);
                    // A reader that keeps up acknowledges what it read.
                    server.ack_stream(id, stream_id, data.len()).expect("ack");
                }
                TransportEvent::StreamRemoteWriteClosed { .. } => fin_received = true,
                _ => {}
            }
        }
    }

    assert!(
        received == payload,
        "the payload arrives whole and in order"
    );
    assert!(
        server_sent * 2 < peer_sent,
        "acknowledgements must be batched: the server sent {server_sent} datagrams \
         for the peer's {peer_sent}"
    );
}

#[test]
fn an_occasional_request_is_read_in_one_poll_and_answered_by_the_write() {
    let (mut server, mut peer, id, stream) = settled_pair();

    peer.write(stream, b"request");
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

    server
        .send_stream(id, StreamId::new(stream), Bytes::from_static(b"reply"))
        .expect("reply");
    std::thread::sleep(Duration::from_millis(2));
    peer.pump();
    assert_eq!(
        peer.read(stream),
        (b"reply".to_vec(), false),
        "the reply leaves with the write, without another poll"
    );
}

#[cfg(feature = "diagnostics")]
#[test]
fn diagnostics_count_the_batch_and_the_datagrams_that_left() {
    let (mut server, mut peer, id, stream) = settled_pair();
    let identity = server.local_peer_id();
    let connection_before = server.connection_diagnostics(id).expect("live connection");
    let sockets_before = crate::datagram_counters(&identity);

    send_burst(&mut peer, stream);
    server.poll(now()).expect("poll");

    let connection = server.connection_diagnostics(id).expect("live connection");
    assert_eq!(
        connection.datagrams_received - connection_before.datagrams_received,
        BURST as u64
    );
    assert!(connection.flushes > connection_before.flushes);
    let sockets = crate::datagram_counters(&identity).since(&sockets_before);
    assert_eq!(sockets.received, BURST as u64);
    assert_eq!(sockets.sent, discard_raw(&peer) as u64);
}
