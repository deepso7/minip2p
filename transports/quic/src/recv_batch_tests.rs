//! How an established connection answers a receive batch: one service after
//! the batch, not one per datagram, and the batch acknowledged by it. Each
//! datagram in a batch owns its allocation, so a chunk the engine buffers
//! pins only its own.

use std::time::{Duration, Instant};

use super::*;
use crate::test_peer::{
    RawPeer, accept, allocation_len, drive_until, listening_server, now, server_with_idle_timeout,
    sid, stream_bytes,
};

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

#[test]
fn a_chunk_the_engine_buffers_pins_only_its_own_datagram() {
    const WINDOW: usize = 1_000;
    const JUNK: usize = 31;
    let mut server = listening_server(QuicLimits {
        stream_receive_window: WINDOW,
        ..QuicLimits::default()
    });
    let (mut peer, id) = accept(&mut server, &mut [], |_| {});
    let stream = peer.open();

    // A window the reader leaves unacknowledged gates the stream, so what
    // follows stays in the engine.
    assert_eq!(peer.write(stream, &[1; WINDOW]), WINDOW);
    let mut events = Vec::new();
    drive_until(
        &mut server,
        &mut [&mut peer],
        &mut events,
        "window",
        |events| stream_bytes(events, stream).len() == WINDOW,
    );
    std::thread::sleep(Duration::from_millis(2));
    discard_raw(&peer);

    // One stream datagram, then junk of the same size in the same burst: one
    // receive call where the platform batches receives, and one GRO batch
    // where it coalesces a segmented train. Where the platform does neither,
    // each datagram has its own call and allocation anyway.
    assert_eq!(peer.write(stream, b"marker"), 6);
    let mut train = Vec::new();
    let transmit = peer
        .conn()
        .poll_transmit(Instant::now(), 1, &mut train)
        .expect("the marker's packet");
    let (to, len) = (transmit.destination, transmit.size);
    // No fixed bit: the endpoint drops these unread.
    train.resize(len * (1 + JUNK), 0);
    let state = quinn_udp::UdpSocketState::new((&peer.socket).into()).expect("peer state");
    let segmented = state.max_gso_segments() > JUNK;
    if segmented {
        let transmit = quinn_udp::Transmit {
            destination: to,
            ecn: None,
            contents: &train,
            segment_size: Some(len),
            src_ip: None,
        };
        state
            .try_send((&peer.socket).into(), &transmit)
            .expect("send train");
    } else {
        for datagram in train.chunks(len) {
            peer.socket.send_to(datagram, to).expect("send");
        }
    }
    std::thread::sleep(Duration::from_millis(20));
    let (calls, read) = (server.socket().recv_calls, server.socket().received);
    server.poll(now()).expect("poll");
    let (calls, read) = (
        server.socket().recv_calls - calls,
        server.socket().received - read,
    );
    if segmented || server.socket().recv_slots() > 1 {
        assert!(read > calls, "{read} datagrams took {calls} receive calls");
    }

    let conn = server.connections.get_mut(&id).expect("live connection");
    let chunk = conn
        .engine()
        .recv_stream(sid(stream))
        .read(true)
        .expect("readable")
        .next(usize::MAX)
        .expect("not reset")
        .expect("the marker is buffered");
    assert_eq!(&chunk.bytes[..], b"marker");
    // The allocation from the chunk's start to its end: the rest of its
    // datagram, or the rest of the whole receive call when they share one.
    let retained = allocation_len(chunk.bytes);
    assert!(
        retained < len,
        "a buffered chunk pins {retained} bytes; its datagram was {len}"
    );
}
