//! Socket I/O through quinn-udp: segmentation offload within the retry
//! queue's bound, and a receive bound counted in logical datagrams.

use std::time::{Duration, Instant};

use super::*;
use crate::test_peer::{RawPeer, accept, listening_server, loopback, now};

/// Sends `len` bytes on a new server stream and reads them on the peer.
fn transfer(server: &mut QuicTransport, peer: &mut RawPeer, id: ConnectionId, len: usize) {
    let stream = server.open_stream(id).expect("open");
    let mut held = server
        .send_stream(id, stream, Bytes::from(vec![5u8; len]))
        .err()
        .and_then(TransportError::into_unsent);
    let mut received = 0;
    let start = Instant::now();
    while received < len {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "stalled at {received} of {len} bytes"
        );
        peer.pump();
        std::thread::sleep(Duration::from_millis(1));
        for event in server.poll(now()).expect("poll") {
            if matches!(event, TransportEvent::StreamWritable { .. })
                && let Some(tail) = held.take()
            {
                held = server
                    .send_stream(id, stream, tail)
                    .err()
                    .and_then(TransportError::into_unsent);
            }
        }
        peer.pump();
        received += peer.read(stream.as_u64()).0.len();
    }
}

#[test]
fn a_single_segment_cap_sends_one_datagram_per_transmit() {
    let mut server = listening_server(QuicLimits::default());
    let (mut peer, id) = accept(&mut server, &mut [], |_| {});
    server.socket().max_segments = 1;
    server.socket().largest_transmit = 0;
    transfer(&mut server, &mut peer, id, 400_000);
    assert_eq!(server.socket().largest_transmit, 1);
}

#[test]
fn segmentation_offload_batches_transmits_where_the_platform_has_it() {
    let mut server = listening_server(QuicLimits::default());
    if server.socket().platform_gso_segments() == 1 {
        return;
    }
    let (mut peer, id) = accept(&mut server, &mut [], |_| {});
    server.socket().largest_transmit = 0;
    transfer(&mut server, &mut peer, id, 400_000);
    assert!(server.socket().largest_transmit > 1);
}

#[test]
fn a_small_retry_queue_holds_whole_transmits_within_its_bound() {
    let mut server = listening_server(QuicLimits {
        max_pending_datagrams: 3,
        ..QuicLimits::default()
    });
    let (mut peer, id) = accept(&mut server, &mut [], |_| {});

    server.socket().blocked = true;
    let stream = server.open_stream(id).expect("open");
    server
        .send_stream(id, stream, Bytes::from(vec![5u8; 100_000]))
        .expect("send");
    for _ in 0..5 {
        let retained = server.socket().retained();
        assert!(
            (1..=3).contains(&retained),
            "{retained} logical datagrams retained"
        );
        std::thread::sleep(Duration::from_millis(1));
        server.poll(now()).expect("poll");
    }

    // Once the socket takes datagrams again, everything goes out.
    server.socket().blocked = false;
    let mut received = 0;
    let start = Instant::now();
    while received < 100_000 {
        assert!(start.elapsed() < Duration::from_secs(20), "{received}");
        peer.pump();
        std::thread::sleep(Duration::from_millis(1));
        server.poll(now()).expect("poll");
        assert!(server.socket().retained() <= 3);
        peer.pump();
        received += peer.read(stream.as_u64()).0.len();
    }
}

#[test]
fn a_burst_past_the_receive_bound_drains_without_another_readiness_edge() {
    let mut transport = loopback(QuicNodeConfig::generate());
    let destination = transport.local_addr();

    // Junk the endpoint drops, sent as segmented trains where the platform
    // can, so the receiver reads GRO batches.
    const SEGMENT: usize = 100;
    const SEGMENTS: usize = 40;
    const TRAINS: usize = 5;
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender");
    let state = quinn_udp::UdpSocketState::new((&sender).into()).expect("sender state");
    let payload = vec![0x40u8; SEGMENT * SEGMENTS];
    for _ in 0..TRAINS {
        if state.max_gso_segments() >= SEGMENTS {
            let train = quinn_udp::Transmit {
                destination,
                ecn: None,
                contents: &payload,
                segment_size: Some(SEGMENT),
                src_ip: None,
            };
            state
                .try_send((&sender).into(), &train)
                .expect("send train");
        } else {
            for datagram in payload.chunks(SEGMENT) {
                sender.send_to(datagram, destination).expect("send");
            }
        }
    }
    std::thread::sleep(Duration::from_millis(50));

    transport.poll(now()).expect("poll");
    // A batch here holds at most one train.
    let first = transport.socket().received;
    assert!(
        (MAX_DATAGRAMS_PER_POLL..MAX_DATAGRAMS_PER_POLL + SEGMENTS).contains(&first),
        "the bound is reached and overshot by less than one batch: {first}"
    );
    // The rest is still queued, and no readiness edge is needed to get it:
    // the driver is told to poll again at once.
    let mut polls = 1;
    while transport.next_deadline() == Some(Deadline::IMMEDIATE) {
        assert!(polls < 10, "the burst never drained");
        transport.poll(now()).expect("poll");
        polls += 1;
    }
    assert_eq!(transport.socket().received, TRAINS * SEGMENTS);
    assert!(!socket::has_queued_input(&transport.socket().udp));
}

#[test]
fn one_receive_call_reads_several_queued_datagrams_where_the_platform_batches() {
    let mut transport = loopback(QuicNodeConfig::generate());
    if transport.socket().recv_slots() == 1 {
        return;
    }
    let destination = transport.local_addr();
    // Junk the endpoint drops, sent one datagram at a time.
    const DATAGRAMS: usize = 16;
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender");
    for _ in 0..DATAGRAMS {
        sender.send_to(&[0x40; 100], destination).expect("send");
    }
    std::thread::sleep(Duration::from_millis(50));

    transport.poll(now()).expect("poll");
    assert_eq!(transport.socket().received, DATAGRAMS);
    let calls = transport.socket().recv_calls;
    assert!(calls < DATAGRAMS, "{calls} receive calls for {DATAGRAMS}");
}

#[test]
fn sockets_report_the_buffers_they_were_granted() {
    let mut server = listening_server(QuicLimits::default());
    let buffers = server.socket().buffers;
    assert!(
        buffers.send_bytes > 0 && buffers.recv_bytes > 0,
        "{buffers:?}"
    );
}

/// The sizes `grow_buffer` asks for when the platform accepts only `accepts`.
fn requests(current: usize, accepts: impl Fn(usize) -> bool) -> Vec<usize> {
    let mut asked = Vec::new();
    crate::socket::grow_buffer(current, |bytes| {
        asked.push(bytes);
        if accepts(bytes) {
            Ok(())
        } else {
            Err(std::io::ErrorKind::OutOfMemory.into())
        }
    });
    asked
}

#[test]
fn buffer_growth_halves_refused_requests_and_never_asks_for_less() {
    use crate::socket::{MIN_SOCKET_BUFFER_BYTES, SOCKET_BUFFER_BYTES};

    assert_eq!(requests(0, |_| true), [SOCKET_BUFFER_BYTES]);
    assert_eq!(
        requests(0, |bytes| bytes <= SOCKET_BUFFER_BYTES / 4),
        [
            SOCKET_BUFFER_BYTES,
            SOCKET_BUFFER_BYTES / 2,
            SOCKET_BUFFER_BYTES / 4
        ]
    );
    // Halving stops at the current size rather than asking for less.
    assert_eq!(
        requests(SOCKET_BUFFER_BYTES / 2, |_| false),
        [SOCKET_BUFFER_BYTES]
    );
    assert!(requests(SOCKET_BUFFER_BYTES, |_| true).is_empty());
    // A platform that refuses everything is given up on at the floor.
    assert_eq!(
        requests(0, |_| false).last(),
        Some(&MIN_SOCKET_BUFFER_BYTES)
    );
}

#[cfg(feature = "diagnostics")]
#[test]
fn diagnostics_report_the_granted_socket_buffers() {
    let mut server = listening_server(QuicLimits::default());
    let granted = server.socket().buffers;
    assert_eq!(
        crate::socket_buffers(&server.local_peer_id()),
        Some(granted)
    );
}
