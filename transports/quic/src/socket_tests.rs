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
