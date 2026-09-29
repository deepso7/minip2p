//! How queued stream writes survive quiche's `stream_send` errors.
//!
//! The remote side is a bare quiche client rather than a second
//! `QuicTransport`, so a test can send STOP_SENDING without resetting the read
//! half and can shape the flow-control and stream credit it grants.

use std::sync::LazyLock;
use std::time::{Duration, Instant};

use super::*;

static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

fn now() -> Now {
    Now::from_millis(EPOCH.elapsed().as_millis() as u64)
}

/// A quiche client on its own loopback socket, pumped by hand.
struct RawPeer {
    conn: quiche::Connection,
    socket: UdpSocket,
}

impl RawPeer {
    /// Starts a handshake to `server`; `tune` adjusts the credit the client
    /// grants.
    fn connect(server: SocketAddr, tune: impl FnOnce(&mut quiche::Config)) -> Self {
        let mut config = build_quiche_config(&QuicNodeConfig::generate()).expect("client config");
        tune(&mut config);
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind client");
        socket.set_nonblocking(true).expect("nonblocking");
        let scid = QuicTransport::generate_scid().expect("scid");
        let local = socket.local_addr().expect("client addr");
        let conn = quiche::connect(None, &scid, local, server, &mut config).expect("connect");
        let mut peer = Self { conn, socket };
        peer.pump();
        peer
    }

    /// Receives everything queued on the socket, services timers, and sends
    /// whatever quiche has to say.
    fn pump(&mut self) {
        let mut buf = [0u8; 65535];
        let local = self.socket.local_addr().expect("client addr");
        while let Ok((len, from)) = self.socket.recv_from(&mut buf) {
            let packet = buf.get_mut(..len).expect("received length fits");
            // A packet quiche rejects is simply lost, as on a real network.
            if self
                .conn
                .recv(packet, quiche::RecvInfo { from, to: local })
                .is_err()
            {
                continue;
            }
        }
        if self.conn.timeout().is_some_and(|timeout| timeout.is_zero()) {
            self.conn.on_timeout();
        }
        let mut out = [0u8; 1350];
        while let Ok((len, info)) = self.conn.send(&mut out) {
            let packet = out.get(..len).expect("sent length fits");
            self.socket.send_to(packet, info.to).expect("client send");
        }
    }

    /// Reads everything readable on `stream`, returning the bytes and FIN.
    fn read(&mut self, stream: u64) -> (Vec<u8>, bool) {
        let mut data = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok((read, fin)) = self.conn.stream_recv(stream, &mut buf) {
            data.extend_from_slice(buf.get(..read).expect("read fits"));
            if fin {
                return (data, true);
            }
        }
        (data, false)
    }
}

fn listening_server(idle_timeout_ms: u64) -> QuicTransport {
    let limits = QuicLimits {
        idle_timeout_ms,
        ..QuicLimits::default()
    };
    let mut server = QuicTransport::new(
        QuicNodeConfig::generate().with_limits(limits),
        "127.0.0.1:0",
    )
    .expect("bind server");
    server.listen_on_bound_addr().expect("listen");
    server
}

/// Polls the server and pumps the peers until `done` accepts the events seen
/// so far. Every poll must succeed.
fn drive_until(
    server: &mut QuicTransport,
    peers: &mut [&mut RawPeer],
    events: &mut Vec<TransportEvent>,
    what: &str,
    mut done: impl FnMut(&[TransportEvent]) -> bool,
) {
    let start = Instant::now();
    while !done(events) {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed out waiting for {what}; events: {events:?}"
        );
        std::thread::sleep(Duration::from_millis(2));
        for peer in peers.iter_mut() {
            peer.pump();
        }
        events.extend(server.poll(now()).expect("poll must not fail"));
        for peer in peers.iter_mut() {
            peer.pump();
        }
    }
}

/// Connects a raw peer and returns the server-side connection id.
fn accept(
    server: &mut QuicTransport,
    others: &mut [&mut RawPeer],
    tune: impl FnOnce(&mut quiche::Config),
) -> (RawPeer, ConnectionId) {
    let mut peer = RawPeer::connect(server.local_addr(), tune);
    let mut events = Vec::new();
    let mut peers: Vec<&mut RawPeer> = others.iter_mut().map(|p| &mut **p).collect();
    peers.push(&mut peer);
    drive_until(server, &mut peers, &mut events, "handshake", |events| {
        events
            .iter()
            .any(|event| matches!(event, TransportEvent::Connected { .. }))
    });
    let id = events
        .iter()
        .find_map(|event| match event {
            TransportEvent::Connected { id, .. } => Some(*id),
            _ => None,
        })
        .expect("connected");
    (peer, id)
}

fn pending_write_bytes(server: &QuicTransport, id: ConnectionId) -> usize {
    server
        .connections
        .get(&id)
        .expect("connection")
        .pending_write_bytes()
}

#[test]
fn stop_sending_drops_queued_writes_and_keeps_the_endpoint_polling() {
    let mut server = listening_server(1_000);
    // A small window for server data on client-opened streams makes most of
    // the server's write queue in the transport.
    let (mut stopper, stopper_id) = accept(&mut server, &mut [], |config| {
        config.set_initial_max_stream_data_bidi_local(1_000);
    });
    let (mut silent, silent_id) = accept(&mut server, &mut [&mut stopper], |_| {});

    stopper.conn.stream_send(0, b"hi", false).expect("open");
    let mut events = Vec::new();
    drive_until(
        &mut server,
        &mut [&mut stopper, &mut silent],
        &mut events,
        "inbound stream",
        |events| {
            events
                .iter()
                .any(|event| matches!(event, TransportEvent::StreamData { .. }))
        },
    );
    let stream = StreamId::new(0);
    server
        .send_stream(stopper_id, stream, vec![7; 10_000])
        .expect("send");
    assert!(pending_write_bytes(&server, stopper_id) > 0);

    stopper
        .conn
        .stream_shutdown(0, quiche::Shutdown::Read, 42)
        .expect("stop sending");
    // The silent peer stops answering, so only its idle timer can close it.
    let mut events = Vec::new();
    drive_until(
        &mut server,
        &mut [&mut stopper],
        &mut events,
        "write stop",
        |events| {
            events
                .iter()
                .any(|event| matches!(event, TransportEvent::StreamWriteStopped { .. }))
        },
    );
    assert_eq!(pending_write_bytes(&server, stopper_id), 0);

    // The read half is still open.
    stopper.conn.stream_send(0, b"more", true).expect("finish");
    drive_until(
        &mut server,
        &mut [&mut stopper],
        &mut events,
        "remote FIN",
        |events| {
            events.iter().any(|event| {
                matches!(event, TransportEvent::StreamClosed { id, stream_id }
                    if *id == stopper_id && *stream_id == stream)
            })
        },
    );
    assert!(events.contains(&TransportEvent::StreamData {
        id: stopper_id,
        stream_id: stream,
        data: b"more".to_vec(),
    }));
    assert!(events.contains(&TransportEvent::StreamRemoteWriteClosed {
        id: stopper_id,
        stream_id: stream,
    }));

    drive_until(
        &mut server,
        &mut [&mut stopper],
        &mut events,
        "idle timeout of the other connection",
        |events| events.contains(&TransportEvent::Closed { id: silent_id }),
    );
    let stops = events
        .iter()
        .filter(|event| matches!(event, TransportEvent::StreamWriteStopped { .. }))
        .collect::<Vec<_>>();
    assert_eq!(
        stops,
        [&TransportEvent::StreamWriteStopped {
            id: stopper_id,
            stream_id: stream,
            error_code: 42,
        }]
    );
}

#[test]
fn stop_sending_is_reported_when_nothing_is_queued() {
    let mut server = listening_server(30_000);
    let (mut peer, id) = accept(&mut server, &mut [], |_| {});

    // STOP_SENDING and FIN land together, before the server ever writes:
    // reading the FIN lets quiche forget the stream, so the stop must be
    // caught first.
    peer.conn
        .stream_send(0, b"hi", true)
        .expect("open and finish");
    peer.conn
        .stream_shutdown(0, quiche::Shutdown::Read, 9)
        .expect("stop sending");
    let stream = StreamId::new(0);
    let mut events = Vec::new();
    drive_until(
        &mut server,
        &mut [&mut peer],
        &mut events,
        "stream close",
        |events| {
            events
                .iter()
                .any(|event| matches!(event, TransportEvent::StreamClosed { .. }))
        },
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, TransportEvent::StreamWriteStopped { .. }))
            .collect::<Vec<_>>(),
        [&TransportEvent::StreamWriteStopped {
            id,
            stream_id: stream,
            error_code: 9,
        }]
    );
    assert!(matches!(
        server.send_stream(id, stream, b"late".to_vec()),
        Err(TransportError::StreamSendFailed { .. } | TransportError::StreamNotFound { .. })
    ));
    assert_eq!(pending_write_bytes(&server, id), 0);
}

#[test]
fn stop_sending_is_reported_while_connection_credit_is_exhausted() {
    let mut server = listening_server(30_000);
    // The peer never reads, so it never raises this connection-level limit.
    let (mut peer, id) = accept(&mut server, &mut [], |config| {
        config.set_initial_max_data(2_000);
    });

    peer.conn.stream_send(0, b"hi", false).expect("open");
    let mut events = Vec::new();
    drive_until(
        &mut server,
        &mut [&mut peer],
        &mut events,
        "inbound stream",
        |events| {
            events
                .iter()
                .any(|event| matches!(event, TransportEvent::StreamData { .. }))
        },
    );
    // Use up the connection's send credit: quiche now lists no stream as
    // writable, stopped or not.
    server
        .send_stream(id, StreamId::new(0), vec![7; 10_000])
        .expect("send");

    peer.conn
        .stream_send(4, b"hi", true)
        .expect("open and finish");
    peer.conn
        .stream_shutdown(4, quiche::Shutdown::Read, 5)
        .expect("stop sending");
    let stream = StreamId::new(4);
    drive_until(
        &mut server,
        &mut [&mut peer],
        &mut events,
        "stream close",
        |events| {
            events.iter().any(|event| {
                matches!(event, TransportEvent::StreamClosed { stream_id, .. } if *stream_id == stream)
            })
        },
    );
    assert!(events.contains(&TransportEvent::StreamWriteStopped {
        id,
        stream_id: stream,
        error_code: 5,
    }));
}

#[test]
fn fin_waiting_for_stream_credit_stays_queued_until_granted() {
    let mut server = listening_server(30_000);
    let (mut peer, id) = accept(&mut server, &mut [], |config| {
        config.set_initial_max_streams_bidi(1);
    });

    let first = server.open_stream(id).expect("first stream");
    server.send_stream(id, first, b"x".to_vec()).expect("send");
    server.close_stream_write(id, first).expect("fin first");
    // The peer has granted one server stream; this FIN has to wait.
    let second = server.open_stream(id).expect("second stream");
    server.close_stream_write(id, second).expect("queue fin");

    // Finishing the first stream lets the peer grant another.
    let mut events = Vec::new();
    let mut first_done = false;
    let mut second_fin = false;
    let start = Instant::now();
    while !second_fin {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "queued FIN never arrived; events: {events:?}"
        );
        std::thread::sleep(Duration::from_millis(2));
        peer.pump();
        events.extend(server.poll(now()).expect("poll must not fail"));
        peer.pump();
        if !first_done && peer.read(first.as_u64()).1 {
            peer.conn
                .stream_send(first.as_u64(), &[], true)
                .expect("peer fin");
            first_done = true;
        }
        second_fin = peer.read(second.as_u64()).1;
    }
    assert!(
        !events.iter().any(|event| matches!(
            event,
            TransportEvent::Error { .. } | TransportEvent::Closed { .. }
        )),
        "{events:?}"
    );
}

#[test]
fn connection_fatal_send_error_closes_only_that_connection() {
    let mut server = listening_server(30_000);
    // libp2p never grants unidirectional streams; allow one so the peer can
    // open a stream the server may read but never write.
    server.quiche_config.set_initial_max_streams_uni(1);
    server.quiche_config.set_initial_max_stream_data_uni(1_000);
    let (mut faulty, faulty_id) = accept(&mut server, &mut [], |_| {});
    let (mut healthy, healthy_id) = accept(&mut server, &mut [&mut faulty], |_| {});

    // Stream 2 is the client's first unidirectional stream: quiche refuses
    // any server write to it, FIN included.
    faulty.conn.stream_send(2, b"uni", false).expect("uni");
    let mut events = Vec::new();
    drive_until(
        &mut server,
        &mut [&mut faulty, &mut healthy],
        &mut events,
        "uni stream",
        |events| {
            events
                .iter()
                .any(|event| matches!(event, TransportEvent::StreamData { .. }))
        },
    );
    server
        .close_stream_write(faulty_id, StreamId::new(2))
        .expect("the FIN is queued; quiche rejects it in the drain");

    healthy
        .conn
        .stream_send(0, b"still here", true)
        .expect("send");
    drive_until(
        &mut server,
        &mut [&mut faulty, &mut healthy],
        &mut events,
        "faulty connection close",
        |events| events.contains(&TransportEvent::Closed { id: faulty_id }),
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, TransportEvent::Error { id, .. } if *id == faulty_id))
            .count(),
        1,
        "the failed write is dropped, not retried on every drain: {events:?}"
    );
    assert!(events.contains(&TransportEvent::StreamData {
        id: healthy_id,
        stream_id: StreamId::new(0),
        data: b"still here".to_vec(),
    }));
    assert!(!events.contains(&TransportEvent::Closed { id: healthy_id }));
    assert!(server.connections.contains_key(&healthy_id));
}

#[test]
fn partially_written_queue_drains_once_the_stream_is_writable() {
    let mut server = listening_server(30_000);
    // The peer grants 1,000 bytes per server stream until it reads.
    let (mut peer, id) = accept(&mut server, &mut [], |config| {
        config.set_initial_max_stream_data_bidi_remote(1_000);
    });

    let stream = server.open_stream(id).expect("open");
    server
        .send_stream(id, stream, vec![7; 10_000])
        .expect("send");
    server.close_stream_write(id, stream).expect("queue fin");
    let connection = server.connections.get(&id).expect("connection");
    assert!(connection.pending_write_bytes() > 0);
    assert_eq!(connection.queued_stream_count(), 1);

    let mut received = Vec::new();
    let mut fin = false;
    let start = Instant::now();
    while !fin {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "queued bytes never arrived; got {} bytes",
            received.len()
        );
        std::thread::sleep(Duration::from_millis(2));
        peer.pump();
        server.poll(now()).expect("poll must not fail");
        peer.pump();
        let (data, done) = peer.read(stream.as_u64());
        received.extend(data);
        fin = done;
    }
    assert_eq!(received, vec![7; 10_000]);
    let connection = server.connections.get(&id).expect("connection");
    assert_eq!(connection.pending_write_bytes(), 0);
    assert_eq!(connection.queued_stream_count(), 0);
}
