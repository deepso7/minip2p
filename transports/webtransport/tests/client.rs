//! `WebTransportClient`'s transport contract over a fake `WebTransportIo`:
//! the limits and byte ownership of Decision 10 in docs/plans/webtransport.md.

use std::collections::{BTreeMap, VecDeque};

use minip2p_core::platform::{Deadline, EntropyError, EntropySource, Now};
use minip2p_core::{Bytes, Multihash, PeerAddr};
use minip2p_identity::Ed25519Keypair;
use minip2p_secure_mux::noise::{
    NoiseConfig, NoiseExtensions, NoiseOutput, NoiseRole, NoiseSession,
};
use minip2p_transport::{
    ConnectionCloseReason, ConnectionId, StreamId, Transport, TransportError, TransportEvent,
};
use minip2p_webtransport::{
    IoError, IoEvent, SessionHandle, StreamHandle, WebTransportClient, WebTransportIo,
    WebTransportLimits,
};

const HASH: &str = "uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g";

/// Counter bytes: Noise only needs distinct secrets here.
struct Entropy(u8);

impl EntropySource for Entropy {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        for byte in output {
            self.0 = self.0.wrapping_add(1);
            *byte = self.0;
        }
        Ok(())
    }
}

/// One stream as the fake platform sees it.
#[derive(Default)]
struct FakeStream {
    /// Every byte `write` accepted, in order.
    written: Vec<u8>,
    /// Accepted writes not yet completed, oldest first.
    in_flight: VecDeque<usize>,
    /// Granted and not yet delivered.
    granted: usize,
    fin: bool,
    reset: bool,
    /// `write` fails, as for a stream the platform no longer has.
    refuse: bool,
}

/// A platform that records calls and delivers what the test queues.
struct FakeIo {
    next: u64,
    /// Most in-flight bytes per stream, as the browser's 64 KiB cap.
    in_flight_cap: usize,
    streams: BTreeMap<u64, FakeStream>,
    closed_sessions: Vec<u64>,
    events: VecDeque<IoEvent>,
}

impl FakeIo {
    fn new() -> Self {
        Self {
            next: 0,
            in_flight_cap: 64 * 1024,
            streams: BTreeMap::new(),
            closed_sessions: Vec::new(),
            events: VecDeque::new(),
        }
    }

    fn handle(&mut self) -> u64 {
        self.next += 1;
        self.next
    }

    fn stream(&mut self, handle: StreamHandle) -> &mut FakeStream {
        self.streams.get_mut(&handle.0).expect("a known stream")
    }

    fn in_flight(&self, handle: StreamHandle) -> usize {
        self.streams
            .get(&handle.0)
            .map_or(0, |stream| stream.in_flight.iter().sum())
    }

    /// Completes the oldest in-flight write of `handle`.
    fn complete(&mut self, handle: StreamHandle) {
        let bytes = self.stream(handle).in_flight.pop_front().expect("a write");
        self.events.push_back(IoEvent::WriteCompleted {
            stream: handle,
            bytes,
        });
    }

    /// Delivers `len` bytes on `handle`, which must have been granted.
    fn deliver(&mut self, handle: StreamHandle, len: usize) {
        let stream = self.stream(handle);
        assert!(len <= stream.granted, "{len} bytes beyond the grant");
        stream.granted -= len;
        self.events.push_back(IoEvent::Data {
            stream: handle,
            bytes: Bytes::from(vec![7u8; len]),
        });
    }

    /// The server opens a stream on `session`.
    fn incoming(&mut self, session: SessionHandle) -> StreamHandle {
        let handle = self.handle();
        self.streams.insert(handle, FakeStream::default());
        self.events.push_back(IoEvent::IncomingStream {
            session,
            stream: StreamHandle(handle),
        });
        StreamHandle(handle)
    }
}

impl WebTransportIo for FakeIo {
    fn connect(&mut self, _url: &str, _certhashes: &[Multihash]) -> Result<SessionHandle, IoError> {
        Ok(SessionHandle(self.handle()))
    }

    fn open_stream(&mut self, _session: SessionHandle) -> Result<StreamHandle, IoError> {
        let handle = self.handle();
        self.streams.insert(handle, FakeStream::default());
        self.events.push_back(IoEvent::StreamOpened {
            stream: StreamHandle(handle),
        });
        Ok(StreamHandle(handle))
    }

    fn write(&mut self, stream: StreamHandle, data: &[u8]) -> Result<usize, IoError> {
        let cap = self.in_flight_cap;
        let room = cap - self.in_flight(stream);
        let state = self.stream(stream);
        if state.refuse {
            return Err(IoError("not writable".into()));
        }
        let accepted = data.len().min(room);
        if accepted > 0 {
            state
                .written
                .extend_from_slice(data.get(..accepted).unwrap_or_default());
            state.in_flight.push_back(accepted);
        }
        Ok(accepted)
    }

    fn close_write(&mut self, stream: StreamHandle) {
        self.stream(stream).fin = true;
    }

    fn reset(&mut self, stream: StreamHandle, _code: u8) {
        if let Some(state) = self.streams.get_mut(&stream.0) {
            state.reset = true;
        }
    }

    fn stop(&mut self, _stream: StreamHandle, _code: u8) {}

    fn grant_read(&mut self, stream: StreamHandle, bytes: usize) {
        self.stream(stream).granted += bytes;
    }

    fn close(&mut self, session: SessionHandle, _code: u32, _reason: &str) {
        self.closed_sessions.push(session.0);
    }

    fn poll_event(&mut self) -> Option<IoEvent> {
        self.events.pop_front()
    }
}

type Client = WebTransportClient<FakeIo, Entropy>;

fn client(limits: WebTransportLimits) -> Client {
    WebTransportClient::with_limits(
        FakeIo::new(),
        Ed25519Keypair::generate(),
        Entropy(0),
        limits,
    )
    .expect("valid limits")
}

fn poll(client: &mut Client) -> Vec<TransportEvent> {
    client.poll(Now::from_millis(0)).expect("poll")
}

/// A connected session: its connection id and platform handle.
struct Conn {
    id: ConnectionId,
    session: SessionHandle,
}

/// Dials a fake server and answers the Noise handshake as it would.
fn connect(client: &mut Client) -> Conn {
    let server = Ed25519Keypair::generate();
    let addr: PeerAddr = format!(
        "/ip4/192.0.2.1/udp/4001/quic-v1/webtransport/certhash/{HASH}/p2p/{}",
        server.peer_id()
    )
    .parse()
    .expect("peer addr");
    let certhashes = addr.transport().certhashes().copied().collect();
    let id = client.dial(&addr).expect("dial");
    let session = SessionHandle(client.io_mut().next);
    client
        .io_mut()
        .events
        .push_back(IoEvent::SessionReady { session });
    assert!(poll(client).is_empty());
    let noise = StreamHandle(client.io_mut().next);

    let mut responder = NoiseSession::new(NoiseConfig {
        role: NoiseRole::Responder,
        identity: server,
        static_secret: [200; 32],
        ephemeral_secret: [201; 32],
        expected_peer: None,
        local_extensions: Some(NoiseExtensions {
            webtransport_certhashes: certhashes,
            stream_muxers: Vec::new(),
        }),
    });
    responder.start().expect("start");
    let mut events = Vec::new();
    // Message one, then message two back, then message three, each as far
    // as the platform's in-flight cap lets it go per round.
    for _ in 0..20 {
        let io = client.io_mut();
        while !io.stream(noise).in_flight.is_empty() {
            io.complete(noise);
        }
        let written = std::mem::take(&mut io.stream(noise).written);
        responder.on_data(written).expect("noise");
        while let Some(output) = responder.poll_output() {
            if let NoiseOutput::Outbound(frame) = output {
                io.events.push_back(IoEvent::Data {
                    stream: noise,
                    bytes: Bytes::from(frame),
                });
            }
        }
        events.extend(poll(client));
        if responder.is_handshake_complete() {
            break;
        }
    }
    assert!(responder.is_handshake_complete());
    assert!(
        matches!(events.as_slice(), [TransportEvent::Connected { id: got, .. }] if *got == id),
        "{events:?}"
    );
    Conn { id, session }
}

fn small_limits() -> WebTransportLimits {
    WebTransportLimits {
        max_connections: 2,
        max_streams_per_connection: 4,
        max_pending_bytes_per_stream: 100,
        max_pending_connection_bytes: 300,
        control_stream_reserve_bytes: 50,
        stream_receive_window: 1_000,
        handshake_timeout_ms: 10_000,
    }
}

#[test]
fn grants_never_exceed_the_window_counting_outstanding_grants() {
    let mut client = client(small_limits());
    let conn = connect(&mut client);
    let stream = client.open_stream(conn.id).expect("open");
    poll(&mut client);
    let handle = StreamHandle(stream.as_u64());
    assert_eq!(client.io_mut().stream(handle).granted, 1_000);

    client.io_mut().deliver(handle, 600);
    poll(&mut client);
    // 600 delivered and unacked, 400 still granted: nothing more to give.
    assert_eq!(client.io_mut().stream(handle).granted, 400);
    client.ack_stream(conn.id, stream, 100).expect("ack");
    assert_eq!(
        client.io_mut().stream(handle).granted,
        500,
        "window 1000 - unacked 500 - outstanding 400 = 100 more"
    );
    client.io_mut().deliver(handle, 500);
    poll(&mut client);
    client.ack_stream(conn.id, stream, 1_000).expect("ack all");
    assert_eq!(client.io_mut().stream(handle).granted, 1_000);
}

/// Bytes `events` delivered, across every stream.
fn delivered(events: &[TransportEvent]) -> usize {
    events
        .iter()
        .map(|event| match event {
            TransportEvent::StreamData { data, .. } => data.len(),
            _ => 0,
        })
        .sum()
}

/// The server opens a stream on `conn`, fills its window and finishes it.
/// Returns the platform handle, or `None` when the client refused it.
fn fill_incoming(
    client: &mut Client,
    session: SessionHandle,
    events: &mut Vec<TransportEvent>,
) -> Option<StreamHandle> {
    let handle = client.io_mut().incoming(session);
    events.extend(poll(client));
    let io = client.io_mut();
    let granted = io.stream(handle).granted;
    if granted == 0 {
        assert!(io.stream(handle).reset, "a refused stream is reset");
        return None;
    }
    io.deliver(handle, granted);
    io.events.push_back(IoEvent::Fin { stream: handle });
    events.extend(poll(client));
    Some(handle)
}

#[test]
fn stream_churn_without_acks_stays_within_the_stream_cap_times_the_window() {
    let mut client = client(small_limits());
    let conn = connect(&mut client);
    let mut events = Vec::new();
    let admitted: Vec<StreamHandle> = (0..10)
        .filter_map(|_| fill_incoming(&mut client, conn.session, &mut events))
        .collect();
    assert_eq!(admitted.len(), 4);
    let incoming = events
        .iter()
        .filter(|event| matches!(event, TransportEvent::IncomingStream { .. }))
        .count();
    assert_eq!(incoming, 4, "refused streams have no event");
    assert_eq!(delivered(&events), 4 * 1_000);

    // Closing one stream frees nothing until its bytes are acknowledged.
    let stream = StreamId::new(admitted[0].0);
    client.close_stream_write(conn.id, stream).expect("fin");
    assert!(fill_incoming(&mut client, conn.session, &mut events).is_none());
    client.ack_stream(conn.id, stream, 1_000).expect("ack");
    assert!(fill_incoming(&mut client, conn.session, &mut events).is_some());
}

#[test]
fn reconnect_churn_leaves_unsettled_connections_until_ack_or_reset() {
    let mut client = client(small_limits());
    let mut held = Vec::new();
    for _ in 0..2 {
        let conn = connect(&mut client);
        let mut events = Vec::new();
        let handle = fill_incoming(&mut client, conn.session, &mut events).expect("admitted");
        client.io_mut().events.push_back(IoEvent::SessionClosed {
            session: conn.session,
            code: 0,
            reason: String::new(),
        });
        let events = poll(&mut client);
        assert!(
            matches!(events.as_slice(), [TransportEvent::Closed { .. }]),
            "{events:?}"
        );
        held.push((conn.id, StreamId::new(handle.0)));
    }
    let addr = format!(
        "/ip4/192.0.2.1/udp/4001/quic-v1/webtransport/certhash/{HASH}/p2p/{}",
        Ed25519Keypair::generate().peer_id()
    )
    .parse()
    .expect("addr");
    assert_eq!(
        client.dial(&addr),
        Err(TransportError::ResourceExhausted {
            resource: "WebTransport connections"
        }),
        "both slots are held by unacknowledged bytes"
    );

    let (first, second) = (held[0], held[1]);
    client
        .ack_stream(first.0, first.1, 400)
        .expect("partial ack");
    assert!(client.dial(&addr).is_err(), "still unsettled");
    client
        .ack_stream(first.0, first.1, 600)
        .expect("ack the rest");
    assert!(client.dial(&addr).is_ok(), "the first slot settled");
    client.reset_stream(second.0, second.1).expect("abandon");
    assert!(client.dial(&addr).is_ok(), "the second slot settled");
    assert_eq!(
        client.reset_stream(second.0, second.1),
        Err(TransportError::ConnectionNotFound { id: second.0 })
    );
}

/// Sends `len` bytes, returning how many were refused as `Full`.
fn send(client: &mut Client, conn: &Conn, stream: StreamId, len: usize) -> usize {
    match client.send_stream(conn.id, stream, Bytes::from(vec![1u8; len])) {
        Ok(()) => 0,
        Err(TransportError::Full { unsent, .. }) => unsent.len(),
        other => {
            other.expect("send");
            0
        }
    }
}

fn writable(events: &[TransportEvent]) -> Vec<StreamId> {
    events
        .iter()
        .filter_map(|event| match event {
            TransportEvent::StreamWritable { stream_id, .. } => Some(*stream_id),
            _ => None,
        })
        .collect()
}

/// Opens a stream the platform reported writable.
fn open(client: &mut Client, conn: &Conn) -> (StreamId, StreamHandle) {
    let stream = client.open_stream(conn.id).expect("open");
    poll(client);
    (stream, StreamHandle(stream.as_u64()))
}

#[test]
fn the_connection_cap_covers_bytes_in_flight_in_the_platform() {
    let mut client = client(small_limits());
    let conn = connect(&mut client);
    let streams: Vec<_> = (0..4).map(|_| open(&mut client, &conn)).collect();
    // Application streams share 300 - 50 reserved = 250 bytes.
    let refused: Vec<usize> = streams
        .iter()
        .map(|(stream, _)| send(&mut client, &conn, *stream, 100))
        .collect();
    assert_eq!(refused, [0, 0, 50, 100]);
    let in_flight: usize = streams
        .iter()
        .map(|(_, handle)| client.io_mut().in_flight(*handle))
        .sum();
    assert_eq!(in_flight, 250, "every accepted byte is in the platform");

    // One write completing frees the shared cap for both waiting streams.
    client.io_mut().complete(streams[0].1);
    let events = poll(&mut client);
    assert_eq!(writable(&events), [streams[2].0, streams[3].0]);
}

#[test]
fn interleaved_partial_completions_release_exactly_their_bytes() {
    let mut client = client(small_limits());
    client.io_mut().in_flight_cap = 30;
    let conn = connect(&mut client);
    let (a, a_handle) = open(&mut client, &conn);
    let (b, b_handle) = open(&mut client, &conn);
    assert_eq!(send(&mut client, &conn, a, 100), 0);
    assert_eq!(send(&mut client, &conn, b, 100), 0);
    assert_eq!(client.io_mut().in_flight(a_handle), 30, "70 wait in Rust");

    // B's completion frees nothing of A's stream cap.
    client.io_mut().complete(b_handle);
    poll(&mut client);
    assert_eq!(send(&mut client, &conn, a, 1), 1);
    // A's 30 bytes free exactly 30, and the next 30 move into flight.
    client.io_mut().complete(a_handle);
    poll(&mut client);
    assert_eq!(client.io_mut().in_flight(a_handle), 30);
    assert_eq!(send(&mut client, &conn, a, 31), 1);
    assert_eq!(client.io_mut().stream(a_handle).written.len(), 60);
}

#[test]
fn late_callbacks_after_reset_or_close_are_ignored() {
    let mut client = client(small_limits());
    let conn = connect(&mut client);
    let (a, a_handle) = open(&mut client, &conn);
    let (b, _) = open(&mut client, &conn);
    assert_eq!(send(&mut client, &conn, a, 100), 0);
    client.reset_stream(conn.id, a).expect("reset");
    assert!(matches!(
        poll(&mut client).as_slice(),
        [TransportEvent::StreamClosed { .. }]
    ));
    let late = [
        IoEvent::WriteCompleted {
            stream: a_handle,
            bytes: 100,
        },
        IoEvent::Data {
            stream: a_handle,
            bytes: Bytes::from_static(b"late"),
        },
        IoEvent::Fin { stream: a_handle },
        IoEvent::Reset {
            stream: a_handle,
            code: 0,
        },
        IoEvent::StopSending {
            stream: a_handle,
            code: 0,
        },
    ];
    client.io_mut().events.extend(late.clone());
    assert!(poll(&mut client).is_empty());
    // The reset freed A's bytes; the late completion freed nothing more.
    assert_eq!(send(&mut client, &conn, b, 100), 0);
    let (c, _) = open(&mut client, &conn);
    assert_eq!(send(&mut client, &conn, c, 100), 0);
    let (d, _) = open(&mut client, &conn);
    assert_eq!(send(&mut client, &conn, d, 100), 50);

    client.close(conn.id).expect("close");
    assert!(matches!(
        poll(&mut client).as_slice(),
        [TransportEvent::Closed {
            reason: ConnectionCloseReason::Local,
            ..
        }]
    ));
    let io = client.io_mut();
    io.events.extend(late);
    io.events.push_back(IoEvent::SessionReady {
        session: conn.session,
    });
    io.events.push_back(IoEvent::SessionClosed {
        session: conn.session,
        code: 0,
        reason: String::new(),
    });
    assert!(poll(&mut client).is_empty());
}

#[test]
fn a_handshake_that_does_not_finish_in_time_closes_with_timed_out() {
    let mut client = client(small_limits());
    let addr: PeerAddr = format!(
        "/ip4/192.0.2.1/udp/4001/quic-v1/webtransport/certhash/{HASH}/p2p/{}",
        Ed25519Keypair::generate().peer_id()
    )
    .parse()
    .expect("addr");
    let id = client.dial(&addr).expect("dial");
    assert!(client.poll(Now::from_millis(5)).expect("poll").is_empty());
    assert_eq!(client.next_deadline(), Some(Deadline::from_millis(10_005)));
    assert!(
        client
            .poll(Now::from_millis(10_004))
            .expect("poll")
            .is_empty()
    );
    assert_eq!(
        client.poll(Now::from_millis(10_005)).expect("poll"),
        [TransportEvent::Closed {
            id,
            reason: ConnectionCloseReason::TimedOut
        }]
    );
    assert_eq!(client.io_mut().closed_sessions.len(), 1);
    assert_eq!(client.next_deadline(), None);
}

#[test]
fn a_peer_reset_resets_the_platform_stream_and_frees_its_writes() {
    let mut client = client(small_limits());
    let conn = connect(&mut client);
    client.io_mut().in_flight_cap = 30;
    let (a, a_handle) = open(&mut client, &conn);
    assert_eq!(send(&mut client, &conn, a, 100), 0);
    client.io_mut().events.push_back(IoEvent::Reset {
        stream: a_handle,
        code: 0,
    });
    assert_eq!(
        poll(&mut client),
        [TransportEvent::StreamClosed {
            id: conn.id,
            stream_id: a
        }]
    );
    assert!(
        client.io_mut().stream(a_handle).reset,
        "our side is reset too"
    );
    // A's 100 pending bytes are free again.
    let (b, _) = open(&mut client, &conn);
    let (c, _) = open(&mut client, &conn);
    assert_eq!(send(&mut client, &conn, b, 100), 0);
    assert_eq!(send(&mut client, &conn, c, 100), 0);
}

/// Whether nothing but `payload` itself still holds its allocation.
fn unpinned(payload: Bytes) -> bool {
    payload.try_into_mut().is_ok()
}

#[test]
fn queued_tails_never_pin_more_than_twice_their_bytes() {
    let mut client = client(small_limits());
    let conn = connect(&mut client);
    // The platform takes nothing: the accepted 100 bytes wait in Rust.
    client.io_mut().in_flight_cap = 0;
    let (a, _) = open(&mut client, &conn);
    let payload = Bytes::from(vec![1u8; 10_000]);
    let refused = client.send_stream(conn.id, a, payload.clone());
    assert!(
        matches!(&refused, Err(TransportError::Full { unsent, .. }) if unsent.len() == 9_900),
        "{refused:?}"
    );
    drop(refused);
    assert!(unpinned(payload), "100 queued bytes pin 10 000");

    // A tail the platform shrinks below half is copied out too.
    client.io_mut().in_flight_cap = 30;
    let (b, b_handle) = open(&mut client, &conn);
    let payload = Bytes::from(vec![2u8; 100]);
    client
        .send_stream(conn.id, b, payload.clone())
        .expect("fits");
    client.io_mut().complete(b_handle);
    poll(&mut client);
    assert_eq!(client.io_mut().stream(b_handle).written.len(), 60);
    assert!(unpinned(payload), "a 40-byte tail pins 100");
}

#[test]
fn stop_sending_after_stream_closed_still_frees_in_flight_writes() {
    let mut client = client(small_limits());
    let conn = connect(&mut client);
    let (a, a_handle) = open(&mut client, &conn);
    assert_eq!(send(&mut client, &conn, a, 100), 0);
    client.close_stream_write(conn.id, a).expect("fin");
    client
        .io_mut()
        .events
        .push_back(IoEvent::Fin { stream: a_handle });
    assert_eq!(
        poll(&mut client),
        [
            TransportEvent::StreamRemoteWriteClosed {
                id: conn.id,
                stream_id: a
            },
            TransportEvent::StreamClosed {
                id: conn.id,
                stream_id: a
            }
        ]
    );

    // The browser rejects the write in flight: no WriteCompleted follows.
    client.io_mut().events.push_back(IoEvent::StopSending {
        stream: a_handle,
        code: 0,
    });
    assert_eq!(poll(&mut client), [], "nothing after StreamClosed");
    let (b, _) = open(&mut client, &conn);
    let (c, _) = open(&mut client, &conn);
    let (d, _) = open(&mut client, &conn);
    assert_eq!(send(&mut client, &conn, b, 100), 0);
    assert_eq!(send(&mut client, &conn, c, 100), 0);
    assert_eq!(
        send(&mut client, &conn, d, 100),
        50,
        "A's 100 bytes are free"
    );
}

#[test]
fn a_write_the_platform_refuses_fails_the_send() {
    let mut client = client(small_limits());
    let conn = connect(&mut client);
    let (a, a_handle) = open(&mut client, &conn);
    client.io_mut().stream(a_handle).refuse = true;
    assert!(matches!(
        client.send_stream(conn.id, a, Bytes::from_static(b"lost")),
        Err(TransportError::StreamSendFailed { .. })
    ));
    assert!(matches!(
        client.send_stream(conn.id, a, Bytes::from_static(b"more")),
        Err(TransportError::StreamSendFailed { .. })
    ));
}

#[test]
fn a_queued_write_the_platform_later_refuses_stops_the_write_side() {
    let mut client = client(small_limits());
    let conn = connect(&mut client);
    client.io_mut().in_flight_cap = 30;
    let (a, a_handle) = open(&mut client, &conn);
    assert_eq!(send(&mut client, &conn, a, 100), 0);
    // 70 bytes wait in Rust; the platform then drops the stream.
    client.io_mut().stream(a_handle).refuse = true;
    client.io_mut().complete(a_handle);
    assert_eq!(
        poll(&mut client),
        [TransportEvent::StreamWriteStopped {
            id: conn.id,
            stream_id: a,
            error_code: 0
        }]
    );
    let (b, _) = open(&mut client, &conn);
    let (c, _) = open(&mut client, &conn);
    assert_eq!(send(&mut client, &conn, b, 100), 0);
    assert_eq!(send(&mut client, &conn, c, 100), 0, "A's bytes are free");
}
