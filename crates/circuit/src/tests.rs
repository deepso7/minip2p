use super::*;
use minip2p_multistream_select::{MultistreamOutput, MultistreamSelect};
use minip2p_secure_mux::noise::{
    NOISE_PROTOCOL_ID, NoiseConfig, NoiseOutput, NoiseRole, NoiseSession,
};
use minip2p_secure_mux::{KEEPALIVE_ACK_TIMEOUT_MS, KEEPALIVE_INTERVAL_MS};
use minip2p_test_support::InMemoryTransport;

#[derive(Clone, Debug)]
struct CounterEntropy(u8);

impl EntropySource for CounterEntropy {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        self.0 = self.0.wrapping_add(1);
        output.fill(self.0);
        Ok(())
    }
}

struct FailingEntropy;

impl EntropySource for FailingEntropy {
    fn fill_bytes(&mut self, _output: &mut [u8]) -> Result<(), EntropyError> {
        Err(EntropyError::failed("injected failure"))
    }
}

struct CloseObservingTransport<T> {
    inner: T,
    dial_id: Option<ConnectionId>,
    closed: Vec<ConnectionId>,
    fail_close_write: bool,
    fail_send: bool,
    full: bool,
    send_calls: usize,
    close_write_calls: usize,
    reset_calls: usize,
}

/// Leaf transport that counts how often it was attached, so a test can
/// prove an attach reached the bottom of a decorator stack.
struct WakeableTransport {
    inner: InMemoryTransport,
    attaches: alloc::sync::Arc<core::sync::atomic::AtomicUsize>,
}

impl Transport for WakeableTransport {
    fn ack_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        bytes: usize,
    ) -> Result<(), TransportError> {
        self.inner.ack_stream(id, stream_id, bytes)
    }

    fn dial(&mut self, addr: &minip2p_core::PeerAddr) -> Result<ConnectionId, TransportError> {
        self.inner.dial(addr)
    }

    fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, TransportError> {
        self.inner.listen(addr)
    }

    fn open_stream(&mut self, id: ConnectionId) -> Result<StreamId, TransportError> {
        self.inner.open_stream(id)
    }

    fn send_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
    ) -> Result<(), TransportError> {
        self.inner.send_stream(id, stream_id, data)
    }

    fn close_stream_write(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        self.inner.close_stream_write(id, stream_id)
    }

    fn reset_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        self.inner.reset_stream(id, stream_id)
    }

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        self.inner.close(id)
    }

    fn poll(&mut self, now: Now) -> Result<Vec<TransportEvent>, TransportError> {
        self.inner.poll(now)
    }
}

impl minip2p_transport::PollSource for WakeableTransport {
    fn attach(
        &mut self,
        _: minip2p_transport::mio::Registry,
        _: minip2p_transport::TokenSpace,
        _: alloc::sync::Arc<minip2p_transport::mio::Waker>,
    ) -> std::io::Result<()> {
        self.attaches
            .fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn dispatch(&mut self, _: &minip2p_transport::mio::event::Event) {}
}

/// The circuit wrapper owns no socket, so attaching it has to reach the
/// transport underneath, or a host would never hear that transport's
/// input.
#[test]
fn attaching_reaches_through_the_circuit_wrapper() {
    let local = identity(1);
    let relay = identity(9).peer_id();
    let (inner, _) = InMemoryTransport::pair(local.peer_id(), relay);
    let attaches = alloc::sync::Arc::new(core::sync::atomic::AtomicUsize::new(0));
    let mut transport = CircuitTransport::new(
        WakeableTransport {
            inner,
            attaches: alloc::sync::Arc::clone(&attaches),
        },
        local,
        CounterEntropy(1),
    );

    let mut poll = minip2p_transport::SharedPoll::new().expect("poll");
    poll.attach(&mut transport).expect("attach");
    assert_eq!(attaches.load(core::sync::atomic::Ordering::SeqCst), 1);
}

impl<T> CloseObservingTransport<T> {
    fn new(inner: T) -> Self {
        Self {
            inner,
            dial_id: None,
            closed: Vec::new(),
            fail_close_write: false,
            fail_send: false,
            full: false,
            send_calls: 0,
            close_write_calls: 0,
            reset_calls: 0,
        }
    }
}

impl<T: Transport> Transport for CloseObservingTransport<T> {
    fn ack_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        bytes: usize,
    ) -> Result<(), TransportError> {
        self.inner.ack_stream(id, stream_id, bytes)
    }

    fn dial(&mut self, address: &minip2p_core::PeerAddr) -> Result<ConnectionId, TransportError> {
        match self.dial_id {
            Some(id) => Ok(id),
            None => self.inner.dial(address),
        }
    }

    fn listen(&mut self, address: &Multiaddr) -> Result<Multiaddr, TransportError> {
        self.inner.listen(address)
    }

    fn open_stream(&mut self, id: ConnectionId) -> Result<StreamId, TransportError> {
        self.inner.open_stream(id)
    }

    fn send_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
    ) -> Result<(), TransportError> {
        self.send_calls += 1;
        if self.fail_send {
            return Err(TransportError::StreamSendFailed {
                id,
                stream_id,
                reason: "injected bridge send failure".to_string(),
            });
        }
        if self.full {
            return Err(TransportError::Full {
                id,
                stream_id,
                unsent: data,
            });
        }
        self.inner.send_stream(id, stream_id, data)
    }

    fn close_stream_write(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        self.close_write_calls += 1;
        if self.fail_close_write {
            return Err(TransportError::StreamCloseWriteFailed {
                id,
                stream_id,
                reason: "injected FIN failure".to_string(),
            });
        }
        self.inner.close_stream_write(id, stream_id)
    }

    fn reset_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        self.reset_calls += 1;
        self.inner.reset_stream(id, stream_id)
    }

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        self.closed.push(id);
        self.inner.close(id)
    }

    fn poll(&mut self, now: Now) -> Result<Vec<TransportEvent>, TransportError> {
        self.inner.poll(now)
    }

    fn next_deadline(&self) -> Option<Deadline> {
        self.inner.next_deadline()
    }

    fn local_addresses(&self) -> Vec<Multiaddr> {
        self.inner.local_addresses()
    }

    fn active_inbound_connection_sources(&self) -> Vec<Multiaddr> {
        self.inner.active_inbound_connection_sources()
    }
}

type CloseObservedCircuit =
    CircuitTransport<CloseObservingTransport<InMemoryTransport>, CounterEntropy>;
type TestCircuit = CircuitTransport<InMemoryTransport, CounterEntropy>;
type CloseObservedPair = (
    CloseObservedCircuit,
    TestCircuit,
    ConnectionId,
    StreamId,
    PeerId,
    PeerId,
);

/// Whether a circuit has authenticated its peer but not finished the
/// upgrade: the exact window in which a decrypted batch can straddle the
/// Yamux selection boundary.
fn selecting_yamux<T, E>(transport: &CircuitTransport<T, E>, id: ConnectionId) -> bool {
    transport.circuits.get(&id).is_some_and(|circuit| {
        circuit.session.peer().is_some() && !circuit.session.is_established()
    })
}

fn established<T, E>(transport: &CircuitTransport<T, E>, id: ConnectionId) -> bool {
    transport
        .circuits
        .get(&id)
        .is_some_and(|circuit| circuit.session.is_established())
}

fn identity(seed: u8) -> Ed25519Keypair {
    Ed25519Keypair::from_secret_key_bytes([seed; 32])
}

fn setup_pair_with_yamux_config(
    yamux_config: Option<YamuxConfig>,
) -> (
    CircuitTransport<InMemoryTransport, CounterEntropy>,
    CircuitTransport<InMemoryTransport, CounterEntropy>,
    ConnectionId,
    StreamId,
    PeerId,
    PeerId,
) {
    let limits = CircuitLimits {
        yamux: yamux_config.unwrap_or_default(),
    };
    let relay = identity(9).peer_id();
    let a_identity = identity(1);
    let b_identity = identity(2);
    let a_peer = a_identity.peer_id();
    let b_peer = b_identity.peer_id();
    let (inner_a, inner_b) = InMemoryTransport::pair(relay, relay);
    let inner_conn = inner_a.connection_id();
    let mut a =
        CircuitTransport::with_limits(inner_a, a_identity, CounterEntropy(10), limits.clone())
            .expect("valid limits");
    let mut b = CircuitTransport::with_limits(inner_b, b_identity, CounterEntropy(20), limits)
        .expect("valid limits");

    let _ = a.poll(Now::from_millis(0)).expect("initial A events");
    let _ = b.poll(Now::from_millis(0)).expect("initial B events");
    let bridge = a.inner_mut().open_stream(inner_conn).expect("bridge open");
    let _ = a.poll(Now::from_millis(0)).expect("local bridge event");
    let _ = b.poll(Now::from_millis(0)).expect("remote bridge event");

    let a_id = a
        .adopt_bridge(BridgeAdoption {
            inner_conn,
            bridge_stream: bridge,
            relay,
            remote_peer: b_peer,
            role: CircuitRole::Initiator,
            pending_data: Bytes::from(Vec::new()),
            unsent_prefix: Bytes::new(),
            remote_write_closed: false,
        })
        .expect("initiator adoption");
    let b_id = b
        .adopt_bridge(BridgeAdoption {
            inner_conn,
            bridge_stream: bridge,
            relay,
            remote_peer: a_peer,
            role: CircuitRole::Responder,
            pending_data: Bytes::from(Vec::new()),
            unsent_prefix: Bytes::new(),
            remote_write_closed: false,
        })
        .expect("responder adoption");
    assert_eq!(a_id, b_id);
    assert!(CircuitTransport::<InMemoryTransport, CounterEntropy>::is_circuit(a_id));
    let incoming = b.poll(Now::from_millis(0)).expect("responder incoming");
    assert!(matches!(
        incoming.as_slice(),
        [TransportEvent::IncomingConnection { id, endpoint }]
            if *id == b_id && endpoint.peer_id().is_none()
    ));
    (a, b, a_id, bridge, a_peer, b_peer)
}

fn setup_pair() -> (
    CircuitTransport<InMemoryTransport, CounterEntropy>,
    CircuitTransport<InMemoryTransport, CounterEntropy>,
    ConnectionId,
    StreamId,
    PeerId,
    PeerId,
) {
    setup_pair_with_yamux_config(None)
}

fn setup_close_observed_pair() -> CloseObservedPair {
    let relay = identity(9).peer_id();
    let a_identity = identity(1);
    let b_identity = identity(2);
    let a_peer = a_identity.peer_id();
    let b_peer = b_identity.peer_id();
    let (inner_a, inner_b) = InMemoryTransport::pair(relay, relay);
    let inner_conn = inner_a.connection_id();
    let mut a = CircuitTransport::new(
        CloseObservingTransport::new(inner_a),
        a_identity,
        CounterEntropy(10),
    );
    let mut b = CircuitTransport::new(inner_b, b_identity, CounterEntropy(20));
    let _ = a.poll(Now::from_millis(0)).expect("initial A events");
    let _ = b.poll(Now::from_millis(0)).expect("initial B events");
    let bridge = a.inner_mut().open_stream(inner_conn).expect("bridge open");
    let _ = a.poll(Now::from_millis(0)).expect("local bridge event");
    let _ = b.poll(Now::from_millis(0)).expect("remote bridge event");
    let a_id = a
        .adopt_bridge(BridgeAdoption {
            inner_conn,
            bridge_stream: bridge,
            relay,
            remote_peer: b_peer,
            role: CircuitRole::Initiator,
            pending_data: Bytes::from(Vec::new()),
            unsent_prefix: Bytes::new(),
            remote_write_closed: false,
        })
        .expect("initiator adoption");
    let b_id = b
        .adopt_bridge(BridgeAdoption {
            inner_conn,
            bridge_stream: bridge,
            relay,
            remote_peer: a_peer,
            role: CircuitRole::Responder,
            pending_data: Bytes::from(Vec::new()),
            unsent_prefix: Bytes::new(),
            remote_write_closed: false,
        })
        .expect("responder adoption");
    assert_eq!(a_id, b_id);
    assert!(matches!(
        b.poll(Now::from_millis(0)).expect("responder incoming").as_slice(),
        [TransportEvent::IncomingConnection { id, .. }] if *id == b_id
    ));
    (a, b, a_id, bridge, a_peer, b_peer)
}

fn complete_handshake<TA, EA, TB, EB>(
    a: &mut CircuitTransport<TA, EA>,
    b: &mut CircuitTransport<TB, EB>,
    circuit_id: ConnectionId,
    a_peer: &PeerId,
    b_peer: &PeerId,
) where
    TA: Transport,
    EA: EntropySource,
    TB: Transport,
    EB: EntropySource,
{
    let mut a_connected = false;
    let mut b_connected = false;
    for _ in 0..32 {
        for event in a.poll(Now::from_millis(0)).expect("drive initiator") {
            if let TransportEvent::Connected { id, endpoint } = event
                && id == circuit_id
            {
                assert_eq!(endpoint.peer_id(), Some(b_peer));
                a_connected = true;
            }
        }
        for event in b.poll(Now::from_millis(0)).expect("drive responder") {
            if let TransportEvent::Connected { id, endpoint } = event
                && id == circuit_id
            {
                assert_eq!(endpoint.peer_id(), Some(a_peer));
                b_connected = true;
            }
        }
        if a_connected && b_connected {
            return;
        }
    }
    panic!("circuit handshake did not complete");
}

#[test]
fn a_quiet_circuit_keeps_alive_without_opening_a_stream() {
    let (mut a, mut b, circuit_id, bridge, a_peer, b_peer) = setup_close_observed_pair();
    complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
    let inner_conn = a
        .circuits
        .get(&circuit_id)
        .expect("initiator circuit")
        .inner_conn;

    assert_eq!(
        a.next_deadline(),
        Some(Deadline::from_millis(KEEPALIVE_INTERVAL_MS)),
        "Connected must arm keepalive without another poll"
    );

    let a_sends = a.inner().send_calls;

    let ping = a
        .poll(Now::from_millis(KEEPALIVE_INTERVAL_MS))
        .expect("initiator keepalive");
    assert!(
        ping.iter()
            .all(|event| !matches!(event, TransportEvent::StreamData { .. })),
        "a yamux ping is not stream data: {ping:?}"
    );
    assert_eq!(
        a.inner().send_calls,
        a_sends + 1,
        "the keepalive deadline must write a Yamux ping to the bridge"
    );

    let ping_wire = b
        .inner_mut()
        .poll(Now::from_millis(KEEPALIVE_INTERVAL_MS))
        .expect("read ping from bridge");
    let ping_bytes = ping_wire
        .into_iter()
        .find_map(|event| match event {
            TransportEvent::StreamData {
                stream_id, data, ..
            } if stream_id == bridge => Some(data),
            _ => None,
        })
        .expect("Yamux ping bytes crossed the bridge");
    b.inject_bridge_data(inner_conn, bridge, ping_bytes);

    let pong_wire = a
        .inner_mut()
        .poll(Now::from_millis(KEEPALIVE_INTERVAL_MS))
        .expect("read pong from bridge");
    let pong_bytes = pong_wire
        .into_iter()
        .find_map(|event| match event {
            TransportEvent::StreamData {
                stream_id, data, ..
            } if stream_id == bridge => Some(data),
            _ => None,
        })
        .expect("Yamux pong bytes crossed the bridge");
    a.inject_bridge_data(inner_conn, bridge, pong_bytes);

    let ack = a
        .poll(Now::from_millis(KEEPALIVE_INTERVAL_MS))
        .expect("initiator sees the pong");
    assert!(
        ack.is_empty(),
        "a keepalive pong is session traffic: {ack:?}"
    );
    assert!(
        a.circuit_ids().contains(&circuit_id),
        "keepalive must not tear the circuit down"
    );
}

#[test]
fn an_unanswered_keepalive_closes_the_circuit_as_timed_out() {
    let (mut a, mut b, circuit_id, _bridge, a_peer, b_peer) = setup_close_observed_pair();
    complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);

    a.poll(Now::from_millis(KEEPALIVE_INTERVAL_MS))
        .expect("ping");
    a.poll(Now::from_millis(KEEPALIVE_INTERVAL_MS))
        .expect("date the hand-off");
    let answer_by = KEEPALIVE_INTERVAL_MS + KEEPALIVE_ACK_TIMEOUT_MS;
    assert_eq!(a.next_deadline(), Some(Deadline::from_millis(answer_by)));

    let events = a.poll(Now::from_millis(answer_by)).expect("time out");
    assert!(
        events.contains(&TransportEvent::Closed {
            id: circuit_id,
            reason: ConnectionCloseReason::TimedOut,
        }),
        "{events:?}"
    );
    assert!(!a.circuit_ids().contains(&circuit_id));
}

#[test]
fn buffered_events_never_expire_keepalive_ahead_of_an_unread_pong() {
    let (mut a, mut b, circuit_id, bridge, a_peer, b_peer) = setup_close_observed_pair();
    complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
    let inner_conn = a
        .circuits
        .get(&circuit_id)
        .expect("initiator circuit")
        .inner_conn;

    a.poll(Now::from_millis(KEEPALIVE_INTERVAL_MS))
        .expect("ping");
    a.poll(Now::from_millis(KEEPALIVE_INTERVAL_MS))
        .expect("date the hand-off");
    let ping_bytes = b
        .inner_mut()
        .poll(Now::from_millis(KEEPALIVE_INTERVAL_MS))
        .expect("read ping from bridge")
        .into_iter()
        .find_map(|event| match event {
            TransportEvent::StreamData {
                stream_id, data, ..
            } if stream_id == bridge => Some(data),
            _ => None,
        })
        .expect("Yamux ping bytes crossed the bridge");
    b.inject_bridge_data(inner_conn, bridge, ping_bytes);

    let stream_id = a.open_stream(circuit_id).expect("open stream");
    let answer_by = Now::from_millis(KEEPALIVE_INTERVAL_MS + KEEPALIVE_ACK_TIMEOUT_MS);

    assert_eq!(
        a.poll(answer_by).expect("drain buffered events"),
        vec![TransportEvent::StreamOpened {
            id: circuit_id,
            stream_id,
        }]
    );
    let events = a.poll(answer_by).expect("read the pong");
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, TransportEvent::Closed { .. })),
        "a pong unread when the deadline came still answers the ping: {events:?}"
    );
    assert!(a.circuit_ids().contains(&circuit_id));
}

#[test]
fn circuit_runs_noise_yamux_and_stream_contract() {
    let (mut a, mut b, circuit_id, _bridge, a_peer, b_peer) = setup_pair();
    complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);

    let stream = a.open_stream(circuit_id).expect("open circuit stream");
    assert_eq!(stream.as_u64() % 2, 1, "initiator streams are odd");
    assert!(a
        .poll(Now::from_millis(0))
        .expect("opened")
        .iter()
        .any(|event| matches!(event, TransportEvent::StreamOpened { id, stream_id } if *id == circuit_id && *stream_id == stream)));
    let incoming = b.poll(Now::from_millis(0)).expect("incoming stream");
    assert!(incoming.iter().any(|event| matches!(event,
        TransportEvent::IncomingStream { id, stream_id }
            if *id == circuit_id && *stream_id == stream
    )));

    a.send_stream(circuit_id, stream, Bytes::from_static(b"hello"))
        .expect("send");
    let data = b.poll(Now::from_millis(0)).expect("data");
    assert!(data.iter().any(|event| matches!(event,
        TransportEvent::StreamData { id, stream_id, data }
            if *id == circuit_id && *stream_id == stream && data[..] == b"hello"[..]
    )));

    a.close_stream_write(circuit_id, stream).expect("FIN");
    let eof = b.poll(Now::from_millis(0)).expect("remote FIN");
    assert!(eof.iter().any(|event| matches!(event,
        TransportEvent::StreamRemoteWriteClosed { id, stream_id }
            if *id == circuit_id && *stream_id == stream
    )));
    b.send_stream(circuit_id, stream, Bytes::from_static(b"reply"))
        .expect("reverse send remains open");
    let reply = a.poll(Now::from_millis(0)).expect("reply");
    assert!(reply.iter().any(|event| matches!(event,
        TransportEvent::StreamData { data, .. } if data[..] == b"reply"[..]
    )));

    b.reset_stream(circuit_id, stream).expect("reset");
    let local_closed = b.poll(Now::from_millis(0)).expect("local reset close");
    assert_eq!(
        local_closed
            .iter()
            .filter(|event| matches!(event, TransportEvent::StreamClosed { id, stream_id } if *id == circuit_id && *stream_id == stream))
            .count(),
        1
    );
    let remote_closed = a.poll(Now::from_millis(0)).expect("remote reset close");
    assert!(remote_closed.iter().any(|event| matches!(event,
        TransportEvent::StreamClosed { id, stream_id }
            if *id == circuit_id && *stream_id == stream
    )));
}

#[test]
fn wrapper_transport_contract_orders_connection_and_stream_events() {
    let (mut a, mut b, circuit_id, _bridge, a_peer, b_peer) = setup_pair();
    let mut a_events = Vec::new();
    let mut b_events = Vec::new();
    for _ in 0..32 {
        a_events.extend(a.poll(Now::from_millis(0)).expect("drive initiator"));
        b_events.extend(b.poll(Now::from_millis(0)).expect("drive responder"));
        let a_connected = a_events.iter().any(
            |event| matches!(event, TransportEvent::Connected { id, .. } if *id == circuit_id),
        );
        let b_connected = b_events.iter().any(
            |event| matches!(event, TransportEvent::Connected { id, .. } if *id == circuit_id),
        );
        if a_connected && b_connected {
            break;
        }
    }
    for (events, expected_peer) in [(&a_events, &b_peer), (&b_events, &a_peer)] {
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, TransportEvent::Connected { id, .. } if *id == circuit_id))
                .count(),
            1,
            "Connected must be emitted exactly once"
        );
        let connected = events
            .iter()
            .position(|event| {
                matches!(event,
                    TransportEvent::Connected { id, endpoint }
                        if *id == circuit_id && endpoint.peer_id() == Some(expected_peer)
                )
            })
            .expect("authenticated Connected event");
        assert!(!events[..connected].iter().any(|event| matches!(
            event,
            TransportEvent::StreamOpened { id, .. }
                | TransportEvent::IncomingStream { id, .. }
                | TransportEvent::StreamData { id, .. }
                | TransportEvent::StreamRemoteWriteClosed { id, .. }
                | TransportEvent::StreamClosed { id, .. }
                if *id == circuit_id
        )));
    }
    assert!(
        a.poll(Now::from_millis(0))
            .expect("idle initiator")
            .is_empty()
    );
    assert!(
        b.poll(Now::from_millis(0))
            .expect("idle responder")
            .is_empty()
    );

    let stream = a.open_stream(circuit_id).expect("open stream");
    a.send_stream(circuit_id, stream, Bytes::from_static(b"ordered"))
        .expect("send immediately after open");
    assert_eq!(
        a.poll(Now::from_millis(0)).expect("local stream event"),
        [TransportEvent::StreamOpened {
            id: circuit_id,
            stream_id: stream,
        }]
    );
    let inbound = b
        .poll(Now::from_millis(0))
        .expect("coalesced stream open and data");
    let incoming = inbound
        .iter()
        .position(|event| {
            matches!(event,
                TransportEvent::IncomingStream { id, stream_id }
                    if *id == circuit_id && *stream_id == stream
            )
        })
        .expect("IncomingStream event");
    let data = inbound
        .iter()
        .position(|event| {
            matches!(event,
                TransportEvent::StreamData { id, stream_id, data }
                    if *id == circuit_id && *stream_id == stream && data[..] == b"ordered"[..]
            )
        })
        .expect("StreamData event");
    assert!(incoming < data, "IncomingStream must precede StreamData");

    a.reset_stream(circuit_id, stream).expect("reset stream");
    assert_eq!(
        a.poll(Now::from_millis(0))
            .expect("immediate local terminal event"),
        [TransportEvent::StreamClosed {
            id: circuit_id,
            stream_id: stream,
        }]
    );
    assert_eq!(
        b.poll(Now::from_millis(0)).expect("remote terminal event"),
        [TransportEvent::StreamClosed {
            id: circuit_id,
            stream_id: stream,
        }]
    );
    assert!(
        a.poll(Now::from_millis(0))
            .expect("no events after local terminal")
            .is_empty()
    );
    assert!(
        b.poll(Now::from_millis(0))
            .expect("no events after remote terminal")
            .is_empty()
    );
}

#[test]
fn wrapper_transport_contract_rejects_unknown_connection_and_stream_ids() {
    let (mut a, mut b, circuit_id, _bridge, a_peer, b_peer) = setup_pair();
    complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
    let unknown_connection =
        ConnectionId::namespaced(ConnectionNamespace::CIRCUIT, 999).expect("circuit id in range");
    let stream = StreamId::new(99);

    assert!(matches!(
        a.open_stream(unknown_connection),
        Err(TransportError::ConnectionNotFound { id }) if id == unknown_connection
    ));
    assert!(matches!(
        a.send_stream(unknown_connection, stream, Bytes::from(vec![1])),
        Err(TransportError::ConnectionNotFound { id }) if id == unknown_connection
    ));
    assert!(matches!(
        a.close_stream_write(unknown_connection, stream),
        Err(TransportError::ConnectionNotFound { id }) if id == unknown_connection
    ));
    assert!(matches!(
        a.reset_stream(unknown_connection, stream),
        Err(TransportError::ConnectionNotFound { id }) if id == unknown_connection
    ));
    assert_eq!(
        a.close(unknown_connection),
        Err(TransportError::ConnectionNotFound {
            id: unknown_connection,
        })
    );

    let oversized_stream = StreamId::new(u64::from(u32::MAX) + 1);
    assert_eq!(
        a.send_stream(unknown_connection, oversized_stream, Bytes::from(vec![1])),
        Err(TransportError::ConnectionNotFound {
            id: unknown_connection,
        })
    );
    assert_eq!(
        a.close_stream_write(unknown_connection, oversized_stream),
        Err(TransportError::ConnectionNotFound {
            id: unknown_connection,
        })
    );
    assert_eq!(
        a.reset_stream(unknown_connection, oversized_stream),
        Err(TransportError::ConnectionNotFound {
            id: unknown_connection,
        })
    );

    let live = a.open_stream(circuit_id).expect("open a live substream");
    let aliased = StreamId::new(live.as_u64() + (1u64 << 32));
    for result in [
        a.send_stream(circuit_id, aliased, Bytes::from(vec![1])),
        a.close_stream_write(circuit_id, aliased),
        a.reset_stream(circuit_id, aliased),
    ] {
        assert_eq!(
            result,
            Err(TransportError::StreamNotFound {
                id: circuit_id,
                stream_id: aliased,
            })
        );
    }

    for result in [
        a.send_stream(circuit_id, stream, Bytes::from(vec![1])),
        a.close_stream_write(circuit_id, stream),
        a.reset_stream(circuit_id, stream),
    ] {
        assert_eq!(
            result,
            Err(TransportError::StreamNotFound {
                id: circuit_id,
                stream_id: stream,
            })
        );
    }
}

#[test]
fn adoption_processes_pending_bridge_bytes_before_live_input() {
    let relay = identity(9).peer_id();
    let a_identity = identity(1);
    let b_identity = identity(2);
    let a_peer = a_identity.peer_id();
    let b_peer = b_identity.peer_id();
    let (inner_a, inner_b) = InMemoryTransport::pair(relay, relay);
    let inner_conn = inner_a.connection_id();
    let mut a = CircuitTransport::new(inner_a, a_identity, CounterEntropy(10));
    let mut b = CircuitTransport::new(inner_b, b_identity, CounterEntropy(20));
    let _ = a.poll(Now::from_millis(0)).expect("initial A events");
    let _ = b.poll(Now::from_millis(0)).expect("initial B events");
    let bridge = a.inner_mut().open_stream(inner_conn).expect("bridge open");
    let _ = a.poll(Now::from_millis(0)).expect("local bridge event");
    let _ = b.poll(Now::from_millis(0)).expect("remote bridge event");
    let circuit_id = a
        .adopt_bridge(BridgeAdoption {
            inner_conn,
            bridge_stream: bridge,
            relay,
            remote_peer: b_peer,
            role: CircuitRole::Initiator,
            pending_data: Bytes::from(Vec::new()),
            unsent_prefix: Bytes::new(),
            remote_write_closed: false,
        })
        .expect("initiator adoption");
    let first_write = b
        .inner_mut()
        .poll(Now::from_millis(0))
        .expect("read pipelined header and proposal")
        .into_iter()
        .find_map(|event| match event {
            TransportEvent::StreamData { data, .. } => Some(data),
            _ => None,
        })
        .expect("initiator header and proposal");
    let split = first_write.len() / 2;
    b.adopt_bridge(BridgeAdoption {
        inner_conn,
        bridge_stream: bridge,
        relay,
        remote_peer: a_peer,
        role: CircuitRole::Responder,
        pending_data: Bytes::from(first_write[..split].to_vec()),
        unsent_prefix: Bytes::new(),
        remote_write_closed: false,
    })
    .expect("responder adoption with partial pending data");
    assert!(matches!(
        b.poll(Now::from_millis(0))
            .expect("incoming event")
            .as_slice(),
        [TransportEvent::IncomingConnection { .. }]
    ));
    b.inject_bridge_data(
        inner_conn,
        bridge,
        Bytes::from(first_write[split..].to_vec()),
    );
    complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
}

#[test]
fn an_unsent_prefix_reaches_the_peer_before_the_circuit_handshake() {
    let relay = identity(9).peer_id();
    let a_identity = identity(1);
    let b_identity = identity(2);
    let a_peer = a_identity.peer_id();
    let b_peer = b_identity.peer_id();
    let (inner_a, inner_b) = InMemoryTransport::pair(relay, relay);
    let inner_conn = inner_a.connection_id();
    let mut a = CircuitTransport::new(inner_a, a_identity, CounterEntropy(10));
    let mut b = CircuitTransport::new(inner_b, b_identity, CounterEntropy(20));
    let _ = a.poll(Now::from_millis(0)).expect("initial A events");
    let _ = b.poll(Now::from_millis(0)).expect("initial B events");
    let bridge = a.inner_mut().open_stream(inner_conn).expect("bridge open");
    let _ = a.poll(Now::from_millis(0)).expect("local bridge event");
    let _ = b.poll(Now::from_millis(0)).expect("remote bridge event");
    let prefix = Bytes::from_static(b"held STATUS tail");
    let circuit_id = a
        .adopt_bridge(BridgeAdoption {
            inner_conn,
            bridge_stream: bridge,
            relay,
            remote_peer: b_peer,
            role: CircuitRole::Initiator,
            pending_data: Bytes::new(),
            unsent_prefix: prefix.clone(),
            remote_write_closed: false,
        })
        .expect("initiator adoption");
    let received: Vec<u8> = b
        .inner_mut()
        .poll(Now::from_millis(0))
        .expect("read the bridge")
        .into_iter()
        .filter_map(|event| match event {
            TransportEvent::StreamData { data, .. } => Some(data),
            _ => None,
        })
        .flatten()
        .collect();
    let handshake = received
        .strip_prefix(prefix.as_ref())
        .expect("the prefix comes first");
    assert!(!handshake.is_empty(), "the handshake follows the prefix");
    b.adopt_bridge(BridgeAdoption {
        inner_conn,
        bridge_stream: bridge,
        relay,
        remote_peer: a_peer,
        role: CircuitRole::Responder,
        pending_data: Bytes::from(handshake.to_vec()),
        unsent_prefix: Bytes::new(),
        remote_write_closed: false,
    })
    .expect("responder adoption");
    let _ = b.poll(Now::from_millis(0)).expect("incoming event");
    complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
}

#[test]
fn adoption_processes_pipelined_selection_and_noise_message() {
    let relay = identity(9).peer_id();
    let a_identity = identity(1);
    let b_identity = identity(2);
    let a_peer = a_identity.peer_id();
    let b_peer = b_identity.peer_id();
    let (inner_a, inner_b) = InMemoryTransport::pair(relay, relay);
    let inner_conn = inner_a.connection_id();
    let mut a = CircuitTransport::new(inner_a, a_identity.clone(), CounterEntropy(10));
    let mut b = CircuitTransport::new(inner_b, b_identity, CounterEntropy(20));
    let _ = a.poll(Now::from_millis(0)).expect("initial A events");
    let _ = b.poll(Now::from_millis(0)).expect("initial B events");
    let bridge = a.inner_mut().open_stream(inner_conn).expect("bridge open");
    let _ = a.poll(Now::from_millis(0)).expect("local bridge event");
    let _ = b.poll(Now::from_millis(0)).expect("remote bridge event");

    let mut select = MultistreamSelect::dialer(NOISE_PROTOCOL_ID);
    select.start();
    let mut pending_data = Vec::new();
    while let Some(output) = select.poll_output() {
        if let MultistreamOutput::OutboundData(bytes) = output {
            pending_data.extend(bytes);
        }
    }
    let mut scripted_listener = MultistreamSelect::listener([NOISE_PROTOCOL_ID.to_string()]);
    scripted_listener.start();
    let listener_header = match scripted_listener.poll_output() {
        Some(MultistreamOutput::OutboundData(bytes)) => bytes,
        other => panic!("expected listener header, got {other:?}"),
    };
    select.on_data(&listener_header);
    while let Some(output) = select.poll_output() {
        if let MultistreamOutput::OutboundData(bytes) = output {
            pending_data.extend(bytes);
        }
    }
    let selection_len = pending_data.len();
    let mut scripted_noise = NoiseSession::new(NoiseConfig {
        role: NoiseRole::Initiator,
        identity: a_identity,
        static_secret: [11; 32],
        ephemeral_secret: [12; 32],
        expected_peer: Some(b_peer),
        local_extensions: None,
    });
    scripted_noise.start().expect("scripted Noise start");
    while let Some(output) = scripted_noise.poll_output() {
        if let NoiseOutput::Outbound(bytes) = output {
            pending_data.extend(bytes);
        }
    }
    assert!(selection_len > 0 && pending_data.len() > selection_len);

    let circuit_id = b
        .adopt_bridge(BridgeAdoption {
            inner_conn,
            bridge_stream: bridge,
            relay,
            remote_peer: a_peer,
            role: CircuitRole::Responder,
            pending_data: Bytes::from(pending_data),
            unsent_prefix: Bytes::new(),
            remote_write_closed: false,
        })
        .expect("responder adopts pipelined selection and Noise msg1");
    let responder_events = b
        .poll(Now::from_millis(0))
        .expect("responder incoming event");
    assert!(
        matches!(
            responder_events.as_slice(),
            [TransportEvent::IncomingConnection { id, .. }] if *id == circuit_id
        ),
        "unexpected pipelined adoption events: {responder_events:?}"
    );

    let a_id = a
        .adopt_bridge(BridgeAdoption {
            inner_conn,
            bridge_stream: bridge,
            relay,
            remote_peer: b_peer,
            role: CircuitRole::Initiator,
            pending_data: Bytes::from(Vec::new()),
            unsent_prefix: Bytes::new(),
            remote_write_closed: false,
        })
        .expect("real initiator adoption");
    assert_eq!(a_id, circuit_id);

    let duplicate_selection = b
        .inner_mut()
        .poll(Now::from_millis(0))
        .expect("duplicate selection");
    assert!(
        duplicate_selection
            .iter()
            .any(|event| matches!(event, TransportEvent::StreamData { .. }))
    );
    let _ = a
        .poll(Now::from_millis(0))
        .expect("initiator consumes pipelined response");

    let mut real_followup = b
        .inner_mut()
        .poll(Now::from_millis(0))
        .expect("real Noise follow-up");
    let duplicate = real_followup
        .iter()
        .position(|event| matches!(event, TransportEvent::StreamData { .. }))
        .expect("duplicate Noise msg1");
    real_followup.remove(duplicate);
    for event in real_followup {
        b.handle_inner_event(event);
    }

    complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
}

#[test]
fn decrypt_batch_crosses_yamux_selection_into_ready_frames() {
    let (mut a, mut b, circuit_id, bridge, _a_peer, _b_peer) = setup_pair();

    for _ in 0..32 {
        let _ = a
            .poll(Now::from_millis(0))
            .expect("drive initiator toward Yamux selection");
        let _ = b
            .poll(Now::from_millis(0))
            .expect("drive responder toward Yamux selection");
        if selecting_yamux(&a, circuit_id) && established(&b, circuit_id) {
            break;
        }
    }
    assert!(selecting_yamux(&a, circuit_id));
    assert!(established(&b, circuit_id));

    let opened = b.open_stream(circuit_id).expect("open responder stream");
    let raw = a
        .inner_mut()
        .poll(Now::from_millis(0))
        .expect("read encrypted bridge batch");
    let chunks: Vec<_> = raw
        .into_iter()
        .filter_map(|event| match event {
            TransportEvent::StreamData {
                stream_id, data, ..
            } if stream_id == bridge => Some(data),
            _ => None,
        })
        .collect();
    assert!(chunks.len() >= 2, "expected selection and Yamux frames");
    let coalesced = chunks.into_iter().flatten().collect();
    let inner_conn = a
        .circuits
        .get(&circuit_id)
        .expect("initiator circuit")
        .inner_conn;
    a.inject_bridge_data(inner_conn, bridge, coalesced);
    assert_eq!(
        a.next_deadline(),
        Some(Deadline::IMMEDIATE),
        "an injected handshake completion queues events to deliver"
    );

    let events = a
        .poll(Now::from_millis(0))
        .expect("drain cross-boundary outputs");
    assert!(
        events.iter().any(
            |event| matches!(event, TransportEvent::Connected { id, .. } if *id == circuit_id)
        )
    );
    assert!(events.iter().any(|event| matches!(
        event,
        TransportEvent::IncomingStream { id, stream_id }
            if *id == circuit_id && *stream_id == opened
    )));
    assert_eq!(
        a.next_deadline(),
        Some(Deadline::from_millis(KEEPALIVE_INTERVAL_MS)),
        "the drain armed the session it established, so the next deadline is real"
    );
    assert!(
        a.poll(Now::from_millis(0))
            .expect("nothing left to do")
            .is_empty()
    );
    assert_eq!(
        a.next_deadline(),
        Some(Deadline::from_millis(KEEPALIVE_INTERVAL_MS)),
        "and no extra wakeup was needed to get there"
    );
}

fn assert_pre_ready_bridge_failure(events: &[TransportEvent], circuit_id: ConnectionId) {
    assert!(matches!(
        events,
        [TransportEvent::Closed {
            id,
            reason: ConnectionCloseReason::Error(_),
        }] if *id == circuit_id
    ));
    assert!(!events.iter().any(|event| matches!(
        event,
        TransportEvent::Connected { id, .. } if *id == circuit_id
    )));
}

#[test]
fn bridge_reset_mid_handshake_is_terminal() {
    let (mut a, _b, circuit_id, bridge, _a_peer, _b_peer) = setup_pair();
    let inner_conn = ConnectionId::new(1);

    a.inject_bridge_closed(inner_conn, bridge);
    let events = a.poll(Now::from_millis(0)).expect("pre-ready bridge reset");
    assert_pre_ready_bridge_failure(&events, circuit_id);
    assert!(
        a.poll(Now::from_millis(0))
            .expect("consume reset acknowledgement")
            .is_empty()
    );

    a.inject_bridge_data(inner_conn, bridge, Bytes::from_static(b"late"));
    a.inject_bridge_remote_write_closed(inner_conn, bridge);
    a.inject_bridge_closed(inner_conn, bridge);
    assert!(
        a.poll(Now::from_millis(0))
            .expect("nothing follows terminal close")
            .is_empty()
    );
}

#[test]
fn bridge_write_stop_fails_the_circuit() {
    let (mut a, _b, circuit_id, bridge, _a_peer, _b_peer) = setup_pair();

    a.inject_bridge_write_stopped(ConnectionId::new(1), bridge);
    let events = a.poll(Now::from_millis(0)).expect("bridge write stop");
    assert_pre_ready_bridge_failure(&events, circuit_id);
}

#[test]
fn bridge_remote_fin_mid_handshake_is_terminal() {
    let (mut a, _b, circuit_id, bridge, _a_peer, _b_peer) = setup_pair();
    let inner_conn = ConnectionId::new(1);

    a.inject_bridge_remote_write_closed(inner_conn, bridge);
    let events = a.poll(Now::from_millis(0)).expect("pre-ready bridge FIN");
    assert_pre_ready_bridge_failure(&events, circuit_id);
    assert!(
        a.poll(Now::from_millis(0))
            .expect("consume reset acknowledgement")
            .is_empty()
    );

    a.inject_bridge_data(inner_conn, bridge, Bytes::from_static(b"late"));
    assert!(
        a.poll(Now::from_millis(0))
            .expect("post-close data is ignored")
            .is_empty()
    );
}

#[test]
fn adoption_is_idempotent_and_close_is_terminal() {
    let (mut a, mut b, circuit_id, bridge, a_peer, b_peer) = setup_pair();
    let relay = identity(9).peer_id();
    let duplicate = a
        .adopt_bridge(BridgeAdoption {
            inner_conn: ConnectionId::new(1),
            bridge_stream: bridge,
            relay,
            remote_peer: b_peer,
            role: CircuitRole::Initiator,
            pending_data: Bytes::from(Vec::new()),
            unsent_prefix: Bytes::new(),
            remote_write_closed: false,
        })
        .expect("identical duplicate is idempotent");
    assert_eq!(duplicate, circuit_id);
    assert_eq!(
        a.adopt_bridge(BridgeAdoption {
            inner_conn: ConnectionId::new(1),
            bridge_stream: bridge,
            relay: identity(8).peer_id(),
            remote_peer: b_peer,
            role: CircuitRole::Initiator,
            pending_data: Bytes::from(Vec::new()),
            unsent_prefix: Bytes::new(),
            remote_write_closed: false,
        }),
        Err(AdoptError::ConflictingAdoption)
    );
    assert_eq!(
        a.adopt_bridge(BridgeAdoption {
            inner_conn: ConnectionId::new(1),
            bridge_stream: bridge,
            relay,
            remote_peer: b_peer,
            role: CircuitRole::Initiator,
            pending_data: Bytes::from(Vec::new()),
            unsent_prefix: Bytes::new(),
            remote_write_closed: true,
        }),
        Err(AdoptError::ConflictingAdoption)
    );
    complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
    a.close(circuit_id).expect("graceful close");
    let events = a.poll(Now::from_millis(0)).expect("closed event");
    assert_eq!(
        events,
        vec![TransportEvent::Closed {
            id: circuit_id,
            reason: ConnectionCloseReason::Local
        }]
    );
    assert!(matches!(
        a.open_stream(circuit_id),
        Err(TransportError::ConnectionNotFound { .. })
    ));
    a.inject_bridge_data(ConnectionId::new(1), bridge, Bytes::from_static(b"late"));
    a.inject_bridge_remote_write_closed(ConnectionId::new(1), bridge);
    a.inject_bridge_closed(ConnectionId::new(1), bridge);
    assert!(
        a.poll(Now::from_millis(0))
            .expect("late bridge events are dropped")
            .is_empty()
    );
}

#[test]
fn ready_close_sends_go_away_then_bridge_fin_without_reset() {
    let (mut a, mut b, circuit_id, _bridge, a_peer, b_peer) = setup_close_observed_pair();
    complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
    let stream = a.open_stream(circuit_id).expect("open stream before close");
    let _ = a.poll(Now::from_millis(0)).expect("local stream open");
    let _ = b.poll(Now::from_millis(0)).expect("remote stream open");
    let _ = a.poll(Now::from_millis(0)).expect("stream acknowledgement");
    a.send_stream(
        circuit_id,
        stream,
        Bytes::from_static(b"queued-before-close"),
    )
    .expect("queue application data before close");

    a.close(circuit_id).expect("graceful circuit close");
    assert_eq!(a.inner().close_write_calls, 1);
    assert_eq!(a.inner().reset_calls, 0);
    assert_eq!(
        a.poll(Now::from_millis(0)).expect("local close event"),
        [
            TransportEvent::StreamClosed {
                id: circuit_id,
                stream_id: stream,
            },
            TransportEvent::Closed {
                id: circuit_id,
                reason: ConnectionCloseReason::Local
            },
        ]
    );

    let peer_wire = b
        .inner_mut()
        .poll(Now::from_millis(0))
        .expect("peer bridge events");
    let data_positions: Vec<_> = peer_wire
        .iter()
        .enumerate()
        .filter_map(|(index, event)| {
            matches!(event, TransportEvent::StreamData { .. }).then_some(index)
        })
        .collect();
    assert_eq!(
        data_positions.len(),
        2,
        "application data and encrypted GoAway must both reach the peer"
    );
    let go_away = data_positions[1];
    let fin = peer_wire
        .iter()
        .position(|event| matches!(event, TransportEvent::StreamRemoteWriteClosed { .. }))
        .expect("bridge FIN reaches the peer");
    assert!(go_away < fin, "GoAway must be queued before bridge FIN");
    assert!(
        !peer_wire
            .iter()
            .any(|event| matches!(event, TransportEvent::StreamClosed { .. }))
    );
    for event in peer_wire {
        b.handle_inner_event(event);
    }
    let peer_events = b
        .poll(Now::from_millis(0))
        .expect("peer observes data then GoAway");
    assert!(
        matches!(
            peer_events.as_slice(),
            [
                TransportEvent::StreamData { id, stream_id, data },
                TransportEvent::StreamClosed {
                    id: stream_closed_id,
                    stream_id: closed_stream,
                },
                TransportEvent::Closed { id: closed_id, .. },
            ] if *id == circuit_id
                && *stream_id == stream
                && data[..] == b"queued-before-close"[..]
                && *stream_closed_id == circuit_id
                && *closed_stream == stream
                && *closed_id == circuit_id
        ),
        "unexpected peer close events: {peer_events:?}"
    );
    assert!(
        b.poll(Now::from_millis(0))
            .expect("terminal peer state")
            .is_empty()
    );
}

#[test]
fn a_close_behind_a_full_bridge_flushes_then_fins_without_reset() {
    let (mut a, mut b, circuit_id, bridge, a_peer, b_peer) = setup_close_observed_pair();
    complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
    let inner_conn = ConnectionId::new(1);
    let stream = a.open_stream(circuit_id).expect("open stream before close");
    let _ = a.poll(Now::from_millis(0)).expect("local stream open");
    let _ = b.poll(Now::from_millis(0)).expect("remote stream open");
    let _ = a.poll(Now::from_millis(0)).expect("stream acknowledgement");
    a.inner_mut().full = true;
    a.send_stream(circuit_id, stream, Bytes::from_static(b"held-behind-full"))
        .expect("the circuit holds what the bridge refused");

    a.close(circuit_id).expect("graceful circuit close");
    assert_eq!(a.inner().reset_calls, 0, "a Full bridge is not reset");
    assert_eq!(a.inner().close_write_calls, 0, "no FIN ahead of held bytes");
    assert!(
        a.has_pending_writes(),
        "the closing bridge still holds bytes"
    );
    assert!(
        a.poll(Now::from_millis(0))
            .expect("local close event")
            .contains(&TransportEvent::Closed {
                id: circuit_id,
                reason: ConnectionCloseReason::Local
            })
    );

    a.inner_mut().full = false;
    a.handle_inner_event(TransportEvent::StreamWritable {
        id: inner_conn,
        stream_id: bridge,
    });
    assert_eq!(a.inner().close_write_calls, 1);
    assert_eq!(a.inner().reset_calls, 0);
    assert!(!a.has_pending_writes());
    assert!(
        a.poll(Now::from_millis(0))
            .expect("nothing more")
            .is_empty()
    );

    let peer_wire = b
        .inner_mut()
        .poll(Now::from_millis(0))
        .expect("peer bridge events");
    assert!(
        peer_wire
            .iter()
            .any(|event| matches!(event, TransportEvent::StreamRemoteWriteClosed { .. })),
        "bridge FIN reaches the peer: {peer_wire:?}"
    );
    for event in peer_wire {
        b.handle_inner_event(event);
    }
    let peer_events = b.poll(Now::from_millis(0)).expect("peer close events");
    assert!(
        peer_events.iter().any(|event| matches!(
            event,
            TransportEvent::StreamData { data, .. } if data[..] == b"held-behind-full"[..]
        )),
        "the held bytes reach the peer: {peer_events:?}"
    );
    assert!(
        peer_events
            .iter()
            .any(|event| matches!(event, TransportEvent::Closed { id, .. } if *id == circuit_id))
    );
}

#[test]
fn gracefully_closed_bridge_tombstones_are_bounded() {
    let (mut a, mut b, circuit_id, bridge, a_peer, b_peer) = setup_close_observed_pair();
    complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
    let inner_conn = ConnectionId::new(1);

    a.close(circuit_id).expect("graceful circuit close");
    let _ = a.poll(Now::from_millis(0)).expect("local close event");
    assert!(a.retired_bridges.contains(&(inner_conn, bridge)));

    for index in 0..MAX_RETIRED_BRIDGES {
        a.retire_bridge((
            inner_conn,
            StreamId::new(10_000 + u64::try_from(index).expect("usize fits u64")),
        ));
    }

    assert_eq!(a.retired_bridges.len(), MAX_RETIRED_BRIDGES);
    assert_eq!(a.retired_bridge_order.len(), MAX_RETIRED_BRIDGES);
    assert!(!a.retired_bridges.contains(&(inner_conn, bridge)));
}

#[test]
fn ready_close_resets_bridge_when_fin_fails() {
    let (mut a, mut b, circuit_id, _bridge, a_peer, b_peer) = setup_close_observed_pair();
    complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
    a.inner_mut().fail_close_write = true;

    a.close(circuit_id).expect("fallback circuit close");
    assert_eq!(a.inner().close_write_calls, 1);
    assert_eq!(a.inner().reset_calls, 1);
    assert_eq!(
        a.poll(Now::from_millis(0)).expect("local close event"),
        [TransportEvent::Closed {
            id: circuit_id,
            reason: ConnectionCloseReason::Local
        }]
    );

    let peer_wire = b
        .inner_mut()
        .poll(Now::from_millis(0))
        .expect("peer bridge events");
    assert!(
        peer_wire
            .iter()
            .any(|event| matches!(event, TransportEvent::StreamData { .. }))
    );
    assert!(
        peer_wire
            .iter()
            .any(|event| matches!(event, TransportEvent::StreamClosed { .. }))
    );
    assert!(
        !peer_wire
            .iter()
            .any(|event| matches!(event, TransportEvent::StreamRemoteWriteClosed { .. }))
    );
    for event in peer_wire {
        b.handle_inner_event(event);
    }
    assert_eq!(
        b.poll(Now::from_millis(0))
            .expect("peer observes terminal close"),
        [TransportEvent::Closed {
            id: circuit_id,
            reason: ConnectionCloseReason::Remote { code: 0 }
        }]
    );
}

#[test]
fn a_dead_bridge_closes_the_circuit_without_an_error_event() {
    let (mut a, mut b, circuit_id, _bridge, a_peer, b_peer) = setup_close_observed_pair();
    complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
    let stream = a.open_stream(circuit_id).expect("open stream");
    let _ = a.poll(Now::from_millis(0)).expect("drain local events");

    a.inner_mut().fail_send = true;
    assert!(matches!(
        a.send_stream(circuit_id, stream, Bytes::from_static(b"lost")),
        Err(TransportError::ConnectionClosed { id, .. }) if id == circuit_id
    ));

    assert!(matches!(
        a.poll(Now::from_millis(0)).expect("teardown events").as_slice(),
        [TransportEvent::Closed {
            id,
            reason: ConnectionCloseReason::Error(_),
        }] if *id == circuit_id
    ));
    assert_eq!(
        a.close(circuit_id),
        Err(TransportError::ConnectionNotFound { id: circuit_id })
    );
}

#[test]
fn close_before_ready_resets_bridge_and_is_terminal() {
    let (mut a, _b, circuit_id, bridge, _a_peer, _b_peer) = setup_close_observed_pair();
    let inner_conn = ConnectionId::new(1);

    a.close(circuit_id).expect("pre-ready close");
    assert_eq!(a.inner().close_write_calls, 0);
    assert_eq!(a.inner().reset_calls, 1);
    assert_eq!(
        a.poll(Now::from_millis(0)).expect("pre-ready close event"),
        [TransportEvent::Closed {
            id: circuit_id,
            reason: ConnectionCloseReason::Local
        }]
    );
    assert_eq!(
        a.close(circuit_id),
        Err(TransportError::ConnectionNotFound { id: circuit_id })
    );
    assert!(
        a.poll(Now::from_millis(0))
            .expect("consume reset acknowledgement")
            .is_empty()
    );
    a.inject_bridge_data(inner_conn, bridge, Bytes::from_static(b"late"));
    assert!(
        a.poll(Now::from_millis(0))
            .expect("post-close data is ignored")
            .is_empty()
    );
}

#[test]
fn a_circuit_holds_its_slot_until_its_delivered_bytes_settle() {
    let (mut a, mut b, circuit_id, _bridge, a_peer, b_peer) = setup_pair();
    complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
    let held = a.open_stream(circuit_id).expect("open");
    let other = a.open_stream(circuit_id).expect("open");
    for stream in [held, other] {
        a.send_stream(circuit_id, stream, Bytes::from_static(b"held"))
            .expect("send");
    }
    let _ = a.poll(Now::from_millis(0)).expect("sent");
    let delivered = b.poll(Now::from_millis(0)).expect("delivered");
    assert!(
        delivered
            .iter()
            .any(|event| matches!(event, TransportEvent::StreamData { .. }))
    );
    assert_eq!(b.circuit_slots(), 1);

    b.inner_mut()
        .close(ConnectionId::new(1))
        .expect("relay connection closes");
    let events = b.poll(Now::from_millis(0)).expect("relay close");
    assert!(events.iter().any(|event| matches!(
        event,
        TransportEvent::Closed {
            id,
            reason: ConnectionCloseReason::Error(message),
        } if *id == circuit_id && message.starts_with("relay connection closed")
    )));
    assert!(!b.contains_circuit(circuit_id));
    assert_eq!(b.circuit_slots(), 1, "the circuit's bytes are unsettled");

    b.ack_stream(circuit_id, held, 2)
        .expect("partial ack after close");
    assert_eq!(
        b.ack_stream(circuit_id, held, 3),
        Err(TransportError::AckExceedsDelivered {
            id: circuit_id,
            stream_id: held,
            acked: 3,
            unacked: 2,
        })
    );
    b.ack_stream(circuit_id, held, 2).expect("final ack");
    assert_eq!(b.circuit_slots(), 1, "the other stream still holds it");
    b.reset_stream(circuit_id, other)
        .expect("abandoning after close settles");
    assert_eq!(b.circuit_slots(), 0);
    b.ack_stream(circuit_id, held, 0).expect("settled: a no-op");
    assert!(
        b.poll(Now::from_millis(0)).expect("quiet").is_empty(),
        "settling produces no events"
    );
}

#[test]
fn relay_connection_close_closes_each_ready_circuit_once() {
    let (mut a, mut b, circuit_id, _bridge, a_peer, b_peer) = setup_pair();
    complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
    let stream = a
        .open_stream(circuit_id)
        .expect("open stream before relay loss");
    let _ = a.poll(Now::from_millis(0)).expect("local stream open");
    let _ = b.poll(Now::from_millis(0)).expect("remote stream open");

    a.inner_mut()
        .close(ConnectionId::new(1))
        .expect("relay connection closes");
    let events = a.poll(Now::from_millis(0)).expect("relay close mapping");
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, TransportEvent::Closed { id, .. } if *id == circuit_id))
            .count(),
        1
    );
    assert!(events.iter().any(|event| matches!(
        event,
        TransportEvent::Closed { id, .. } if *id == ConnectionId::new(1)
    )));
    assert!(!events.iter().any(|event| matches!(
        event,
        TransportEvent::StreamClosed { id, stream_id }
            if *id == circuit_id && *stream_id == stream
    )));
    assert!(
        a.poll(Now::from_millis(0))
            .expect("relay close is terminal")
            .is_empty()
    );
}

#[test]
fn circuit_opens_wait_for_yamux_capacity_and_cancel_without_a_syn() {
    let config = YamuxConfig {
        max_streams: 1,
        ..YamuxConfig::default()
    };
    let (mut a, mut b, circuit_id, _, a_peer, b_peer) = setup_pair_with_yamux_config(Some(config));
    complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
    let first = a.open_stream(circuit_id).expect("first stream");
    let opened = |stream| TransportEvent::StreamOpened {
        id: circuit_id,
        stream_id: stream,
    };
    assert!(
        a.poll(Now::from_millis(0))
            .unwrap()
            .contains(&opened(first))
    );
    b.poll(Now::from_millis(0)).unwrap();
    let cancelled = a.open_stream(circuit_id).expect("queued second");
    let third = a.open_stream(circuit_id).expect("queued third");
    assert!(matches!(
        a.send_stream(circuit_id, third, Bytes::from_static(b"queued")),
        Err(TransportError::Full { .. })
    ));
    a.reset_stream(circuit_id, cancelled).unwrap();
    let events = a.poll(Now::from_millis(0)).unwrap();
    assert!(!events.contains(&opened(cancelled)));
    assert!(!events.contains(&opened(third)));
    assert!(b.poll(Now::from_millis(0)).unwrap().is_empty());
    a.reset_stream(circuit_id, first).unwrap();
    assert!(
        a.poll(Now::from_millis(0))
            .unwrap()
            .contains(&opened(third))
    );
    a.send_stream(circuit_id, third, Bytes::from_static(b"queued"))
        .unwrap();
    a.close_stream_write(circuit_id, third).unwrap();
    let mut events = Vec::new();
    for _ in 0..4 {
        events.extend(b.poll(Now::from_millis(0)).unwrap());
        a.poll(Now::from_millis(0)).unwrap();
    }
    assert!(!events.iter().any(|event| matches!(event,
        TransportEvent::IncomingStream { stream_id, .. } if *stream_id == cancelled
    )));
    assert!(events.iter().any(|event| matches!(event,
        TransportEvent::StreamData { stream_id, data, .. }
        if *stream_id == third && data.as_ref() == b"queued"
    )));
    assert!(events.contains(&TransportEvent::StreamRemoteWriteClosed {
        id: circuit_id,
        stream_id: third,
    }));
}

#[test]
fn yamux_backpressure_is_stream_scoped_and_session_survives() {
    let max_buffered_send = 64;
    let config = YamuxConfig {
        receive_window: 256 * 1024,
        max_frame_len: 64 * 1024,
        max_streams: 8,
        max_buffered_send,
        max_total_buffered_send: 128,
        control_stream_reserve: 0,
        ..YamuxConfig::default()
    };
    let (mut a, mut b, circuit_id, _bridge, a_peer, b_peer) =
        setup_pair_with_yamux_config(Some(config));
    complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);

    let initiator_stream = a.open_stream(circuit_id).expect("initiator stream");
    assert_eq!(initiator_stream.as_u64() % 2, 1);
    let _ = a.poll(Now::from_millis(0)).expect("local open");
    let _ = b.poll(Now::from_millis(0)).expect("remote open");

    let payload = Bytes::from(vec![7u8; 4 * max_buffered_send]);
    let Err(TransportError::Full {
        id,
        stream_id,
        unsent,
    }) = a.send_stream(circuit_id, initiator_stream, payload.clone())
    else {
        panic!("send beyond the Yamux stream cap must be Full");
    };
    assert_eq!((id, stream_id), (circuit_id, initiator_stream));
    assert_eq!(unsent, payload.slice(max_buffered_send..));

    let events = a.poll(Now::from_millis(0)).expect("flush accepted prefix");
    assert!(events.iter().any(|event| matches!(
        event,
        TransportEvent::StreamWritable { id, stream_id }
            if *id == circuit_id && *stream_id == initiator_stream
    )));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, TransportEvent::Closed { .. })),
        "Full must not tear the circuit down"
    );
    a.send_stream(
        circuit_id,
        initiator_stream,
        Bytes::from_static(b"still-alive"),
    )
    .expect("backpressure must not poison the stream");
    let _ = a.poll(Now::from_millis(0)).expect("flush small data");
    let received: Vec<u8> = b
        .poll(Now::from_millis(0))
        .expect("data")
        .into_iter()
        .filter_map(|event| match event {
            TransportEvent::StreamData { data, .. } => Some(data),
            _ => None,
        })
        .flat_map(|data| data.to_vec())
        .collect();
    let mut expected = payload[..max_buffered_send].to_vec();
    expected.extend_from_slice(b"still-alive");
    assert_eq!(received, expected);

    let responder_stream = b.open_stream(circuit_id).expect("responder stream");
    assert_eq!(responder_stream.as_u64() % 2, 0);
}

#[test]
fn a_reader_that_never_acks_stalls_its_sender_until_it_does() {
    let (mut a, mut b, circuit_id, bridge, a_peer, b_peer) = setup_pair();
    complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
    let stream = a.open_stream(circuit_id).expect("stream");
    let window = YamuxConfig::default().receive_window as usize;
    let payload = Bytes::from(vec![7u8; 4 * window]);
    let mut held = a
        .send_stream(circuit_id, stream, payload.clone())
        .err()
        .and_then(TransportError::into_unsent);

    let drive = |a: &mut CircuitTransport<_, _>,
                 b: &mut CircuitTransport<InMemoryTransport, _>,
                 held: &mut Option<Bytes>,
                 ack: bool| {
        let mut delivered = 0;
        for _ in 0..64 {
            for event in a.poll(Now::from_millis(0)).expect("poll a") {
                if matches!(event, TransportEvent::StreamWritable { .. })
                    && let Some(tail) = held.take()
                {
                    *held = a
                        .send_stream(circuit_id, stream, tail)
                        .err()
                        .and_then(TransportError::into_unsent);
                }
            }
            for event in b.poll(Now::from_millis(0)).expect("poll b") {
                if let TransportEvent::StreamData {
                    id,
                    stream_id,
                    data,
                } = event
                {
                    delivered += data.len();
                    if ack {
                        b.ack_stream(id, stream_id, data.len()).expect("ack");
                    }
                }
            }
        }
        delivered
    };

    let stalled = drive(&mut a, &mut b, &mut held, false);
    assert_eq!(stalled, window, "a reader that never acks gets one window");
    assert!(held.is_some(), "and the sender holds its tail");
    assert_eq!(
        b.inner().unacked(bridge),
        0,
        "the circuit acknowledges every bridge byte its session took"
    );

    b.ack_stream(circuit_id, stream, stalled).expect("ack");
    let rest = drive(&mut a, &mut b, &mut held, true);
    assert_eq!(stalled + rest, payload.len(), "acking resumes the sender");
    assert!(held.is_none());
}

#[test]
fn closing_a_circuit_drops_its_queued_writable() {
    let config = YamuxConfig {
        max_buffered_send: 64,
        max_total_buffered_send: 128,
        control_stream_reserve: 0,
        ..YamuxConfig::default()
    };
    let (mut a, mut b, circuit_id, _bridge, a_peer, b_peer) =
        setup_pair_with_yamux_config(Some(config));
    complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
    let stream = a.open_stream(circuit_id).expect("stream");
    let _ = a.poll(Now::from_millis(0)).expect("local open");
    let _ = b.poll(Now::from_millis(0)).expect("remote open");

    assert!(matches!(
        a.send_stream(circuit_id, stream, Bytes::from(vec![7u8; 256])),
        Err(TransportError::Full { .. })
    ));
    a.close(circuit_id).expect("close");
    let events = a.poll(Now::from_millis(0)).expect("poll");
    assert!(events.contains(&TransportEvent::Closed {
        id: circuit_id,
        reason: ConnectionCloseReason::Local
    }));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, TransportEvent::StreamWritable { .. })),
        "no Writable for a closed circuit: {events:?}"
    );
}

#[test]
fn adoption_rejects_invalid_preconditions_without_consuming_ids() {
    let relay = identity(9).peer_id();
    let local = identity(1);
    let remote = identity(2).peer_id();
    let (inner, _) = InMemoryTransport::pair(local.peer_id(), relay);
    let mut transport = CircuitTransport::new(inner, local, CounterEntropy(1));
    assert_eq!(
        transport.adopt_bridge(BridgeAdoption {
            inner_conn: ConnectionId::new(99),
            bridge_stream: StreamId::new(1),
            relay,
            remote_peer: remote,
            role: CircuitRole::Initiator,
            pending_data: Bytes::from(Vec::new()),
            unsent_prefix: Bytes::new(),
            remote_write_closed: false,
        }),
        Err(AdoptError::UnknownConnection)
    );
    assert!(transport.circuit_ids().is_empty());
}

#[test]
fn direct_connection_wins_before_and_during_circuit_handshake() {
    let local = identity(1);
    let remote = identity(2).peer_id();
    let relay = identity(9).peer_id();
    let (inner, _) = InMemoryTransport::pair(local.peer_id(), remote);
    let mut direct_first = CircuitTransport::new(inner, local, CounterEntropy(1));
    let _ = direct_first
        .poll(Now::from_millis(0))
        .expect("record direct connection");
    assert_eq!(
        direct_first.adopt_bridge(BridgeAdoption {
            inner_conn: ConnectionId::new(1),
            bridge_stream: StreamId::new(1),
            relay,
            remote_peer: remote,
            role: CircuitRole::Initiator,
            pending_data: Bytes::from(Vec::new()),
            unsent_prefix: Bytes::new(),
            remote_write_closed: false,
        }),
        Err(AdoptError::PeerAlreadyDirect)
    );

    let (mut a, _b, circuit_id, _bridge, _a_peer, b_peer) = setup_pair();
    a.inner_mut().push_event(TransportEvent::Connected {
        id: ConnectionId::new(2),
        endpoint: Box::new(ConnectionEndpoint::with_peer_id(
            "/ip4/198.51.100.1/udp/5001/quic-v1"
                .parse()
                .expect("direct endpoint"),
            b_peer,
        )),
    });
    let events = a
        .poll(Now::from_millis(0))
        .expect("direct connection arrives");
    assert!(events.contains(&TransportEvent::Closed {
        id: circuit_id,
        reason: ConnectionCloseReason::Local,
    }));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, TransportEvent::Error { .. }))
    );
    assert!(events.iter().any(|event| matches!(
        event,
        TransportEvent::Connected { id, .. } if *id == ConnectionId::new(2)
    )));
}

#[test]
fn a_circuit_completing_after_a_direct_connection_never_reports_connected() {
    let (mut a, mut b, circuit_id, _bridge, _a_peer, b_peer) = setup_pair();
    for _ in 0..32 {
        let _ = a.poll(Now::from_millis(0)).expect("drive initiator");
        let _ = b.poll(Now::from_millis(0)).expect("drive responder");
        if selecting_yamux(&a, circuit_id) && established(&b, circuit_id) {
            break;
        }
    }
    assert!(selecting_yamux(&a, circuit_id));
    assert!(established(&b, circuit_id));

    let direct = ConnectionId::new(2);
    a.direct_by_conn.insert(direct, b_peer);
    a.direct_by_peer.entry(b_peer).or_default().insert(direct);

    let events = a.poll(Now::from_millis(0)).expect("complete the upgrade");
    assert_eq!(
        events,
        [TransportEvent::Closed {
            id: circuit_id,
            reason: ConnectionCloseReason::Local,
        }]
    );
    assert!(!a.circuits.contains_key(&circuit_id));
}

#[test]
fn adoption_failures_leave_bridge_and_identifier_ownership_with_caller() {
    let local = identity(1);
    let remote = identity(2).peer_id();
    let relay = identity(9).peer_id();
    let (inner, _) = InMemoryTransport::pair(local.peer_id(), relay);
    let mut transport = CircuitTransport::new(inner, local, FailingEntropy);
    let _ = transport
        .poll(Now::from_millis(0))
        .expect("activate wrapped connection");
    let adoption = BridgeAdoption {
        inner_conn: ConnectionId::new(1),
        bridge_stream: StreamId::new(7),
        relay,
        remote_peer: remote,
        role: CircuitRole::Initiator,
        pending_data: Bytes::from(Vec::new()),
        unsent_prefix: Bytes::new(),
        remote_write_closed: false,
    };
    let unconsumed = transport
        .circuit_id_allocator
        .peek()
        .expect("fresh allocator");

    assert!(matches!(
        transport.adopt_bridge(adoption.clone()),
        Err(AdoptError::Entropy(_))
    ));
    assert!(transport.circuit_ids().is_empty());
    assert_eq!(transport.circuit_id_allocator.peek(), Some(unconsumed));

    assert_eq!(
        transport.adopt_bridge(BridgeAdoption {
            remote_write_closed: true,
            ..adoption.clone()
        }),
        Err(AdoptError::RemoteWriteClosed)
    );
    assert!(transport.circuit_ids().is_empty());
    assert_eq!(transport.circuit_id_allocator.peek(), Some(unconsumed));

    transport.circuit_id_allocator = ConnectionIdAllocator::starting_at(
        ConnectionNamespace::CIRCUIT,
        ConnectionId::MAX_SEQUENCE + 1,
    );
    assert_eq!(
        transport.adopt_bridge(BridgeAdoption {
            remote_write_closed: false,
            ..adoption
        }),
        Err(AdoptError::IdsExhausted)
    );
}

#[test]
fn wrapped_high_bit_ids_are_rejected_without_becoming_circuits() {
    let local = identity(1);
    let relay = identity(9).peer_id();
    let (inner, _) = InMemoryTransport::pair(local.peer_id(), relay);
    let mut transport = CircuitTransport::new(inner, local, CounterEntropy(1));
    let _ = transport
        .poll(Now::from_millis(0))
        .expect("initial direct event");
    let collision =
        ConnectionId::namespaced(ConnectionNamespace::CIRCUIT, 77).expect("circuit id in range");
    transport
        .inner_mut()
        .push_event(TransportEvent::IncomingConnection {
            id: collision,
            endpoint: Box::new(ConnectionEndpoint::new(
                "/ip4/203.0.113.7/udp/7007/quic-v1"
                    .parse()
                    .expect("collision endpoint"),
            )),
        });
    let events = transport
        .poll(Now::from_millis(0))
        .expect("collision event");
    assert_eq!(
        events,
        vec![TransportEvent::Error {
            id: collision,
            message: "wrapped transport allocated in the circuit connection-ID namespace"
                .to_string(),
        }]
    );
    assert!(transport.circuit_ids().is_empty());
}

#[test]
fn wrapped_dial_returning_a_circuit_id_is_closed_and_rejected() {
    let local = identity(1);
    let relay = identity(9).peer_id();
    let (inner, _) = InMemoryTransport::pair(local.peer_id(), relay);
    let collision =
        ConnectionId::namespaced(ConnectionNamespace::CIRCUIT, 77).expect("circuit id in range");
    let mut observed = CloseObservingTransport::new(inner);
    observed.dial_id = Some(collision);
    let mut transport = CircuitTransport::new(observed, local, CounterEntropy(1));
    let address = minip2p_core::PeerAddr::new(
        "/ip4/203.0.113.7/udp/7007/quic-v1"
            .parse()
            .expect("dial transport address"),
        relay,
    )
    .expect("dial address");

    assert_eq!(
        transport.dial(&address),
        Err(TransportError::DialFailed {
            id: collision,
            reason: "wrapped transport allocated in the circuit connection-ID namespace"
                .to_string(),
        })
    );
    assert_eq!(transport.inner().closed, vec![collision]);
    assert!(transport.circuit_ids().is_empty());
}

/// An adoption of a fresh bridge on `transport`'s relay connection.
fn fresh_adoption(transport: &mut TestCircuit, remote_peer: PeerId) -> BridgeAdoption {
    let inner_conn = transport.inner().connection_id();
    let bridge_stream = transport
        .inner_mut()
        .open_stream(inner_conn)
        .expect("bridge");
    BridgeAdoption {
        inner_conn,
        bridge_stream,
        relay: identity(9).peer_id(),
        remote_peer,
        role: CircuitRole::Initiator,
        pending_data: Bytes::new(),
        unsent_prefix: Bytes::new(),
        remote_write_closed: false,
    }
}

#[test]
fn an_unsent_prefix_longer_than_one_noise_frame_is_refused() {
    let (mut a, _b, _circuit_id, _bridge, _a_peer, _b_peer) = setup_pair();
    let mut adoption = fresh_adoption(&mut a, identity(3).peer_id());
    adoption.unsent_prefix = Bytes::from(vec![0; minip2p_secure_mux::NOISE_WIRE_FRAME + 1]);
    assert_eq!(
        a.adopt_bridge(adoption.clone()),
        Err(AdoptError::PrefixTooLong)
    );
    adoption.unsent_prefix = Bytes::from(vec![0; minip2p_secure_mux::NOISE_WIRE_FRAME]);
    a.adopt_bridge(adoption).expect("one frame fits");
}
