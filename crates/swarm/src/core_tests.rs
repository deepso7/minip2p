use super::*;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::vec;

use crate::IdentifyFailure;
use crate::state::OUTBOUND_NEGOTIATION_TIMEOUT_MS;
use minip2p_core::platform::EntropyError;
use minip2p_identify::IDENTIFY_PROTOCOL_ID;
use minip2p_identity::Ed25519Keypair;
use minip2p_multistream_select::{MultistreamOutput, MultistreamSelect};
use minip2p_ping::PING_PROTOCOL_ID;
use minip2p_transport::{ConnectionCloseReason, ConnectionEndpoint, TransportEvent};

#[test]
fn error_predicates_separate_retryable_gone_and_closed() {
    let (conn_id, stream_id) = (ConnectionId::new(1), StreamId::new(2));
    let peer_id = PeerId::from_public_key_protobuf(b"predicate-peer");
    let unsent = Bytes::from_static(b"tail");
    let full = DriverError::Full {
        conn_id,
        stream_id,
        unsent: unsent.clone(),
    };
    let swarm_full = DriverError::from(SwarmError::Full {
        conn_id,
        stream_id,
        unsent,
    });
    let gone = [
        DriverError::from(SwarmError::StreamNotFound {
            peer_id,
            conn_id,
            stream_id,
        }),
        DriverError::from(SwarmError::NotConnected { peer_id }),
        DriverError::from(TransportError::ConnectionNotFound { id: conn_id }),
        DriverError::from(TransportError::ConnectionClosed {
            id: conn_id,
            reason: "reset exhausted the control reserve".into(),
        }),
        DriverError::from(TransportError::StreamNotFound {
            id: conn_id,
            stream_id,
        }),
    ];
    let write_closed = DriverError::from(SwarmError::WriteClosed { conn_id, stream_id });
    let not_ready = DriverError::from(SwarmError::StreamNotReady { conn_id, stream_id });

    for error in [&full, &swarm_full] {
        assert!(error.is_retryable() && !error.is_stream_gone(), "{error}");
    }
    for error in &gone {
        assert!(error.is_stream_gone() && !error.is_retryable(), "{error}");
    }
    for error in [&write_closed, &not_ready] {
        assert!(!error.is_retryable() && !error.is_stream_gone(), "{error}");
    }
}

/// Counter-based entropy: no OS, no `getrandom`, fully deterministic.
struct SeqEntropy(u8);

impl EntropySource for SeqEntropy {
    fn fill_bytes(
        &mut self,
        output: &mut [u8],
    ) -> Result<(), minip2p_core::platform::EntropyError> {
        for byte in output.iter_mut() {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

/// Entropy source with nothing to give -- an embedded target with no RNG,
/// or a hardware RNG that failed its health check.
struct BrokenEntropy;

impl EntropySource for BrokenEntropy {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        // Partially written and then failed: per the `EntropySource`
        // contract the buffer holds no entropy, so this is exactly the
        // payload a driver that ignored the error would put on the wire.
        output.fill(0);
        Err(EntropyError::unavailable("no RNG in this test"))
    }
}

/// Transport that replays a scripted batch and records opened streams.
#[derive(Default)]
struct ScriptedTransport {
    initial: Vec<TransportEvent>,
    next_stream_id: u64,
    next_conn_id: u64,
    opened: usize,
    deadline: Option<Deadline>,
    /// When set, every locally opened stream gets a multistream-select
    /// listener that answers the dialer, so identify and ping streams
    /// actually reach the negotiated state and carry payloads.
    negotiate: bool,
    /// Listeners for streams still negotiating, keyed by stream id.
    negotiators: BTreeMap<StreamId, MultistreamSelect>,
    /// Protocol frames written after negotiation completed. This is the
    /// wire as the remote peer would see it.
    sent: Vec<(StreamId, Vec<u8>)>,
    close_count: usize,
    /// Second `close` returns `ConnectionNotFound` (TCP after map removal).
    fail_second_close: bool,
    /// Every `close` fails with a non-`ConnectionNotFound` error.
    refuse_close: bool,
    /// Every `send_stream` ends its connection, as a fatal session
    /// failure does: `Closed` is queued and `ConnectionClosed` returned.
    sends_end_connection: bool,
    /// The stream or connection has already ended in the transport:
    /// every `send_stream`, `close_stream_write` and `reset_stream` fails
    /// with this error.
    ended: Option<Ended>,
    /// The stream operations attempted, in order.
    stream_ops: Vec<&'static str>,
    /// Bound addresses; `listen` accepts these (certhashes ignored).
    addrs: Vec<Multiaddr>,
    address_revision: u64,
    /// Swapped in by the next `poll`, as a certificate rotation does:
    /// the revision moves and each changed address is announced.
    rotate_to: Option<Vec<Multiaddr>>,
    /// A slow peer: opens report `StreamOpened` at once, but the
    /// listener's answers, and an Identify reply once Identify
    /// negotiates, are held until the first poll at or past this time.
    answer_at_ms: Option<u64>,
    held: Vec<TransportEvent>,
    /// With `answer_at_ms`, holds the Identify reply further, until the
    /// first poll at or past this time.
    reply_at_ms: Option<u64>,
    held_reply: Vec<TransportEvent>,
}

impl ScriptedTransport {
    /// Frames the size of a ping payload that reached the wire.
    fn ping_frames(&self) -> Vec<&[u8]> {
        self.sent
            .iter()
            .map(|(_, data)| data.as_slice())
            .filter(|data| data.len() == PING_PAYLOAD_LEN)
            .collect()
    }
}

impl Transport for ScriptedTransport {
    fn ack_stream(
        &mut self,
        _id: ConnectionId,
        _stream_id: StreamId,
        _bytes: usize,
    ) -> Result<(), TransportError> {
        Ok(())
    }

    fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
        self.next_conn_id += 1;
        Ok(ConnectionId::new(self.next_conn_id))
    }

    fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, TransportError> {
        self.addrs
            .iter()
            .find(|bound| bound.without_certhashes() == addr.without_certhashes())
            .cloned()
            .ok_or(TransportError::Unsupported {
                operation: "listen",
            })
    }

    fn local_addresses(&self) -> Vec<Multiaddr> {
        self.addrs.clone()
    }

    fn local_addresses_revision(&self) -> Option<u64> {
        Some(self.address_revision)
    }

    fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
        self.next_stream_id += 1;
        self.opened += 1;
        let stream_id = StreamId::new(self.next_stream_id);
        if self.answer_at_ms.is_some() {
            self.initial.push(TransportEvent::StreamOpened {
                id: ConnectionId::new(1),
                stream_id,
            });
        }
        if self.negotiate {
            let mut listener = MultistreamSelect::listener(vec![
                IDENTIFY_PROTOCOL_ID.to_string(),
                PING_PROTOCOL_ID.to_string(),
            ]);
            listener.start();
            self.negotiators.insert(stream_id, listener);
        }
        Ok(stream_id)
    }

    fn send_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
    ) -> Result<(), TransportError> {
        self.stream_ops.push("send");
        if let Some(ended) = self.ended {
            return Err(ended(id, stream_id));
        }
        if self.sends_end_connection {
            let reason = String::from("session failed");
            self.initial.push(TransportEvent::Closed {
                id,
                reason: ConnectionCloseReason::Error(reason.clone()),
            });
            return Err(TransportError::ConnectionClosed { id, reason });
        }
        let Some(negotiator) = self.negotiators.get_mut(&stream_id) else {
            // Negotiation is done (or was never scripted): this is
            // protocol payload, which is what tests assert on.
            self.sent.push((stream_id, data.to_vec()));
            return Ok(());
        };

        negotiator.on_data(&data);
        let mut negotiated = None;
        let mut outbound = Vec::new();
        while let Some(output) = negotiator.poll_output() {
            match output {
                MultistreamOutput::OutboundData(bytes) => outbound.push(bytes),
                MultistreamOutput::Negotiated { protocol } => negotiated = Some(protocol),
                other => {
                    return Err(TransportError::PollError {
                        reason: alloc::format!("unexpected multistream output: {other:?}"),
                    });
                }
            }
        }
        if negotiated.is_some() {
            self.negotiators.remove(&stream_id);
        }
        // The dialer only learns the protocol was accepted on its next
        // poll, so hand the answer back as inbound stream data.
        let answers = if self.answer_at_ms.is_some() {
            &mut self.held
        } else {
            &mut self.initial
        };
        for data in outbound {
            answers.push(TransportEvent::StreamData {
                id,
                stream_id,
                data: Bytes::from(data),
            });
        }
        let answers = if self.reply_at_ms.is_some() {
            &mut self.held_reply
        } else {
            answers
        };
        if self.answer_at_ms.is_some() && negotiated.as_deref() == Some(IDENTIFY_PROTOCOL_ID) {
            let reply = minip2p_identify::IdentifyMessage {
                protocol_version: None,
                agent_version: None,
                public_key: None,
                listen_addrs: Vec::new(),
                observed_addr: None,
                protocols: Vec::new(),
            };
            answers.push(TransportEvent::StreamData {
                id,
                stream_id,
                data: Bytes::from(minip2p_core::encode_frame(&reply.encode())),
            });
            answers.push(TransportEvent::StreamRemoteWriteClosed { id, stream_id });
        }
        Ok(())
    }

    fn close_stream_write(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        self.stream_ops.push("close_write");
        self.ended.map_or(Ok(()), |ended| Err(ended(id, stream_id)))
    }

    fn reset_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        self.stream_ops.push("reset");
        self.ended.map_or(Ok(()), |ended| Err(ended(id, stream_id)))
    }

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        self.close_count += 1;
        if self.refuse_close {
            return Err(TransportError::CloseFailed {
                id,
                reason: String::from("close refused"),
            });
        }
        if self.fail_second_close && self.close_count > 1 {
            return Err(TransportError::ConnectionNotFound { id });
        }
        Ok(())
    }

    fn poll(&mut self, now: Now) -> Result<Vec<TransportEvent>, TransportError> {
        let mut events = core::mem::take(&mut self.initial);
        if self.answer_at_ms.is_some_and(|at| now.monotonic_ms >= at) {
            events.append(&mut self.held);
        }
        if self.reply_at_ms.is_some_and(|at| now.monotonic_ms >= at) {
            events.append(&mut self.held_reply);
        }
        if let Some(addrs) = self.rotate_to.take() {
            for addr in &addrs {
                if !self.addrs.contains(addr) {
                    events.push(TransportEvent::Listening { addr: addr.clone() });
                }
            }
            self.addrs = addrs;
            self.address_revision += 1;
        }
        Ok(events)
    }

    fn next_deadline(&self) -> Option<Deadline> {
        self.deadline
    }
}

fn swarm(initial: Vec<TransportEvent>) -> SwarmCore<ScriptedTransport, SeqEntropy> {
    swarm_with(
        ScriptedTransport {
            initial,
            ..ScriptedTransport::default()
        },
        SeqEntropy(1),
    )
}

/// Same swarm, with the transport and entropy source chosen by the test.
fn swarm_with<E: EntropySource>(
    transport: ScriptedTransport,
    entropy: E,
) -> SwarmCore<ScriptedTransport, E> {
    let keypair = Ed25519Keypair::generate();
    let identify = IdentifyConfig {
        protocol_version: "test/1".into(),
        agent_version: "test/1".into(),
        protocols: Vec::new(),
        public_key: keypair.public_key().encode_protobuf(),
    };
    SwarmCore::new(
        transport,
        identify,
        SwarmTimeouts::default(),
        keypair.peer_id(),
        entropy,
    )
    .expect("default timeouts")
}

/// A transport already holding a connection to `peer`, whose
/// multistream-select listener answers so protocol streams negotiate.
fn negotiating_transport(peer: &PeerId) -> ScriptedTransport {
    ScriptedTransport {
        initial: vec![TransportEvent::Connected {
            id: ConnectionId::new(1),
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                "/ip4/198.51.100.7/udp/4001/quic-v1"
                    .parse()
                    .expect("endpoint"),
                *peer,
            )),
        }],
        negotiate: true,
        ..ScriptedTransport::default()
    }
}

/// Drives the swarm far enough for a queued ping to finish negotiating
/// its stream and reach the transport.
fn settle<E: EntropySource>(swarm: &mut SwarmCore<ScriptedTransport, E>, from_ms: u64) {
    for step in 0..8 {
        swarm.poll(Now::from_millis(from_ms + step)).expect("poll");
    }
}

/// The whole point of the extraction: this drives a connection open and
/// close with no clock, no OS entropy, and no `std` wrapper -- the same
/// path an embedded host takes.
#[test]
fn core_drives_without_a_clock_or_os_entropy() {
    let peer = Ed25519Keypair::generate().peer_id();
    let mut swarm = swarm(vec![TransportEvent::Connected {
        id: ConnectionId::new(1),
        endpoint: Box::new(ConnectionEndpoint::with_peer_id(
            "/ip4/198.51.100.7/udp/4001/quic-v1"
                .parse()
                .expect("endpoint"),
            peer,
        )),
    }]);

    let events = swarm.poll(Now::from_millis(5_000)).expect("poll");
    assert!(
        events.iter().any(|event| matches!(
            event,
            SwarmEvent::ConnectionEstablished { peer_id, .. } if *peer_id == peer
        )),
        "expected the connection to surface: {events:?}"
    );
    // Identify started, so an action really was dispatched to the
    // transport during that poll.
    assert!(swarm.transport().opened > 0);
    assert!(swarm.connected_peers().contains(&peer));
    assert!(swarm.state.is_idle(), "core must settle after the open");

    // ...and the close half of the lifecycle, on the same timeline.
    swarm.transport_mut().initial = vec![TransportEvent::Closed {
        id: ConnectionId::new(1),
        reason: ConnectionCloseReason::Local,
    }];
    let events = swarm.poll(Now::from_millis(6_000)).expect("poll");
    assert!(
        events.iter().any(|event| matches!(
            event,
            SwarmEvent::ConnectionClosed { peer_id, .. } if *peer_id == peer
        )),
        "expected the close to surface: {events:?}"
    );
    assert!(swarm.connected_peers().is_empty());
}

/// A stream operation that ends its connection is reported once, as the
/// close's reason, not also as a transport error.
#[test]
fn an_operation_that_ends_its_connection_is_reported_once() {
    let peer = Ed25519Keypair::generate().peer_id();
    let id = ConnectionId::new(1);
    let mut swarm = swarm_with(
        ScriptedTransport {
            initial: vec![TransportEvent::Connected {
                id,
                endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                    "/ip4/198.51.100.7/udp/4001/quic-v1"
                        .parse()
                        .expect("endpoint"),
                    peer,
                )),
            }],
            sends_end_connection: true,
            ..ScriptedTransport::default()
        },
        SeqEntropy(1),
    );

    // Identify's negotiation write ends the connection during this poll;
    // the next one delivers its close.
    let mut events = swarm.poll(Now::from_millis(5_000)).expect("poll");
    events.extend(swarm.poll(Now::from_millis(5_001)).expect("poll"));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, SwarmEvent::Error(_))),
        "{events:?}"
    );
    let closes: Vec<_> = events
        .iter()
        .filter(|event| matches!(event, SwarmEvent::ConnectionClosed { .. }))
        .collect();
    assert!(
        matches!(
            closes.as_slice(),
            [SwarmEvent::ConnectionClosed { peer_id, conn_id, reason }]
                if *peer_id == peer
                    && *conn_id == id
                    && *reason == ConnectionCloseReason::Error("session failed".into())
        ),
        "{events:?}"
    );
}

#[test]
fn actions_from_one_batched_event_run_before_the_next_event() {
    let peer = Ed25519Keypair::generate().peer_id();
    let id = ConnectionId::new(1);
    let mut swarm = swarm(vec![
        TransportEvent::Connected {
            id,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                "/ip4/198.51.100.7/udp/4001/quic-v1"
                    .parse()
                    .expect("endpoint"),
                peer,
            )),
        },
        TransportEvent::Closed {
            id,
            reason: ConnectionCloseReason::Local,
        },
    ]);

    swarm.poll(Now::from_millis(5_000)).expect("poll");
    assert!(
        swarm.transport().opened > 0,
        "the Connected event's protocol opens must run before Closed mutates core state"
    );
}

/// Arms a core outbound-negotiation timer due at
/// `now + OUTBOUND_NEGOTIATION_TIMEOUT_MS`.
fn arm_negotiation_timer(swarm: &mut SwarmCore<ScriptedTransport, SeqEntropy>, now: Now) {
    swarm.state.start_outbound(
        ConnectionId::new(1),
        StreamId::new(1),
        "/app/1",
        ProtocolKind::User("/app/1".to_string()),
    );
    swarm.state.handle_transport_event(
        TransportEvent::StreamOpened {
            id: ConnectionId::new(1),
            stream_id: StreamId::new(1),
        },
        now.monotonic_ms,
    );
}

#[test]
fn core_timers_are_reported_at_their_absolute_due_time() {
    // At a realistic uptime a timer armed now must be reported at
    // now + timeout, not as an already expired small value.
    let now = Now::from_millis(3_600_000);
    let mut swarm = swarm(Vec::new());
    swarm.poll(now).expect("poll");
    let due = Deadline::from_millis(3_600_000 + OUTBOUND_NEGOTIATION_TIMEOUT_MS);
    arm_negotiation_timer(&mut swarm, now);

    let deadline = swarm.next_deadline(now).expect("armed");
    assert_eq!(deadline, due);
    assert!(!deadline.is_expired_at(now), "must not read as already due");
}

#[test]
fn next_deadline_folds_transport_and_core_timers() {
    let now = Now::from_millis(1_000);
    let core_due = Deadline::from_millis(1_000 + OUTBOUND_NEGOTIATION_TIMEOUT_MS);
    let mut swarm = swarm(Vec::new());
    swarm.poll(now).expect("poll");
    assert_eq!(swarm.next_deadline(now), None, "nothing armed");

    let transport = Deadline::from_millis(1_400);
    swarm.transport_mut().deadline = Some(transport);
    assert_eq!(swarm.next_deadline(now), Some(transport));

    arm_negotiation_timer(&mut swarm, now);
    assert_eq!(
        swarm.next_deadline(now),
        Some(transport),
        "the nearer transport timer wins"
    );

    swarm.transport_mut().deadline = Some(Deadline::NEVER);
    assert_eq!(
        swarm.next_deadline(now),
        Some(core_due),
        "the nearer core timer wins"
    );
}

#[test]
fn queued_work_is_reported_as_immediately_due() {
    let now = Now::from_millis(1_000);
    let mut swarm = swarm(Vec::new());
    swarm.poll(now).expect("poll");
    assert_eq!(swarm.next_deadline(now), None);

    // A deferred action has no timer of its own; without this a host
    // would idle until unrelated I/O happened to wake it.
    swarm.state.deferred_closes.push_back(ConnectionId::new(1));
    assert_eq!(swarm.next_deadline(now), Some(Deadline::IMMEDIATE));

    swarm.state.deferred_closes.clear();
    swarm.state.events.push_back(SwarmEvent::ConnectionClosed {
        peer_id: Ed25519Keypair::generate().peer_id(),
        conn_id: ConnectionId::new(1),
        reason: ConnectionCloseReason::Local,
    });
    assert_eq!(swarm.next_deadline(now), Some(Deadline::IMMEDIATE));
}

#[test]
fn ping_draws_from_the_injected_entropy_source() {
    let peer = Ed25519Keypair::generate().peer_id();
    let mut swarm = swarm(vec![TransportEvent::Connected {
        id: ConnectionId::new(1),
        endpoint: Box::new(ConnectionEndpoint::with_peer_id(
            "/ip4/198.51.100.7/udp/4001/quic-v1"
                .parse()
                .expect("endpoint"),
            peer,
        )),
    }]);
    swarm.poll(Now::from_millis(0)).expect("poll");

    let before = swarm.entropy.0;
    // Reaches the core rather than failing for want of an OS RNG.
    swarm.ping(&peer, 1_000).expect("ping queues");

    // The nonce came from the injected source, not `getrandom`: the
    // counter advanced by exactly one payload.
    assert_eq!(
        swarm.entropy.0,
        before.wrapping_add(PING_PAYLOAD_LEN as u8),
        "ping must consume PING_PAYLOAD_LEN bytes of injected entropy"
    );
}

/// A ping nonce that an attacker can predict lets them pre-compute the
/// reply, so a failed draw must refuse the ping outright -- never fall
/// back to whatever the buffer happened to contain.
#[test]
fn ping_is_refused_when_the_entropy_source_fails() {
    let peer = Ed25519Keypair::generate().peer_id();
    let mut swarm = swarm_with(negotiating_transport(&peer), BrokenEntropy);
    swarm.poll(Now::from_millis(0)).expect("poll");
    assert!(
        swarm.connected_peers().contains(&peer),
        "the peer must be connected, so the ping fails for entropy alone"
    );

    let error = swarm
        .ping(&peer, 1_000)
        .expect_err("a ping must not be sent with a payload the RNG never produced");
    assert!(
        matches!(error, DriverError::Entropy),
        "expected DriverError::Entropy, got {error:?}"
    );

    // And nothing weak escaped: driving the swarm on cannot flush a
    // payload the caller was told was never generated.
    settle(&mut swarm, 2_000);
    assert!(
        swarm.transport().ping_frames().is_empty(),
        "no ping payload may reach the wire: {:?}",
        swarm.transport().ping_frames()
    );
}

/// The positive direction, observed on the wire rather than through the
/// helper: the bytes the source produced are the bytes that get sent.
#[test]
fn ping_sends_the_payload_the_entropy_source_produced() {
    let peer = Ed25519Keypair::generate().peer_id();
    let mut swarm = swarm_with(negotiating_transport(&peer), SeqEntropy(0xA0));
    swarm.poll(Now::from_millis(0)).expect("poll");

    swarm.ping(&peer, 1_000).expect("ping queues");
    settle(&mut swarm, 2_000);

    // SeqEntropy(0xA0) hands out 0xA0, 0xA1, ... one byte at a time.
    let expected: [u8; PING_PAYLOAD_LEN] = core::array::from_fn(|i| 0xA0u8.wrapping_add(i as u8));
    assert_eq!(
        swarm.transport().ping_frames(),
        vec![expected.as_slice()],
        "the ping payload on the wire must be exactly the drawn bytes"
    );
}

#[test]
fn a_second_close_of_the_same_connection_is_not_a_runtime_error() {
    let peer = Ed25519Keypair::generate().peer_id();
    let conn = ConnectionId::new(1);
    let address = "/ip4/198.51.100.7/udp/4001/quic-v1"
        .parse()
        .expect("endpoint");
    let mut swarm = swarm_with(
        ScriptedTransport {
            initial: vec![TransportEvent::Connected {
                id: conn,
                endpoint: Box::new(ConnectionEndpoint::with_peer_id(address, peer)),
            }],
            fail_second_close: true,
            ..ScriptedTransport::default()
        },
        SeqEntropy(1),
    );
    swarm.poll(Now::from_millis(0)).expect("connect");
    swarm.disconnect(&peer, 1).expect("first close");
    swarm.disconnect(&peer, 2).expect("second close");
    let events = swarm.poll(Now::from_millis(3)).expect("poll");
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, SwarmEvent::Error(_))),
        "already-gone close must not surface as Error: {events:?}"
    );
}

/// How a scripted transport fails an operation on an ended target.
type Ended = fn(ConnectionId, StreamId) -> TransportError;

fn stream_not_found(id: ConnectionId, stream_id: StreamId) -> TransportError {
    TransportError::StreamNotFound { id, stream_id }
}

fn connection_not_found(id: ConnectionId, _: StreamId) -> TransportError {
    TransportError::ConnectionNotFound { id }
}

fn connection_closed(id: ConnectionId, _: StreamId) -> TransportError {
    TransportError::ConnectionClosed {
        id,
        reason: String::from("connection is closing"),
    }
}

/// Each way a transport says the target already ended, paired with the
/// terminal event that reports the end right behind it.
fn ended_targets(conn: ConnectionId, stream_id: StreamId) -> [(Ended, TransportEvent); 3] {
    let stream_closed = TransportEvent::StreamClosed {
        id: conn,
        stream_id,
    };
    let closed = TransportEvent::Closed {
        id: conn,
        reason: ConnectionCloseReason::Remote { code: 0 },
    };
    [
        (stream_not_found, stream_closed),
        (connection_not_found, closed.clone()),
        (connection_closed, closed),
    ]
}

/// What a remote dialer writes to propose `protocol` on a new stream.
fn proposal(protocol: &str) -> Bytes {
    let mut dialer = MultistreamSelect::dialer(protocol);
    dialer.start();
    let mut bytes = Vec::new();
    while let Some(output) = dialer.poll_output() {
        if let MultistreamOutput::OutboundData(data) = output {
            bytes.extend_from_slice(&data);
        }
    }
    Bytes::from(bytes)
}

/// A swarm serving `/app/1`, connected to a peer.
fn app_swarm(peer: &PeerId) -> SwarmCore<ScriptedTransport, SeqEntropy> {
    let mut transport = negotiating_transport(peer);
    transport.negotiate = false;
    let mut swarm = swarm_with(transport, SeqEntropy(1));
    swarm.add_protocol("/app/1").expect("protocol");
    swarm.poll(Now::from_millis(0)).expect("connect");
    swarm
}

/// The transport emits a stream's last events and its end in one poll,
/// and has already forgotten the stream (or connection) by the time the
/// swarm acts on the earlier ones. Each action the swarm queues hits the
/// ended target; the terminal event right behind reports the end, so no
/// action may add a runtime error.
#[test]
fn queued_actions_on_an_already_ended_target_are_not_runtime_errors() {
    let peer = Ed25519Keypair::generate().peer_id();
    let conn = ConnectionId::new(1);
    let stream_id = StreamId::new(7);
    let opened = TransportEvent::IncomingStream {
        id: conn,
        stream_id,
    };
    let propose = |protocol| TransportEvent::StreamData {
        id: conn,
        stream_id,
        data: proposal(protocol),
    };
    // Negotiating answers with a send; an Identify reply then closes its
    // write side; a stop on a stream still negotiating resets it.
    let scenarios = [
        ("send", vec![opened.clone(), propose("/app/1")]),
        (
            "close_write",
            vec![opened.clone(), propose(IDENTIFY_PROTOCOL_ID)],
        ),
        (
            "reset",
            vec![
                opened.clone(),
                TransportEvent::StreamWriteStopped {
                    id: conn,
                    stream_id,
                    error_code: 0,
                },
            ],
        ),
    ];
    for (action, batch) in scenarios {
        for (ended, terminal) in ended_targets(conn, stream_id) {
            let mut swarm = app_swarm(&peer);
            let mut batch = batch.clone();
            batch.push(terminal.clone());
            swarm.transport_mut().initial = batch;
            swarm.transport_mut().ended = Some(ended);
            let events = swarm.poll(Now::from_millis(1)).expect("poll");
            let error = ended(conn, stream_id);
            assert!(
                swarm.transport().stream_ops.contains(&action),
                "{action} never reached the transport ({error}): {:?}",
                swarm.transport().stream_ops
            );
            assert!(
                !events
                    .iter()
                    .any(|event| matches!(event, SwarmEvent::Error(_))),
                "{action} on an ended target ({error}) surfaced as Error: {events:?}"
            );
        }
    }
}

/// An [`app_swarm`] with an inbound `/app/1` stream that negotiated
/// before the transport ended it with `ended`.
fn ended_user_stream(
    peer: &PeerId,
    ended: Ended,
) -> (
    SwarmCore<ScriptedTransport, SeqEntropy>,
    ConnectionId,
    StreamId,
) {
    let (conn, stream_id) = (ConnectionId::new(1), StreamId::new(7));
    let mut swarm = app_swarm(peer);
    swarm.transport_mut().initial = vec![
        TransportEvent::IncomingStream {
            id: conn,
            stream_id,
        },
        TransportEvent::StreamData {
            id: conn,
            stream_id,
            data: proposal("/app/1"),
        },
    ];
    let events = swarm.poll(Now::from_millis(1)).expect("poll");
    assert!(
        events
            .iter()
            .any(|event| matches!(event, SwarmEvent::StreamReady { .. })),
        "{events:?}"
    );
    swarm.transport_mut().ended = Some(ended);
    (swarm, conn, stream_id)
}

#[test]
fn a_reset_of_an_ended_stream_leaves_no_reset_pending() {
    let peer = Ed25519Keypair::generate().peer_id();
    for ended in [stream_not_found, connection_not_found, connection_closed] {
        let (mut swarm, conn, stream_id) = ended_user_stream(&peer, ended);
        // No terminal event follows: the reset alone must clear its
        // marker, so a second reset reaches the transport again.
        for at in [2, 3] {
            swarm
                .reset_stream(&peer, conn, stream_id, at)
                .expect("reset");
        }
        let resets = swarm.transport().stream_ops.iter();
        assert_eq!(
            resets.filter(|op| **op == "reset").count(),
            2,
            "{}",
            ended(conn, stream_id)
        );
    }
}

#[test]
fn a_write_side_close_the_transport_refuses_is_still_reported() {
    let peer = Ed25519Keypair::generate().peer_id();
    let (mut swarm, conn, stream_id) = ended_user_stream(&peer, |id, stream_id| {
        TransportError::StreamCloseWriteFailed {
            id,
            stream_id,
            reason: String::from("local stream write side is already closed"),
        }
    });
    swarm
        .close_stream_write(&peer, conn, stream_id, 2)
        .expect("close");
    let events = swarm.poll(Now::from_millis(3)).expect("poll");
    assert!(
        events.iter().any(|event| matches!(
            event,
            SwarmEvent::Error(error) if error.stream_id == Some(stream_id)
        )),
        "{events:?}"
    );
}

#[test]
fn application_writes_and_closes_on_an_ended_stream_still_fail() {
    let peer = Ed25519Keypair::generate().peer_id();
    for (ended, terminal) in ended_targets(ConnectionId::new(1), StreamId::new(7)) {
        let (mut swarm, conn, stream_id) = ended_user_stream(&peer, ended);
        // Before the swarm reads the end, the transport's refusal is the
        // caller's: the write must not look accepted.
        let write = swarm.send_stream(&peer, conn, stream_id, Bytes::from_static(b"x"), 2);
        assert!(
            write.as_ref().is_err_and(DriverError::is_stream_gone),
            "{write:?}"
        );

        swarm.transport_mut().initial = vec![terminal];
        swarm.poll(Now::from_millis(3)).expect("poll");
        let write = swarm.send_stream(&peer, conn, stream_id, Bytes::from_static(b"x"), 4);
        let close = swarm.close_stream_write(&peer, conn, stream_id, 4);
        for result in [write, close] {
            assert!(
                result.as_ref().is_err_and(DriverError::is_stream_gone),
                "{result:?}"
            );
        }
    }
}

#[test]
fn resetting_a_stream_the_transport_already_forgot_is_not_a_runtime_error() {
    let peer = Ed25519Keypair::generate().peer_id();
    let conn = ConnectionId::new(1);
    let address = "/ip4/198.51.100.7/udp/4001/quic-v1"
        .parse()
        .expect("endpoint");
    let mut swarm = swarm_with(
        ScriptedTransport {
            initial: vec![TransportEvent::Connected {
                id: conn,
                endpoint: Box::new(ConnectionEndpoint::with_peer_id(address, peer)),
            }],
            ended: Some(stream_not_found),
            ..ScriptedTransport::default()
        },
        SeqEntropy(1),
    );
    swarm.add_protocol("/app/1").expect("protocol");
    swarm.poll(Now::from_millis(0)).expect("connect");
    let (conn_id, stream_id) = swarm.open_stream(&peer, "/app/1", 1).expect("open");
    swarm
        .abandon_stream(&peer, conn_id, stream_id, 2)
        .expect("abandon");
    let events = swarm.poll(Now::from_millis(3)).expect("poll");
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, SwarmEvent::Error(_))),
        "an already-gone stream's reset must not surface as Error: {events:?}"
    );
}

/// Polls a swarm with `timeouts` at each of `polls` against a peer that
/// agrees to Identify only at `answer_at_ms` and replies at
/// `reply_at_ms`, as on a loaded slow link, and returns every event with
/// the time of the poll that produced it.
fn identify_a_slow_peer(
    timeouts: SwarmTimeouts,
    answer_at_ms: u64,
    reply_at_ms: u64,
    polls: &[u64],
) -> Vec<(u64, SwarmEvent)> {
    let peer = Ed25519Keypair::generate().peer_id();
    let transport = ScriptedTransport {
        answer_at_ms: Some(answer_at_ms),
        reply_at_ms: Some(reply_at_ms),
        ..negotiating_transport(&peer)
    };
    let keypair = Ed25519Keypair::generate();
    let mut swarm = crate::SwarmBuilder::new(&keypair)
        .timeouts(timeouts)
        .build_core(transport, SeqEntropy(1))
        .expect("build");
    let mut events = Vec::new();
    for &now_ms in polls {
        for event in swarm.poll(Now::from_millis(now_ms)).expect("poll") {
            events.push((now_ms, event));
        }
    }
    events
}

fn identify_failures(events: &[(u64, SwarmEvent)]) -> Vec<(u64, IdentifyFailure)> {
    events
        .iter()
        .filter_map(|(at, event)| match event {
            SwarmEvent::IdentifyFailed { cause, .. } => Some((*at, *cause)),
            _ => None,
        })
        .collect()
}

fn became_ready(events: &[(u64, SwarmEvent)]) -> bool {
    events
        .iter()
        .any(|(_, event)| matches!(event, SwarmEvent::PeerReady { .. }))
}

#[test]
fn the_default_first_identify_deadline_covers_a_slow_negotiation() {
    // 15 s negotiating, 25 s in all: past the negotiation deadline, inside
    // the Identify one.
    let events = identify_a_slow_peer(
        SwarmTimeouts::default(),
        15_000,
        25_000,
        &[
            0, 1, 2, 12_000, 15_000, 15_001, 20_000, 25_000, 25_001, 25_002,
        ],
    );
    assert!(identify_failures(&events).is_empty(), "{events:?}");
    assert!(became_ready(&events), "{events:?}");
}

#[test]
fn a_first_identify_that_never_completes_fails_at_30s() {
    let events = identify_a_slow_peer(
        SwarmTimeouts::default(),
        u64::MAX,
        u64::MAX,
        &[0, 1, 2, 10_000, 20_000, 29_999, 30_000, 60_000],
    );
    assert_eq!(
        identify_failures(&events),
        [(30_000, IdentifyFailure::TimedOut)],
        "{events:?}"
    );
    assert!(!became_ready(&events), "{events:?}");
}

#[test]
fn a_raised_identify_deadline_alone_lets_a_slower_peer_become_ready() {
    let polls = [0, 1, 2, 30_000, 35_000, 35_001, 35_002, 35_003];
    let defaults = identify_a_slow_peer(SwarmTimeouts::default(), 35_000, 35_000, &polls);
    assert_eq!(
        identify_failures(&defaults),
        [(30_000, IdentifyFailure::TimedOut)],
        "{defaults:?}"
    );
    assert!(!became_ready(&defaults), "{defaults:?}");

    // The negotiation deadline stays at its 30 s default, which the 35 s
    // answer also exceeds.
    let raised = identify_a_slow_peer(
        SwarmTimeouts {
            identify_ms: 40_000,
            ..SwarmTimeouts::default()
        },
        35_000,
        35_000,
        &polls,
    );
    assert!(identify_failures(&raised).is_empty(), "{raised:?}");
    assert!(became_ready(&raised), "{raised:?}");
}

#[test]
fn negotiation_deadline_starts_when_the_transport_opens_the_stream() {
    let peer = Ed25519Keypair::generate().peer_id();
    let conn = ConnectionId::new(1);
    let address = "/ip4/198.51.100.7/udp/4001/quic-v1"
        .parse()
        .expect("endpoint");
    let mut swarm = swarm(vec![TransportEvent::Connected {
        id: conn,
        endpoint: Box::new(ConnectionEndpoint::with_peer_id(address, peer)),
    }]);
    swarm.add_protocol("/app/1").expect("protocol");
    swarm.poll(Now::from_millis(0)).expect("connect");
    // The transport holds the open (no `StreamOpened`), as QUIC does
    // while it waits for the peer's stream credit.
    let (conn_id, stream_id) = swarm.open_stream(&peer, "/app/1", 0).expect("open");
    let timed_out = |events: &[SwarmEvent]| {
        events.iter().any(
            |event| matches!(event, SwarmEvent::Error(error) if error.stream_id == Some(stream_id)),
        )
    };

    let opened_at = 3 * OUTBOUND_NEGOTIATION_TIMEOUT_MS;
    let events = swarm.poll(Now::from_millis(opened_at)).expect("held");
    assert!(
        !timed_out(&events),
        "a held open is not negotiating: {events:?}"
    );

    swarm
        .transport_mut()
        .initial
        .push(TransportEvent::StreamOpened {
            id: conn_id,
            stream_id,
        });
    swarm.poll(Now::from_millis(opened_at)).expect("opened");
    let due = opened_at + OUTBOUND_NEGOTIATION_TIMEOUT_MS;
    assert_eq!(
        swarm.next_deadline(Now::from_millis(opened_at)),
        Some(Deadline::from_millis(due))
    );
    let events = swarm.poll(Now::from_millis(due - 1)).expect("not yet due");
    assert!(!timed_out(&events), "{events:?}");
    let events = swarm.poll(Now::from_millis(due)).expect("due");
    assert!(timed_out(&events), "{events:?}");
}

#[test]
fn abort_dial_restores_pending_when_close_fails() {
    let peer = Ed25519Keypair::generate().peer_id();
    let addr = PeerAddr::new(
        "/ip4/198.51.100.8/udp/4001/quic-v1".parse().expect("addr"),
        peer,
    )
    .expect("peer addr");
    let mut swarm = swarm_with(
        ScriptedTransport {
            refuse_close: true,
            ..ScriptedTransport::default()
        },
        SeqEntropy(1),
    );
    let conn_id = swarm.dial(&addr).expect("dial");
    // Record a transport error before the failed abort so restore must
    // keep last_error — not rebuild via note_dial (which clears it).
    swarm.transport_mut().initial.push(TransportEvent::Error {
        id: conn_id,
        message: String::from("refused"),
    });
    let _ = swarm.poll(Now::from_millis(0)).expect("record error");
    assert!(
        swarm.abort_dial(conn_id).is_err(),
        "close refusal must surface"
    );
    // Pending dial was restored: a later close still emits DialFailed,
    // not a silent half-aborted dial that can still establish.
    swarm.transport_mut().initial.push(TransportEvent::Closed {
        id: conn_id,
        reason: ConnectionCloseReason::Local,
    });
    let events = swarm.poll(Now::from_millis(1)).expect("poll");
    assert!(
        matches!(
            events.as_slice(),
            [SwarmEvent::DialFailed {
                conn_id: failed,
                reason,
                ..
            }] if *failed == conn_id && reason == "refused"
        ),
        "got {events:?}"
    );
}

#[test]
fn a_failed_abort_retry_keeps_the_veto() {
    let peer = Ed25519Keypair::generate().peer_id();
    let addr = PeerAddr::new(
        "/ip4/198.51.100.12/udp/4001/quic-v1".parse().expect("addr"),
        peer,
    )
    .expect("peer addr");
    let mut swarm = swarm_with(
        ScriptedTransport {
            refuse_close: true,
            ..ScriptedTransport::default()
        },
        SeqEntropy(1),
    );
    let conn_id = swarm.dial(&addr).expect("dial");
    swarm.abort_dial(conn_id).expect_err("close refused");
    swarm.veto_establish(conn_id);
    // The host retries the abort, and closing fails again.
    swarm.abort_dial(conn_id).expect_err("close refused");
    swarm
        .transport_mut()
        .initial
        .push(TransportEvent::Connected {
            id: conn_id,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                addr.transport().clone(),
                peer,
            )),
        });
    // The rejection's own close is refused too, which surfaces as a
    // runtime error beside the DialFailed.
    let events = swarm.poll(Now::from_millis(1)).expect("late connected");
    assert!(
        events.iter().any(|event| matches!(
            event,
            SwarmEvent::DialFailed { conn_id: failed, .. } if *failed == conn_id
        )) && !events
            .iter()
            .any(|event| matches!(event, SwarmEvent::ConnectionEstablished { .. })),
        "the veto survives the retried abort; got {events:?}"
    );
    assert_eq!(swarm.connection_id(&peer), None);
}

#[test]
fn an_aborted_dial_that_connects_anyway_never_establishes() {
    let peer = Ed25519Keypair::generate().peer_id();
    let addr = PeerAddr::new(
        "/ip4/198.51.100.11/udp/4001/quic-v1".parse().expect("addr"),
        peer,
    )
    .expect("peer addr");
    let mut swarm = swarm_with(ScriptedTransport::default(), SeqEntropy(1));
    let conn_id = swarm.dial(&addr).expect("dial");
    // The transport has already queued the handshake's completion when
    // the host aborts; `close` does not drop it.
    swarm
        .transport_mut()
        .initial
        .push(TransportEvent::Connected {
            id: conn_id,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                addr.transport().clone(),
                peer,
            )),
        });
    assert!(swarm.abort_dial(conn_id).expect("abort"));
    let events = swarm.poll(Now::from_millis(1)).expect("late connected");
    assert!(
        events.is_empty(),
        "an aborted dial stays silent; got {events:?}"
    );
    assert_eq!(swarm.connection_id(&peer), None);

    swarm.transport_mut().initial.push(TransportEvent::Closed {
        id: conn_id,
        reason: ConnectionCloseReason::Local,
    });
    let events = swarm.poll(Now::from_millis(2)).expect("closed");
    assert!(events.is_empty(), "got {events:?}");
    assert!(!swarm.state.has_tracked_connections());
}

#[test]
fn veto_establish_closes_dial_without_replacing_existing_peer() {
    let peer = Ed25519Keypair::generate().peer_id();
    let existing_addr = PeerAddr::new(
        "/ip4/198.51.100.9/udp/4001/quic-v1".parse().expect("addr"),
        peer,
    )
    .expect("peer addr");
    let late_addr = PeerAddr::new(
        "/ip4/198.51.100.10/udp/4001/quic-v1".parse().expect("addr"),
        peer,
    )
    .expect("peer addr");
    let existing = ConnectionId::new(1);
    let late = ConnectionId::new(2);
    let mut swarm = swarm_with(ScriptedTransport::default(), SeqEntropy(1));
    swarm
        .transport_mut()
        .initial
        .push(TransportEvent::Connected {
            id: existing,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                existing_addr.transport().clone(),
                peer,
            )),
        });
    let _ = swarm.poll(Now::from_millis(0)).expect("existing");
    assert_eq!(swarm.connection_id(&peer), Some(existing));

    swarm.state.note_dial(late, late_addr.clone());
    swarm.veto_establish(late);
    swarm
        .transport_mut()
        .initial
        .push(TransportEvent::Connected {
            id: late,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                late_addr.transport().clone(),
                peer,
            )),
        });
    let events = swarm.poll(Now::from_millis(1)).expect("vetoed");
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                SwarmEvent::DialFailed { conn_id, .. } if *conn_id == late
            )
        }),
        "vetoed dial should DialFailed; got {events:?}"
    );
    assert!(
        events.iter().all(|event| {
            !matches!(
                event,
                SwarmEvent::ConnectionEstablished { conn_id, .. } if *conn_id == late
            )
        }),
        "vetoed dial must not establish; got {events:?}"
    );
    assert!(
        events.iter().all(|event| {
            !matches!(
                event,
                SwarmEvent::ConnectionReplaced { old, .. } if *old == existing
            )
        }),
        "existing connection must not be replaced; got {events:?}"
    );
    assert_eq!(swarm.connection_id(&peer), Some(existing));
    assert!(
        swarm.transport().close_count >= 1,
        "late dial must be closed; close_count={}",
        swarm.transport().close_count
    );
}

/// A loopback WebTransport address whose certhash digest is `byte`s.
fn webtransport(byte: u8) -> Multiaddr {
    let mut addr: Multiaddr = "/ip4/127.0.0.1/udp/4001/quic-v1/webtransport"
        .parse()
        .expect("multiaddr");
    addr.push(minip2p_core::Protocol::Certhash(
        minip2p_core::Multihash::wrap(0x12, &[byte; 32]).expect("multihash"),
    ));
    addr
}

fn listen_changes(events: &[SwarmEvent]) -> Vec<Vec<PeerAddr>> {
    events
        .iter()
        .filter_map(|event| match event {
            SwarmEvent::ListenAddressesChanged { addrs } => Some(addrs.clone()),
            _ => None,
        })
        .collect()
}

/// A swarm listening on a `quic-v1` and a WebTransport address.
fn rotating_swarm() -> SwarmCore<ScriptedTransport, SeqEntropy> {
    let quic: Multiaddr = "/ip4/127.0.0.1/udp/4001/quic-v1".parse().expect("quic");
    let mut swarm = swarm_with(
        ScriptedTransport {
            addrs: vec![quic, webtransport(1)],
            ..ScriptedTransport::default()
        },
        SeqEntropy(1),
    );
    swarm.listen_on_bound_addrs().expect("listen");
    assert!(listen_changes(&swarm.poll(Now::from_millis(0)).expect("poll")).is_empty());
    swarm
}

#[test]
fn a_rotated_listen_address_is_reported_once_and_advertised_by_the_same_poll() {
    let mut swarm = rotating_swarm();
    let quic = swarm.transport().addrs[0].clone();
    swarm.transport_mut().rotate_to = Some(vec![quic.clone(), webtransport(2)]);

    let events = swarm.poll(Now::from_millis(1)).expect("poll");

    let local = swarm.local_peer_id;
    let expected = vec![
        PeerAddr::new(quic.clone(), local).expect("quic peer addr"),
        PeerAddr::new(webtransport(2), local).expect("wt peer addr"),
    ];
    assert_eq!(listen_changes(&events), [expected]);
    assert_eq!(swarm.listened_addrs(), [quic, webtransport(2)]);
    // Identify built from this poll's events already advertises it.
    assert!(swarm.local_addresses().contains(&webtransport(2)));
    assert!(!swarm.local_addresses().contains(&webtransport(1)));
}

#[test]
fn an_external_address_change_leaves_the_listen_set_alone() {
    let mut swarm = rotating_swarm();
    let listened = swarm.listened_addrs().to_vec();
    let external: Multiaddr = "/ip4/203.0.113.9/udp/4001/quic-v1".parse().expect("ext");
    swarm.set_external_addresses(vec![external.clone()]);

    let events = swarm.poll(Now::from_millis(1)).expect("poll");

    assert!(listen_changes(&events).is_empty(), "{events:?}");
    assert_eq!(swarm.listened_addrs(), listened);
    assert!(swarm.local_addresses().contains(&external));
}
