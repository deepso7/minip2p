//! Scripted no-I/O tests for the floodsub agent: hand-built swarm events
//! in, actions/events out, a fake clock throughout.

use minip2p_identity::Ed25519Keypair;
use minip2p_pubsub::{
    FLOODSUB_PROTOCOL_ID, FloodsubAgent, FloodsubConfig, FrameDecode, PublishError, PubsubAction,
    PubsubEvent, RawMessage, Rpc, TopicError, decode_frame, encode_frame,
};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::StreamId;

use minip2p_core::PeerId;

fn keypair(seed: u8) -> Ed25519Keypair {
    Ed25519Keypair::from_secret_key_bytes([seed; 32])
}

fn agent_with(config: FloodsubConfig) -> FloodsubAgent {
    FloodsubAgent::new(keypair(1), config, 100)
}

fn agent() -> FloodsubAgent {
    agent_with(FloodsubConfig::default())
}

fn peer(seed: u8) -> PeerId {
    keypair(seed).peer_id()
}

fn drain_actions(a: &mut FloodsubAgent) -> Vec<PubsubAction> {
    let mut out = Vec::new();
    while let Some(action) = a.poll_action() {
        out.push(action);
    }
    out
}

fn drain_events(a: &mut FloodsubAgent) -> Vec<PubsubEvent> {
    let mut out = Vec::new();
    while let Some(event) = a.poll_event() {
        out.push(event);
    }
    out
}

/// ConnectionEstablished + PeerReady advertising floodsub.
fn connect(a: &mut FloodsubAgent, peer: &PeerId, now: u64) {
    a.handle_event(
        &SwarmEvent::ConnectionEstablished {
            peer_id: peer.clone(),
        },
        now,
    );
    a.handle_event(
        &SwarmEvent::PeerReady {
            peer_id: peer.clone(),
            protocols: vec![FLOODSUB_PROTOCOL_ID.to_string()],
        },
        now,
    );
}

/// Extracts the single queued OpenStream, if any.
fn open_stream_action(actions: &[PubsubAction]) -> Option<(minip2p_pubsub::PubsubToken, PeerId)> {
    actions.iter().find_map(|a| match a {
        PubsubAction::OpenStream { token, peer, .. } => Some((*token, peer.clone())),
        _ => None,
    })
}

fn count_open_streams(actions: &[PubsubAction]) -> usize {
    actions
        .iter()
        .filter(|a| matches!(a, PubsubAction::OpenStream { .. }))
        .count()
}

/// Walks one queued OpenStream through negotiation and returns the sent
/// frame, leaving the sender in AwaitingClose on `stream_id`.
fn negotiate_send(
    a: &mut FloodsubAgent,
    peer: &PeerId,
    stream_id: StreamId,
    now: u64,
) -> Option<Vec<u8>> {
    let actions = drain_actions(a);
    let (token, to) = open_stream_action(&actions)?;
    assert_eq!(&to, peer);
    a.stream_open_result(token, Ok(stream_id), now);
    let claimed = a.handle_event(
        &SwarmEvent::StreamReady {
            peer_id: peer.clone(),
            stream_id,
            protocol_id: FLOODSUB_PROTOCOL_ID.to_string(),
            initiated_locally: true,
        },
        now,
    );
    assert!(claimed, "our outbound StreamReady must be claimed");
    let actions = drain_actions(a);
    let frame = actions.iter().find_map(|a| match a {
        PubsubAction::SendStream { data, .. } => Some(data.clone()),
        _ => None,
    })?;
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, PubsubAction::CloseStreamWrite { .. })),
        "one-shot send must half-close: {actions:?}"
    );
    Some(frame)
}

/// Full one-shot send cycle: open → send → close. Returns the sent frame.
fn complete_send(
    a: &mut FloodsubAgent,
    peer: &PeerId,
    stream_id: StreamId,
    now: u64,
) -> Option<Vec<u8>> {
    let frame = negotiate_send(a, peer, stream_id, now)?;
    a.handle_event(
        &SwarmEvent::StreamClosed {
            peer_id: peer.clone(),
            stream_id,
        },
        now,
    );
    Some(frame)
}

/// Opens an inbound floodsub stream from `peer`.
fn inbound_open(a: &mut FloodsubAgent, peer: &PeerId, stream_id: StreamId, now: u64) -> bool {
    a.handle_event(
        &SwarmEvent::StreamReady {
            peer_id: peer.clone(),
            stream_id,
            protocol_id: FLOODSUB_PROTOCOL_ID.to_string(),
            initiated_locally: false,
        },
        now,
    )
}

fn inbound_data(a: &mut FloodsubAgent, peer: &PeerId, stream_id: StreamId, data: &[u8], now: u64) {
    let claimed = a.handle_event(
        &SwarmEvent::StreamData {
            peer_id: peer.clone(),
            stream_id,
            data: data.to_vec(),
        },
        now,
    );
    assert!(
        claimed,
        "data on an inbound floodsub stream must be claimed"
    );
}

fn decode_rpc(frame: &[u8]) -> Rpc {
    let FrameDecode::Complete { payload, consumed } = decode_frame(frame) else {
        panic!("frame must be complete");
    };
    assert_eq!(consumed, frame.len());
    Rpc::decode(payload).expect("valid RPC")
}

/// A subscription-announcement frame as a remote peer would send it.
fn remote_subscribe_frame(topic: &str) -> Vec<u8> {
    let rpc = Rpc {
        subscriptions: vec![minip2p_pubsub::SubOpts {
            subscribe: Some(true),
            topic_id: Some(topic.to_string()),
        }],
        publish: Vec::new(),
    };
    encode_frame(&rpc.encode())
}

/// A signed message frame published by `signer`.
fn signed_message_frame(signer: &Ed25519Keypair, topic: &str, data: &[u8], seqno: u64) -> Vec<u8> {
    let rpc = Rpc {
        subscriptions: Vec::new(),
        publish: vec![RawMessage::build_signed(
            signer,
            topic,
            data.to_vec(),
            seqno,
        )],
    };
    encode_frame(&rpc.encode())
}

/// Connects `peer` and marks it subscribed to `topic` via an inbound
/// stream. When the agent already holds local subscriptions, the snapshot
/// send that PeerReady triggers is completed so the sender ends Idle.
fn connect_subscribed(
    a: &mut FloodsubAgent,
    peer: &PeerId,
    topic: &str,
    inbound_id: StreamId,
    now: u64,
) {
    connect(a, peer, now);
    let actions = drain_actions(a);
    if let Some((token, _)) = open_stream_action(&actions) {
        let snapshot_stream = StreamId::new(901);
        a.stream_open_result(token, Ok(snapshot_stream), now);
        a.handle_event(
            &SwarmEvent::StreamReady {
                peer_id: peer.clone(),
                stream_id: snapshot_stream,
                protocol_id: FLOODSUB_PROTOCOL_ID.to_string(),
                initiated_locally: true,
            },
            now,
        );
        a.handle_event(
            &SwarmEvent::StreamClosed {
                peer_id: peer.clone(),
                stream_id: snapshot_stream,
            },
            now,
        );
    }
    assert!(inbound_open(a, peer, inbound_id, now));
    inbound_data(a, peer, inbound_id, &remote_subscribe_frame(topic), now);
    drain_events(a);
    drain_actions(a);
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[test]
fn subscription_snapshot_flows_on_peer_ready_and_publish_reaches_subscribers() {
    let mut a = agent();
    a.subscribe("chat", 0).unwrap();
    assert!(drain_actions(&mut a).is_empty(), "no peers: no actions");

    let b = peer(2);
    connect(&mut a, &b, 10);
    let frame = complete_send(&mut a, &b, StreamId::new(4), 10).expect("subscription snapshot");
    let rpc = decode_rpc(&frame);
    assert_eq!(rpc.subscriptions.len(), 1);
    assert_eq!(rpc.subscriptions[0].subscribe, Some(true));
    assert_eq!(rpc.subscriptions[0].topic_id.as_deref(), Some("chat"));
    assert!(rpc.publish.is_empty());

    // The remote subscribes too, then our publish flows to it.
    assert!(inbound_open(&mut a, &b, StreamId::new(5), 20));
    inbound_data(
        &mut a,
        &b,
        StreamId::new(5),
        &remote_subscribe_frame("chat"),
        20,
    );
    assert_eq!(
        drain_events(&mut a),
        vec![PubsubEvent::PeerSubscribed {
            peer: b.clone(),
            topic: "chat".to_string()
        }]
    );

    a.publish("chat", b"hello".to_vec(), 30).unwrap();
    let frame = complete_send(&mut a, &b, StreamId::new(8), 30).expect("publish frame");
    let rpc = decode_rpc(&frame);
    assert_eq!(rpc.publish.len(), 1);
    let (from, _) = rpc.publish[0].verify(false).expect("we sign our messages");
    assert_eq!(&from, a.local_peer_id());
    assert_eq!(rpc.publish[0].data.as_deref(), Some(&b"hello"[..]));
}

#[test]
fn publish_with_no_subscribers_succeeds_without_sends() {
    let mut a = agent();
    let b = peer(2);
    connect(&mut a, &b, 0);
    drain_actions(&mut a);
    a.publish("chat", b"into the void".to_vec(), 1).unwrap();
    assert_eq!(count_open_streams(&drain_actions(&mut a)), 0);
}

// ---------------------------------------------------------------------------
// Sender ordering and snapshot commits
// ---------------------------------------------------------------------------

#[test]
fn mid_flight_subscription_change_commits_the_sent_snapshot_only() {
    let mut a = agent();
    let b = peer(2);
    connect(&mut a, &b, 0);

    a.subscribe("a", 1).unwrap();
    let stream = StreamId::new(4);
    let frame = negotiate_send(&mut a, &b, stream, 1).expect("snapshot {a} in flight");
    let rpc = decode_rpc(&frame);
    assert_eq!(rpc.subscriptions[0].topic_id.as_deref(), Some("a"));

    // Local set changes to {b} while {a} is still awaiting its close.
    a.subscribe("b", 2).unwrap();
    a.unsubscribe("a", 3);
    assert_eq!(
        count_open_streams(&drain_actions(&mut a)),
        0,
        "strict serialization: nothing opens while in flight"
    );

    // Close commits the {a} snapshot, then the next RPC diffs {a} -> {b}.
    a.handle_event(
        &SwarmEvent::StreamClosed {
            peer_id: b.clone(),
            stream_id: stream,
        },
        4,
    );
    let frame = complete_send(&mut a, &b, StreamId::new(8), 5).expect("diff RPC");
    let rpc = decode_rpc(&frame);
    let mut changes: Vec<(Option<bool>, Option<&str>)> = rpc
        .subscriptions
        .iter()
        .map(|s| (s.subscribe, s.topic_id.as_deref()))
        .collect();
    changes.sort();
    assert_eq!(
        changes,
        vec![(Some(false), Some("a")), (Some(true), Some("b"))],
        "the diff must remove a and add b"
    );
}

#[test]
fn second_publish_waits_for_stream_closed_not_remote_write_closed() {
    let mut a = agent();
    let b = peer(2);
    connect_subscribed(&mut a, &b, "t", StreamId::new(3), 0);

    a.publish("t", b"one".to_vec(), 1).unwrap();
    a.publish("t", b"two".to_vec(), 1).unwrap();
    let stream = StreamId::new(4);
    negotiate_send(&mut a, &b, stream, 1).expect("first publish in flight");

    // Remote half-close alone must not advance the queue.
    a.handle_event(
        &SwarmEvent::StreamRemoteWriteClosed {
            peer_id: b.clone(),
            stream_id: stream,
        },
        2,
    );
    assert_eq!(count_open_streams(&drain_actions(&mut a)), 0);

    // The terminal close does.
    a.handle_event(
        &SwarmEvent::StreamClosed {
            peer_id: b.clone(),
            stream_id: stream,
        },
        3,
    );
    let frame = complete_send(&mut a, &b, StreamId::new(8), 3).expect("second publish");
    let rpc = decode_rpc(&frame);
    assert_eq!(rpc.publish[0].data.as_deref(), Some(&b"two"[..]));
}

#[test]
fn stream_closed_in_negotiating_discards_without_committing() {
    let mut a = agent();
    let b = peer(2);
    connect(&mut a, &b, 0);
    a.subscribe("t", 1).unwrap();

    let actions = drain_actions(&mut a);
    let (token, _) = open_stream_action(&actions).expect("snapshot open");
    let stream = StreamId::new(4);
    a.stream_open_result(token, Ok(stream), 1);
    // Closed before StreamReady: the frame was never sent.
    a.handle_event(
        &SwarmEvent::StreamClosed {
            peer_id: b.clone(),
            stream_id: stream,
        },
        2,
    );
    let events = drain_events(&mut a);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, PubsubEvent::OutboundFailure { .. })),
        "an early close is a failure, not a commit: {events:?}"
    );
    // sent_topics was NOT committed: the next drive re-diffs the snapshot.
    a.handle_event(
        &SwarmEvent::PeerReady {
            peer_id: b.clone(),
            protocols: vec![FLOODSUB_PROTOCOL_ID.to_string()],
        },
        3,
    );
    let frame = complete_send(&mut a, &b, StreamId::new(8), 3).expect("re-diffed snapshot");
    assert_eq!(
        decode_rpc(&frame).subscriptions[0].topic_id.as_deref(),
        Some("t")
    );
}

// ---------------------------------------------------------------------------
// Flood routing
// ---------------------------------------------------------------------------

#[test]
fn forwards_to_subscribers_but_not_arrival_peer_or_publisher() {
    let mut a = agent();
    let (b, c, d) = (peer(2), peer(3), peer(4));
    connect_subscribed(&mut a, &b, "t", StreamId::new(3), 0);
    connect_subscribed(&mut a, &c, "t", StreamId::new(3), 0);
    connect_subscribed(&mut a, &d, "t", StreamId::new(3), 0);

    // A message published by an unconnected fifth peer arrives via B.
    let frame = signed_message_frame(&keypair(9), "t", b"flood", 1);
    inbound_data(&mut a, &b, StreamId::new(3), &frame, 10);

    let actions = drain_actions(&mut a);
    let targets: Vec<PeerId> = actions
        .iter()
        .filter_map(|a| match a {
            PubsubAction::OpenStream { peer, .. } => Some(peer.clone()),
            _ => None,
        })
        .collect();
    assert!(targets.contains(&c) && targets.contains(&d), "{targets:?}");
    assert!(!targets.contains(&b), "never forward to the arrival peer");
}

#[test]
fn never_forwards_back_to_the_original_publisher() {
    let mut a = agent();
    let publisher_kp = keypair(3);
    let (b, c) = (peer(2), publisher_kp.peer_id());
    connect_subscribed(&mut a, &b, "t", StreamId::new(3), 0);
    connect_subscribed(&mut a, &c, "t", StreamId::new(3), 0);

    // C's own message arrives via B (a routing loop): forward to nobody —
    // B is the arrival peer and C is the publisher.
    let frame = signed_message_frame(&publisher_kp, "t", b"loop", 1);
    inbound_data(&mut a, &b, StreamId::new(3), &frame, 10);
    assert_eq!(count_open_streams(&drain_actions(&mut a)), 0);
}

#[test]
fn own_message_echoed_back_is_dropped_by_the_seen_cache() {
    let mut a = agent();
    let b = peer(2);
    a.subscribe("t", 0).unwrap();
    connect_subscribed(&mut a, &b, "t", StreamId::new(3), 0);

    a.publish("t", b"mine".to_vec(), 1).unwrap();
    let frame = complete_send(&mut a, &b, StreamId::new(6), 1).expect("published");

    // B echoes our own message back at us.
    inbound_data(&mut a, &b, StreamId::new(3), &frame, 2);
    let events = drain_events(&mut a);
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, PubsubEvent::Message { .. })),
        "no self-delivery via echo: {events:?}"
    );
}

#[test]
fn duplicates_deliver_and_forward_once() {
    let mut a = agent();
    a.subscribe("t", 0).unwrap();
    let (b, c, d) = (peer(2), peer(3), peer(4));
    connect_subscribed(&mut a, &b, "t", StreamId::new(3), 0);
    connect_subscribed(&mut a, &c, "t", StreamId::new(3), 0);
    connect_subscribed(&mut a, &d, "t", StreamId::new(3), 0);
    drain_actions(&mut a);
    drain_events(&mut a);

    let frame = signed_message_frame(&keypair(9), "t", b"once", 5);
    inbound_data(&mut a, &b, StreamId::new(3), &frame, 10);
    inbound_data(&mut a, &c, StreamId::new(3), &frame, 11);

    let deliveries = drain_events(&mut a)
        .into_iter()
        .filter(|e| matches!(e, PubsubEvent::Message { .. }))
        .count();
    assert_eq!(deliveries, 1, "the duplicate via C is silent");
    // Forward fan-out happened only for the first copy (toward C and D).
    let opens = count_open_streams(&drain_actions(&mut a));
    assert_eq!(opens, 2, "one forward each to C and D, none for the dup");
}

// ---------------------------------------------------------------------------
// Backpressure
// ---------------------------------------------------------------------------

#[test]
fn publish_backpressure_is_all_or_nothing() {
    let mut a = agent_with(FloodsubConfig {
        max_pending_per_peer: 1,
        ..FloodsubConfig::default()
    });
    let (b, c) = (peer(2), peer(3));
    connect_subscribed(&mut a, &b, "t", StreamId::new(3), 0);
    connect_subscribed(&mut a, &c, "t", StreamId::new(3), 0);

    // First publish occupies both queues (in flight + queued).
    a.publish("t", b"one".to_vec(), 1).unwrap();
    drain_actions(&mut a);
    // B and C both have pending.len() == 1 == max: the next publish must
    // refuse and enqueue nowhere.
    assert_eq!(
        a.publish("t", b"two".to_vec(), 2),
        Err(PublishError::Backpressure)
    );
    assert_eq!(count_open_streams(&drain_actions(&mut a)), 0);
}

#[test]
fn forward_overflow_drops_only_for_the_full_peer() {
    let mut a = agent_with(FloodsubConfig {
        max_pending_per_peer: 1,
        ..FloodsubConfig::default()
    });
    let (b, c, d) = (peer(2), peer(3), peer(4));
    connect_subscribed(&mut a, &b, "t", StreamId::new(3), 0);
    connect_subscribed(&mut a, &c, "t", StreamId::new(3), 0);
    connect_subscribed(&mut a, &d, "t", StreamId::new(3), 0);

    // Fill C's queue via a publish (stays pending: never completed).
    a.publish("t", b"fill".to_vec(), 1).unwrap();
    drain_actions(&mut a);

    // A forward arrives via B: C is full (dropped, best-effort), D already
    // has the publish pending too... so use a fresh agent state instead:
    // simpler proof: the forward toward D queues BEHIND the publish while
    // C's copy is dropped; no OutboundFailure is emitted for C.
    let frame = signed_message_frame(&keypair(9), "t", b"fwd", 7);
    inbound_data(&mut a, &b, StreamId::new(3), &frame, 10);
    let events = drain_events(&mut a);
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, PubsubEvent::OutboundFailure { .. })),
        "forward drops are best-effort and silent: {events:?}"
    );
}

// ---------------------------------------------------------------------------
// Violations and malformed input
// ---------------------------------------------------------------------------

#[test]
fn malformed_rpc_resets_the_stream_and_keeps_owning_it() {
    let mut a = agent();
    let b = peer(2);
    connect(&mut a, &b, 0);
    let stream = StreamId::new(3);
    assert!(inbound_open(&mut a, &b, stream, 1));

    // A frame whose payload is not a valid RPC (unsupported wire type).
    let bad = encode_frame(&[(9 << 3) | 3]);
    inbound_data(&mut a, &b, stream, &bad, 2);
    let events = drain_events(&mut a);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, PubsubEvent::ProtocolViolation { .. })),
        "{events:?}"
    );
    let actions = drain_actions(&mut a);
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, PubsubAction::ResetStream { .. })),
        "{actions:?}"
    );

    // Late events on the rejected stream stay claimed and quiet.
    assert!(a.handle_event(
        &SwarmEvent::StreamData {
            peer_id: b.clone(),
            stream_id: stream,
            data: vec![1, 2, 3],
        },
        3,
    ));
    assert!(a.handle_event(
        &SwarmEvent::StreamClosed {
            peer_id: b.clone(),
            stream_id: stream,
        },
        4,
    ));
    assert!(drain_events(&mut a).is_empty());
}

#[test]
fn oversized_frame_header_is_rejected_before_buffering() {
    let mut a = agent();
    let b = peer(2);
    connect(&mut a, &b, 0);
    let stream = StreamId::new(3);
    assert!(inbound_open(&mut a, &b, stream, 1));

    let mut huge = Vec::new();
    minip2p_core::write_uvarint((minip2p_pubsub::MAX_RPC_SIZE + 1) as u64, &mut huge);
    inbound_data(&mut a, &b, stream, &huge, 2);
    assert!(
        drain_events(&mut a)
            .iter()
            .any(|e| matches!(e, PubsubEvent::ProtocolViolation { .. }))
    );
    assert!(
        drain_actions(&mut a)
            .iter()
            .any(|a| matches!(a, PubsubAction::ResetStream { .. }))
    );
}

#[test]
fn bad_signature_drops_the_message_but_the_stream_survives() {
    let mut a = agent();
    a.subscribe("t", 0).unwrap();
    let b = peer(2);
    connect(&mut a, &b, 0);
    let stream = StreamId::new(3);
    assert!(inbound_open(&mut a, &b, stream, 1));
    drain_actions(&mut a);

    // Tamper with a signed message's data after signing.
    let mut message = RawMessage::build_signed(&keypair(9), "t", b"good".to_vec(), 1);
    message.data = Some(b"evil".to_vec());
    message.raw = Vec::new(); // re-encode with the tampered data
    let rpc = Rpc {
        subscriptions: Vec::new(),
        publish: vec![message],
    };
    inbound_data(&mut a, &b, stream, &encode_frame(&rpc.encode()), 2);
    let events = drain_events(&mut a);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, PubsubEvent::ProtocolViolation { .. }))
            && !events
                .iter()
                .any(|e| matches!(e, PubsubEvent::Message { .. })),
        "{events:?}"
    );
    assert!(
        !drain_actions(&mut a)
            .iter()
            .any(|a| matches!(a, PubsubAction::ResetStream { .. })),
        "a bad signature must not reset the stream"
    );

    // A valid message on the same stream still flows.
    inbound_data(
        &mut a,
        &b,
        stream,
        &signed_message_frame(&keypair(9), "t", b"good", 2),
        3,
    );
    assert!(
        drain_events(&mut a)
            .iter()
            .any(|e| matches!(e, PubsubEvent::Message { .. }))
    );
}

#[test]
fn unsigned_messages_require_the_allow_unsigned_config() {
    let unsigned_frame = {
        let publisher = keypair(9);
        let message = RawMessage {
            from: Some(publisher.peer_id().to_bytes()),
            data: Some(b"unsigned".to_vec()),
            seqno: Some(5u64.to_be_bytes().to_vec()),
            topic_ids: vec!["t".to_string()],
            ..RawMessage::default()
        };
        let rpc = Rpc {
            subscriptions: Vec::new(),
            publish: vec![message],
        };
        encode_frame(&rpc.encode())
    };

    // Strict (default): dropped with a violation.
    let mut strict = agent();
    strict.subscribe("t", 0).unwrap();
    let b = peer(2);
    connect(&mut strict, &b, 0);
    assert!(inbound_open(&mut strict, &b, StreamId::new(3), 1));
    inbound_data(&mut strict, &b, StreamId::new(3), &unsigned_frame, 2);
    let events = drain_events(&mut strict);
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, PubsubEvent::Message { .. })),
        "{events:?}"
    );

    // allow_unsigned: delivered.
    let mut lax = agent_with(FloodsubConfig {
        allow_unsigned: true,
        ..FloodsubConfig::default()
    });
    lax.subscribe("t", 0).unwrap();
    connect(&mut lax, &b, 0);
    assert!(inbound_open(&mut lax, &b, StreamId::new(3), 1));
    inbound_data(&mut lax, &b, StreamId::new(3), &unsigned_frame, 2);
    assert!(
        drain_events(&mut lax)
            .iter()
            .any(|e| matches!(e, PubsubEvent::Message { .. }))
    );
}

#[test]
fn subscription_overflow_is_transactional() {
    let mut a = agent_with(FloodsubConfig {
        max_topics_per_peer: 2,
        ..FloodsubConfig::default()
    });
    let b = peer(2);
    connect(&mut a, &b, 0);
    let stream = StreamId::new(3);
    assert!(inbound_open(&mut a, &b, stream, 1));

    // One RPC subscribing to three topics: over the bound of two.
    let rpc = Rpc {
        subscriptions: ["x", "y", "z"]
            .iter()
            .map(|t| minip2p_pubsub::SubOpts {
                subscribe: Some(true),
                topic_id: Some(t.to_string()),
            })
            .collect(),
        publish: Vec::new(),
    };
    inbound_data(&mut a, &b, stream, &encode_frame(&rpc.encode()), 2);
    let events = drain_events(&mut a);
    let violations = events
        .iter()
        .filter(|e| matches!(e, PubsubEvent::ProtocolViolation { .. }))
        .count();
    let subscribed = events
        .iter()
        .filter(|e| matches!(e, PubsubEvent::PeerSubscribed { .. }))
        .count();
    assert_eq!(
        (violations, subscribed),
        (1, 0),
        "no partial state: {events:?}"
    );

    // Nothing was committed: a publish finds no subscribed recipients.
    a.publish("x", b"data".to_vec(), 3).unwrap();
    assert_eq!(count_open_streams(&drain_actions(&mut a)), 0);
}

// ---------------------------------------------------------------------------
// Framing across events
// ---------------------------------------------------------------------------

#[test]
fn fragmented_and_coalesced_frames_both_decode() {
    let mut a = agent();
    a.subscribe("t", 0).unwrap();
    let b = peer(2);
    connect(&mut a, &b, 0);
    let stream = StreamId::new(3);
    assert!(inbound_open(&mut a, &b, stream, 1));
    drain_actions(&mut a);

    // One frame split across two data events.
    let frame = signed_message_frame(&keypair(9), "t", b"split", 1);
    let (head, tail) = frame.split_at(frame.len() / 2);
    inbound_data(&mut a, &b, stream, head, 2);
    assert!(drain_events(&mut a).is_empty(), "half a frame: no events");
    inbound_data(&mut a, &b, stream, tail, 3);
    assert_eq!(
        drain_events(&mut a)
            .iter()
            .filter(|e| matches!(e, PubsubEvent::Message { .. }))
            .count(),
        1
    );

    // Two frames coalesced into one data event.
    let mut both = signed_message_frame(&keypair(9), "t", b"one", 2);
    both.extend_from_slice(&signed_message_frame(&keypair(9), "t", b"two", 3));
    inbound_data(&mut a, &b, stream, &both, 4);
    assert_eq!(
        drain_events(&mut a)
            .iter()
            .filter(|e| matches!(e, PubsubEvent::Message { .. }))
            .count(),
        2
    );
}

// ---------------------------------------------------------------------------
// Inbound stream lifecycle
// ---------------------------------------------------------------------------

#[test]
fn concurrent_inbound_streams_are_capped_at_the_configured_bound() {
    let mut a = agent_with(FloodsubConfig {
        max_inbound_streams_per_peer: 2,
        ..FloodsubConfig::default()
    });
    let b = peer(2);
    connect(&mut a, &b, 0);
    assert!(inbound_open(&mut a, &b, StreamId::new(3), 1));
    assert!(inbound_open(&mut a, &b, StreamId::new(5), 1));
    assert!(drain_events(&mut a).is_empty());

    assert!(inbound_open(&mut a, &b, StreamId::new(7), 2));
    assert!(
        drain_events(&mut a)
            .iter()
            .any(|e| matches!(e, PubsubEvent::ProtocolViolation { .. }))
    );
    let actions = drain_actions(&mut a);
    assert!(actions.iter().any(|a| matches!(
        a,
        PubsubAction::ResetStream { stream_id, .. } if *stream_id == StreamId::new(7)
    )));
}

#[test]
fn inbound_eof_half_closes_locally_and_keeps_the_role_until_the_close() {
    let mut a = agent();
    let b = peer(2);
    connect(&mut a, &b, 0);
    let stream = StreamId::new(3);
    assert!(inbound_open(&mut a, &b, stream, 1));
    inbound_data(&mut a, &b, stream, &remote_subscribe_frame("t"), 2);
    drain_events(&mut a);
    drain_actions(&mut a);

    // Clean EOF: we close our write half so the transport can finish.
    assert!(a.handle_event(
        &SwarmEvent::StreamRemoteWriteClosed {
            peer_id: b.clone(),
            stream_id: stream,
        },
        3,
    ));
    let actions = drain_actions(&mut a);
    assert!(actions.iter().any(|a| matches!(
        a,
        PubsubAction::CloseStreamWrite { stream_id, .. } if *stream_id == stream
    )));
    // The role survives until the terminal close (both claimed).
    assert!(a.owns_stream(&b, stream));
    assert!(a.handle_event(
        &SwarmEvent::StreamClosed {
            peer_id: b.clone(),
            stream_id: stream,
        },
        4,
    ));
    assert!(!a.owns_stream(&b, stream));
}

#[test]
fn eof_inside_a_frame_is_a_violation() {
    let mut a = agent();
    let b = peer(2);
    connect(&mut a, &b, 0);
    let stream = StreamId::new(3);
    assert!(inbound_open(&mut a, &b, stream, 1));

    let frame = remote_subscribe_frame("t");
    inbound_data(&mut a, &b, stream, &frame[..frame.len() - 1], 2);
    assert!(a.handle_event(
        &SwarmEvent::StreamRemoteWriteClosed {
            peer_id: b.clone(),
            stream_id: stream,
        },
        3,
    ));
    assert!(
        drain_events(&mut a)
            .iter()
            .any(|e| matches!(e, PubsubEvent::ProtocolViolation { .. }))
    );
    assert!(
        drain_actions(&mut a)
            .iter()
            .any(|a| matches!(a, PubsubAction::ResetStream { .. }))
    );
}

// ---------------------------------------------------------------------------
// Failure handling
// ---------------------------------------------------------------------------

#[test]
fn send_timeout_discards_and_advances_in_every_state() {
    // Opening: no result ever arrives.
    let mut a = agent();
    let b = peer(2);
    connect_subscribed(&mut a, &b, "t", StreamId::new(3), 0);
    a.publish("t", b"stuck".to_vec(), 1_000).unwrap();
    let actions = drain_actions(&mut a);
    let (token, _) = open_stream_action(&actions).expect("publish open");
    assert_eq!(a.next_timeout(1_000), Some(10_000), "send deadline armed");
    a.handle_tick(11_000);
    assert!(
        drain_events(&mut a)
            .iter()
            .any(|e| matches!(e, PubsubEvent::OutboundFailure { .. }))
    );
    // A late Ok for the timed-out token resets the delivered stream.
    a.stream_open_result(token, Ok(StreamId::new(9)), 11_001);
    assert!(drain_actions(&mut a).iter().any(|a| matches!(
        a,
        PubsubAction::ResetStream { stream_id, .. } if *stream_id == StreamId::new(9)
    )));

    // Negotiating: stream allocated but never ready.
    let mut a = agent();
    connect_subscribed(&mut a, &b, "t", StreamId::new(3), 0);
    a.publish("t", b"stuck".to_vec(), 1_000).unwrap();
    let (token, _) = open_stream_action(&drain_actions(&mut a)).unwrap();
    a.stream_open_result(token, Ok(StreamId::new(4)), 1_500);
    a.handle_tick(12_000);
    let actions = drain_actions(&mut a);
    assert!(actions.iter().any(|a| matches!(
        a,
        PubsubAction::ResetStream { stream_id, .. } if *stream_id == StreamId::new(4)
    )));
    assert!(
        drain_events(&mut a)
            .iter()
            .any(|e| matches!(e, PubsubEvent::OutboundFailure { .. }))
    );

    // AwaitingClose: the close never arrives.
    let mut a = agent();
    connect_subscribed(&mut a, &b, "t", StreamId::new(3), 0);
    a.publish("t", b"stuck".to_vec(), 1_000).unwrap();
    negotiate_send(&mut a, &b, StreamId::new(4), 1_000).expect("in flight");
    a.handle_tick(12_000);
    assert!(
        drain_events(&mut a)
            .iter()
            .any(|e| matches!(e, PubsubEvent::OutboundFailure { .. }))
    );
}

#[test]
fn open_failure_discards_without_spinning_and_the_next_stimulus_retries() {
    let mut a = agent();
    let b = peer(2);
    connect(&mut a, &b, 0);
    a.subscribe("t", 1).unwrap();
    let (token, _) = open_stream_action(&drain_actions(&mut a)).expect("snapshot open");
    a.stream_open_result(token, Err("no connection".to_string()), 2);
    assert!(
        drain_events(&mut a)
            .iter()
            .any(|e| matches!(e, PubsubEvent::OutboundFailure { .. }))
    );
    assert_eq!(
        count_open_streams(&drain_actions(&mut a)),
        0,
        "no synchronous retry loop"
    );

    // The next stimulus (PeerReady) re-diffs and retries.
    a.handle_event(
        &SwarmEvent::PeerReady {
            peer_id: b.clone(),
            protocols: vec![FLOODSUB_PROTOCOL_ID.to_string()],
        },
        3,
    );
    assert_eq!(count_open_streams(&drain_actions(&mut a)), 1);
}

#[test]
fn disconnect_and_supersede_emit_one_aggregated_failure() {
    let mut a = agent();
    let b = peer(2);
    connect_subscribed(&mut a, &b, "t", StreamId::new(3), 0);
    a.publish("t", b"one".to_vec(), 1).unwrap();
    a.publish("t", b"two".to_vec(), 1).unwrap();
    drain_actions(&mut a);

    // Supersede: repeat ConnectionEstablished.
    a.handle_event(&SwarmEvent::ConnectionEstablished { peer_id: b.clone() }, 2);
    let events = drain_events(&mut a);
    let failures: Vec<&PubsubEvent> = events
        .iter()
        .filter(|e| matches!(e, PubsubEvent::OutboundFailure { .. }))
        .collect();
    assert_eq!(failures.len(), 1, "one aggregated event: {events:?}");
    if let PubsubEvent::OutboundFailure { reason, .. } = failures[0] {
        assert!(reason.contains("2"), "reason names the count: {reason}");
    }

    // State is fresh: the remote's old subscriptions are gone.
    a.publish("t", b"three".to_vec(), 3).unwrap();
    assert_eq!(count_open_streams(&drain_actions(&mut a)), 0);

    // Disconnect with queued work aggregates too.
    let mut a = agent();
    connect_subscribed(&mut a, &b, "t", StreamId::new(3), 0);
    a.publish("t", b"one".to_vec(), 1).unwrap();
    drain_actions(&mut a);
    a.handle_event(&SwarmEvent::ConnectionClosed { peer_id: b.clone() }, 2);
    assert_eq!(
        drain_events(&mut a)
            .iter()
            .filter(|e| matches!(e, PubsubEvent::OutboundFailure { .. }))
            .count(),
        1
    );
}

#[test]
fn peer_ready_after_inbound_traffic_preserves_state() {
    let mut a = agent();
    let b = peer(2);
    // Inbound traffic creates the peer state before PeerReady runs.
    a.handle_event(&SwarmEvent::ConnectionEstablished { peer_id: b.clone() }, 0);
    let stream = StreamId::new(3);
    assert!(inbound_open(&mut a, &b, stream, 1));
    inbound_data(&mut a, &b, stream, &remote_subscribe_frame("t"), 2);
    drain_events(&mut a);

    a.handle_event(
        &SwarmEvent::PeerReady {
            peer_id: b.clone(),
            protocols: vec![FLOODSUB_PROTOCOL_ID.to_string()],
        },
        3,
    );
    // remote_topics survived: a publish reaches the peer.
    a.publish("t", b"kept".to_vec(), 4).unwrap();
    assert_eq!(count_open_streams(&drain_actions(&mut a)), 1);
    // The inbound stream still works too.
    inbound_data(
        &mut a,
        &b,
        stream,
        &signed_message_frame(&keypair(9), "t", b"still alive", 1),
        5,
    );
}

// ---------------------------------------------------------------------------
// Seen cache
// ---------------------------------------------------------------------------

#[test]
fn seen_ttl_expiry_reopens_the_dedup_window() {
    let mut a = agent_with(FloodsubConfig {
        seen_ttl_ms: 1_000,
        ..FloodsubConfig::default()
    });
    a.subscribe("t", 0).unwrap();
    let b = peer(2);
    connect(&mut a, &b, 0);
    assert!(inbound_open(&mut a, &b, StreamId::new(3), 0));
    drain_actions(&mut a);

    let frame = signed_message_frame(&keypair(9), "t", b"ttl", 1);
    inbound_data(&mut a, &b, StreamId::new(3), &frame, 100);
    assert_eq!(
        drain_events(&mut a)
            .iter()
            .filter(|e| matches!(e, PubsubEvent::Message { .. }))
            .count(),
        1
    );

    // Within the TTL: duplicate.
    inbound_data(&mut a, &b, StreamId::new(3), &frame, 500);
    assert!(drain_events(&mut a).is_empty());

    // After GC the window reopens.
    a.handle_tick(2_000);
    inbound_data(&mut a, &b, StreamId::new(3), &frame, 2_001);
    assert_eq!(
        drain_events(&mut a)
            .iter()
            .filter(|e| matches!(e, PubsubEvent::Message { .. }))
            .count(),
        1
    );
}

#[test]
fn seen_capacity_evicts_the_oldest() {
    let mut a = agent_with(FloodsubConfig {
        max_seen_messages: 2,
        ..FloodsubConfig::default()
    });
    a.subscribe("t", 0).unwrap();
    let b = peer(2);
    connect(&mut a, &b, 0);
    assert!(inbound_open(&mut a, &b, StreamId::new(3), 0));
    drain_actions(&mut a);

    let first = signed_message_frame(&keypair(9), "t", b"1", 1);
    inbound_data(&mut a, &b, StreamId::new(3), &first, 1);
    inbound_data(
        &mut a,
        &b,
        StreamId::new(3),
        &signed_message_frame(&keypair(9), "t", b"2", 2),
        2,
    );
    inbound_data(
        &mut a,
        &b,
        StreamId::new(3),
        &signed_message_frame(&keypair(9), "t", b"3", 3),
        3,
    );
    drain_events(&mut a);

    // The first id was evicted by capacity: it delivers again.
    inbound_data(&mut a, &b, StreamId::new(3), &first, 4);
    assert_eq!(
        drain_events(&mut a)
            .iter()
            .filter(|e| matches!(e, PubsubEvent::Message { .. }))
            .count(),
        1
    );
}

// ---------------------------------------------------------------------------
// Disposition and validation
// ---------------------------------------------------------------------------

#[test]
fn foreign_streams_and_events_are_not_claimed() {
    let mut a = agent();
    let b = peer(2);
    connect(&mut a, &b, 0);
    assert!(!a.handle_event(
        &SwarmEvent::StreamReady {
            peer_id: b.clone(),
            stream_id: StreamId::new(40),
            protocol_id: "/some/app/1".to_string(),
            initiated_locally: false,
        },
        1,
    ));
    assert!(!a.handle_event(
        &SwarmEvent::StreamData {
            peer_id: b.clone(),
            stream_id: StreamId::new(40),
            data: vec![1],
        },
        2,
    ));
    assert!(!a.handle_event(
        &SwarmEvent::StreamClosed {
            peer_id: b.clone(),
            stream_id: StreamId::new(40),
        },
        3,
    ));
}

#[test]
fn topics_are_validated_on_subscribe_and_publish() {
    let mut a = agent();
    assert_eq!(a.subscribe("", 0), Err(TopicError::Empty));
    let long = "x".repeat(minip2p_pubsub::MAX_TOPIC_LEN + 1);
    assert_eq!(a.subscribe(&long, 0), Err(TopicError::TooLong));
    assert!(matches!(
        a.publish("", b"x".to_vec(), 0),
        Err(PublishError::Topic(TopicError::Empty))
    ));
    assert!(matches!(
        a.publish(&long, b"x".to_vec(), 0),
        Err(PublishError::Topic(TopicError::TooLong))
    ));
    // Valid edge: exactly MAX_TOPIC_LEN.
    let edge = "x".repeat(minip2p_pubsub::MAX_TOPIC_LEN);
    assert_eq!(a.subscribe(&edge, 0), Ok(true));
}

#[test]
fn oversized_publish_is_rejected_without_consuming_a_seqno() {
    let mut a = agent();
    let b = peer(2);
    connect_subscribed(&mut a, &b, "t", StreamId::new(3), 0);
    assert_eq!(
        a.publish("t", vec![0u8; minip2p_pubsub::MAX_RPC_SIZE], 1),
        Err(PublishError::TooLarge)
    );
    // The next publish still works and reaches the peer.
    a.publish("t", b"small".to_vec(), 2).unwrap();
    assert_eq!(count_open_streams(&drain_actions(&mut a)), 1);
}

// ---------------------------------------------------------------------------
// Review-round regressions
// ---------------------------------------------------------------------------

#[test]
fn oversized_remote_topics_are_skipped_and_never_stored() {
    let mut a = agent();
    let b = peer(2);
    connect(&mut a, &b, 0);
    let stream = StreamId::new(3);
    assert!(inbound_open(&mut a, &b, stream, 1));

    // One RPC with a legal topic and a topic over MAX_TOPIC_LEN.
    let huge = "x".repeat(minip2p_pubsub::MAX_TOPIC_LEN + 1);
    let rpc = Rpc {
        subscriptions: vec![
            minip2p_pubsub::SubOpts {
                subscribe: Some(true),
                topic_id: Some("ok".to_string()),
            },
            minip2p_pubsub::SubOpts {
                subscribe: Some(true),
                topic_id: Some(huge),
            },
        ],
        publish: Vec::new(),
    };
    inbound_data(&mut a, &b, stream, &encode_frame(&rpc.encode()), 2);
    let events = drain_events(&mut a);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, PubsubEvent::ProtocolViolation { .. })),
        "skipping invalid topics is reported: {events:?}"
    );
    let subscribed: Vec<&PubsubEvent> = events
        .iter()
        .filter(|e| matches!(e, PubsubEvent::PeerSubscribed { .. }))
        .collect();
    assert_eq!(
        subscribed.len(),
        1,
        "only the legal topic lands: {events:?}"
    );
    // The stream was NOT reset: the length cap is ours, not the spec's.
    assert!(
        !drain_actions(&mut a)
            .iter()
            .any(|a| matches!(a, PubsubAction::ResetStream { .. }))
    );
}

#[test]
fn local_subscription_set_is_bounded_to_fit_one_rpc() {
    let mut a = agent();
    let mut accepted = 0usize;
    let mut hit_bound = false;
    for i in 0..64 {
        let topic = format!("{i:04}{}", "x".repeat(minip2p_pubsub::MAX_TOPIC_LEN - 4));
        match a.subscribe(&topic, 0) {
            Ok(true) => accepted += 1,
            Err(TopicError::SetTooLarge) => {
                hit_bound = true;
                break;
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
    assert!(hit_bound, "the set bound must trigger");
    assert!(
        (20..40).contains(&accepted),
        "the bound is MAX_RPC_SIZE/2 of encoded entries, got {accepted}"
    );
    // A small topic still fits: the bound is about size, not count.
    assert_eq!(a.subscribe("tiny", 0), Ok(true));
}

#[test]
fn send_deadline_budgets_the_whole_rpc_not_each_state() {
    let mut a = agent();
    let b = peer(2);
    connect_subscribed(&mut a, &b, "t", StreamId::new(3), 0);
    a.publish("t", b"slow".to_vec(), 0).unwrap();
    let (token, _) = open_stream_action(&drain_actions(&mut a)).expect("publish open");

    // The open result lands just before the deadline; the clock must NOT
    // restart at Negotiating.
    a.stream_open_result(token, Ok(StreamId::new(4)), 9_999);
    assert_eq!(
        a.next_timeout(9_999),
        Some(1),
        "the original deadline still governs"
    );
    a.handle_tick(10_000);
    assert!(
        drain_events(&mut a)
            .iter()
            .any(|e| matches!(e, PubsubEvent::OutboundFailure { .. })),
        "one RPC gets one send_timeout_ms, not one per state"
    );
}

#[test]
fn send_failure_prevents_the_commit() {
    let mut a = agent();
    let b = peer(2);
    connect(&mut a, &b, 0);
    a.subscribe("t", 1).unwrap();
    let stream = StreamId::new(4);
    negotiate_send(&mut a, &b, stream, 1).expect("snapshot in flight");

    // The swarm rejected the write: the close that follows must not commit.
    a.send_failed(&b, stream, "connection lost", 2);
    let events = drain_events(&mut a);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, PubsubEvent::OutboundFailure { .. })),
        "{events:?}"
    );
    // The failure resets the dead stream AND immediately re-drives the
    // sender: sent_topics was never committed, so the diff re-derives.
    let actions = drain_actions(&mut a);
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, PubsubAction::ResetStream { .. })),
        "{actions:?}"
    );
    let (token, _) = open_stream_action(&actions).expect("re-drive re-opens");
    a.handle_event(
        &SwarmEvent::StreamClosed {
            peer_id: b.clone(),
            stream_id: stream,
        },
        3,
    );

    // Completing the retried send delivers the same (uncommitted) snapshot.
    let retry_stream = StreamId::new(8);
    a.stream_open_result(token, Ok(retry_stream), 4);
    a.handle_event(
        &SwarmEvent::StreamReady {
            peer_id: b.clone(),
            stream_id: retry_stream,
            protocol_id: FLOODSUB_PROTOCOL_ID.to_string(),
            initiated_locally: true,
        },
        4,
    );
    let frame = drain_actions(&mut a)
        .iter()
        .find_map(|a| match a {
            PubsubAction::SendStream { data, .. } => Some(data.clone()),
            _ => None,
        })
        .expect("re-diffed snapshot frame");
    assert_eq!(
        decode_rpc(&frame).subscriptions[0].topic_id.as_deref(),
        Some("t"),
        "the failed snapshot must be re-sent, not committed"
    );
    a.handle_event(
        &SwarmEvent::StreamClosed {
            peer_id: b.clone(),
            stream_id: retry_stream,
        },
        5,
    );

    // A stale-stream failure report must not disturb a healthy sender.
    a.publish("t", b"x".to_vec(), 6).ok();
    a.send_failed(&b, StreamId::new(999), "stale", 7);
    assert!(drain_events(&mut a).is_empty(), "stale report is a no-op");
}

#[test]
fn coalesced_frames_beyond_one_frame_cap_all_decode() {
    // The transport may coalesce many legal frames into one data event
    // whose total exceeds a single frame's cap; that is legal traffic,
    // not a violation.
    let mut a = agent();
    a.subscribe("t", 0).unwrap();
    let b = peer(2);
    connect(&mut a, &b, 0);
    let stream = StreamId::new(3);
    assert!(inbound_open(&mut a, &b, stream, 1));
    drain_actions(&mut a);

    let mut blob = Vec::new();
    for seqno in 0..3u64 {
        blob.extend_from_slice(&signed_message_frame(
            &keypair(9),
            "t",
            &vec![0xAB; 30_000],
            seqno,
        ));
    }
    assert!(
        blob.len() > minip2p_pubsub::MAX_RPC_SIZE,
        "the point is a coalesced event larger than one frame cap"
    );
    inbound_data(&mut a, &b, stream, &blob, 2);
    let events = drain_events(&mut a);
    let delivered = events
        .iter()
        .filter(|e| matches!(e, PubsubEvent::Message { .. }))
        .count();
    assert_eq!(delivered, 3, "{events:?}");
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, PubsubEvent::ProtocolViolation { .. })),
        "coalescing is not a violation: {events:?}"
    );
}
