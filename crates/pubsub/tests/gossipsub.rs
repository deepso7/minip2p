//! Scripted no-I/O tests for the long-lived gossipsub router.

use minip2p_core::PeerId;
use minip2p_identity::Ed25519Keypair;
use minip2p_pubsub::{
    ControlGraft, ControlIHave, ControlIWant, ControlMessage, ControlPrune, FrameDecode,
    GossipsubAgent, GossipsubConfig, MESHSUB_PROTOCOL_ID_V10, MESHSUB_PROTOCOL_ID_V11,
    PubsubAction, PubsubEvent, RawMessage, Rpc, SubOpts, decode_frame, encode_frame,
};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{ConnectionId, StreamId};

fn keypair(seed: u8) -> Ed25519Keypair {
    Ed25519Keypair::from_secret_key_bytes([seed; 32])
}

fn peer(seed: u8) -> PeerId {
    keypair(seed).peer_id()
}

fn agent_with(config: GossipsubConfig) -> GossipsubAgent {
    GossipsubAgent::new(keypair(1), config, 100, 7)
}

fn agent() -> GossipsubAgent {
    agent_with(GossipsubConfig::default())
}

fn drain_actions(agent: &mut GossipsubAgent) -> Vec<PubsubAction> {
    let mut actions = Vec::new();
    while let Some(action) = agent.poll_action() {
        actions.push(action);
    }
    actions
}

fn drain_events(agent: &mut GossipsubAgent) -> Vec<PubsubEvent> {
    let mut events = Vec::new();
    while let Some(event) = agent.poll_event() {
        events.push(event);
    }
    events
}

fn connect(agent: &mut GossipsubAgent, peer: &PeerId, protocols: &[&str], now_ms: u64) {
    agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            peer_id: peer.clone(),
            conn_id: ConnectionId::new(1),
        },
        now_ms,
    );
    agent.handle_event(
        &SwarmEvent::PeerReady {
            peer_id: peer.clone(),
            protocols: protocols.iter().map(|id| (*id).to_string()).collect(),
        },
        now_ms,
    );
}

fn make_ready(
    agent: &mut GossipsubAgent,
    peer: &PeerId,
    stream_id: StreamId,
    negotiated: &str,
    now_ms: u64,
) -> Vec<PubsubAction> {
    let actions = drain_actions(agent);
    let (token, protocol_id) = actions
        .iter()
        .find_map(|action| match action {
            PubsubAction::OpenStream {
                token, protocol_id, ..
            } => Some((*token, protocol_id.clone())),
            _ => None,
        })
        .expect("outbound open");
    assert!(protocol_id == MESHSUB_PROTOCOL_ID_V10 || protocol_id == MESHSUB_PROTOCOL_ID_V11);
    agent.stream_open_result(peer, token, Ok(stream_id), now_ms);
    assert!(agent.handle_event(
        &SwarmEvent::StreamReady {
            peer_id: peer.clone(),
            conn_id: ConnectionId::new(1),
            stream_id,
            protocol_id: negotiated.to_string(),
            initiated_locally: true,
        },
        now_ms,
    ));
    drain_actions(agent)
}

fn inbound_open(agent: &mut GossipsubAgent, peer: &PeerId, stream_id: StreamId, now_ms: u64) {
    assert!(agent.handle_event(
        &SwarmEvent::StreamReady {
            peer_id: peer.clone(),
            conn_id: ConnectionId::new(1),
            stream_id,
            protocol_id: MESHSUB_PROTOCOL_ID_V11.to_string(),
            initiated_locally: false,
        },
        now_ms,
    ));
}

fn inbound_rpc(
    agent: &mut GossipsubAgent,
    peer: &PeerId,
    stream_id: StreamId,
    rpc: Rpc,
    now_ms: u64,
) {
    assert!(agent.handle_event(
        &SwarmEvent::StreamData {
            peer_id: peer.clone(),
            conn_id: ConnectionId::new(1),
            stream_id,
            data: encode_frame(&rpc.encode()),
        },
        now_ms,
    ));
}

fn remote_subscribe(
    agent: &mut GossipsubAgent,
    peer: &PeerId,
    stream_id: StreamId,
    topic: &str,
    now_ms: u64,
) {
    inbound_rpc(
        agent,
        peer,
        stream_id,
        Rpc {
            subscriptions: vec![SubOpts {
                subscribe: Some(true),
                topic_id: Some(topic.to_string()),
            }],
            publish: Vec::new(),
            control: None,
        },
        now_ms,
    );
}

fn sent(actions: &[PubsubAction]) -> Option<(Vec<u8>, minip2p_pubsub::PubsubToken, StreamId)> {
    actions.iter().find_map(|action| match action {
        PubsubAction::SendStream {
            data,
            token,
            stream_id,
            ..
        } => Some((data.clone(), *token, *stream_id)),
        _ => None,
    })
}

fn ack(agent: &mut GossipsubAgent, peer: &PeerId, actions: &[PubsubAction], now_ms: u64) {
    let (_, token, stream_id) = sent(actions).expect("send action");
    agent.send_result(peer, stream_id, token, Ok(()), now_ms);
}

fn decode_rpc(frame: &[u8]) -> Rpc {
    let FrameDecode::Complete { payload, consumed } = decode_frame(frame) else {
        panic!("complete frame expected")
    };
    assert_eq!(consumed, frame.len());
    Rpc::decode(payload).expect("valid emitted RPC")
}

#[test]
fn build_time_subscribe_does_not_arm_heartbeat() {
    let mut agent = agent();
    agent.subscribe("room", 0).unwrap();
    assert_eq!(agent.next_timeout(50_000), None);

    let remote = peer(2);
    connect(
        &mut agent,
        &remote,
        &[MESHSUB_PROTOCOL_ID_V11, MESHSUB_PROTOCOL_ID_V10],
        50_000,
    );
    assert_eq!(agent.next_timeout(50_000), Some(1_000));
    assert!(agent.mesh_peers("room").is_empty());
}

#[test]
fn prefers_v11_but_encodes_for_the_actually_negotiated_version() {
    let mut agent = agent();
    agent.subscribe("room", 0).unwrap();
    let remote = peer(2);
    connect(
        &mut agent,
        &remote,
        &[MESHSUB_PROTOCOL_ID_V10, MESHSUB_PROTOCOL_ID_V11],
        1,
    );
    let open = drain_actions(&mut agent);
    assert!(open.iter().any(|action| matches!(
        action,
        PubsubAction::OpenStream { protocol_id, .. } if protocol_id == MESHSUB_PROTOCOL_ID_V11
    )));
    // Put the action back through the manual ready sequence using its token.
    let token = open
        .iter()
        .find_map(|action| match action {
            PubsubAction::OpenStream { token, .. } => Some(*token),
            _ => None,
        })
        .unwrap();
    let stream = StreamId::new(4);
    agent.stream_open_result(&remote, token, Ok(stream), 1);
    agent.handle_event(
        &SwarmEvent::StreamReady {
            peer_id: remote.clone(),
            conn_id: ConnectionId::new(1),
            stream_id: stream,
            protocol_id: MESHSUB_PROTOCOL_ID_V10.to_string(),
            initiated_locally: true,
        },
        1,
    );
    let subscription = drain_actions(&mut agent);
    ack(&mut agent, &remote, &subscription, 1);
    drain_actions(&mut agent);

    inbound_open(&mut agent, &remote, StreamId::new(5), 2);
    remote_subscribe(&mut agent, &remote, StreamId::new(5), "room", 2);
    drain_events(&mut agent);
    agent.handle_tick(1_001);
    let graft = drain_actions(&mut agent);
    ack(&mut agent, &remote, &graft, 1_001);
    drain_actions(&mut agent);
    agent.unsubscribe("room", 1_002);
    let unsubscribe = drain_actions(&mut agent);
    ack(&mut agent, &remote, &unsubscribe, 1_002);
    let prune = drain_actions(&mut agent);
    let rpc = decode_rpc(&sent(&prune).unwrap().0);
    assert_eq!(rpc.control.unwrap().prune[0].backoff, None);
}

#[test]
fn join_promotes_known_peer_and_sender_stays_long_lived() {
    let mut agent = agent();
    let remote = peer(2);
    connect(&mut agent, &remote, &[MESHSUB_PROTOCOL_ID_V11], 0);
    assert!(
        make_ready(
            &mut agent,
            &remote,
            StreamId::new(4),
            MESHSUB_PROTOCOL_ID_V11,
            0
        )
        .is_empty()
    );
    inbound_open(&mut agent, &remote, StreamId::new(5), 0);
    remote_subscribe(&mut agent, &remote, StreamId::new(5), "room", 0);
    drain_events(&mut agent);

    agent.subscribe("room", 1).unwrap();
    assert_eq!(agent.mesh_peers("room"), vec![remote.clone()]);
    let subscription = drain_actions(&mut agent);
    let rpc = decode_rpc(&sent(&subscription).unwrap().0);
    assert_eq!(rpc.subscriptions[0].subscribe, Some(true));
    assert!(
        !subscription
            .iter()
            .any(|action| matches!(action, PubsubAction::CloseStreamWrite { .. }))
    );
    ack(&mut agent, &remote, &subscription, 1);
    let graft = drain_actions(&mut agent);
    assert_eq!(
        decode_rpc(&sent(&graft).unwrap().0).control.unwrap().graft[0]
            .topic_id
            .as_deref(),
        Some("room")
    );
    assert!(
        !graft
            .iter()
            .any(|action| matches!(action, PubsubAction::OpenStream { .. }))
    );

    inbound_rpc(
        &mut agent,
        &remote,
        StreamId::new(5),
        Rpc {
            subscriptions: vec![SubOpts {
                subscribe: Some(false),
                topic_id: Some("room".to_string()),
            }],
            ..Rpc::default()
        },
        2,
    );
    assert!(
        agent.mesh_peers("room").is_empty(),
        "remote unsubscribe immediately removes its mesh membership"
    );
}

#[test]
fn unknown_graft_is_ignored_without_amplification() {
    let mut agent = agent();
    let remote = peer(2);
    connect(&mut agent, &remote, &[MESHSUB_PROTOCOL_ID_V11], 0);
    assert!(
        make_ready(
            &mut agent,
            &remote,
            StreamId::new(4),
            MESHSUB_PROTOCOL_ID_V11,
            0,
        )
        .is_empty()
    );
    inbound_open(&mut agent, &remote, StreamId::new(5), 0);
    inbound_rpc(
        &mut agent,
        &remote,
        StreamId::new(5),
        Rpc {
            control: Some(ControlMessage {
                graft: vec![ControlGraft {
                    topic_id: Some("unknown".to_string()),
                }],
                ..ControlMessage::default()
            }),
            ..Rpc::default()
        },
        1,
    );
    assert!(agent.mesh_peers("unknown").is_empty());
    assert!(drain_actions(&mut agent).is_empty());
}

#[test]
fn empty_mesh_publish_falls_back_without_grafting() {
    let mut agent = agent();
    agent.subscribe("room", 0).unwrap();
    let remote = peer(2);
    connect(&mut agent, &remote, &[MESHSUB_PROTOCOL_ID_V11], 1);
    let subscription = make_ready(
        &mut agent,
        &remote,
        StreamId::new(4),
        MESHSUB_PROTOCOL_ID_V11,
        1,
    );
    ack(&mut agent, &remote, &subscription, 1);
    drain_actions(&mut agent);
    inbound_open(&mut agent, &remote, StreamId::new(5), 1);
    remote_subscribe(&mut agent, &remote, StreamId::new(5), "room", 1);
    drain_events(&mut agent);

    agent
        .publish("room", b"before heartbeat".to_vec(), 2)
        .unwrap();
    assert!(agent.mesh_peers("room").is_empty());
    let publish = drain_actions(&mut agent);
    let rpc = decode_rpc(&sent(&publish).unwrap().0);
    assert_eq!(
        rpc.publish[0].data.as_deref(),
        Some(&b"before heartbeat"[..])
    );
    assert!(rpc.control.is_none(), "fallback does not implicitly GRAFT");
}

#[test]
fn heartbeat_repairs_mesh_and_received_prune_blocks_regraft() {
    let config = GossipsubConfig {
        d: 1,
        d_low: 1,
        d_high: 2,
        ..GossipsubConfig::default()
    };
    let mut agent = agent_with(config);
    agent.subscribe("room", 0).unwrap();
    let remote = peer(2);
    connect(&mut agent, &remote, &[MESHSUB_PROTOCOL_ID_V11], 10);
    let subscription = make_ready(
        &mut agent,
        &remote,
        StreamId::new(4),
        MESHSUB_PROTOCOL_ID_V11,
        10,
    );
    ack(&mut agent, &remote, &subscription, 10);
    drain_actions(&mut agent);
    inbound_open(&mut agent, &remote, StreamId::new(5), 10);
    remote_subscribe(&mut agent, &remote, StreamId::new(5), "room", 10);
    drain_events(&mut agent);

    agent.handle_tick(1_010);
    assert_eq!(agent.mesh_peers("room"), vec![remote.clone()]);
    let graft = drain_actions(&mut agent);
    ack(&mut agent, &remote, &graft, 1_010);
    drain_actions(&mut agent);

    inbound_rpc(
        &mut agent,
        &remote,
        StreamId::new(5),
        Rpc {
            control: Some(ControlMessage {
                prune: vec![ControlPrune {
                    topic_id: Some("room".to_string()),
                    backoff: Some(120),
                    peers: Vec::new(),
                }],
                ..ControlMessage::default()
            }),
            ..Rpc::default()
        },
        1_011,
    );
    assert!(agent.mesh_peers("room").is_empty());
    agent.handle_tick(2_010);
    assert!(agent.mesh_peers("room").is_empty());
}

#[test]
fn ihave_deduplicates_and_obeys_per_heartbeat_budgets() {
    let config = GossipsubConfig {
        max_ihave_messages_per_heartbeat: 1,
        max_iwant_ids_per_heartbeat: 2,
        ..GossipsubConfig::default()
    };
    let mut agent = agent_with(config);
    let remote = peer(2);
    connect(&mut agent, &remote, &[MESHSUB_PROTOCOL_ID_V11], 0);
    make_ready(
        &mut agent,
        &remote,
        StreamId::new(4),
        MESHSUB_PROTOCOL_ID_V11,
        0,
    );
    inbound_open(&mut agent, &remote, StreamId::new(5), 0);
    let ihave = |ids: Vec<Vec<u8>>| Rpc {
        control: Some(ControlMessage {
            ihave: vec![ControlIHave {
                topic_id: Some("room".to_string()),
                message_ids: ids,
            }],
            ..ControlMessage::default()
        }),
        ..Rpc::default()
    };
    inbound_rpc(
        &mut agent,
        &remote,
        StreamId::new(5),
        ihave(vec![vec![1], vec![1], vec![2], vec![3]]),
        1,
    );
    let want = drain_actions(&mut agent);
    let ids = &decode_rpc(&sent(&want).unwrap().0).control.unwrap().iwant[0].message_ids;
    assert_eq!(ids, &vec![vec![1], vec![2]]);
    ack(&mut agent, &remote, &want, 1);
    drain_actions(&mut agent);

    inbound_rpc(
        &mut agent,
        &remote,
        StreamId::new(5),
        ihave(vec![vec![4]]),
        2,
    );
    assert!(drain_actions(&mut agent).is_empty());
}

#[test]
fn iwant_serves_cached_message_bytes() {
    let mut agent = agent();
    let remote = peer(2);
    connect(&mut agent, &remote, &[MESHSUB_PROTOCOL_ID_V11], 0);
    assert!(
        make_ready(
            &mut agent,
            &remote,
            StreamId::new(4),
            MESHSUB_PROTOCOL_ID_V11,
            0,
        )
        .is_empty()
    );
    inbound_open(&mut agent, &remote, StreamId::new(5), 0);
    agent.publish("room", b"cached".to_vec(), 1).unwrap();
    assert!(drain_actions(&mut agent).is_empty(), "no topic peers");

    let mut id = agent.local_peer_id().to_bytes();
    id.extend_from_slice(&100u64.to_be_bytes());
    inbound_rpc(
        &mut agent,
        &remote,
        StreamId::new(5),
        Rpc {
            control: Some(ControlMessage {
                iwant: vec![ControlIWant {
                    message_ids: vec![id],
                }],
                ..ControlMessage::default()
            }),
            ..Rpc::default()
        },
        2,
    );
    let served = drain_actions(&mut agent);
    let rpc = decode_rpc(&sent(&served).unwrap().0);
    assert_eq!(rpc.publish.len(), 1);
    assert_eq!(rpc.publish[0].data.as_deref(), Some(&b"cached"[..]));
}

#[test]
fn two_publishes_share_stream_and_failed_second_send_retries_in_order() {
    let mut agent = agent();
    let remote = peer(2);
    connect(&mut agent, &remote, &[MESHSUB_PROTOCOL_ID_V11], 0);
    make_ready(
        &mut agent,
        &remote,
        StreamId::new(4),
        MESHSUB_PROTOCOL_ID_V11,
        0,
    );
    inbound_open(&mut agent, &remote, StreamId::new(5), 0);
    remote_subscribe(&mut agent, &remote, StreamId::new(5), "room", 0);
    drain_events(&mut agent);

    agent.publish("room", b"one".to_vec(), 1).unwrap();
    agent.publish("room", b"two".to_vec(), 1).unwrap();
    let first = drain_actions(&mut agent);
    assert_eq!(
        decode_rpc(&sent(&first).unwrap().0).publish[0]
            .data
            .as_deref(),
        Some(&b"one"[..])
    );
    assert!(
        !first
            .iter()
            .any(|action| matches!(action, PubsubAction::OpenStream { .. }))
    );
    ack(&mut agent, &remote, &first, 2);
    let second = drain_actions(&mut agent);
    let (_, second_token, stream_id) = sent(&second).unwrap();
    assert_eq!(
        decode_rpc(&sent(&second).unwrap().0).publish[0]
            .data
            .as_deref(),
        Some(&b"two"[..])
    );
    agent.send_result(
        &remote,
        stream_id,
        second_token,
        Err("blocked".to_string()),
        2,
    );
    let reset = drain_actions(&mut agent);
    assert_eq!(
        reset
            .iter()
            .filter(|action| matches!(action, PubsubAction::ResetStream { .. }))
            .count(),
        1
    );
    agent.send_result(&remote, stream_id, second_token, Ok(()), 3);
    assert!(drain_actions(&mut agent).is_empty(), "late result is stale");

    agent.handle_tick(1_000);
    let retry = make_ready(
        &mut agent,
        &remote,
        StreamId::new(8),
        MESHSUB_PROTOCOL_ID_V11,
        1_000,
    );
    assert_eq!(
        decode_rpc(&sent(&retry).unwrap().0).publish[0]
            .data
            .as_deref(),
        Some(&b"two"[..])
    );
}

#[test]
fn stream_reopen_resyncs_an_acked_unsubscribe() {
    let mut agent = agent();
    agent.subscribe("room", 0).unwrap();
    let remote = peer(2);
    connect(&mut agent, &remote, &[MESHSUB_PROTOCOL_ID_V11], 10);
    let subscribed = make_ready(
        &mut agent,
        &remote,
        StreamId::new(4),
        MESHSUB_PROTOCOL_ID_V11,
        10,
    );
    ack(&mut agent, &remote, &subscribed, 10);
    drain_actions(&mut agent);
    agent.unsubscribe("room", 11);
    let unsubscribed = drain_actions(&mut agent);
    ack(&mut agent, &remote, &unsubscribed, 11);
    drain_actions(&mut agent);
    agent.handle_event(
        &SwarmEvent::StreamClosed {
            peer_id: remote.clone(),
            conn_id: ConnectionId::new(1),
            stream_id: StreamId::new(4),
        },
        12,
    );
    agent.handle_tick(1_010);
    let resync = make_ready(
        &mut agent,
        &remote,
        StreamId::new(8),
        MESHSUB_PROTOCOL_ID_V11,
        1_010,
    );
    let rpc = decode_rpc(&sent(&resync).unwrap().0);
    assert_eq!(rpc.subscriptions.len(), 1);
    assert_eq!(rpc.subscriptions[0].subscribe, Some(false));
    assert_eq!(rpc.subscriptions[0].topic_id.as_deref(), Some("room"));
}

#[test]
fn valid_message_delivers_once_and_invalid_signature_never_delivers() {
    let mut agent = agent();
    agent.subscribe("room", 0).unwrap();
    let remote = peer(2);
    connect(&mut agent, &remote, &[MESHSUB_PROTOCOL_ID_V11], 0);
    let subscription = make_ready(
        &mut agent,
        &remote,
        StreamId::new(4),
        MESHSUB_PROTOCOL_ID_V11,
        0,
    );
    ack(&mut agent, &remote, &subscription, 0);
    drain_actions(&mut agent);
    inbound_open(&mut agent, &remote, StreamId::new(5), 0);
    let signer = keypair(9);
    let valid = RawMessage::build_signed(&signer, "room", b"hello".to_vec(), 1);
    inbound_rpc(
        &mut agent,
        &remote,
        StreamId::new(5),
        Rpc {
            publish: vec![valid.clone(), valid],
            ..Rpc::default()
        },
        1,
    );
    assert_eq!(
        drain_events(&mut agent)
            .into_iter()
            .filter(|event| matches!(event, PubsubEvent::Message { .. }))
            .count(),
        1
    );

    let mut invalid = RawMessage::build_signed(&signer, "room", b"bad".to_vec(), 2);
    invalid.signature.as_mut().unwrap()[0] ^= 1;
    invalid.raw = Vec::new();
    inbound_rpc(
        &mut agent,
        &remote,
        StreamId::new(5),
        Rpc {
            publish: vec![invalid],
            ..Rpc::default()
        },
        2,
    );
    let events = drain_events(&mut agent);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, PubsubEvent::ProtocolViolation { .. }))
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, PubsubEvent::Message { .. }))
    );
}

#[test]
fn v11_leave_prune_carries_backoff() {
    let mut agent = agent();
    agent.subscribe("room", 0).unwrap();
    let remote = peer(2);
    connect(&mut agent, &remote, &[MESHSUB_PROTOCOL_ID_V11], 1);
    let subscription = make_ready(
        &mut agent,
        &remote,
        StreamId::new(4),
        MESHSUB_PROTOCOL_ID_V11,
        1,
    );
    ack(&mut agent, &remote, &subscription, 1);
    drain_actions(&mut agent);
    inbound_open(&mut agent, &remote, StreamId::new(5), 1);
    inbound_rpc(
        &mut agent,
        &remote,
        StreamId::new(5),
        Rpc {
            control: Some(ControlMessage {
                graft: vec![ControlGraft {
                    topic_id: Some("room".to_string()),
                }],
                ..ControlMessage::default()
            }),
            ..Rpc::default()
        },
        2,
    );
    assert_eq!(agent.mesh_peers("room"), vec![remote.clone()]);

    agent.unsubscribe("room", 3);
    let unsubscribe = drain_actions(&mut agent);
    ack(&mut agent, &remote, &unsubscribe, 3);
    let prune = drain_actions(&mut agent);
    assert_eq!(
        decode_rpc(&sent(&prune).unwrap().0).control.unwrap().prune[0].backoff,
        Some(10)
    );
}

#[test]
fn large_subscription_resync_is_split_without_dropping_entries() {
    let mut agent = agent();
    for index in 0..80 {
        let topic = format!("{index:02}-{}", "x".repeat(1_000));
        agent.subscribe(&topic, 0).unwrap();
    }
    let remote = peer(2);
    connect(&mut agent, &remote, &[MESHSUB_PROTOCOL_ID_V11], 1);
    let mut actions = make_ready(
        &mut agent,
        &remote,
        StreamId::new(4),
        MESHSUB_PROTOCOL_ID_V11,
        1,
    );
    let mut announced = 0;
    while let Some((frame, _, _)) = sent(&actions) {
        let FrameDecode::Complete { payload, .. } = decode_frame(&frame) else {
            panic!("complete frame")
        };
        assert!(payload.len() <= minip2p_pubsub::MAX_RPC_SIZE);
        announced += Rpc::decode(payload).unwrap().subscriptions.len();
        ack(&mut agent, &remote, &actions, 1);
        actions = drain_actions(&mut agent);
    }
    assert_eq!(announced, 80);
}
