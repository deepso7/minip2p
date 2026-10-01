//! Shared gossipsub bench fixtures: a local agent whose peers are joined
//! through real swarm events, with every send acknowledged so nothing is in
//! flight when a measurement starts.
//!
//! Fixed policy across fixtures: StrictSign (unsigned messages rejected),
//! entropy seed [`ENTROPY_SEED`], and every `SendStream` acknowledged as
//! successful at once.

#![allow(
    dead_code,
    reason = "each bench binary uses a subset of these fixtures"
)]

use std::collections::{BTreeMap, BTreeSet};

use minip2p_core::PeerId;
use minip2p_identity::Ed25519Keypair;
use minip2p_pubsub::{
    ControlMessage, FrameDecode, GossipsubAction, GossipsubAgent, GossipsubConfig, GossipsubToken,
    MESHSUB_PROTOCOL_ID_V11, RawMessage, Rpc, SubOpts, decode_frame, encode_frame,
};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{ConnectionId, StreamId};

pub const PEER_COUNT: u16 = 32;
const PAYLOAD_LEN: usize = 60 * 1024;
pub const TOPIC: &str = "benchmark";
const INITIAL_SEQNO: u64 = 100;
const ENTROPY_SEED: u64 = 7;
/// Key index of the local agent; remote peers start at [`FIRST_PEER`].
const LOCAL: u16 = 1;
const FIRST_PEER: u16 = 2;

/// Deterministic identity for key `index`. Indices below 256 keep the
/// historical `[index; 32]` secret, so the publish fixture is unchanged.
fn keypair(index: u16) -> Ed25519Keypair {
    let [high, low] = index.to_be_bytes();
    let mut secret = [low; 32];
    secret[0] ^= high;
    Ed25519Keypair::from_secret_key_bytes(secret)
}

fn peer(index: u16) -> PeerId {
    keypair(index).peer_id()
}

fn conn_id(index: u16) -> ConnectionId {
    ConnectionId::new(u64::from(index))
}

fn inbound_stream(index: u16) -> StreamId {
    StreamId::new(u64::from(index) * 2 + 1)
}

/// The `(token, peer, stream_id, data)` of a send, or the action itself.
fn as_send(
    action: GossipsubAction,
) -> Result<(GossipsubToken, PeerId, StreamId, Vec<u8>), GossipsubAction> {
    match action {
        GossipsubAction::SendStream {
            token,
            peer,
            stream_id,
            data,
        } => Ok((token, peer, stream_id, data)),
        other => Err(other),
    }
}

/// Drains actions, acknowledging every send as successful, until the agent
/// emits no more. Any other action fails: fixtures leave nothing pending.
fn ack_sends(agent: &mut GossipsubAgent, now_ms: u64) {
    loop {
        let mut sends = Vec::new();
        while let Some(action) = agent.poll_action() {
            sends.push(as_send(action).expect("only sends while acknowledging"));
        }
        if sends.is_empty() {
            return;
        }
        for (token, peer, stream_id, _) in sends {
            agent.send_result(&peer, stream_id, token, Ok(()), now_ms);
        }
    }
}

/// Connects key `index` and has it subscribe to `topics`. The outbound
/// stream carries our subscriptions and any GRAFT; the inbound subscribe is
/// what makes the peer eligible for (and, below `d_low`, added to) a mesh.
fn join_peer(agent: &mut GossipsubAgent, index: u16, topics: &[String]) {
    let remote = peer(index);
    let conn_id = conn_id(index);
    let outbound = StreamId::new(u64::from(index) * 2);
    let inbound = inbound_stream(index);

    agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            peer_id: remote.clone(),
            conn_id,
        },
        0,
    );
    agent.handle_event(
        &SwarmEvent::PeerReady {
            peer_id: remote.clone(),
            conn_id,
            protocols: vec![MESHSUB_PROTOCOL_ID_V11.into()],
        },
        0,
    );

    let mut opened = Vec::new();
    while let Some(action) = agent.poll_action() {
        opened.push(action);
    }
    let token = opened
        .iter()
        .find_map(|action| match action {
            GossipsubAction::OpenStream {
                token,
                peer: opened_peer,
                ..
            } if opened_peer == &remote => Some(*token),
            _ => None,
        })
        .expect("outbound open for joining peer");
    agent.stream_open_result(&remote, token, Ok(outbound), 0);
    assert!(agent.handle_event(
        &SwarmEvent::StreamReady {
            peer_id: remote.clone(),
            conn_id,
            stream_id: outbound,
            protocol_id: MESHSUB_PROTOCOL_ID_V11.into(),
            initiated_locally: true,
        },
        0,
    ));
    ack_sends(agent, 0);

    assert!(agent.handle_event(
        &SwarmEvent::StreamReady {
            peer_id: remote.clone(),
            conn_id,
            stream_id: inbound,
            protocol_id: MESHSUB_PROTOCOL_ID_V11.into(),
            initiated_locally: false,
        },
        0,
    ));
    let subscriptions = topics
        .iter()
        .map(|topic| SubOpts {
            subscribe: Some(true),
            topic_id: Some(topic.clone()),
        })
        .collect();
    assert!(
        agent.handle_event(
            &SwarmEvent::StreamData {
                peer_id: remote,
                conn_id,
                stream_id: inbound,
                data: encode_frame(
                    &Rpc {
                        subscriptions,
                        publish: Vec::new(),
                        control: None,
                    }
                    .encode(),
                ),
            },
            0,
        )
    );
    ack_sends(agent, 0);
}

fn agent(config: GossipsubConfig) -> GossipsubAgent {
    GossipsubAgent::new(keypair(LOCAL), config, INITIAL_SEQNO, ENTROPY_SEED)
        .expect("valid gossipsub config")
}

/// An agent subscribed to [`TOPIC`] whose mesh is exactly `peers` peers
/// (`d = d_low = d_high = peers`), each grafted as it joins.
fn subscribed_mesh(peers: u16) -> GossipsubAgent {
    let degree = usize::from(peers);
    let mut agent = agent(GossipsubConfig {
        d: degree,
        d_low: degree,
        d_high: degree,
        ..GossipsubConfig::default()
    });
    agent.subscribe(TOPIC, 0).expect("subscribe");
    let topics = [TOPIC.to_string()];
    for index in FIRST_PEER..FIRST_PEER + peers {
        join_peer(&mut agent, index, &topics);
    }
    while agent.poll_event().is_some() {}
    assert_eq!(agent.mesh_peers(TOPIC).len(), degree);
    agent
}

/// Publish fixture: a 32-peer mesh and a 60 KiB payload.
pub fn setup() -> (GossipsubAgent, Vec<u8>) {
    (subscribed_mesh(PEER_COUNT), vec![0x5a; PAYLOAD_LEN])
}

// --- Forwarding --------------------------------------------------------------

/// Payload of the forwarded message.
pub const FORWARD_PAYLOAD_LEN: usize = 1024;

/// A mesh of `n` peers and one inbound frame, delivered by the first mesh
/// peer and authored and StrictSigned by that same peer, carrying a fresh
/// [`FORWARD_PAYLOAD_LEN`]-byte message on [`TOPIC`].
pub struct Forward {
    pub agent: GossipsubAgent,
    pub frame: SwarmEvent,
    /// The mesh minus the delivering peer: exactly where the message must go.
    pub recipients: BTreeSet<PeerId>,
}

pub fn forward_fixture(n: u16) -> Forward {
    let agent = subscribed_mesh(n);
    let source = keypair(FIRST_PEER);
    let message = RawMessage::build_signed(&source, TOPIC, vec![0x5a; FORWARD_PAYLOAD_LEN], 1);
    let frame = SwarmEvent::StreamData {
        peer_id: source.peer_id(),
        conn_id: conn_id(FIRST_PEER),
        stream_id: inbound_stream(FIRST_PEER),
        data: encode_frame(
            &Rpc {
                subscriptions: Vec::new(),
                publish: vec![message],
                control: None,
            }
            .encode(),
        ),
    };
    let mut recipients: BTreeSet<PeerId> = agent.mesh_peers(TOPIC).into_iter().collect();
    assert!(
        recipients.remove(&source.peer_id()),
        "source is a mesh peer"
    );
    Forward {
        agent,
        frame,
        recipients,
    }
}

/// The measured forwarding operation: hand the inbound frame to the agent and
/// drain its outbound actions. Returned so their drop is not measured.
pub fn forward(agent: &mut GossipsubAgent, frame: &SwarmEvent) -> Vec<GossipsubAction> {
    assert!(agent.handle_event(frame, 0));
    let mut actions = Vec::new();
    while let Some(action) = agent.poll_action() {
        actions.push(action);
    }
    actions
}

/// Asserts `actions` are one send to each of `recipients` and nothing else.
pub fn assert_forwarded(recipients: &BTreeSet<PeerId>, actions: Vec<GossipsubAction>) {
    let sends = actions.len();
    let sent: BTreeSet<PeerId> = actions
        .into_iter()
        .map(|action| as_send(action).expect("forwarding only sends").1)
        .collect();
    assert_eq!(sends, recipients.len(), "one send per recipient");
    assert_eq!(&sent, recipients, "sent to the non-source mesh");
}

// --- Heartbeat ---------------------------------------------------------------
//
// 1,000 peers and 100 topics `t0..t99`, all joined by the agent. Peer `i`
// subscribes to topics `i mod 100` and `(i + 1) mod 100`, so each topic has 20
// subscribers. The config is the default (`d = 6`, `d_lazy = 6`,
// `mcache_len = 5`, `mcache_gossip = 3`) except `d_low = d`, so joining grafts
// each mesh up to `d`. The agent then publishes one 1 KiB message per topic
// into each of the 5 cache windows (500 cached messages, under the 512 cap),
// with a heartbeat between windows, and acknowledges every send. The measured
// heartbeat keeps every mesh as is, sends IHAVE for the 3 newest windows
// (3 ids per topic) to 6 non-mesh subscribers per topic, and expires the
// oldest window.

const HEARTBEAT_PEERS: u16 = 1_000;
const HEARTBEAT_TOPICS: u16 = 100;
const HEARTBEAT_CACHE_WINDOWS: u64 = 5;
const HEARTBEAT_GOSSIP_WINDOWS: usize = 3;
/// When the measured heartbeat is due.
pub const HEARTBEAT_AT_MS: u64 = HEARTBEAT_INTERVAL_MS * HEARTBEAT_CACHE_WINDOWS;
const HEARTBEAT_INTERVAL_MS: u64 = 1_000;

fn heartbeat_topic(index: u16) -> String {
    format!("t{index}")
}

/// Topics subscribed by heartbeat peer `i` (0-based).
fn heartbeat_peer_topics(i: u16) -> [String; 2] {
    [
        heartbeat_topic(i % HEARTBEAT_TOPICS),
        heartbeat_topic((i + 1) % HEARTBEAT_TOPICS),
    ]
}

/// The heartbeat peers subscribed to `topic`, in join order.
fn heartbeat_subscribers(topic: &str) -> Vec<PeerId> {
    (0..HEARTBEAT_PEERS)
        .filter(|i| heartbeat_peer_topics(*i).iter().any(|t| t == topic))
        .map(|i| peer(FIRST_PEER + i))
        .collect()
}

/// The expected mesh for `topic`: with `d_low = d`, the first `d` subscribers
/// to join are grafted, and nothing later changes it.
fn heartbeat_mesh(topic: &str) -> Vec<PeerId> {
    let mut mesh = heartbeat_subscribers(topic);
    mesh.truncate(GossipsubConfig::default().d);
    mesh.sort();
    mesh
}

/// The wire id (`from ++ seqno`) of the agent's publish to topic `t{topic}` in
/// cache window `window`: the fixture publishes topics in order, window by window.
fn heartbeat_message_id(window: u64, topic: u16) -> Vec<u8> {
    let seqno = INITIAL_SEQNO + window * u64::from(HEARTBEAT_TOPICS) + u64::from(topic);
    let mut id = peer(LOCAL).to_bytes();
    id.extend_from_slice(&seqno.to_be_bytes());
    id
}

pub fn heartbeat_fixture() -> GossipsubAgent {
    let mut config = GossipsubConfig::default();
    config.d_low = config.d;
    assert_eq!(config.heartbeat_interval_ms, HEARTBEAT_INTERVAL_MS);
    assert_eq!(config.mcache_len as u64, HEARTBEAT_CACHE_WINDOWS);
    assert_eq!(config.mcache_gossip, HEARTBEAT_GOSSIP_WINDOWS);
    let degree = config.d;
    let mut agent = agent(config);

    let topics: Vec<String> = (0..HEARTBEAT_TOPICS).map(heartbeat_topic).collect();
    for topic in &topics {
        agent.subscribe(topic, 0).expect("subscribe");
    }
    // The first event arms the heartbeat for `HEARTBEAT_INTERVAL_MS`.
    for i in 0..HEARTBEAT_PEERS {
        join_peer(&mut agent, FIRST_PEER + i, &heartbeat_peer_topics(i));
    }
    let mut now = 0;
    for window in 0..HEARTBEAT_CACHE_WINDOWS {
        if window > 0 {
            now += HEARTBEAT_INTERVAL_MS;
            agent.handle_tick(now);
            ack_sends(&mut agent, now);
        }
        for topic in &topics {
            agent
                .publish(topic, vec![0x5a; FORWARD_PAYLOAD_LEN], now)
                .expect("publish into the cache");
            ack_sends(&mut agent, now);
        }
    }
    assert_eq!(now + HEARTBEAT_INTERVAL_MS, HEARTBEAT_AT_MS);
    assert_eq!(agent.next_timeout(now), Some(HEARTBEAT_INTERVAL_MS));
    while agent.poll_event().is_some() {}

    for (index, topic) in (0..HEARTBEAT_TOPICS).zip(&topics) {
        let subscribers = heartbeat_subscribers(topic);
        assert_eq!(
            subscribers.len(),
            usize::from(2 * HEARTBEAT_PEERS / HEARTBEAT_TOPICS),
            "topic {index} subscribers"
        );
        assert_eq!(heartbeat_mesh(topic).len(), degree);
        assert_eq!(
            agent.mesh_peers(topic),
            heartbeat_mesh(topic),
            "topic {index} mesh"
        );
    }
    agent
}

/// The measured heartbeat: one tick at [`HEARTBEAT_AT_MS`].
pub fn heartbeat(agent: &mut GossipsubAgent) {
    agent.handle_tick(HEARTBEAT_AT_MS);
}

/// Asserts the tick ran a heartbeat: the next one is a full interval away,
/// no mesh changed, and for every topic exactly `d_lazy` non-mesh subscribers
/// got IHAVE for exactly that topic's messages in the 3 newest windows.
pub fn assert_heartbeat_ran(agent: &mut GossipsubAgent) {
    assert_eq!(
        agent.next_timeout(HEARTBEAT_AT_MS),
        Some(HEARTBEAT_INTERVAL_MS)
    );
    // topic -> peer -> advertised ids
    let mut gossip: BTreeMap<String, BTreeMap<PeerId, BTreeSet<Vec<u8>>>> = BTreeMap::new();
    let mut ihave_ids = 0;
    while let Some(action) = agent.poll_action() {
        let (_, peer, _, data) = as_send(action).expect("heartbeat only sends");
        let payload = match decode_frame(&data) {
            FrameDecode::Complete { payload, consumed } if consumed == data.len() => Some(payload),
            _ => None,
        }
        .expect("each heartbeat send is one complete frame");
        let rpc = Rpc::decode(payload).expect("valid heartbeat RPC");
        let control: ControlMessage = rpc.control.expect("heartbeat sends control");
        assert!(control.graft.is_empty() && control.prune.is_empty());
        for ihave in control.ihave {
            let topic = ihave.topic_id.expect("IHAVE names its topic");
            ihave_ids += ihave.message_ids.len();
            gossip
                .entry(topic)
                .or_default()
                .entry(peer.clone())
                .or_default()
                .extend(ihave.message_ids);
        }
    }

    let gossip_peers = GossipsubConfig::default().d_lazy;
    let newest = HEARTBEAT_CACHE_WINDOWS - HEARTBEAT_GOSSIP_WINDOWS as u64..HEARTBEAT_CACHE_WINDOWS;
    assert_eq!(gossip.len(), usize::from(HEARTBEAT_TOPICS), "IHAVE topics");
    // The per-peer sets below would hide duplicates, so count every id sent.
    assert_eq!(
        ihave_ids,
        usize::from(HEARTBEAT_TOPICS) * gossip_peers * HEARTBEAT_GOSSIP_WINDOWS,
        "IHAVE ids sent"
    );
    for index in 0..HEARTBEAT_TOPICS {
        let topic = heartbeat_topic(index);
        let recipients = gossip.get(&topic).expect("IHAVE for every topic");
        assert_eq!(recipients.len(), gossip_peers, "{topic} gossip peers");
        let subscribers = heartbeat_subscribers(&topic);
        let mesh = heartbeat_mesh(&topic);
        assert_eq!(agent.mesh_peers(&topic), mesh, "{topic} mesh unchanged");
        let expected: BTreeSet<Vec<u8>> = newest
            .clone()
            .map(|window| heartbeat_message_id(window, index))
            .collect();
        for (peer, ids) in recipients {
            assert!(
                subscribers.contains(peer) && !mesh.contains(peer),
                "{topic} gossip target"
            );
            assert_eq!(ids, &expected, "{topic} IHAVE ids");
        }
    }
}
