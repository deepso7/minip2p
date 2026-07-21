//! Deterministic, sans-I/O gossipsub routing and stream management.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use minip2p_core::PeerId;
use minip2p_identity::Ed25519Keypair;
use minip2p_swarm::SwarmEvent;
use minip2p_transport::StreamId;

use super::config::GossipsubConfig;
use super::mcache::MessageCache;
use crate::events::{PublishError, PubsubAction, PubsubEvent, PubsubToken, TopicError};
use crate::message::{
    ControlGraft, ControlIHave, ControlIWant, ControlMessage, ControlPrune, FrameDecode,
    MAX_RPC_SIZE, MAX_TOPIC_LEN, MESHSUB_PROTOCOL_ID_V10, MESHSUB_PROTOCOL_ID_V11, RawMessage, Rpc,
    SubOpts, decode_frame, encode_frame,
};
use crate::seen::{MessageId, SeenCache, message_id};

const MAX_PREFIX_LEN: usize = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MeshsubVersion {
    V10,
    V11,
}

impl MeshsubVersion {
    fn protocol_id(self) -> &'static str {
        match self {
            Self::V10 => MESHSUB_PROTOCOL_ID_V10,
            Self::V11 => MESHSUB_PROTOCOL_ID_V11,
        }
    }

    fn from_protocol_id(protocol_id: &str) -> Option<Self> {
        match protocol_id {
            MESHSUB_PROTOCOL_ID_V10 => Some(Self::V10),
            MESHSUB_PROTOCOL_ID_V11 => Some(Self::V11),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StreamRole {
    Outbound,
    Inbound,
    Rejected,
}

#[derive(Clone, Debug)]
enum ControlItem {
    Graft(String),
    Prune { topic: String, backoff_ms: u64 },
    IHave { topic: String, id: MessageId },
    IWant(MessageId),
}

#[derive(Clone, Debug, Default)]
struct ControlBuffer {
    graft: BTreeSet<String>,
    prune: BTreeMap<String, u64>,
    ihave: BTreeMap<String, BTreeSet<MessageId>>,
    iwant: BTreeSet<MessageId>,
}

impl ControlBuffer {
    fn is_empty(&self) -> bool {
        self.graft.is_empty()
            && self.prune.is_empty()
            && self.ihave.is_empty()
            && self.iwant.is_empty()
    }

    fn len(&self) -> usize {
        self.graft.len()
            + self.prune.len()
            + self.ihave.values().map(BTreeSet::len).sum::<usize>()
            + self.iwant.len()
    }

    fn push(&mut self, item: ControlItem) {
        match item {
            ControlItem::Graft(topic) => {
                if !self.prune.contains_key(&topic) {
                    self.graft.insert(topic);
                }
            }
            ControlItem::Prune { topic, backoff_ms } => {
                self.graft.remove(&topic);
                self.prune.insert(topic, backoff_ms);
            }
            ControlItem::IHave { topic, id } => {
                self.ihave.entry(topic).or_default().insert(id);
            }
            ControlItem::IWant(id) => {
                self.iwant.insert(id);
            }
        }
    }

    fn merge(&mut self, items: Vec<ControlItem>) {
        for item in items {
            self.push(item);
        }
    }

    fn pop_first(&mut self) -> Option<ControlItem> {
        if let Some(topic) = self.graft.iter().next().cloned() {
            self.graft.remove(&topic);
            return Some(ControlItem::Graft(topic));
        }
        if let Some((topic, backoff_ms)) = self
            .prune
            .iter()
            .next()
            .map(|(topic, backoff)| (topic.clone(), *backoff))
        {
            self.prune.remove(&topic);
            return Some(ControlItem::Prune { topic, backoff_ms });
        }
        if let Some((topic, id)) = self
            .ihave
            .iter()
            .find_map(|(topic, ids)| ids.iter().next().cloned().map(|id| (topic.clone(), id)))
        {
            if let Some(ids) = self.ihave.get_mut(&topic) {
                ids.remove(&id);
                if ids.is_empty() {
                    self.ihave.remove(&topic);
                }
            }
            return Some(ControlItem::IHave { topic, id });
        }
        if let Some(id) = self.iwant.iter().next().cloned() {
            self.iwant.remove(&id);
            return Some(ControlItem::IWant(id));
        }
        None
    }

    fn take_frame(&mut self, version: MeshsubVersion) -> Option<(Vec<u8>, Vec<ControlItem>)> {
        if self.is_empty() {
            return None;
        }
        let mut items = Vec::new();
        // Re-encoding is deliberately exact across nested protobuf-varint
        // boundaries. The configured control budgets bound this quadratic
        // packing pass; replace it with size accounting only if profiling
        // shows it matters.
        while let Some(item) = self.pop_first() {
            items.push(item);
            let body = encode_control_items(&items, version);
            if body.len() > MAX_RPC_SIZE {
                let item = items.pop().expect("just pushed");
                self.push(item);
                break;
            }
        }
        if items.is_empty() {
            // This can only be reached for a hostile, nearly-frame-sized
            // message id. Such ids are filtered before entering the buffer.
            return None;
        }
        Some((encode_control_items(&items, version), items))
    }
}

fn encode_control_items(items: &[ControlItem], version: MeshsubVersion) -> Vec<u8> {
    let mut control = ControlMessage::default();
    for item in items {
        match item {
            ControlItem::Graft(topic) => control.graft.push(ControlGraft {
                topic_id: Some(topic.clone()),
            }),
            ControlItem::Prune { topic, backoff_ms } => control.prune.push(ControlPrune {
                topic_id: Some(topic.clone()),
                peers: Vec::new(),
                backoff: (version == MeshsubVersion::V11)
                    .then_some(backoff_ms.saturating_add(999) / 1_000),
            }),
            ControlItem::IHave { topic, id } => {
                if let Some(last) = control.ihave.last_mut()
                    && last.topic_id.as_deref() == Some(topic.as_str())
                {
                    last.message_ids.push(id.clone());
                } else {
                    control.ihave.push(ControlIHave {
                        topic_id: Some(topic.clone()),
                        message_ids: alloc::vec![id.clone()],
                    });
                }
            }
            ControlItem::IWant(id) => {
                if let Some(iwant) = control.iwant.first_mut() {
                    iwant.message_ids.push(id.clone());
                } else {
                    control.iwant.push(ControlIWant {
                        message_ids: alloc::vec![id.clone()],
                    });
                }
            }
        }
    }
    Rpc {
        subscriptions: Vec::new(),
        publish: Vec::new(),
        control: Some(control),
    }
    .encode()
}

#[derive(Clone, Debug)]
enum FrameCommit {
    Subscriptions(Vec<SubOpts>),
    Control(Vec<ControlItem>),
    Message,
}

#[derive(Clone, Debug, Default)]
enum SendState {
    #[default]
    Idle,
    Opening {
        token: PubsubToken,
        since_ms: u64,
    },
    Negotiating {
        stream_id: StreamId,
        since_ms: u64,
    },
    Ready {
        stream_id: StreamId,
        in_flight: Option<(PubsubToken, FrameCommit)>,
    },
}

impl SendState {
    fn establishment_since(&self) -> Option<u64> {
        match self {
            Self::Opening { since_ms, .. } | Self::Negotiating { since_ms, .. } => Some(*since_ms),
            Self::Idle | Self::Ready { .. } => None,
        }
    }
}

#[derive(Debug, Default)]
struct PeerState {
    sender: SendState,
    pending_messages: VecDeque<Vec<u8>>,
    acknowledged_topics: BTreeSet<String>,
    announced_topics: BTreeSet<String>,
    subscription_queue: VecDeque<SubOpts>,
    inbound: BTreeMap<StreamId, Vec<u8>>,
    remote_topics: BTreeSet<String>,
    advertised_version: Option<MeshsubVersion>,
    outbound_version: Option<MeshsubVersion>,
    pending_control: ControlBuffer,
}

impl PeerState {
    fn queued_work(&self) -> usize {
        // Subscription resync is connection-scoped bookkeeping rather than
        // dropped application/control payload. Messages remain at the queue
        // front while in flight; only control moves into the commit record.
        let in_flight_control = match &self.sender {
            SendState::Ready {
                in_flight: Some((_, FrameCommit::Control(items))),
                ..
            } => items.len(),
            _ => 0,
        };
        self.pending_messages.len() + self.pending_control.len() + in_flight_control
    }
}

/// A deterministic, sans-I/O gossipsub router supporting meshsub v1.0 and
/// the v1.1 PRUNE backoff extension.
pub struct GossipsubAgent {
    keypair: Ed25519Keypair,
    local_peer_id: PeerId,
    config: GossipsubConfig,
    actions: VecDeque<PubsubAction>,
    events: VecDeque<PubsubEvent>,
    topics: BTreeSet<String>,
    peers: BTreeMap<PeerId, PeerState>,
    roles: BTreeMap<PeerId, BTreeMap<StreamId, StreamRole>>,
    mesh: BTreeMap<String, BTreeSet<PeerId>>,
    fanout: BTreeMap<String, BTreeSet<PeerId>>,
    fanout_last_pub: BTreeMap<String, u64>,
    backoff: BTreeMap<(String, PeerId), u64>,
    mcache: MessageCache,
    seen: SeenCache,
    iwant_requested: BTreeSet<MessageId>,
    ihave_budget: BTreeMap<PeerId, usize>,
    iwant_served: BTreeMap<PeerId, usize>,
    next_heartbeat_ms: Option<u64>,
    next_token: u64,
    next_seqno: u64,
    rng: SplitMix64,
}

impl GossipsubAgent {
    /// Creates a router. `initial_seqno` must not repeat across restarts;
    /// `entropy_seed` controls deterministic peer selection. Call
    /// [`GossipsubConfig::validate`] first when constructing this concrete
    /// agent directly; [`PubsubAgent::new`](crate::PubsubAgent::new) does so
    /// automatically.
    pub fn new(
        keypair: Ed25519Keypair,
        config: GossipsubConfig,
        initial_seqno: u64,
        entropy_seed: u64,
    ) -> Self {
        let local_peer_id = keypair.peer_id();
        let mcache = MessageCache::new(config.mcache_len, config.max_mcache_messages);
        Self {
            keypair,
            local_peer_id,
            config,
            actions: VecDeque::new(),
            events: VecDeque::new(),
            topics: BTreeSet::new(),
            peers: BTreeMap::new(),
            roles: BTreeMap::new(),
            mesh: BTreeMap::new(),
            fanout: BTreeMap::new(),
            fanout_last_pub: BTreeMap::new(),
            backoff: BTreeMap::new(),
            mcache,
            seen: SeenCache::default(),
            iwant_requested: BTreeSet::new(),
            ihave_budget: BTreeMap::new(),
            iwant_served: BTreeMap::new(),
            next_heartbeat_ms: None,
            next_token: 0,
            next_seqno: initial_seqno,
            rng: SplitMix64::new(entropy_seed),
        }
    }

    /// The peer id this agent publishes as.
    pub fn local_peer_id(&self) -> &PeerId {
        &self.local_peer_id
    }

    /// Our current subscriptions.
    pub fn subscriptions(&self) -> Vec<String> {
        self.topics.iter().cloned().collect()
    }

    /// Current mesh peers for `topic`, in deterministic peer-id order.
    pub fn mesh_peers(&self, topic: &str) -> Vec<PeerId> {
        self.mesh
            .get(topic)
            .map(|peers| peers.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Joins a topic and immediately promotes already-known eligible peers.
    pub fn subscribe(&mut self, topic: &str, now_ms: u64) -> Result<bool, TopicError> {
        validate_topic(topic)?;
        if !self.topics.insert(String::from(topic)) {
            return Ok(false);
        }

        let mut selected = self.fanout.remove(topic).unwrap_or_default();
        selected.retain(|peer| self.peer_is_eligible(peer, topic, now_ms));
        if selected.len() > self.config.d {
            let keep = self.select_peers(selected.iter().cloned().collect(), self.config.d);
            selected = keep.into_iter().collect();
        }
        if selected.len() < self.config.d {
            let candidates = self
                .eligible_topic_peers(topic, now_ms)
                .into_iter()
                .filter(|peer| !selected.contains(peer))
                .collect();
            for peer in self.select_peers(candidates, self.config.d - selected.len()) {
                selected.insert(peer);
            }
        }
        self.fanout_last_pub.remove(topic);
        for peer in &selected {
            self.queue_control(peer, ControlItem::Graft(String::from(topic)), now_ms);
        }
        self.mesh.insert(String::from(topic), selected);
        self.drive_all_senders(now_ms);
        Ok(true)
    }

    /// Leaves a topic and PRUNEs every current mesh member.
    pub fn unsubscribe(&mut self, topic: &str, now_ms: u64) -> bool {
        if !self.topics.remove(topic) {
            return false;
        }
        let peers = self.mesh.remove(topic).unwrap_or_default();
        for peer in peers {
            self.record_backoff(topic, &peer, self.config.unsubscribe_backoff_ms, now_ms);
            self.queue_control(
                &peer,
                ControlItem::Prune {
                    topic: String::from(topic),
                    backoff_ms: self.config.unsubscribe_backoff_ms,
                },
                now_ms,
            );
        }
        self.drive_all_senders(now_ms);
        true
    }

    /// Publishes a signed message using mesh, empty-mesh fallback, or fanout.
    pub fn publish(&mut self, topic: &str, data: Vec<u8>, now_ms: u64) -> Result<(), PublishError> {
        self.arm_heartbeat(now_ms);
        validate_topic(topic).map_err(PublishError::Topic)?;

        let recipients = if self.topics.contains(topic) {
            let mesh = self.mesh.get(topic).cloned().unwrap_or_default();
            if mesh.is_empty() {
                let candidates = self.eligible_topic_peers(topic, now_ms);
                self.select_peers(candidates, self.config.d)
            } else {
                mesh.into_iter().collect()
            }
        } else {
            self.select_fanout(topic, now_ms)
        };
        if recipients.iter().any(|peer| {
            self.peers.get(peer).is_some_and(|state| {
                state.pending_messages.len() >= self.config.max_pending_per_peer
            })
        }) {
            return Err(PublishError::Backpressure);
        }

        let seqno = self.next_seqno;
        let message = RawMessage::build_signed(&self.keypair, topic, data, seqno);
        let body = Rpc {
            subscriptions: Vec::new(),
            publish: alloc::vec![message.clone()],
            control: None,
        }
        .encode();
        if body.len() > MAX_RPC_SIZE {
            return Err(PublishError::TooLarge);
        }
        self.next_seqno = self.next_seqno.wrapping_add(1);
        let id = message_id(&self.local_peer_id.to_bytes(), &seqno.to_be_bytes());
        self.seen.insert(
            id.clone(),
            now_ms,
            self.config.seen_ttl_ms,
            self.config.max_seen_messages,
        );
        self.mcache
            .put(id, message, alloc::vec![String::from(topic)]);

        let frame = encode_frame(&body);
        for peer in recipients {
            if let Some(state) = self.peers.get_mut(&peer) {
                state.pending_messages.push_back(frame.clone());
            }
            self.drive_sender(&peer, now_ms);
        }
        Ok(())
    }

    /// Feeds one swarm event. Returns whether this agent owns the event.
    pub fn handle_event(&mut self, event: &SwarmEvent, now_ms: u64) -> bool {
        self.arm_heartbeat(now_ms);
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                self.on_connection_established(peer_id);
                false
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                self.remove_peer(peer_id, "connection closed");
                false
            }
            SwarmEvent::PeerReady { peer_id, protocols } => {
                let version = if protocols.iter().any(|p| p == MESHSUB_PROTOCOL_ID_V11) {
                    Some(MeshsubVersion::V11)
                } else if protocols.iter().any(|p| p == MESHSUB_PROTOCOL_ID_V10) {
                    Some(MeshsubVersion::V10)
                } else {
                    None
                };
                if let Some(version) = version {
                    self.peers
                        .entry(peer_id.clone())
                        .or_default()
                        .advertised_version = Some(version);
                    self.drive_sender(peer_id, now_ms);
                }
                false
            }
            SwarmEvent::StreamReady {
                peer_id,
                stream_id,
                protocol_id,
                initiated_locally,
                ..
            } => self.on_stream_ready(peer_id, *stream_id, protocol_id, *initiated_locally, now_ms),
            SwarmEvent::StreamData {
                peer_id,
                stream_id,
                data,
                ..
            } => self.on_stream_data(peer_id, *stream_id, data, now_ms),
            SwarmEvent::StreamRemoteWriteClosed {
                peer_id, stream_id, ..
            } => self.on_remote_write_closed(peer_id, *stream_id),
            SwarmEvent::StreamClosed {
                peer_id, stream_id, ..
            } => self.on_stream_closed(peer_id, *stream_id),
            _ => false,
        }
    }

    /// Echoes a synchronous stream-write result.
    pub fn send_result(
        &mut self,
        peer: &PeerId,
        stream_id: StreamId,
        token: PubsubToken,
        result: Result<(), String>,
        now_ms: u64,
    ) {
        let current = self.peers.get(peer).is_some_and(|state| {
            matches!(
                &state.sender,
                SendState::Ready {
                    stream_id: expected,
                    in_flight: Some((expected_token, _)),
                } if *expected == stream_id && *expected_token == token
            )
        });
        if !current {
            return;
        }
        let commit = {
            let state = self.peers.get_mut(peer).expect("checked above");
            let SendState::Ready { in_flight, .. } = &mut state.sender else {
                return;
            };
            in_flight.take().expect("checked above").1
        };
        match result {
            Ok(()) => {
                self.commit_frame(peer, commit);
                self.drive_sender(peer, now_ms);
            }
            Err(reason) => {
                self.restore_commit(peer, commit);
                self.actions.push_back(PubsubAction::ResetStream {
                    peer: peer.clone(),
                    stream_id,
                });
                if let Some(state) = self.peers.get_mut(peer) {
                    state.sender = SendState::Idle;
                    state.outbound_version = None;
                    state.subscription_queue.clear();
                }
                self.events.push_back(PubsubEvent::OutboundFailure {
                    peer: peer.clone(),
                    reason: format!("send failed: {reason}"),
                });
            }
        }
    }

    /// Echoes an outbound open result.
    pub fn stream_open_result(
        &mut self,
        peer: &PeerId,
        token: PubsubToken,
        result: Result<StreamId, String>,
        _now_ms: u64,
    ) {
        let current = self.peers.get(peer).is_some_and(|state| {
            matches!(&state.sender, SendState::Opening { token: expected, .. } if *expected == token)
        });
        if !current {
            if let Ok(stream_id) = result {
                self.reject_stream(peer, stream_id);
            }
            return;
        }
        let since_ms = match &self.peers.get(peer).expect("checked").sender {
            SendState::Opening { since_ms, .. } => *since_ms,
            _ => return,
        };
        match result {
            Ok(stream_id) => {
                if let Some(state) = self.peers.get_mut(peer) {
                    state.sender = SendState::Negotiating {
                        stream_id,
                        since_ms,
                    };
                }
                self.roles
                    .entry(peer.clone())
                    .or_default()
                    .insert(stream_id, StreamRole::Outbound);
            }
            Err(reason) => {
                if let Some(state) = self.peers.get_mut(peer) {
                    state.sender = SendState::Idle;
                }
                self.events.push_back(PubsubEvent::OutboundFailure {
                    peer: peer.clone(),
                    reason: format!("open failed: {reason}"),
                });
            }
        }
    }

    /// Advances establishment timeouts and due heartbeats.
    pub fn handle_tick(&mut self, now_ms: u64) {
        let was_unarmed = self.next_heartbeat_ms.is_none();
        self.arm_heartbeat(now_ms);
        self.seen.gc(now_ms);

        let timed_out: Vec<(PeerId, Option<StreamId>)> = self
            .peers
            .iter()
            .filter_map(|(peer, state)| {
                let since = state.sender.establishment_since()?;
                (now_ms.saturating_sub(since) >= self.config.send_timeout_ms).then(|| {
                    let stream = match state.sender {
                        SendState::Negotiating { stream_id, .. } => Some(stream_id),
                        _ => None,
                    };
                    (peer.clone(), stream)
                })
            })
            .collect();
        for (peer, stream) in timed_out {
            if let Some(stream_id) = stream {
                self.reject_stream(&peer, stream_id);
            }
            if let Some(state) = self.peers.get_mut(&peer) {
                state.sender = SendState::Idle;
                state.outbound_version = None;
                state.subscription_queue.clear();
            }
            self.events.push_back(PubsubEvent::OutboundFailure {
                peer,
                reason: "stream establishment timed out".to_string(),
            });
        }

        if !was_unarmed && self.next_heartbeat_ms.is_some_and(|due| now_ms >= due) {
            self.heartbeat(now_ms);
            self.next_heartbeat_ms = Some(now_ms.saturating_add(self.config.heartbeat_interval_ms));
        }
    }

    /// Next action for the driver.
    pub fn poll_action(&mut self) -> Option<PubsubAction> {
        self.actions.pop_front()
    }

    /// Next application event.
    pub fn poll_event(&mut self) -> Option<PubsubEvent> {
        self.events.pop_front()
    }

    /// Milliseconds until the next due timer.
    pub fn next_timeout(&self, now_ms: u64) -> Option<u64> {
        let mut due = self.next_heartbeat_ms;
        if let Some(expiry) = self.seen.next_expiry() {
            due = Some(due.map_or(expiry, |current| current.min(expiry)));
        }
        for state in self.peers.values() {
            if let Some(since) = state.sender.establishment_since() {
                let expiry = since.saturating_add(self.config.send_timeout_ms);
                due = Some(due.map_or(expiry, |current| current.min(expiry)));
            }
        }
        due.map(|deadline| deadline.saturating_sub(now_ms))
    }

    /// Whether this agent owns a stream lifecycle.
    pub fn owns_stream(&self, peer: &PeerId, stream_id: StreamId) -> bool {
        self.roles
            .get(peer)
            .is_some_and(|streams| streams.contains_key(&stream_id))
    }

    fn arm_heartbeat(&mut self, now_ms: u64) {
        if self.next_heartbeat_ms.is_none() {
            self.next_heartbeat_ms = Some(now_ms.saturating_add(self.config.heartbeat_interval_ms));
        }
    }

    fn on_connection_established(&mut self, peer: &PeerId) {
        if self.peers.contains_key(peer) {
            self.remove_peer(peer, "connection superseded");
            self.peers.insert(peer.clone(), PeerState::default());
        }
    }

    fn remove_peer(&mut self, peer: &PeerId, cause: &str) {
        if let Some(state) = self.peers.get(peer) {
            let dropped = state.queued_work();
            if dropped > 0 {
                self.events.push_back(PubsubEvent::OutboundFailure {
                    peer: peer.clone(),
                    reason: format!("{cause}; dropped {dropped} queued items"),
                });
            }
        }
        self.peers.remove(peer);
        self.roles.remove(peer);
        self.ihave_budget.remove(peer);
        self.iwant_served.remove(peer);
        for peers in self.mesh.values_mut() {
            peers.remove(peer);
        }
        for peers in self.fanout.values_mut() {
            peers.remove(peer);
        }
    }

    fn on_stream_ready(
        &mut self,
        peer: &PeerId,
        stream_id: StreamId,
        protocol_id: &str,
        initiated_locally: bool,
        now_ms: u64,
    ) -> bool {
        let Some(version) = MeshsubVersion::from_protocol_id(protocol_id) else {
            return self.owns_stream(peer, stream_id);
        };
        if initiated_locally {
            let ours = self.peers.get(peer).is_some_and(|state| {
                matches!(&state.sender, SendState::Negotiating { stream_id: expected, .. } if *expected == stream_id)
            });
            if !ours {
                return self.owns_stream(peer, stream_id);
            }
            let current_topics: Vec<String> = self.topics.iter().cloned().collect();
            if let Some(state) = self.peers.get_mut(peer) {
                state.outbound_version = Some(version);
                state.subscription_queue.clear();
                for topic in current_topics {
                    state.subscription_queue.push_back(SubOpts {
                        subscribe: Some(true),
                        topic_id: Some(topic),
                    });
                }
                let withdrawals: Vec<String> = state
                    .announced_topics
                    .difference(&self.topics)
                    .cloned()
                    .collect();
                for topic in withdrawals {
                    state.subscription_queue.push_back(SubOpts {
                        subscribe: Some(false),
                        topic_id: Some(topic),
                    });
                }
                state.sender = SendState::Ready {
                    stream_id,
                    in_flight: None,
                };
            }
            self.drive_sender(peer, now_ms);
            return true;
        }

        let state = self.peers.entry(peer.clone()).or_default();
        if state.inbound.len() >= self.config.max_inbound_streams_per_peer {
            self.events.push_back(PubsubEvent::ProtocolViolation {
                peer: peer.clone(),
                reason: "too many concurrent inbound streams".to_string(),
            });
            self.reject_stream(peer, stream_id);
            return true;
        }
        state.inbound.insert(stream_id, Vec::new());
        self.roles
            .entry(peer.clone())
            .or_default()
            .insert(stream_id, StreamRole::Inbound);
        true
    }

    fn on_stream_data(
        &mut self,
        peer: &PeerId,
        stream_id: StreamId,
        data: &[u8],
        now_ms: u64,
    ) -> bool {
        match self.role(peer, stream_id) {
            Some(StreamRole::Inbound) => {}
            Some(_) => return true,
            None => return false,
        }
        const CAP: usize = MAX_RPC_SIZE + MAX_PREFIX_LEN;
        let mut offset = 0;
        while offset < data.len() {
            let Some(buf) = self
                .peers
                .get_mut(peer)
                .and_then(|state| state.inbound.get_mut(&stream_id))
            else {
                return true;
            };
            let room = CAP.saturating_sub(buf.len());
            if room == 0 {
                self.violation_reset(peer, stream_id, "inbound buffer overflow");
                return true;
            }
            let take = room.min(data.len() - offset);
            buf.extend_from_slice(&data[offset..offset + take]);
            offset += take;

            let mut head = 0;
            while let Some(step) = self.take_frame(peer, stream_id, &mut head) {
                match step {
                    Ok(payload) => match Rpc::decode(&payload) {
                        Ok(rpc) => {
                            if !self.process_rpc(peer, stream_id, rpc, now_ms) {
                                return true;
                            }
                        }
                        Err(error) => {
                            self.violation_reset(
                                peer,
                                stream_id,
                                &format!("malformed RPC: {error}"),
                            );
                            return true;
                        }
                    },
                    Err(reason) => {
                        self.violation_reset(peer, stream_id, &reason);
                        return true;
                    }
                }
            }
            if head > 0
                && let Some(buf) = self
                    .peers
                    .get_mut(peer)
                    .and_then(|state| state.inbound.get_mut(&stream_id))
            {
                buf.drain(..head);
            }
        }
        true
    }

    fn take_frame(
        &mut self,
        peer: &PeerId,
        stream_id: StreamId,
        head: &mut usize,
    ) -> Option<Result<Vec<u8>, String>> {
        let buf = self.peers.get_mut(peer)?.inbound.get_mut(&stream_id)?;
        match decode_frame(&buf[*head..]) {
            FrameDecode::Complete { payload, consumed } => {
                let payload = payload.to_vec();
                *head += consumed;
                Some(Ok(payload))
            }
            FrameDecode::Incomplete => None,
            FrameDecode::TooLarge { len } => Some(Err(format!("frame of {len} bytes"))),
            FrameDecode::Error(error) => Some(Err(format!("malformed frame: {error}"))),
        }
    }

    fn on_remote_write_closed(&mut self, peer: &PeerId, stream_id: StreamId) -> bool {
        match self.role(peer, stream_id) {
            Some(StreamRole::Inbound) => {}
            Some(_) => return true,
            None => return false,
        }
        let leftover = self
            .peers
            .get_mut(peer)
            .and_then(|state| state.inbound.remove(&stream_id))
            .is_some_and(|buf| !buf.is_empty());
        if leftover {
            self.violation_reset(peer, stream_id, "EOF inside a frame");
        } else {
            self.actions.push_back(PubsubAction::CloseStreamWrite {
                peer: peer.clone(),
                stream_id,
            });
        }
        true
    }

    fn on_stream_closed(&mut self, peer: &PeerId, stream_id: StreamId) -> bool {
        let Some(role) = self.role(peer, stream_id) else {
            return false;
        };
        if let Some(streams) = self.roles.get_mut(peer) {
            streams.remove(&stream_id);
            if streams.is_empty() {
                self.roles.remove(peer);
            }
        }
        match role {
            StreamRole::Outbound => {
                let (commit, failed_establishment) = self
                    .peers
                    .get_mut(peer)
                    .map(|state| {
                        let sender = core::mem::take(&mut state.sender);
                        state.outbound_version = None;
                        state.subscription_queue.clear();
                        match sender {
                            SendState::Ready {
                                stream_id: expected,
                                in_flight,
                            } if expected == stream_id => {
                                (in_flight.map(|(_, commit)| commit), false)
                            }
                            SendState::Negotiating {
                                stream_id: expected,
                                ..
                            } if expected == stream_id => (None, true),
                            other => {
                                state.sender = other;
                                (None, false)
                            }
                        }
                    })
                    .unwrap_or((None, false));
                if let Some(commit) = commit {
                    self.restore_commit(peer, commit);
                }
                if failed_establishment {
                    self.events.push_back(PubsubEvent::OutboundFailure {
                        peer: peer.clone(),
                        reason: "stream closed during negotiation".to_string(),
                    });
                }
            }
            StreamRole::Inbound => {
                if let Some(state) = self.peers.get_mut(peer) {
                    state.inbound.remove(&stream_id);
                }
            }
            StreamRole::Rejected => {}
        }
        true
    }

    fn process_rpc(&mut self, peer: &PeerId, stream_id: StreamId, rpc: Rpc, now_ms: u64) -> bool {
        if !self.apply_subscriptions(peer, stream_id, &rpc.subscriptions) {
            return false;
        }
        for message in rpc.publish {
            self.process_message(peer, message, now_ms);
        }
        if let Some(control) = rpc.control {
            self.process_control(peer, control, now_ms);
        }
        self.drive_sender(peer, now_ms);
        true
    }

    fn apply_subscriptions(
        &mut self,
        peer: &PeerId,
        stream_id: StreamId,
        subscriptions: &[SubOpts],
    ) -> bool {
        if subscriptions.is_empty() {
            return true;
        }
        let Some(state) = self.peers.get_mut(peer) else {
            return true;
        };
        let mut candidate = state.remote_topics.clone();
        let mut invalid = false;
        for sub in subscriptions {
            let (Some(subscribe), Some(topic)) = (sub.subscribe, sub.topic_id.as_ref()) else {
                continue;
            };
            if validate_topic(topic).is_err() {
                invalid = true;
                continue;
            }
            if subscribe {
                candidate.insert(topic.clone());
            } else {
                candidate.remove(topic);
            }
        }
        if candidate.len() > self.config.max_topics_per_peer {
            self.violation_reset(peer, stream_id, "subscription set exceeds the bound");
            return false;
        }
        let added: Vec<String> = candidate
            .difference(&state.remote_topics)
            .cloned()
            .collect();
        let removed: Vec<String> = state
            .remote_topics
            .difference(&candidate)
            .cloned()
            .collect();
        state.remote_topics = candidate;
        if invalid {
            self.events.push_back(PubsubEvent::ProtocolViolation {
                peer: peer.clone(),
                reason: "subscription entries with invalid topics skipped".to_string(),
            });
        }
        for topic in added {
            self.events.push_back(PubsubEvent::PeerSubscribed {
                peer: peer.clone(),
                topic,
            });
        }
        for topic in removed {
            if let Some(mesh) = self.mesh.get_mut(&topic) {
                mesh.remove(peer);
            }
            if let Some(fanout) = self.fanout.get_mut(&topic) {
                fanout.remove(peer);
            }
            self.events.push_back(PubsubEvent::PeerUnsubscribed {
                peer: peer.clone(),
                topic,
            });
        }
        true
    }

    fn process_control(&mut self, peer: &PeerId, control: ControlMessage, now_ms: u64) {
        for graft in control.graft {
            let Some(topic) = graft.topic_id else {
                continue;
            };
            if !self.topics.contains(&topic) {
                continue;
            }
            if self.is_backed_off(&topic, peer, now_ms) {
                self.record_backoff(&topic, peer, self.config.prune_backoff_ms, now_ms);
                self.queue_control(
                    peer,
                    ControlItem::Prune {
                        topic,
                        backoff_ms: self.config.prune_backoff_ms,
                    },
                    now_ms,
                );
            } else {
                // GRAFT itself asserts mesh interest. Spec-following peers
                // announce the subscription first; an unannounced GRAFT is
                // accepted optimistically and heartbeat eligibility later
                // reconciles it.
                self.mesh.entry(topic).or_default().insert(peer.clone());
            }
        }
        for prune in control.prune {
            let Some(topic) = prune.topic_id else {
                continue;
            };
            if validate_topic(&topic).is_err() {
                continue;
            }
            if let Some(mesh) = self.mesh.get_mut(&topic) {
                mesh.remove(peer);
            }
            let supplied = prune.backoff.unwrap_or(0).saturating_mul(1_000);
            let backoff = if supplied == 0 {
                self.config.prune_backoff_ms
            } else {
                supplied.min(self.config.max_backoff_ms)
            };
            self.record_backoff(&topic, peer, backoff, now_ms);
        }
        for ihave in control.ihave {
            let count = self.ihave_budget.entry(peer.clone()).or_default();
            if *count >= self.config.max_ihave_messages_per_heartbeat {
                continue;
            }
            *count += 1;
            let mut requested = Vec::new();
            for id in ihave
                .message_ids
                .into_iter()
                .take(self.config.max_ihave_length)
            {
                if self.iwant_requested.len() >= self.config.max_iwant_ids_per_heartbeat {
                    break;
                }
                if self.seen.contains(&id) || self.iwant_requested.contains(&id) {
                    continue;
                }
                if !control_item_fits(&ControlItem::IWant(id.clone())) {
                    continue;
                }
                self.iwant_requested.insert(id.clone());
                requested.push(id);
            }
            for id in requested {
                self.queue_control(peer, ControlItem::IWant(id), now_ms);
            }
        }
        for iwant in control.iwant {
            for id in iwant.message_ids {
                let served = *self.iwant_served.get(peer).unwrap_or(&0);
                if served >= self.config.max_iwant_serves_per_heartbeat {
                    break;
                }
                let Some(message) = self.mcache.get(&id).cloned() else {
                    continue;
                };
                let body = Rpc {
                    subscriptions: Vec::new(),
                    publish: alloc::vec![message],
                    control: None,
                }
                .encode();
                if body.len() <= MAX_RPC_SIZE && self.queue_message(peer, encode_frame(&body)) {
                    *self.iwant_served.entry(peer.clone()).or_default() += 1;
                }
            }
        }
    }

    fn process_message(&mut self, arrival: &PeerId, message: RawMessage, now_ms: u64) {
        let (from, seqno, signed) = match message.verify(self.config.allow_unsigned) {
            Ok(value) => value,
            Err(error) => {
                self.events.push_back(PubsubEvent::ProtocolViolation {
                    peer: arrival.clone(),
                    reason: format!("message rejected: {error}"),
                });
                return;
            }
        };
        let id = message_id(&from.to_bytes(), &seqno);
        if self.seen.contains(&id) {
            return;
        }
        self.seen.insert(
            id.clone(),
            now_ms,
            self.config.seen_ttl_ms,
            self.config.max_seen_messages,
        );
        if message
            .topic_ids
            .iter()
            .any(|topic| self.topics.contains(topic))
        {
            self.events.push_back(PubsubEvent::Message {
                from: from.clone(),
                topics: message.topic_ids.clone(),
                data: message.data.clone().unwrap_or_default(),
                seqno,
                signed,
            });
        }

        let recipients: BTreeSet<PeerId> = message
            .topic_ids
            .iter()
            .filter_map(|topic| self.mesh.get(topic))
            .flatten()
            .filter(|peer| **peer != *arrival && **peer != from)
            .cloned()
            .collect();
        let frame = encode_frame(
            &Rpc {
                subscriptions: Vec::new(),
                publish: alloc::vec![message.clone()],
                control: None,
            }
            .encode(),
        );
        for peer in recipients {
            if self.queue_message(&peer, frame.clone()) {
                self.drive_sender(&peer, now_ms);
            }
        }
        self.mcache.put(id, message.clone(), message.topic_ids);
    }

    fn heartbeat(&mut self, now_ms: u64) {
        self.backoff.retain(|_, expiry| *expiry > now_ms);
        self.ihave_budget.clear();
        self.iwant_served.clear();
        self.iwant_requested.clear();

        let expired_fanout: Vec<String> = self
            .fanout_last_pub
            .iter()
            .filter(|(_, last)| {
                self.config.fanout_ttl_ms == 0
                    || now_ms.saturating_sub(**last) >= self.config.fanout_ttl_ms
            })
            .map(|(topic, _)| topic.clone())
            .collect();
        for topic in expired_fanout {
            self.fanout.remove(&topic);
            self.fanout_last_pub.remove(&topic);
        }

        let topics: Vec<String> = self.topics.iter().cloned().collect();
        for topic in topics {
            let eligible: BTreeSet<PeerId> = self
                .eligible_topic_peers(&topic, now_ms)
                .into_iter()
                .collect();
            let mut current = self.mesh.remove(&topic).unwrap_or_default();
            current.retain(|peer| eligible.contains(peer));
            if current.len() < self.config.d_low {
                let candidates = eligible
                    .iter()
                    .filter(|peer| !current.contains(*peer))
                    .cloned()
                    .collect();
                for peer in
                    self.select_peers(candidates, self.config.d.saturating_sub(current.len()))
                {
                    current.insert(peer.clone());
                    self.queue_control(&peer, ControlItem::Graft(topic.clone()), now_ms);
                }
            } else if current.len() > self.config.d_high {
                let retained: BTreeSet<PeerId> = self
                    .select_peers(current.iter().cloned().collect(), self.config.d)
                    .into_iter()
                    .collect();
                let pruned: Vec<PeerId> = current.difference(&retained).cloned().collect();
                current = retained;
                for peer in pruned {
                    self.record_backoff(&topic, &peer, self.config.prune_backoff_ms, now_ms);
                    self.queue_control(
                        &peer,
                        ControlItem::Prune {
                            topic: topic.clone(),
                            backoff_ms: self.config.prune_backoff_ms,
                        },
                        now_ms,
                    );
                }
            }
            self.mesh.insert(topic, current);
        }

        let fanout_topics: Vec<String> = self.fanout.keys().cloned().collect();
        for topic in fanout_topics {
            let eligible: BTreeSet<PeerId> = self
                .eligible_topic_peers(&topic, now_ms)
                .into_iter()
                .collect();
            let mut current = self.fanout.remove(&topic).unwrap_or_default();
            current.retain(|peer| eligible.contains(peer));
            if current.len() < self.config.d {
                let candidates = eligible
                    .iter()
                    .filter(|peer| !current.contains(*peer))
                    .cloned()
                    .collect();
                for peer in self.select_peers(candidates, self.config.d - current.len()) {
                    current.insert(peer);
                }
            }
            self.fanout.insert(topic, current);
        }

        let gossip_topics: Vec<String> = self
            .peers
            .values()
            .flat_map(|state| state.remote_topics.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        for topic in gossip_topics {
            let ids = self.mcache.gossip_ids(&topic, self.config.mcache_gossip);
            if ids.is_empty() || self.config.d_lazy == 0 {
                continue;
            }
            let mesh = self.mesh.get(&topic).cloned().unwrap_or_default();
            let fanout = self.fanout.get(&topic).cloned().unwrap_or_default();
            let candidates: Vec<PeerId> = self
                .peers
                .iter()
                .filter(|(peer, state)| {
                    state.advertised_version.is_some()
                        && state.remote_topics.contains(&topic)
                        && !mesh.contains(*peer)
                        && !fanout.contains(*peer)
                })
                .map(|(peer, _)| peer.clone())
                .collect();
            for peer in self.select_peers(candidates, self.config.d_lazy) {
                for id in ids.iter().take(self.config.max_ihave_length) {
                    self.queue_control(
                        &peer,
                        ControlItem::IHave {
                            topic: topic.clone(),
                            id: id.clone(),
                        },
                        now_ms,
                    );
                }
            }
        }
        self.mcache.shift();
        self.drive_all_senders(now_ms);
    }

    fn drive_all_senders(&mut self, now_ms: u64) {
        let peers: Vec<PeerId> = self.peers.keys().cloned().collect();
        for peer in peers {
            self.drive_sender(&peer, now_ms);
        }
    }

    fn drive_sender(&mut self, peer: &PeerId, now_ms: u64) {
        let state_kind = self.peers.get(peer).map(|state| match state.sender {
            SendState::Idle => 0,
            SendState::Ready {
                in_flight: None, ..
            } => 1,
            _ => 2,
        });
        match state_kind {
            Some(0) => {
                let Some(version) = self
                    .peers
                    .get(peer)
                    .and_then(|state| state.advertised_version)
                else {
                    return;
                };
                let token = self.allocate_token();
                if let Some(state) = self.peers.get_mut(peer) {
                    state.sender = SendState::Opening {
                        token,
                        since_ms: now_ms,
                    };
                }
                self.actions.push_back(PubsubAction::OpenStream {
                    token,
                    peer: peer.clone(),
                    protocol_id: String::from(version.protocol_id()),
                });
            }
            Some(1) => self.emit_next_frame(peer),
            _ => {}
        }
    }

    fn emit_next_frame(&mut self, peer: &PeerId) {
        let (stream_id, version) = match self.peers.get(peer) {
            Some(PeerState {
                sender:
                    SendState::Ready {
                        stream_id,
                        in_flight: None,
                    },
                outbound_version: Some(version),
                ..
            }) => (*stream_id, *version),
            _ => return,
        };

        let work = if self
            .peers
            .get(peer)
            .is_some_and(|state| !state.subscription_queue.is_empty())
        {
            let mut subscriptions = Vec::new();
            // Subscription and control commits intentionally occupy separate
            // RPCs. This keeps each acknowledgement atomic at the cost of one
            // extra write after a reopen; each category is still packed
            // greedily to the exact wire limit.
            while let Some(next) = self
                .peers
                .get(peer)
                .and_then(|state| state.subscription_queue.front().cloned())
            {
                subscriptions.push(next);
                let body = Rpc {
                    subscriptions: subscriptions.clone(),
                    publish: Vec::new(),
                    control: None,
                }
                .encode();
                if body.len() > MAX_RPC_SIZE {
                    subscriptions.pop();
                    break;
                }
                self.peers
                    .get_mut(peer)
                    .expect("peer exists")
                    .subscription_queue
                    .pop_front();
            }
            let body = Rpc {
                subscriptions: subscriptions.clone(),
                publish: Vec::new(),
                control: None,
            }
            .encode();
            Some((
                encode_frame(&body),
                FrameCommit::Subscriptions(subscriptions),
            ))
        } else {
            self.enqueue_live_subscription_diff(peer);
            if self
                .peers
                .get(peer)
                .is_some_and(|state| !state.subscription_queue.is_empty())
            {
                self.emit_next_frame(peer);
                return;
            }
            if let Some((body, items)) = self
                .peers
                .get_mut(peer)
                .and_then(|state| state.pending_control.take_frame(version))
            {
                Some((encode_frame(&body), FrameCommit::Control(items)))
            } else {
                self.peers
                    .get(peer)
                    .and_then(|state| state.pending_messages.front().cloned())
                    .map(|frame| (frame, FrameCommit::Message))
            }
        };
        let Some((frame, commit)) = work else { return };
        let token = self.allocate_token();
        if let Some(state) = self.peers.get_mut(peer)
            && let SendState::Ready { in_flight, .. } = &mut state.sender
        {
            *in_flight = Some((token, commit));
        }
        self.actions.push_back(PubsubAction::SendStream {
            token,
            peer: peer.clone(),
            stream_id,
            data: frame,
        });
    }

    fn enqueue_live_subscription_diff(&mut self, peer: &PeerId) {
        let Some(state) = self.peers.get_mut(peer) else {
            return;
        };
        for topic in self.topics.difference(&state.acknowledged_topics) {
            state.subscription_queue.push_back(SubOpts {
                subscribe: Some(true),
                topic_id: Some(topic.clone()),
            });
        }
        for topic in state.acknowledged_topics.difference(&self.topics) {
            state.subscription_queue.push_back(SubOpts {
                subscribe: Some(false),
                topic_id: Some(topic.clone()),
            });
        }
    }

    fn commit_frame(&mut self, peer: &PeerId, commit: FrameCommit) {
        let Some(state) = self.peers.get_mut(peer) else {
            return;
        };
        match commit {
            FrameCommit::Subscriptions(subscriptions) => {
                for sub in subscriptions {
                    let (Some(subscribe), Some(topic)) = (sub.subscribe, sub.topic_id) else {
                        continue;
                    };
                    if subscribe {
                        state.acknowledged_topics.insert(topic.clone());
                        state.announced_topics.insert(topic);
                    } else {
                        state.acknowledged_topics.remove(&topic);
                        state.announced_topics.insert(topic);
                    }
                }
            }
            FrameCommit::Control(_) => {}
            FrameCommit::Message => {
                state.pending_messages.pop_front();
            }
        }
    }

    fn restore_commit(&mut self, peer: &PeerId, commit: FrameCommit) {
        if let FrameCommit::Control(items) = commit
            && let Some(state) = self.peers.get_mut(peer)
        {
            state.pending_control.merge(items);
        }
    }

    fn queue_control(&mut self, peer: &PeerId, item: ControlItem, _now_ms: u64) {
        if let Some(state) = self.peers.get_mut(peer) {
            state.pending_control.push(item);
        }
    }

    fn queue_message(&mut self, peer: &PeerId, frame: Vec<u8>) -> bool {
        let Some(state) = self.peers.get_mut(peer) else {
            return false;
        };
        if state.pending_messages.len() >= self.config.max_pending_per_peer {
            self.events.push_back(PubsubEvent::OutboundFailure {
                peer: peer.clone(),
                reason: "outbound message dropped: queue is full".to_string(),
            });
            return false;
        }
        state.pending_messages.push_back(frame);
        true
    }

    fn select_fanout(&mut self, topic: &str, now_ms: u64) -> Vec<PeerId> {
        let reusable = self.config.fanout_ttl_ms != 0
            && self
                .fanout_last_pub
                .get(topic)
                .is_some_and(|last| now_ms.saturating_sub(*last) < self.config.fanout_ttl_ms);
        let mut peers = if reusable {
            self.fanout.remove(topic).unwrap_or_default()
        } else {
            BTreeSet::new()
        };
        peers.retain(|peer| self.peer_is_eligible(peer, topic, now_ms));
        if peers.len() < self.config.d {
            let candidates = self
                .eligible_topic_peers(topic, now_ms)
                .into_iter()
                .filter(|peer| !peers.contains(peer))
                .collect();
            for peer in self.select_peers(candidates, self.config.d - peers.len()) {
                peers.insert(peer);
            }
        }
        self.fanout.insert(String::from(topic), peers.clone());
        self.fanout_last_pub.insert(String::from(topic), now_ms);
        peers.into_iter().collect()
    }

    fn eligible_topic_peers(&self, topic: &str, now_ms: u64) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter(|(peer, state)| {
                state.advertised_version.is_some()
                    && state.remote_topics.contains(topic)
                    && !self.is_backed_off(topic, peer, now_ms)
            })
            .map(|(peer, _)| peer.clone())
            .collect()
    }

    fn peer_is_eligible(&self, peer: &PeerId, topic: &str, now_ms: u64) -> bool {
        self.peers.get(peer).is_some_and(|state| {
            state.advertised_version.is_some()
                && state.remote_topics.contains(topic)
                && !self.is_backed_off(topic, peer, now_ms)
        })
    }

    fn select_peers(&mut self, mut peers: Vec<PeerId>, count: usize) -> Vec<PeerId> {
        for index in (1..peers.len()).rev() {
            let chosen = (self.rng.next() as usize) % (index + 1);
            peers.swap(index, chosen);
        }
        peers.truncate(count.min(peers.len()));
        peers
    }

    fn is_backed_off(&self, topic: &str, peer: &PeerId, now_ms: u64) -> bool {
        self.backoff
            .get(&(String::from(topic), peer.clone()))
            .is_some_and(|expiry| *expiry > now_ms)
    }

    fn record_backoff(&mut self, topic: &str, peer: &PeerId, duration_ms: u64, now_ms: u64) {
        let expiry = now_ms.saturating_add(duration_ms);
        self.backoff
            .entry((String::from(topic), peer.clone()))
            .and_modify(|current| *current = (*current).max(expiry))
            .or_insert(expiry);
    }

    fn allocate_token(&mut self) -> PubsubToken {
        let token = PubsubToken(self.next_token);
        self.next_token = self.next_token.wrapping_add(1);
        token
    }

    fn role(&self, peer: &PeerId, stream_id: StreamId) -> Option<StreamRole> {
        self.roles
            .get(peer)
            .and_then(|streams| streams.get(&stream_id))
            .copied()
    }

    fn reject_stream(&mut self, peer: &PeerId, stream_id: StreamId) {
        self.roles
            .entry(peer.clone())
            .or_default()
            .insert(stream_id, StreamRole::Rejected);
        self.actions.push_back(PubsubAction::ResetStream {
            peer: peer.clone(),
            stream_id,
        });
    }

    fn violation_reset(&mut self, peer: &PeerId, stream_id: StreamId, reason: &str) {
        if let Some(state) = self.peers.get_mut(peer) {
            state.inbound.remove(&stream_id);
        }
        self.events.push_back(PubsubEvent::ProtocolViolation {
            peer: peer.clone(),
            reason: reason.to_string(),
        });
        self.reject_stream(peer, stream_id);
    }
}

fn control_item_fits(item: &ControlItem) -> bool {
    encode_control_items(core::slice::from_ref(item), MeshsubVersion::V11).len() <= MAX_RPC_SIZE
}

fn validate_topic(topic: &str) -> Result<(), TopicError> {
    if topic.is_empty() {
        Err(TopicError::Empty)
    } else if topic.len() > MAX_TOPIC_LEN {
        Err(TopicError::TooLong)
    } else {
        Ok(())
    }
}

#[derive(Debug)]
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_flight_control_ownership_preserves_later_aliases() {
        let mut buffer = ControlBuffer::default();
        buffer.push(ControlItem::Graft(String::from("topic")));
        let (_, in_flight) = buffer.take_frame(MeshsubVersion::V11).unwrap();
        buffer.push(ControlItem::Graft(String::from("topic")));
        assert_eq!(buffer.len(), 1, "later alias remains independently queued");

        // Failure merges the owned item back and deterministically coalesces
        // it with the later alias.
        buffer.merge(in_flight);
        assert_eq!(buffer.len(), 1);

        let (_, in_flight) = buffer.take_frame(MeshsubVersion::V11).unwrap();
        buffer.push(ControlItem::Prune {
            topic: String::from("topic"),
            backoff_ms: 10_000,
        });
        buffer.merge(in_flight);
        let (body, _) = buffer.take_frame(MeshsubVersion::V11).unwrap();
        let control = Rpc::decode(&body).unwrap().control.unwrap();
        assert!(control.graft.is_empty());
        assert_eq!(control.prune.len(), 1, "later PRUNE supersedes GRAFT");
    }

    #[test]
    fn oversized_control_buffer_splits_without_dropping_ids() {
        let mut buffer = ControlBuffer::default();
        for index in 0..3_000u32 {
            let mut id = alloc::vec![0xA5; 32];
            id[..4].copy_from_slice(&index.to_be_bytes());
            buffer.push(ControlItem::IWant(id));
        }

        let mut frames = 0;
        let mut ids = 0;
        while let Some((body, _)) = buffer.take_frame(MeshsubVersion::V11) {
            assert!(body.len() <= MAX_RPC_SIZE);
            let control = Rpc::decode(&body).unwrap().control.unwrap();
            ids += control
                .iwant
                .iter()
                .map(|iwant| iwant.message_ids.len())
                .sum::<usize>();
            frames += 1;
        }
        assert!(frames > 1);
        assert_eq!(ids, 3_000);
    }
}
