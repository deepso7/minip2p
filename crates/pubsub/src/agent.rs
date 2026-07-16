//! The floodsub state machine: subscription tracking, StrictSign publish,
//! flood-forwarding, and the per-peer one-shot stream senders.
//!
//! Stream model (see the crate README): one RPC per outbound stream —
//! open, write, half-close, wait for the close — strictly serialized per
//! peer; any number of RPCs per inbound stream, several inbound streams per
//! peer. This is the intersection of go-libp2p's persistent streams and
//! rust-libp2p's one-shot handler.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use minip2p_core::PeerId;
use minip2p_identity::Ed25519Keypair;
use minip2p_swarm::SwarmEvent;
use minip2p_transport::StreamId;

use crate::config::FloodsubConfig;
use crate::events::{PublishError, PubsubAction, PubsubEvent, PubsubToken, TopicError};
use crate::message::{
    FLOODSUB_PROTOCOL_ID, FrameDecode, MAX_RPC_SIZE, MAX_TOPIC_LEN, RawMessage, Rpc, SubOpts,
    decode_frame, encode_frame,
};
use crate::seen::{MessageId, SeenCache};

/// Longest possible frame prefix; bounds the inbound reassembly buffers.
const MAX_PREFIX_LEN: usize = 10;

/// Roles a floodsub-owned stream can play. Streams stay in the role map
/// until their terminal `StreamClosed`, so their lifecycle events are
/// claimed rather than leaked to the application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StreamRole {
    /// Our one-shot RPC sender stream (write-only).
    Outbound,
    /// A remote's RPC stream (read-only).
    Inbound,
    /// A reset was issued; owned until the close, events ignored.
    Rejected,
}

/// The exact work an in-flight sender carries. Freezing the frame and (for
/// subscriptions) the encoded snapshot into the state means a local change
/// mid-send can never corrupt the commit.
#[derive(Clone, Debug)]
enum OutboundWork {
    /// The frame encodes the diff from `sent_topics` to `snapshot`;
    /// committing sets `sent_topics = snapshot`.
    Subscriptions {
        frame: Vec<u8>,
        snapshot: BTreeSet<String>,
    },
    /// The front of `pending`; committing pops it.
    Publish { frame: Vec<u8> },
}

impl OutboundWork {
    fn frame(&self) -> &[u8] {
        match self {
            Self::Subscriptions { frame, .. } | Self::Publish { frame } => frame,
        }
    }

    fn describe(&self) -> &'static str {
        match self {
            Self::Subscriptions { .. } => "subscription update",
            Self::Publish { .. } => "message",
        }
    }
}

/// Per-peer one-shot sender: strictly serialized, commit only on the
/// in-flight stream's `StreamClosed` (i.e. only from `AwaitingClose`).
#[derive(Clone, Debug, Default)]
enum SendState {
    #[default]
    Idle,
    /// `OpenStream` issued; waiting for the token echo.
    Opening {
        token: PubsubToken,
        since_ms: u64,
        work: OutboundWork,
    },
    /// Stream allocated; waiting for multistream negotiation.
    Negotiating {
        stream_id: StreamId,
        since_ms: u64,
        work: OutboundWork,
    },
    /// Frame written and write half closed; waiting for the close.
    AwaitingClose {
        stream_id: StreamId,
        since_ms: u64,
        work: OutboundWork,
    },
}

impl SendState {
    fn since_ms(&self) -> Option<u64> {
        match self {
            Self::Idle => None,
            Self::Opening { since_ms, .. }
            | Self::Negotiating { since_ms, .. }
            | Self::AwaitingClose { since_ms, .. } => Some(*since_ms),
        }
    }
}

#[derive(Debug, Default)]
struct PeerState {
    sender: SendState,
    /// Framed publish/forward RPCs awaiting their turn (subscription
    /// updates never queue here — they re-diff at send time).
    pending: VecDeque<Vec<u8>>,
    /// The subscription snapshot last COMMITTED to this peer.
    sent_topics: BTreeSet<String>,
    /// Concurrent inbound streams and their reassembly buffers.
    inbound: BTreeMap<StreamId, Vec<u8>>,
    /// Topics the remote has announced.
    remote_topics: BTreeSet<String>,
}

impl PeerState {
    /// Distinct work items that would be lost if this peer vanished. An
    /// in-flight `Publish` is still the front of `pending` (it is only
    /// peeked until commit), so counting the sender again would double-
    /// count it; an in-flight subscription diff lives only in the sender.
    fn queued_work(&self) -> usize {
        let in_flight_subscription = match &self.sender {
            SendState::Idle => 0,
            SendState::Opening { work, .. }
            | SendState::Negotiating { work, .. }
            | SendState::AwaitingClose { work, .. } => {
                usize::from(matches!(work, OutboundWork::Subscriptions { .. }))
            }
        };
        self.pending.len() + in_flight_subscription
    }
}

/// Sans-I/O floodsub agent. Feed [`SwarmEvent`]s and ticks, execute the
/// [`PubsubAction`]s, surface the [`PubsubEvent`]s.
pub struct FloodsubAgent {
    keypair: Ed25519Keypair,
    local_peer_id: PeerId,
    config: FloodsubConfig,
    actions: VecDeque<PubsubAction>,
    events: VecDeque<PubsubEvent>,
    topics: BTreeSet<String>,
    peers: BTreeMap<PeerId, PeerState>,
    roles: BTreeMap<PeerId, BTreeMap<StreamId, StreamRole>>,
    tokens: BTreeMap<PubsubToken, PeerId>,
    /// Tokens whose send timed out while still `Opening`: a late `Ok`
    /// result must reset the stream it delivers, not leak it.
    stale_tokens: BTreeMap<PubsubToken, PeerId>,
    next_token: u64,
    next_seqno: u64,
    seen: SeenCache,
}

impl FloodsubAgent {
    /// Creates an agent publishing as `keypair`'s peer id.
    ///
    /// `initial_seqno` seeds the strictly-increasing publish counter.
    /// Message ids are `(from, seqno)`, so restarts must not reuse old
    /// seqnos: hosts with a clock pass wall-clock nanoseconds; no_std
    /// embedders supply their own monotonic-across-restarts seed.
    pub fn new(keypair: Ed25519Keypair, config: FloodsubConfig, initial_seqno: u64) -> Self {
        let local_peer_id = keypair.peer_id();
        Self {
            keypair,
            local_peer_id,
            config,
            actions: VecDeque::new(),
            events: VecDeque::new(),
            topics: BTreeSet::new(),
            peers: BTreeMap::new(),
            roles: BTreeMap::new(),
            tokens: BTreeMap::new(),
            stale_tokens: BTreeMap::new(),
            next_token: 0,
            next_seqno: initial_seqno,
            seen: SeenCache::default(),
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

    /// Subscribes to `topic`. Returns `Ok(false)` when already subscribed.
    ///
    /// The whole subscription set is bounded so that any snapshot or diff
    /// RPC provably fits in [`MAX_RPC_SIZE`]: a peer that had to reject an
    /// oversized snapshot frame would silently miss our subscriptions while
    /// the commit recorded them as delivered.
    pub fn subscribe(&mut self, topic: &str, now_ms: u64) -> Result<bool, TopicError> {
        validate_topic(topic)?;
        if self.topics.contains(topic) {
            return Ok(false);
        }
        // A full set of N subscribes and a diff of A adds + R removes are
        // both bounded by (full set + full previous set); capping the full
        // set's encoding at half the RPC budget keeps every diff legal.
        let mut projected: Vec<SubOpts> = self
            .topics
            .iter()
            .chain(core::iter::once(&String::from(topic)))
            .map(|t| SubOpts {
                subscribe: Some(true),
                topic_id: Some(t.clone()),
            })
            .collect();
        let rpc = Rpc {
            subscriptions: core::mem::take(&mut projected),
            publish: Vec::new(),
        };
        if rpc.encode().len() > MAX_RPC_SIZE / 2 {
            return Err(TopicError::SetTooLarge);
        }
        self.topics.insert(String::from(topic));
        self.drive_all_senders(now_ms);
        Ok(true)
    }

    /// Unsubscribes from `topic`. Returns `false` when not subscribed.
    pub fn unsubscribe(&mut self, topic: &str, now_ms: u64) -> bool {
        if !self.topics.remove(topic) {
            return false;
        }
        self.drive_all_senders(now_ms);
        true
    }

    /// Publishes `data` on `topic`, signed with our identity.
    ///
    /// All-or-nothing backpressure: if any subscribed recipient's queue is
    /// full the publish is refused and nothing is enqueued anywhere. There
    /// is no self-delivery — the caller already has the message.
    pub fn publish(&mut self, topic: &str, data: Vec<u8>, now_ms: u64) -> Result<(), PublishError> {
        validate_topic(topic).map_err(PublishError::Topic)?;

        let recipients: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, state)| state.remote_topics.contains(topic))
            .map(|(peer, _)| peer.clone())
            .collect();
        for peer in &recipients {
            if let Some(state) = self.peers.get(peer)
                && state.pending.len() >= self.config.max_pending_per_peer
            {
                return Err(PublishError::Backpressure);
            }
        }

        let seqno = self.next_seqno;
        let message = RawMessage::build_signed(&self.keypair, topic, data, seqno);
        let rpc = Rpc {
            subscriptions: Vec::new(),
            publish: alloc::vec![message],
        };
        let body = rpc.encode();
        if body.len() > MAX_RPC_SIZE {
            return Err(PublishError::TooLarge);
        }
        self.next_seqno = self.next_seqno.wrapping_add(1);

        let id: MessageId = (self.local_peer_id.to_bytes(), seqno.to_be_bytes());
        self.seen.insert(
            id,
            now_ms,
            self.config.seen_ttl_ms,
            self.config.max_seen_messages,
        );

        let frame = encode_frame(&body);
        for peer in recipients {
            if let Some(state) = self.peers.get_mut(&peer) {
                state.pending.push_back(frame.clone());
            }
            self.drive_sender(&peer, now_ms);
        }
        Ok(())
    }

    /// Feeds one swarm event. Returns `true` when the event belongs to the
    /// floodsub control plane and must not reach the application.
    pub fn handle_event(&mut self, event: &SwarmEvent, now_ms: u64) -> bool {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id } => {
                self.on_connection_established(peer_id, now_ms);
                false
            }
            SwarmEvent::ConnectionClosed { peer_id } => {
                self.on_connection_closed(peer_id);
                false
            }
            SwarmEvent::PeerReady { peer_id, protocols } => {
                if protocols.iter().any(|p| p == FLOODSUB_PROTOCOL_ID) {
                    // Entry-or-initialize: inbound traffic may have created
                    // the state already; only a supersede starts fresh.
                    self.peers.entry(peer_id.clone()).or_default();
                    self.drive_sender(peer_id, now_ms);
                }
                false
            }
            SwarmEvent::StreamReady {
                peer_id,
                stream_id,
                protocol_id,
                initiated_locally,
            } => self.on_stream_ready(peer_id, *stream_id, protocol_id, *initiated_locally, now_ms),
            SwarmEvent::StreamData {
                peer_id,
                stream_id,
                data,
            } => self.on_stream_data(peer_id, *stream_id, data, now_ms),
            SwarmEvent::StreamRemoteWriteClosed { peer_id, stream_id } => {
                self.on_stream_remote_write_closed(peer_id, *stream_id)
            }
            SwarmEvent::StreamClosed { peer_id, stream_id } => {
                self.on_stream_closed(peer_id, *stream_id, now_ms)
            }
            _ => false,
        }
    }

    /// Reports a synchronous failure of a [`PubsubAction::SendStream`].
    ///
    /// Without this feedback, the in-flight sender would sit in
    /// `AwaitingClose` and the stream's eventual close would **commit**
    /// work whose frame was never accepted by the swarm. The failed work
    /// is discarded with an [`PubsubEvent::OutboundFailure`] and the
    /// stream is reset; successful sends need no echo.
    pub fn send_failed(&mut self, peer: &PeerId, stream_id: StreamId, reason: &str, now_ms: u64) {
        let Some(state) = self.peers.get_mut(peer) else {
            return;
        };
        match core::mem::take(&mut state.sender) {
            SendState::AwaitingClose {
                stream_id: expected,
                work,
                ..
            } if expected == stream_id => {
                self.reject_stream(peer, stream_id);
                self.fail_in_flight(peer, work, &format!("send failed: {reason}"));
                self.drive_sender(peer, now_ms);
            }
            other => {
                // Not the in-flight send (stale stream): leave the sender
                // untouched.
                state.sender = other;
            }
        }
    }

    /// Reports the result of a [`PubsubAction::OpenStream`].
    pub fn stream_open_result(
        &mut self,
        token: PubsubToken,
        result: Result<StreamId, String>,
        now_ms: u64,
    ) {
        let Some(peer) = self.tokens.remove(&token) else {
            // The send timed out while opening (or the peer is gone). A
            // late-arriving stream must be reset, not leaked.
            if let (Some(peer), Ok(stream_id)) = (self.stale_tokens.remove(&token), result) {
                self.reject_stream(&peer, stream_id);
            }
            return;
        };
        let Some(state) = self.peers.get_mut(&peer) else {
            return;
        };
        let SendState::Opening {
            token: expected,
            since_ms,
            work,
        } = core::mem::take(&mut state.sender)
        else {
            return;
        };
        if expected != token {
            // A newer open superseded this one; reset the stale stream.
            if let Ok(stream_id) = result {
                self.reject_stream(&peer, stream_id);
            }
            return;
        }
        match result {
            Ok(stream_id) => {
                // `send_timeout_ms` budgets the WHOLE RPC (open through
                // close): keep the original timestamp, or each state
                // transition would grant the deadline anew.
                state.sender = SendState::Negotiating {
                    stream_id,
                    since_ms,
                    work,
                };
                self.roles
                    .entry(peer.clone())
                    .or_default()
                    .insert(stream_id, StreamRole::Outbound);
            }
            Err(reason) => {
                // No immediate re-drive: a synchronously failing open would
                // otherwise spin the subscription re-diff in a tight loop.
                // The next stimulus (PeerReady, publish, subscribe, tick
                // timeout of nothing — i.e. connection events) retries.
                let _ = now_ms;
                self.fail_in_flight(&peer, work, &format!("open failed: {reason}"));
            }
        }
    }

    /// Advances timers: seen-cache GC and stuck-send deadlines.
    pub fn handle_tick(&mut self, now_ms: u64) {
        self.seen.gc(now_ms);

        let deadline = self.config.send_timeout_ms;
        let stuck: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, state)| {
                state
                    .sender
                    .since_ms()
                    .is_some_and(|since| now_ms.saturating_sub(since) >= deadline)
            })
            .map(|(peer, _)| peer.clone())
            .collect();
        for peer in stuck {
            let Some(state) = self.peers.get_mut(&peer) else {
                continue;
            };
            let sender = core::mem::take(&mut state.sender);
            let work = match sender {
                SendState::Idle => continue,
                SendState::Opening { token, work, .. } => {
                    if let Some(peer) = self.tokens.remove(&token) {
                        self.stale_tokens.insert(token, peer);
                    }
                    work
                }
                SendState::Negotiating {
                    stream_id, work, ..
                }
                | SendState::AwaitingClose {
                    stream_id, work, ..
                } => {
                    self.reject_stream(&peer, stream_id);
                    work
                }
            };
            self.fail_in_flight(&peer, work, "send timed out");
            self.drive_sender(&peer, now_ms);
        }
    }

    /// Next action for the driver to execute.
    pub fn poll_action(&mut self) -> Option<PubsubAction> {
        self.actions.pop_front()
    }

    /// Next event for the application.
    pub fn poll_event(&mut self) -> Option<PubsubEvent> {
        self.events.pop_front()
    }

    /// Milliseconds until the next due timer (`Some(0)` = due now), or
    /// `None` when no timer is armed.
    pub fn next_timeout(&self, now_ms: u64) -> Option<u64> {
        let mut due: Option<u64> = self.seen.next_expiry();
        for state in self.peers.values() {
            if let Some(since) = state.sender.since_ms() {
                let deadline = since.saturating_add(self.config.send_timeout_ms);
                due = Some(due.map_or(deadline, |d| d.min(deadline)));
            }
        }
        due.map(|deadline| deadline.saturating_sub(now_ms))
    }

    /// Whether the agent owns `(peer, stream_id)`.
    pub fn owns_stream(&self, peer: &PeerId, stream_id: StreamId) -> bool {
        self.roles
            .get(peer)
            .is_some_and(|streams| streams.contains_key(&stream_id))
    }

    // -----------------------------------------------------------------------
    // Connection lifecycle
    // -----------------------------------------------------------------------

    fn on_connection_established(&mut self, peer: &PeerId, _now_ms: u64) {
        if !self.peers.contains_key(peer) {
            return;
        }
        // A repeat establishment is a supersede: the old connection's
        // streams are gone and stream ids now address the replacement.
        // Start fresh; the remote resends its subscriptions and PeerReady
        // re-queues ours.
        self.drop_peer_work(peer, "connection superseded");
        self.roles.remove(peer);
        self.tokens.retain(|_, dialed| dialed != peer);
        self.stale_tokens.retain(|_, dialed| dialed != peer);
        self.peers.insert(peer.clone(), PeerState::default());
    }

    fn on_connection_closed(&mut self, peer: &PeerId) {
        if !self.peers.contains_key(peer) {
            return;
        }
        self.drop_peer_work(peer, "connection closed");
        self.roles.remove(peer);
        self.tokens.retain(|_, dialed| dialed != peer);
        self.stale_tokens.retain(|_, dialed| dialed != peer);
        self.peers.remove(peer);
    }

    /// Emits the aggregated failure for a peer's queued + in-flight work.
    fn drop_peer_work(&mut self, peer: &PeerId, cause: &str) {
        let Some(state) = self.peers.get(peer) else {
            return;
        };
        let dropped = state.queued_work();
        if dropped > 0 {
            self.events.push_back(PubsubEvent::OutboundFailure {
                peer: peer.clone(),
                reason: format!("{cause}; dropped {dropped} queued RPCs"),
            });
        }
    }

    // -----------------------------------------------------------------------
    // Stream lifecycle
    // -----------------------------------------------------------------------

    fn on_stream_ready(
        &mut self,
        peer: &PeerId,
        stream_id: StreamId,
        protocol_id: &str,
        initiated_locally: bool,
        now_ms: u64,
    ) -> bool {
        if initiated_locally {
            let Some(state) = self.peers.get_mut(peer) else {
                return self.owns_stream(peer, stream_id);
            };
            if let SendState::Negotiating {
                stream_id: expected,
                since_ms,
                work,
            } = core::mem::take(&mut state.sender)
            {
                if expected == stream_id {
                    self.actions.push_back(PubsubAction::SendStream {
                        peer: peer.clone(),
                        stream_id,
                        data: work.frame().to_vec(),
                    });
                    self.actions.push_back(PubsubAction::CloseStreamWrite {
                        peer: peer.clone(),
                        stream_id,
                    });
                    if let Some(state) = self.peers.get_mut(peer) {
                        state.sender = SendState::AwaitingClose {
                            stream_id,
                            since_ms,
                            work,
                        };
                    }
                    return true;
                }
                // Not ours: restore and fall through to the role check.
                if let Some(state) = self.peers.get_mut(peer) {
                    state.sender = SendState::Negotiating {
                        stream_id: expected,
                        since_ms,
                        work,
                    };
                }
            }
            return self.owns_stream(peer, stream_id);
        }

        if protocol_id != FLOODSUB_PROTOCOL_ID {
            return self.owns_stream(peer, stream_id);
        }

        // Inbound floodsub stream. The remote may negotiate before our
        // PeerReady handling ran; it is connected by definition.
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
        let _ = now_ms;
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
            Some(_) => return true, // write-only or rejected: tolerated, dropped
            None => return false,
        }

        // Feed the reassembly buffer in bounded slices, draining complete
        // frames between top-ups. This keeps the buffer capped at one
        // maximum frame WITHOUT rejecting legal traffic the transport
        // coalesced (one data event may carry many frames), and never
        // copies an oversized chunk before the bound is enforced.
        const CAP: usize = MAX_RPC_SIZE + MAX_PREFIX_LEN;
        let mut offset = 0;
        while offset < data.len() {
            {
                let Some(state) = self.peers.get_mut(peer) else {
                    return true;
                };
                let Some(buf) = state.inbound.get_mut(&stream_id) else {
                    return true; // reset mid-drain: swallow the rest
                };
                let room = CAP.saturating_sub(buf.len());
                if room == 0 {
                    // Legal frames always complete within CAP (a declared
                    // length over MAX_RPC_SIZE is rejected from the header
                    // alone), so a full buffer that still decodes as
                    // Incomplete can never legally complete.
                    self.violation_reset(peer, stream_id, "inbound buffer overflow");
                    return true;
                }
                let take = room.min(data.len() - offset);
                buf.extend_from_slice(&data[offset..offset + take]);
                offset += take;
            }

            while let Some(step) = self.take_frame(peer, stream_id) {
                match step {
                    Ok(payload) => match Rpc::decode(&payload) {
                        Ok(rpc) => {
                            if !self.process_rpc(peer, stream_id, rpc, now_ms) {
                                return true;
                            }
                        }
                        Err(e) => {
                            self.violation_reset(peer, stream_id, &format!("malformed RPC: {e}"));
                            return true;
                        }
                    },
                    Err(reason) => {
                        self.violation_reset(peer, stream_id, &reason);
                        return true;
                    }
                }
            }
        }
        true
    }

    /// Pops the next complete frame off a stream's reassembly buffer.
    /// `None` = wait for more bytes; `Some(Err)` = the framing broke.
    fn take_frame(
        &mut self,
        peer: &PeerId,
        stream_id: StreamId,
    ) -> Option<Result<Vec<u8>, String>> {
        let buf = self.peers.get_mut(peer)?.inbound.get_mut(&stream_id)?;
        match decode_frame(buf) {
            FrameDecode::Complete { payload, consumed } => {
                let payload = payload.to_vec();
                buf.drain(..consumed);
                Some(Ok(payload))
            }
            FrameDecode::Incomplete => None,
            FrameDecode::TooLarge { len } => Some(Err(format!("frame of {len} bytes"))),
            FrameDecode::Error(e) => Some(Err(format!("malformed frame: {e}"))),
        }
    }

    fn on_stream_remote_write_closed(&mut self, peer: &PeerId, stream_id: StreamId) -> bool {
        match self.role(peer, stream_id) {
            Some(StreamRole::Inbound) => {}
            Some(_) => return true, // outbound: never advances the sender
            None => return false,
        }

        // Remote EOF. Data events already consumed every complete frame;
        // leftover bytes are a frame that will never complete.
        let leftover = self
            .peers
            .get_mut(peer)
            .and_then(|state| state.inbound.remove(&stream_id))
            .is_some_and(|buf| !buf.is_empty());
        if leftover {
            self.violation_reset(peer, stream_id, "EOF inside a frame");
            return true;
        }
        // Close our (unused) write half so the transport can report the
        // terminal close; the role stays until then.
        self.actions.push_back(PubsubAction::CloseStreamWrite {
            peer: peer.clone(),
            stream_id,
        });
        true
    }

    fn on_stream_closed(&mut self, peer: &PeerId, stream_id: StreamId, now_ms: u64) -> bool {
        let Some(role) = self.role(peer, stream_id) else {
            return false;
        };
        if let Some(streams) = self.roles.get_mut(peer) {
            streams.remove(&stream_id);
            if streams.is_empty() {
                self.roles.remove(peer);
            }
        }
        if role == StreamRole::Outbound
            && let Some(state) = self.peers.get_mut(peer)
        {
            match core::mem::take(&mut state.sender) {
                SendState::AwaitingClose {
                    stream_id: expected,
                    work,
                    ..
                } if expected == stream_id => {
                    // The one place work commits.
                    match work {
                        OutboundWork::Subscriptions { snapshot, .. } => {
                            state.sent_topics = snapshot;
                        }
                        OutboundWork::Publish { .. } => {
                            state.pending.pop_front();
                        }
                    }
                    self.drive_sender(peer, now_ms);
                }
                SendState::Negotiating {
                    stream_id: expected,
                    work,
                    ..
                } if expected == stream_id => {
                    // Closed before the frame was ever sent: failure, not
                    // commit.
                    self.fail_in_flight(peer, work, "stream closed before send");
                    self.drive_sender(peer, now_ms);
                }
                other => {
                    // A stale outbound stream closing must not disturb an
                    // unrelated in-flight send.
                    state.sender = other;
                }
            }
        }
        if role == StreamRole::Inbound
            && let Some(state) = self.peers.get_mut(peer)
        {
            state.inbound.remove(&stream_id);
        }
        true
    }

    // -----------------------------------------------------------------------
    // RPC processing
    // -----------------------------------------------------------------------

    /// Processes one decoded RPC from `peer`. Returns `false` when the
    /// stream was reset (stop draining its buffer).
    fn process_rpc(&mut self, peer: &PeerId, stream_id: StreamId, rpc: Rpc, now_ms: u64) -> bool {
        // Subscriptions apply transactionally: validate the whole resulting
        // set before mutating anything or emitting any event.
        if !rpc.subscriptions.is_empty() {
            let Some(state) = self.peers.get_mut(peer) else {
                return true;
            };
            let mut candidate = state.remote_topics.clone();
            let mut skipped_invalid = false;
            for sub in &rpc.subscriptions {
                let (Some(subscribe), Some(topic)) = (sub.subscribe, sub.topic_id.as_ref()) else {
                    continue; // be liberal: ignore incomplete entries
                };
                if validate_topic(topic).is_err() {
                    // Remote topics obey the same bounds as local ones —
                    // otherwise a peer could park megabytes of topic
                    // strings in `remote_topics`. Skipped, not reset:
                    // the length cap is ours, not the spec's.
                    skipped_invalid = true;
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
            if skipped_invalid {
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
                self.events.push_back(PubsubEvent::PeerUnsubscribed {
                    peer: peer.clone(),
                    topic,
                });
            }
        }

        for message in rpc.publish {
            self.process_message(peer, message, now_ms);
        }
        true
    }

    fn process_message(&mut self, arrival: &PeerId, message: RawMessage, now_ms: u64) {
        let (from, seqno) = match message.verify(self.config.allow_unsigned) {
            Ok(v) => v,
            Err(e) => {
                // A bad message is dropped; the stream survives (only
                // structurally-broken streams get reset).
                self.events.push_back(PubsubEvent::ProtocolViolation {
                    peer: arrival.clone(),
                    reason: format!("message rejected: {e}"),
                });
                return;
            }
        };

        let id: MessageId = (from.to_bytes(), seqno.to_be_bytes());
        if self.seen.contains(&id) {
            return; // duplicate: silent
        }
        self.seen.insert(
            id,
            now_ms,
            self.config.seen_ttl_ms,
            self.config.max_seen_messages,
        );

        if message.topic_ids.iter().any(|t| self.topics.contains(t)) {
            self.events.push_back(PubsubEvent::Message {
                from: from.clone(),
                topics: message.topic_ids.clone(),
                data: message.data.clone().unwrap_or_default(),
                seqno,
            });
        }

        // Flood-forward, embedding the received bytes verbatim: not back to
        // the arrival peer, never to the original publisher.
        let rpc = Rpc {
            subscriptions: Vec::new(),
            publish: alloc::vec![message.clone()],
        };
        let frame = encode_frame(&rpc.encode());
        let recipients: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(candidate, state)| {
                *candidate != arrival
                    && **candidate != from
                    && message
                        .topic_ids
                        .iter()
                        .any(|t| state.remote_topics.contains(t))
            })
            .map(|(peer, _)| peer.clone())
            .collect();
        for peer in recipients {
            let Some(state) = self.peers.get_mut(&peer) else {
                continue;
            };
            if state.pending.len() >= self.config.max_pending_per_peer {
                continue; // best-effort: drop the forward for this peer only
            }
            state.pending.push_back(frame.clone());
            self.drive_sender(&peer, now_ms);
        }
    }

    // -----------------------------------------------------------------------
    // Sender driving
    // -----------------------------------------------------------------------

    fn drive_all_senders(&mut self, now_ms: u64) {
        let peers: Vec<PeerId> = self.peers.keys().cloned().collect();
        for peer in peers {
            self.drive_sender(&peer, now_ms);
        }
    }

    /// Starts the next outbound RPC when the sender is idle: a subscription
    /// diff when the committed snapshot is stale, else the front of the
    /// queue.
    fn drive_sender(&mut self, peer: &PeerId, now_ms: u64) {
        let Some(state) = self.peers.get_mut(peer) else {
            return;
        };
        if !matches!(state.sender, SendState::Idle) {
            return;
        }

        let work = if state.sent_topics != self.topics {
            let mut subscriptions = Vec::new();
            for topic in self.topics.difference(&state.sent_topics) {
                subscriptions.push(SubOpts {
                    subscribe: Some(true),
                    topic_id: Some(topic.clone()),
                });
            }
            for topic in state.sent_topics.difference(&self.topics) {
                subscriptions.push(SubOpts {
                    subscribe: Some(false),
                    topic_id: Some(topic.clone()),
                });
            }
            let rpc = Rpc {
                subscriptions,
                publish: Vec::new(),
            };
            OutboundWork::Subscriptions {
                frame: encode_frame(&rpc.encode()),
                snapshot: self.topics.clone(),
            }
        } else if let Some(front) = state.pending.front() {
            OutboundWork::Publish {
                frame: front.clone(),
            }
        } else {
            return;
        };

        let token = PubsubToken(self.next_token);
        self.next_token += 1;
        self.tokens.insert(token, peer.clone());
        state.sender = SendState::Opening {
            token,
            since_ms: now_ms,
            work,
        };
        self.actions.push_back(PubsubAction::OpenStream {
            token,
            peer: peer.clone(),
            protocol_id: FLOODSUB_PROTOCOL_ID.to_string(),
        });
    }

    /// Discards in-flight work with a per-item failure event. `Publish`
    /// work is popped from the queue here (it was only peeked at start);
    /// a subscription diff needs no revert — `sent_topics` was never
    /// committed, so the next idle pass re-diffs.
    fn fail_in_flight(&mut self, peer: &PeerId, work: OutboundWork, reason: &str) {
        if let OutboundWork::Publish { .. } = work
            && let Some(state) = self.peers.get_mut(peer)
        {
            state.pending.pop_front();
        }
        self.events.push_back(PubsubEvent::OutboundFailure {
            peer: peer.clone(),
            reason: format!("{} discarded: {reason}", work.describe()),
        });
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn role(&self, peer: &PeerId, stream_id: StreamId) -> Option<StreamRole> {
        self.roles
            .get(peer)
            .and_then(|streams| streams.get(&stream_id))
            .copied()
    }

    /// Resets `stream_id` and keeps it owned (role `Rejected`) until its
    /// terminal close, so its remaining events cannot leak to the app.
    fn reject_stream(&mut self, peer: &PeerId, stream_id: StreamId) {
        self.actions.push_back(PubsubAction::ResetStream {
            peer: peer.clone(),
            stream_id,
        });
        self.roles
            .entry(peer.clone())
            .or_default()
            .insert(stream_id, StreamRole::Rejected);
        if let Some(state) = self.peers.get_mut(peer) {
            state.inbound.remove(&stream_id);
        }
    }

    fn violation_reset(&mut self, peer: &PeerId, stream_id: StreamId, reason: &str) {
        self.events.push_back(PubsubEvent::ProtocolViolation {
            peer: peer.clone(),
            reason: reason.to_string(),
        });
        self.reject_stream(peer, stream_id);
    }
}

fn validate_topic(topic: &str) -> Result<(), TopicError> {
    if topic.is_empty() {
        return Err(TopicError::Empty);
    }
    if topic.len() > MAX_TOPIC_LEN {
        return Err(TopicError::TooLong);
    }
    Ok(())
}
