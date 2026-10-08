//! Shared scripted-test harness: a fake clock, canned peers, and frame
//! builders for driving a [`NatAgent`] with no I/O.

// Each integration-test binary compiles its own copy of this module and
// uses a different subset of the helpers.
#![expect(
    dead_code,
    reason = "each integration test imports only the shared helpers it needs"
)]

use minip2p_autonat::{AutoNatServer, AutoNatServerInput, AutoNatServerOutput, ResponseStatus};
use minip2p_core::{ConnectId, Multiaddr, PeerAddr, PeerId, SansIoProtocol};
use minip2p_dcutr::{
    FrameDecode, HolePunch, HolePunchType, decode_frame as dcutr_decode_frame,
    encode_frame as dcutr_encode_frame,
};
use minip2p_nat::{
    BridgeRole, ConnectLegs, DialStart, NatAction, NatAgent, NatConfig, NatEvent, NatSwarm,
    NatSwarmError, NatToken, Now, ReservationPolicy, is_named,
};
use minip2p_relay::{
    HOP_PROTOCOL_ID, HopMessage, HopMessageType, Peer, Reservation, Status, StopMessage,
    StopMessageType, encode_frame as relay_encode_frame,
};
use minip2p_swarm::{DriverError, IdentifyMessage, SwarmError, SwarmEvent};
use minip2p_transport::{Bytes, ConnectionId, StreamId};
use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};

pub const TEST_CIRCUIT_ID: u64 = (1 << 63) | 77;

pub const RACE: ConnectLegs = ConnectLegs {
    direct_racing: true,
    allow_relay: true,
    target_addrs: Vec::new(),
    deadline_ms: None,
};
pub const RELAY_NOW: ConnectLegs = ConnectLegs {
    direct_racing: false,
    allow_relay: true,
    target_addrs: Vec::new(),
    deadline_ms: None,
};
pub const NO_RELAY: ConnectLegs = ConnectLegs {
    direct_racing: true,
    allow_relay: false,
    target_addrs: Vec::new(),
    deadline_ms: None,
};

pub fn start(agent: &mut Node, n: u64, peer: PeerId, legs: ConnectLegs, now: Now) -> ConnectId {
    let id = ConnectId::from_u64(n);
    agent.connect(id, peer, legs, now);
    id
}

pub const TARGET_ADDR: &str = "/ip4/192.0.2.10/udp/4001/quic-v1";
pub const RELAY_TRANSPORT_ADDR: &str = "/ip4/203.0.113.1/udp/4001/quic-v1";
pub const LISTEN_ADDR: &str = "/ip4/198.51.100.5/udp/4500/quic-v1";
pub const REMOTE_OBSERVED_ADDR: &str = "/ip4/8.8.8.8/udp/4002/quic-v1";
/// A public mapping of our own socket, as a peer would report it.
pub const OUR_OBSERVED_ADDR: &str = "/ip4/203.0.113.77/udp/45678/quic-v1";

pub fn peer(tag: &[u8]) -> PeerId {
    PeerId::from_public_key_protobuf(tag)
}

pub fn maddr(s: &str) -> Multiaddr {
    s.parse().expect("valid multiaddr")
}

pub fn at(ms: u64) -> Now {
    Now::from_mono(ms)
}

pub fn at_unix(ms: u64, secs: u64) -> Now {
    Now {
        mono_ms: ms,
        unix_secs: Some(secs),
    }
}

/// A framed HOP STATUS response carrying `status`.
pub fn hop_status(status: Status) -> Vec<u8> {
    let msg = HopMessage {
        kind: HopMessageType::Status,
        peer: None,
        reservation: None,
        limit: None,
        status: Some(status),
    };
    relay_encode_frame(&msg.encode())
}

/// A framed DCUtR CONNECT (the responder's reply) advertising `addrs`.
/// Observed addresses travel as binary multiaddrs on the wire.
pub fn dcutr_connect_reply(addrs: &[Multiaddr]) -> Vec<u8> {
    let msg = HolePunch {
        kind: HolePunchType::Connect,
        obs_addrs: addrs.iter().map(Multiaddr::to_bytes).collect(),
    };
    dcutr_encode_frame(&msg.encode())
}

/// A framed STOP CONNECT from a relay, naming `source_peer_id` (raw bytes).
pub fn stop_connect_raw(source_peer_id: Vec<u8>) -> Vec<u8> {
    let msg = StopMessage {
        kind: StopMessageType::Connect,
        peer: Some(Peer {
            id: source_peer_id,
            addrs: Vec::new(),
        }),
        limit: None,
        status: None,
    };
    relay_encode_frame(&msg.encode())
}

/// A framed STOP CONNECT from a relay, naming `source` as the initiator.
pub fn stop_connect(source: &PeerId) -> Vec<u8> {
    stop_connect_raw(source.to_bytes())
}

/// A framed DCUtR SYNC.
pub fn dcutr_sync() -> Vec<u8> {
    let msg = HolePunch {
        kind: HolePunchType::Sync,
        obs_addrs: Vec::new(),
    };
    dcutr_encode_frame(&msg.encode())
}

/// Counts `SendRandomUdp` actions.
pub fn blast_count(actions: &[Out]) -> usize {
    actions
        .iter()
        .filter(|action| matches!(action, Out::SendRandomUdp { .. }))
        .count()
}

/// A framed HOP STATUS:OK reservation response with an optional expiry.
pub fn hop_reserve_ok(expire_unix_secs: Option<u64>) -> Vec<u8> {
    let msg = HopMessage {
        kind: HopMessageType::Status,
        peer: None,
        reservation: Some(Reservation {
            expire: expire_unix_secs,
            addrs: Vec::new(),
            voucher: None,
        }),
        limit: None,
        status: Some(Status::Ok),
    };
    relay_encode_frame(&msg.encode())
}

/// Runs `request_bytes` through a real [`AutoNatServer`] and returns the
/// wire bytes of the given response — public with `addrs`, or a dial error.
#[expect(
    clippy::panic,
    reason = "the shared test helper must fail at the unexpected AutoNAT response"
)]
pub fn autonat_response(request_bytes: &[u8], public_addrs: Option<&[Multiaddr]>) -> Vec<u8> {
    let mut server = AutoNatServer::new();
    server
        .handle_input(AutoNatServerInput::Data(request_bytes.to_vec()))
        .expect("well-formed AutoNAT request");
    assert!(matches!(
        server.poll_output(),
        Some(AutoNatServerOutput::Request(_))
    ));
    let response = match public_addrs {
        Some(addrs) => AutoNatServerInput::RespondPublic {
            addrs: addrs.to_vec(),
        },
        None => AutoNatServerInput::RespondError {
            status: ResponseStatus::DialError,
            reason: "dial-back failed".into(),
        },
    };
    server.handle_input(response).expect("respond");
    match server.poll_output() {
        Some(AutoNatServerOutput::Outbound(bytes)) => bytes,
        other => panic!("expected outbound response, got {other:?}"),
    }
}

/// Feeds an `IdentifyReceived` event whose `observed_addr` is `addr`'s
/// binary encoding, as if `reporter` told us where it sees us from.
pub fn identify_observed(node: &mut Node, reporter: &PeerId, addr: &Multiaddr, now: Now) {
    node.handle_event(
        &SwarmEvent::IdentifyReceived {
            peer_id: reporter.clone(),
            info: IdentifyMessage {
                observed_addr: Some(addr.to_bytes()),
                ..IdentifyMessage::default()
            },
        },
        false,
        now,
    );
}

/// Decodes the observed addresses out of a framed DCUtR message.
#[expect(
    clippy::panic,
    reason = "the shared test helper requires a complete DCUtR frame"
)]
pub fn dcutr_obs_addrs(frame: &[u8]) -> Vec<Multiaddr> {
    let FrameDecode::Complete { payload, .. } = dcutr_decode_frame(frame) else {
        panic!("expected a complete DCUtR frame");
    };
    let msg = HolePunch::decode(payload).expect("valid HolePunch message");
    msg.obs_addrs
        .iter()
        .map(|bytes| Multiaddr::from_bytes(bytes).expect("valid multiaddr"))
        .collect()
}

/// Extracts the payload of the single `SendStream` on `stream`.
pub fn sent_data_on(actions: &[Out], stream: StreamId) -> Vec<u8> {
    let mut found = actions.iter().filter_map(|action| match action {
        Out::SendStream {
            stream_id, data, ..
        } if *stream_id == stream => Some(data.clone()),
        _ => None,
    });
    let data = found.next().expect("expected a SendStream on the stream");
    assert!(found.next().is_none(), "more than one SendStream");
    data
}

/// Finds the token of the single parked `Dial` targeting `peer`.
pub fn dial_token_for(actions: &[Out], peer: &PeerId) -> NatToken {
    let mut tokens = actions.iter().filter_map(|action| match action {
        Out::Dial {
            token,
            addr,
            conn: None,
        } if addr.peer_id() == peer => Some(*token),
        _ => None,
    });
    let token = tokens.next().expect("expected a parked Dial for the peer");
    assert!(tokens.next().is_none(), "more than one Dial for the peer");
    token
}

/// Finds the connection of the single started `Dial` targeting `peer`.
pub fn dial_conn_for(actions: &[Out], peer: &PeerId) -> ConnectionId {
    let mut conns = actions.iter().filter_map(|action| match action {
        Out::Dial {
            addr,
            conn: Some(conn),
            ..
        } if addr.peer_id() == peer => Some(*conn),
        _ => None,
    });
    let conn = conns.next().expect("expected a started Dial for the peer");
    assert!(conns.next().is_none(), "more than one Dial for the peer");
    conn
}

/// Counts `Dial`s targeting `peer`.
pub fn dial_count_for(actions: &[Out], peer: &PeerId) -> usize {
    actions
        .iter()
        .filter(|action| matches!(action, Out::Dial { addr, .. } if addr.peer_id() == peer))
        .count()
}

/// Finds the stream of the single successful `OpenStream` toward `peer`.
pub fn opened_stream_for(actions: &[Out], peer: &PeerId) -> StreamId {
    let mut streams = actions.iter().filter_map(|action| match action {
        Out::OpenStream {
            peer: p,
            opened: Some((_, stream)),
            ..
        } if p == peer => Some(*stream),
        _ => None,
    });
    let stream = streams.next().expect("expected an OpenStream for the peer");
    assert!(
        streams.next().is_none(),
        "more than one OpenStream for peer"
    );
    stream
}

/// Finds the stream of the single successful `OpenStream`.
pub fn opened_stream(actions: &[Out]) -> StreamId {
    let mut streams = actions.iter().filter_map(|action| match action {
        Out::OpenStream {
            opened: Some((_, stream)),
            ..
        } => Some(*stream),
        _ => None,
    });
    let stream = streams.next().expect("expected an OpenStream");
    assert!(streams.next().is_none(), "more than one OpenStream");
    stream
}

pub fn has_hop_open(actions: &[Out]) -> bool {
    actions.iter().any(|action| {
        matches!(
            action,
            Out::OpenStream { protocol_id, .. } if protocol_id == HOP_PROTOCOL_ID
        )
    })
}

pub fn send_stream_count(actions: &[Out]) -> usize {
    actions
        .iter()
        .filter(|action| matches!(action, Out::SendStream { .. }))
        .count()
}

pub fn has_reset_for(actions: &[Out], stream: StreamId) -> bool {
    actions
        .iter()
        .any(|action| matches!(action, Out::ResetStream { stream_id, .. } if *stream_id == stream))
}

pub fn promote_token(actions: &[Out]) -> NatToken {
    let mut tokens = actions.iter().filter_map(|action| match action {
        Out::PromoteBridge { token, .. } => Some(*token),
        _ => None,
    });
    let token = tokens.next().expect("expected PromoteBridge action");
    assert!(tokens.next().is_none(), "more than one promotion action");
    token
}

pub fn promoted_pending_data(actions: &[Out]) -> &[u8] {
    actions
        .iter()
        .find_map(|action| match action {
            Out::PromoteBridge { pending_data, .. } => Some(pending_data.as_slice()),
            _ => None,
        })
        .expect("expected PromoteBridge action")
}

pub fn complete_promotion(
    node: &mut Node,
    target: &PeerId,
    actions: &[Out],
    now: Now,
) -> ConnectionId {
    let conn_id = ConnectionId::new(TEST_CIRCUIT_ID);
    node.promote_result(promote_token(actions), Ok(conn_id), now);
    node.handle_event(
        &SwarmEvent::ConnectionEstablished {
            peer_id: target.clone(),
            conn_id,
        },
        true,
        now,
    );
    conn_id
}

/// Scripted world around one agent: a local node, a target peer, and one
/// configured relay.
pub struct Harness {
    pub agent: Node,
    pub local: PeerId,
    pub target: PeerId,
    pub relay: PeerId,
    pub relay_addr: PeerAddr,
    next_connect: u64,
}

impl Harness {
    /// An agent with one relay configured and a validated listen address.
    ///
    /// Reservation housekeeping is disabled: this harness scripts the
    /// dialer-side race in isolation. Housekeeping tests configure their
    /// own policy explicitly.
    pub fn with_relay(mut config: NatConfig) -> Self {
        let local = peer(b"local-peer");
        let target = peer(b"target-peer");
        let relay = peer(b"relay-peer");
        let relay_addr =
            PeerAddr::new(maddr(RELAY_TRANSPORT_ADDR), relay.clone()).expect("valid relay addr");
        config.relays = vec![relay_addr.clone()];
        config.reservation_policy = ReservationPolicy::Never;
        let mut agent = Node::new(local.clone(), config);
        agent.set_listen_addrs(&[maddr(LISTEN_ADDR)]);
        Self {
            agent,
            local,
            target,
            relay,
            relay_addr,
            next_connect: 1,
        }
    }

    /// An agent with no relay configured.
    pub fn without_relay(config: NatConfig) -> Self {
        let local = peer(b"local-peer");
        let target = peer(b"target-peer");
        let relay = peer(b"relay-peer");
        let relay_addr =
            PeerAddr::new(maddr(RELAY_TRANSPORT_ADDR), relay.clone()).expect("valid relay addr");
        let mut agent = Node::new(local.clone(), config);
        agent.set_listen_addrs(&[maddr(LISTEN_ADDR)]);
        Self {
            agent,
            local,
            target,
            relay,
            relay_addr,
            next_connect: 1,
        }
    }

    pub fn start(&mut self, legs: ConnectLegs, now: Now) -> ConnectId {
        self.start_peer(self.target.clone(), legs, now)
    }

    pub fn start_peer(&mut self, peer: PeerId, legs: ConnectLegs, now: Now) -> ConnectId {
        let id = ConnectId::from_u64(self.next_connect);
        self.next_connect += 1;
        self.agent.connect(id, peer, legs, now);
        id
    }

    /// Marks the relay connection as established and identify-complete
    /// (advertising the HOP protocol).
    pub fn relay_session_ready(&mut self, now: Now) {
        self.agent.handle_event(
            &SwarmEvent::ConnectionEstablished {
                conn_id: minip2p_transport::ConnectionId::new(1),
                peer_id: self.relay.clone(),
            },
            false,
            now,
        );
        self.agent.handle_event(
            &SwarmEvent::PeerReady {
                peer_id: self.relay.clone(),
                conn_id: ConnectionId::new(1),
                protocols: vec![HOP_PROTOCOL_ID.to_string()],
            },
            false,
            now,
        );
    }

    pub fn stream_ready(&mut self, stream: StreamId, now: Now) {
        self.agent.handle_event(
            &SwarmEvent::StreamReady {
                conn_id: minip2p_transport::ConnectionId::new(1),
                peer_id: self.relay.clone(),
                stream_id: stream,
                protocol_id: HOP_PROTOCOL_ID.to_string(),
                initiated_locally: true,
            },
            false,
            now,
        );
    }

    pub fn stream_data(&mut self, stream: StreamId, data: Vec<u8>, now: Now) {
        self.agent.handle_event(
            &SwarmEvent::StreamData {
                conn_id: minip2p_transport::ConnectionId::new(1),
                peer_id: self.relay.clone(),
                stream_id: stream,
                data: Bytes::from(data),
            },
            false,
            now,
        );
    }

    pub fn target_connected(&mut self, now: Now) {
        self.agent.handle_event(
            &SwarmEvent::ConnectionEstablished {
                conn_id: minip2p_transport::ConnectionId::new(1),
                peer_id: self.target.clone(),
            },
            false,
            now,
        );
    }
}

/// One swarm command the agent issued or one action it queued, in the shape
/// tests assert on. Swarm commands carry what the fake swarm answered.
#[derive(Clone, Debug)]
pub enum Out {
    /// `conn` is `None` for a dial the fake parked (named address).
    Dial {
        token: NatToken,
        addr: PeerAddr,
        conn: Option<ConnectionId>,
    },
    /// `opened` is `None` when the fake refused the open.
    OpenStream {
        peer: PeerId,
        protocol_id: String,
        opened: Option<(ConnectionId, StreamId)>,
    },
    SendStream {
        peer: PeerId,
        conn: ConnectionId,
        stream_id: StreamId,
        data: Vec<u8>,
    },
    CloseStreamWrite {
        peer: PeerId,
        conn: ConnectionId,
        stream_id: StreamId,
    },
    ResetStream {
        peer: PeerId,
        conn: ConnectionId,
        stream_id: StreamId,
    },
    Ping {
        peer: PeerId,
    },
    SendRandomUdp {
        target: Multiaddr,
        payload_len: usize,
    },
    PromoteBridge {
        token: NatToken,
        inner_conn: ConnectionId,
        relay: PeerId,
        stream_id: StreamId,
        remote_peer: PeerId,
        role: BridgeRole,
        pending_data: Vec<u8>,
        remote_write_closed: bool,
    },
    CloseCircuit {
        conn_id: ConnectionId,
    },
}

impl From<NatAction> for Out {
    fn from(action: NatAction) -> Self {
        match action {
            NatAction::SendRandomUdp {
                target,
                payload_len,
            } => Out::SendRandomUdp {
                target,
                payload_len,
            },
            NatAction::PromoteBridge {
                token,
                inner_conn,
                relay,
                stream_id,
                remote_peer,
                role,
                pending_data,
                remote_write_closed,
            } => Out::PromoteBridge {
                token,
                inner_conn,
                relay,
                stream_id,
                remote_peer,
                role,
                pending_data,
                remote_write_closed,
            },
            NatAction::CloseCircuit { conn_id } => Out::CloseCircuit { conn_id },
        }
    }
}

/// The scripted swarm every NAT test runs against: connection and readiness
/// state mirrored from the events a test feeds, and a log of the commands
/// the agent issued. Dials start connections numbered from 1000 and streams
/// are numbered from 1000; tests read both back from the log.
#[derive(Default)]
pub struct FakeSwarm {
    connections: BTreeMap<PeerId, ConnectionId>,
    ready: BTreeMap<PeerId, (ConnectionId, Vec<String>)>,
    calls: Vec<Out>,
    next_conn: u64,
    next_stream: u64,
    /// Park dials to named addresses instead of rejecting them.
    pub park_named: bool,
    /// Refuse every dial with this reason.
    pub refuse_dials: Option<String>,
    /// Refuse every stream open with this reason.
    pub refuse_opens: Option<String>,
    /// The id the next stream open returns, as a transport that numbers
    /// streams per connection reuses ids across connections.
    pub next_stream_id: Option<StreamId>,
}

impl FakeSwarm {
    /// Applies `event` to the mirrored connection and readiness state, as a
    /// swarm does before it delivers the event.
    pub fn apply(&mut self, event: &SwarmEvent) {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, conn_id } => {
                self.connect(peer_id, *conn_id);
            }
            SwarmEvent::ConnectionReplaced { peer_id, new, .. } => self.connect(peer_id, *new),
            SwarmEvent::ConnectionClosed { peer_id, conn_id } => {
                if self.connections.get(peer_id) == Some(conn_id) {
                    self.connections.remove(peer_id);
                    self.ready.remove(peer_id);
                }
            }
            SwarmEvent::PeerReady {
                peer_id,
                conn_id,
                protocols,
            } => self.make_ready(peer_id, *conn_id, protocols),
            _ => {}
        }
    }

    /// Makes `conn` `peer`'s current, not yet ready, connection.
    pub fn connect(&mut self, peer: &PeerId, conn: ConnectionId) {
        self.connections.insert(peer.clone(), conn);
        self.ready.remove(peer);
    }

    /// Marks `conn` as `peer`'s ready connection advertising `protocols`.
    pub fn make_ready(&mut self, peer: &PeerId, conn: ConnectionId, protocols: &[String]) {
        self.connections.insert(peer.clone(), conn);
        self.ready.insert(peer.clone(), (conn, protocols.to_vec()));
    }

    /// Drops `peer`'s connection without an event.
    pub fn disconnect(&mut self, peer: &PeerId) {
        self.connections.remove(peer);
        self.ready.remove(peer);
    }

    pub fn take_calls(&mut self) -> Vec<Out> {
        core::mem::take(&mut self.calls)
    }
}

impl NatSwarm for FakeSwarm {
    fn connection(&self, peer: &PeerId) -> Option<ConnectionId> {
        self.connections.get(peer).copied()
    }

    fn readiness(&self, peer: &PeerId) -> Option<(ConnectionId, &[String])> {
        self.ready
            .get(peer)
            .map(|(conn, protocols)| (*conn, protocols.as_slice()))
    }

    fn dial(&mut self, addr: &PeerAddr, token: NatToken) -> Result<DialStart, NatSwarmError> {
        if let Some(reason) = &self.refuse_dials {
            return Err(NatSwarmError::Swarm(DriverError::Invariant {
                reason: Box::leak(reason.clone().into_boxed_str()),
            }));
        }
        let start = if is_named(addr) {
            if !self.park_named {
                return Err(NatSwarmError::NamedAddress(addr.clone()));
            }
            DialStart::Deferred(token)
        } else {
            self.next_conn += 1;
            DialStart::Started(ConnectionId::new(1_000 + self.next_conn))
        };
        self.calls.push(Out::Dial {
            token,
            addr: addr.clone(),
            conn: match start {
                DialStart::Started(conn) => Some(conn),
                DialStart::Deferred(_) => None,
            },
        });
        Ok(start)
    }

    fn open_stream(
        &mut self,
        peer: &PeerId,
        protocol_id: &str,
        _now_ms: u64,
    ) -> Result<(ConnectionId, StreamId), NatSwarmError> {
        let opened = match (&self.refuse_opens, self.connections.get(peer)) {
            (None, Some(conn)) => {
                self.next_stream += 1;
                let stream = self
                    .next_stream_id
                    .take()
                    .unwrap_or(StreamId::new(1_000 + self.next_stream));
                Some((*conn, stream))
            }
            _ => None,
        };
        self.calls.push(Out::OpenStream {
            peer: peer.clone(),
            protocol_id: protocol_id.into(),
            opened,
        });
        opened.ok_or_else(|| {
            NatSwarmError::Swarm(DriverError::Swarm(SwarmError::NotConnected {
                peer_id: peer.clone(),
            }))
        })
    }

    fn send_stream(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
        _now_ms: u64,
    ) -> Result<(), NatSwarmError> {
        self.calls.push(Out::SendStream {
            peer: peer.clone(),
            conn: conn_id,
            stream_id,
            data: data.to_vec(),
        });
        Ok(())
    }

    fn close_stream_write(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        _now_ms: u64,
    ) -> Result<(), NatSwarmError> {
        self.calls.push(Out::CloseStreamWrite {
            peer: peer.clone(),
            conn: conn_id,
            stream_id,
        });
        Ok(())
    }

    fn reset_stream(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        _now_ms: u64,
    ) -> Result<(), NatSwarmError> {
        self.calls.push(Out::ResetStream {
            peer: peer.clone(),
            conn: conn_id,
            stream_id,
        });
        Ok(())
    }

    fn ping(&mut self, peer: &PeerId, _now_ms: u64) -> Result<(), NatSwarmError> {
        self.calls.push(Out::Ping { peer: peer.clone() });
        Ok(())
    }
}

/// A [`NatAgent`] wired to its own [`FakeSwarm`]. Agent calls that take
/// the swarm are wrapped; the rest reach the agent through `Deref`.
pub struct Node {
    pub agent: NatAgent,
    pub swarm: FakeSwarm,
}

impl Deref for Node {
    type Target = NatAgent;
    fn deref(&self) -> &NatAgent {
        &self.agent
    }
}

impl DerefMut for Node {
    fn deref_mut(&mut self) -> &mut NatAgent {
        &mut self.agent
    }
}

impl Node {
    pub fn new(local: PeerId, config: NatConfig) -> Self {
        Self {
            agent: NatAgent::new(local, config),
            swarm: FakeSwarm::default(),
        }
    }

    pub fn connect(&mut self, id: ConnectId, peer: PeerId, legs: ConnectLegs, now: Now) {
        self.agent.connect(&mut self.swarm, id, peer, legs, now);
    }

    pub fn cancel(&mut self, id: ConnectId, now: Now) {
        self.agent.cancel(&mut self.swarm, id, now);
    }

    /// Mirrors `event` into the fake swarm, then feeds it to the agent.
    pub fn handle_event(&mut self, event: &SwarmEvent, is_circuit: bool, now: Now) -> bool {
        self.swarm.apply(event);
        self.agent
            .handle_event(&mut self.swarm, event, is_circuit, now)
    }

    /// Feeds `event` without mirroring it: the fake swarm is already past
    /// it, as when a host hands over events it buffered.
    pub fn deliver_late(&mut self, event: &SwarmEvent, is_circuit: bool, now: Now) -> bool {
        self.agent
            .handle_event(&mut self.swarm, event, is_circuit, now)
    }

    pub fn handle_tick(&mut self, now: Now) {
        self.agent.handle_tick(&mut self.swarm, now);
    }

    pub fn dial_result(&mut self, token: NatToken, result: Result<ConnectionId, String>, now: Now) {
        self.agent.dial_result(&mut self.swarm, token, result, now);
    }

    pub fn promote_result(
        &mut self,
        token: NatToken,
        result: Result<ConnectionId, minip2p_nat::PromoteError>,
        now: Now,
    ) {
        self.agent
            .promote_result(&mut self.swarm, token, result, now);
    }

    pub fn path(&self, peer: &PeerId) -> Option<&minip2p_nat::Path> {
        self.agent.path(&self.swarm, peer)
    }
}

/// Everything the agent did since the last drain: swarm commands first, in
/// issue order, then queued actions.
pub fn drain_actions(node: &mut Node) -> Vec<Out> {
    let mut out = node.swarm.take_calls();
    out.extend(core::iter::from_fn(|| node.agent.poll_action()).map(Out::from));
    out
}

pub fn drain_events(node: &mut Node) -> Vec<NatEvent> {
    core::iter::from_fn(|| node.agent.poll_event()).collect()
}
