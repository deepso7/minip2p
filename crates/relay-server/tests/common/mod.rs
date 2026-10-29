//! Shared scripted-test harness: a fake [`RelaySwarm`] that logs every
//! command the agent issues, and helpers that drive a [`RelayServerAgent`]
//! through it with no I/O.

// Each integration-test binary compiles its own copy of this module and
// uses a different subset of the helpers.
#![expect(
    dead_code,
    reason = "each integration test imports only the shared helpers it needs"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

use minip2p_core::platform::Now;
use minip2p_core::{Multiaddr, PeerId};
use minip2p_relay::{
    HOP_PROTOCOL_ID, HopMessage, HopMessageType, Peer, STOP_PROTOCOL_ID, Status, encode_frame,
    encode_stop_status,
};
use minip2p_relay_server::{
    RelayServerAgent, RelayServerConfig, RelayServerEvent, RelaySwarm, RelaySwarmError, StreamKey,
};
use minip2p_swarm::{DriverError, SwarmError, SwarmEvent};
use minip2p_transport::{Bytes, ConnectionId, StreamId, TransportError};

/// The remote address a connection gets when a test names none. It names a
/// host, not an IP, so the connection has no admission key.
pub const DEFAULT_REMOTE_ADDR: &str = "/dns4/peer.invalid/tcp/4001";

/// One command the agent issued, with what the fake swarm answered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Call {
    /// `opened` is `None` when the fake refused the open.
    Open {
        peer: PeerId,
        protocol_id: String,
        opened: Option<StreamKey>,
    },
    /// The whole chunk written, and how much of it the stream took.
    Send {
        peer: PeerId,
        stream: StreamKey,
        data: Vec<u8>,
        accepted: usize,
    },
    Ack {
        stream: StreamKey,
        bytes: usize,
    },
    Close {
        peer: PeerId,
        stream: StreamKey,
    },
    Reset {
        peer: PeerId,
        stream: StreamKey,
    },
}

/// The scripted swarm every relay-server test runs against: connection
/// state mirrored from the events a test feeds, scripted write outcomes, and
/// a log of the commands the agent issued. Opened streams are numbered from
/// 1000 on the peer's current connection unless a test picks one.
#[derive(Default)]
pub struct FakeSwarm {
    connections: BTreeMap<PeerId, ConnectionId>,
    /// Each live connection's remote address.
    pub remote_addrs: BTreeMap<ConnectionId, Multiaddr>,
    calls: Vec<Call>,
    next_stream: u64,
    /// The stream the next open returns, whatever connection it is on.
    pub next_open: Option<StreamKey>,
    /// Refuse every stream open.
    pub refuse_opens: bool,
    /// Streams that take at most this many more bytes, refusing the rest
    /// as Full. A stream not listed takes everything.
    pub credit: BTreeMap<StreamKey, usize>,
    /// Streams whose writes fail outright.
    pub failing_sends: BTreeSet<StreamKey>,
    /// Streams whose half-closes fail.
    pub failing_closes: BTreeSet<StreamKey>,
}

impl FakeSwarm {
    /// Applies `event` to the mirrored connection state, as a swarm does
    /// before it delivers the event.
    pub fn apply(&mut self, event: &SwarmEvent) {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, conn_id } => {
                self.connect(peer_id, *conn_id);
            }
            SwarmEvent::ConnectionReplaced { peer_id, old, new } => {
                self.remote_addrs.remove(old);
                self.connect(peer_id, *new);
            }
            SwarmEvent::ConnectionClosed {
                peer_id, conn_id, ..
            } => {
                if self.connections.get(peer_id) == Some(conn_id) {
                    self.connections.remove(peer_id);
                }
                self.remote_addrs.remove(conn_id);
            }
            _ => {}
        }
    }

    /// Makes `conn` `peer`'s current connection.
    pub fn connect(&mut self, peer: &PeerId, conn: ConnectionId) {
        self.connections.insert(peer.clone(), conn);
        self.remote_addrs
            .entry(conn)
            .or_insert_with(|| maddr(DEFAULT_REMOTE_ADDR));
    }

    pub fn take_calls(&mut self) -> Vec<Call> {
        core::mem::take(&mut self.calls)
    }
}

impl RelaySwarm for FakeSwarm {
    fn connection_remote_addr(&self, conn_id: ConnectionId) -> Option<&Multiaddr> {
        self.remote_addrs.get(&conn_id)
    }

    fn open_stream(
        &mut self,
        peer: &PeerId,
        protocol_id: &str,
        _now_ms: u64,
    ) -> Result<StreamKey, RelaySwarmError> {
        let opened = match (self.refuse_opens, self.connections.get(peer)) {
            (false, Some(conn_id)) => {
                self.next_stream += 1;
                Some(self.next_open.take().unwrap_or(StreamKey {
                    conn_id: *conn_id,
                    stream_id: StreamId::new(1_000 + self.next_stream),
                }))
            }
            _ => None,
        };
        self.calls.push(Call::Open {
            peer: peer.clone(),
            protocol_id: protocol_id.into(),
            opened,
        });
        opened.ok_or_else(|| {
            RelaySwarmError(DriverError::Swarm(SwarmError::NotConnected {
                peer_id: peer.clone(),
            }))
        })
    }

    fn send_stream(
        &mut self,
        peer: &PeerId,
        stream: StreamKey,
        data: Bytes,
        _now_ms: u64,
    ) -> Result<(), RelaySwarmError> {
        if self.failing_sends.contains(&stream) {
            self.calls.push(Call::Send {
                peer: peer.clone(),
                stream,
                data: data.to_vec(),
                accepted: 0,
            });
            return Err(RelaySwarmError(DriverError::Transport(
                TransportError::StreamNotFound {
                    id: stream.conn_id,
                    stream_id: stream.stream_id,
                },
            )));
        }
        let accepted = match self.credit.get_mut(&stream) {
            Some(credit) => {
                let accepted = data.len().min(*credit);
                *credit -= accepted;
                accepted
            }
            None => data.len(),
        };
        self.calls.push(Call::Send {
            peer: peer.clone(),
            stream,
            data: data.to_vec(),
            accepted,
        });
        if accepted < data.len() {
            return Err(RelaySwarmError(DriverError::Full {
                conn_id: stream.conn_id,
                stream_id: stream.stream_id,
                unsent: data.slice(accepted..),
            }));
        }
        Ok(())
    }

    fn ack_stream(&mut self, stream: StreamKey, bytes: usize) {
        self.calls.push(Call::Ack { stream, bytes });
    }

    fn close_stream_write(
        &mut self,
        peer: &PeerId,
        stream: StreamKey,
        _now_ms: u64,
    ) -> Result<(), RelaySwarmError> {
        self.calls.push(Call::Close {
            peer: peer.clone(),
            stream,
        });
        if self.failing_closes.contains(&stream) {
            return Err(RelaySwarmError(DriverError::Invariant {
                reason: "scripted close failure",
            }));
        }
        Ok(())
    }

    fn reset_stream(
        &mut self,
        peer: &PeerId,
        stream: StreamKey,
        _now_ms: u64,
    ) -> Result<(), RelaySwarmError> {
        self.calls.push(Call::Reset {
            peer: peer.clone(),
            stream,
        });
        Ok(())
    }
}

/// A [`RelayServerAgent`] wired to its own [`FakeSwarm`]. Agent calls that
/// take the swarm are wrapped, and check the agent's indexes after each;
/// the rest reach the agent through `Deref`.
pub struct Node {
    pub agent: RelayServerAgent,
    pub swarm: FakeSwarm,
}

impl Deref for Node {
    type Target = RelayServerAgent;
    fn deref(&self) -> &RelayServerAgent {
        &self.agent
    }
}

impl DerefMut for Node {
    fn deref_mut(&mut self) -> &mut RelayServerAgent {
        &mut self.agent
    }
}

impl Node {
    /// A relay announcing [`direct_addr`].
    pub fn new(config: RelayServerConfig) -> Self {
        let mut node = Self::unannounced(config);
        node.agent
            .replace_announce_addrs(vec![direct_addr()])
            .expect("valid announce address");
        node
    }

    /// A relay with no address to announce.
    pub fn unannounced(config: RelayServerConfig) -> Self {
        Self {
            agent: RelayServerAgent::new(peer(b"relay"), config).expect("valid config"),
            swarm: FakeSwarm::default(),
        }
    }

    /// Mirrors `event` into the fake swarm, then feeds it to the agent.
    pub fn handle_event(&mut self, event: &SwarmEvent, is_circuit: bool, now: Now) -> bool {
        self.swarm.apply(event);
        let claimed = self
            .agent
            .handle_event(&mut self.swarm, event, is_circuit, now);
        self.agent.assert_indexes_consistent();
        claimed
    }

    pub fn handle_tick(&mut self, now: Now) {
        self.agent.handle_tick(&mut self.swarm, now);
        self.agent.assert_indexes_consistent();
    }

    /// Every command the agent issued since the last call.
    pub fn calls(&mut self) -> Vec<Call> {
        self.swarm.take_calls()
    }

    /// Every event the agent emitted since the last call.
    pub fn events(&mut self) -> Vec<RelayServerEvent> {
        core::iter::from_fn(|| self.agent.poll_event()).collect()
    }

    pub fn establish(&mut self, peer: &PeerId, conn_id: ConnectionId) {
        self.establish_as(peer, conn_id, false);
    }

    /// Establishes `conn_id` from `address`, its admission key.
    pub fn establish_from(&mut self, peer: &PeerId, conn_id: ConnectionId, address: &str) {
        self.swarm.remote_addrs.insert(conn_id, maddr(address));
        self.establish(peer, conn_id);
    }

    pub fn establish_as(&mut self, peer: &PeerId, conn_id: ConnectionId, is_circuit: bool) {
        self.handle_event(
            &SwarmEvent::ConnectionEstablished {
                peer_id: peer.clone(),
                conn_id,
            },
            is_circuit,
            at(0),
        );
    }

    pub fn replace(
        &mut self,
        peer: &PeerId,
        old: ConnectionId,
        new: ConnectionId,
        new_is_circuit: bool,
        now_ms: u64,
    ) {
        self.handle_event(
            &SwarmEvent::ConnectionReplaced {
                peer_id: peer.clone(),
                old,
                new,
            },
            new_is_circuit,
            at(now_ms),
        );
    }

    pub fn close_connection(&mut self, peer: &PeerId, conn_id: ConnectionId, now_ms: u64) {
        self.handle_event(
            &SwarmEvent::ConnectionClosed {
                peer_id: peer.clone(),
                conn_id,
                reason: minip2p_swarm::ConnectionCloseReason::Local,
            },
            false,
            at(now_ms),
        );
    }

    /// An inbound HOP stream finished negotiating.
    pub fn hop_ready(&mut self, peer: &PeerId, stream: StreamKey, now: Now) -> bool {
        self.handle_event(
            &SwarmEvent::StreamReady {
                peer_id: peer.clone(),
                conn_id: stream.conn_id,
                stream_id: stream.stream_id,
                protocol_id: HOP_PROTOCOL_ID.into(),
                initiated_locally: false,
            },
            false,
            now,
        )
    }

    /// The relay's outbound STOP stream finished negotiating.
    pub fn stop_ready(&mut self, peer: &PeerId, stream: StreamKey, now: Now) -> bool {
        self.handle_event(
            &SwarmEvent::StreamReady {
                peer_id: peer.clone(),
                conn_id: stream.conn_id,
                stream_id: stream.stream_id,
                protocol_id: STOP_PROTOCOL_ID.into(),
                initiated_locally: true,
            },
            false,
            now,
        )
    }

    /// Opens a HOP stream at time 0 and delivers `request`, with
    /// `pipelined` coalesced behind it.
    pub fn feed_hop(
        &mut self,
        peer: &PeerId,
        stream: StreamKey,
        request: HopMessage,
        pipelined: &[u8],
    ) {
        self.hop_ready(peer, stream, at(0));
        let mut data = encode_frame(&request.encode());
        data.extend_from_slice(pipelined);
        self.data(peer, stream, &data, at(0));
    }

    pub fn data(&mut self, peer: &PeerId, stream: StreamKey, data: &[u8], now: Now) -> bool {
        self.handle_event(
            &SwarmEvent::StreamData {
                peer_id: peer.clone(),
                conn_id: stream.conn_id,
                stream_id: stream.stream_id,
                data: Bytes::copy_from_slice(data),
            },
            false,
            now,
        )
    }

    pub fn stop_status(&mut self, peer: &PeerId, stream: StreamKey, status: Status, now: Now) {
        self.data(peer, stream, &stop_status(status), now);
    }

    pub fn half_close(&mut self, peer: &PeerId, stream: StreamKey, now: Now) -> bool {
        self.handle_event(
            &SwarmEvent::StreamRemoteWriteClosed {
                peer_id: peer.clone(),
                conn_id: stream.conn_id,
                stream_id: stream.stream_id,
            },
            false,
            now,
        )
    }

    pub fn stream_closed(&mut self, peer: &PeerId, stream: StreamKey, now: Now) -> bool {
        self.handle_event(
            &SwarmEvent::StreamClosed {
                peer_id: peer.clone(),
                conn_id: stream.conn_id,
                stream_id: stream.stream_id,
            },
            false,
            now,
        )
    }

    pub fn writable(&mut self, peer: &PeerId, stream: StreamKey, now: Now) -> bool {
        self.handle_event(
            &SwarmEvent::StreamWritable {
                peer_id: peer.clone(),
                conn_id: stream.conn_id,
                stream_id: stream.stream_id,
            },
            false,
            now,
        )
    }

    /// Commits `peer`'s reservation over `stream`, then forgets the
    /// commands and the event it took.
    pub fn reserve(&mut self, peer: &PeerId, stream: StreamKey) {
        self.establish(peer, stream.conn_id);
        self.feed_hop(peer, stream, reserve_request(), &[]);
        let events = self.events();
        assert!(
            matches!(events[..], [RelayServerEvent::ReservationAccepted { .. }]),
            "{events:?}"
        );
        self.calls();
    }
}

/// A relay with one reserved destination (connection 60) and a source
/// (connection 61) whose CONNECT is waiting on its STOP exchange.
pub struct Fixture {
    pub node: Node,
    pub source: PeerId,
    pub destination: PeerId,
    pub source_stream: StreamKey,
    pub stop_stream: StreamKey,
}

pub const DESTINATION_CONN: ConnectionId = ConnectionId::new(60);
pub const SOURCE_CONN: ConnectionId = ConnectionId::new(61);

/// A CONNECT admitted, its STOP stream negotiated at `now_ms` and its STOP
/// request sent. Rate limits are off.
pub fn pending_stop(config: RelayServerConfig, now_ms: u64) -> Fixture {
    pending_stop_with_payload(config, now_ms, &[])
}

/// [`pending_stop`] with `pipelined` payload in the CONNECT's read.
pub fn pending_stop_with_payload(
    config: RelayServerConfig,
    now_ms: u64,
    pipelined: &[u8],
) -> Fixture {
    let mut fixture = opening_stop_with_payload(config, pipelined);
    assert!(
        fixture
            .node
            .stop_ready(&fixture.destination, fixture.stop_stream, at(now_ms))
    );
    let calls = fixture.node.calls();
    assert_eq!(
        sends_on(&calls, fixture.stop_stream).len(),
        1,
        "STOP request"
    );
    fixture
}

/// A CONNECT admitted at time 0 whose STOP stream (stream 3 on connection
/// 60) is still negotiating. Rate limits are off.
pub fn opening_stop(config: RelayServerConfig) -> Fixture {
    opening_stop_with_payload(config, &[])
}

fn opening_stop_with_payload(mut config: RelayServerConfig, pipelined: &[u8]) -> Fixture {
    config.reservation_rate_limit_per_peer = None;
    config.reservation_rate_limit_per_ip = None;
    config.circuit_rate_limit_per_peer = None;
    config.circuit_rate_limit_per_ip = None;
    let source = peer(b"source-connected-circuit");
    let destination = peer(b"destination-connected-circuit");
    let mut node = Node::new(config);
    node.reserve(
        &destination,
        StreamKey {
            conn_id: DESTINATION_CONN,
            stream_id: StreamId::new(1),
        },
    );
    node.establish(&source, SOURCE_CONN);
    let source_stream = StreamKey {
        conn_id: SOURCE_CONN,
        stream_id: StreamId::new(2),
    };
    let stop_stream = StreamKey {
        conn_id: DESTINATION_CONN,
        stream_id: StreamId::new(3),
    };
    node.swarm.next_open = Some(stop_stream);
    node.feed_hop(
        &source,
        source_stream,
        connect_request(&destination),
        pipelined,
    );
    assert_eq!(opened(&node.calls()), Some(stop_stream), "STOP open");
    Fixture {
        node,
        source,
        destination,
        source_stream,
        stop_stream,
    }
}

/// A committed circuit: [`pending_stop`], then STOP accepted at
/// `commit_ms`. The setup's commands and events are forgotten.
pub fn connected_circuit(config: RelayServerConfig, commit_ms: u64) -> Fixture {
    let mut fixture = pending_stop(config, commit_ms);
    let Fixture {
        node,
        destination,
        stop_stream,
        ..
    } = &mut fixture;
    node.stop_status(destination, *stop_stream, Status::Ok, at(commit_ms));
    assert!(matches!(
        node.events()[..],
        [RelayServerEvent::CircuitOpened { .. }]
    ));
    node.calls();
    fixture
}

pub fn peer(tag: &[u8]) -> PeerId {
    PeerId::from_public_key_protobuf(tag)
}

pub fn maddr(s: &str) -> Multiaddr {
    Multiaddr::from_str(s).expect("valid multiaddr")
}

pub fn at(ms: u64) -> Now {
    Now::from_millis(ms)
}

pub fn direct_addr() -> Multiaddr {
    maddr("/ip4/192.0.2.1/tcp/4001")
}

pub fn key(conn: u64, stream: u64) -> StreamKey {
    StreamKey {
        conn_id: ConnectionId::new(conn),
        stream_id: StreamId::new(stream),
    }
}

pub fn reserve_request() -> HopMessage {
    HopMessage {
        kind: HopMessageType::Reserve,
        peer: None,
        reservation: None,
        limit: None,
        status: None,
    }
}

pub fn connect_request(destination: &PeerId) -> HopMessage {
    HopMessage {
        kind: HopMessageType::Connect,
        peer: Some(Peer {
            id: destination.to_bytes(),
            addrs: Vec::new(),
        }),
        reservation: None,
        limit: None,
        status: None,
    }
}

/// A framed STOP STATUS.
pub fn stop_status(status: Status) -> Vec<u8> {
    encode_stop_status(status).expect("STOP status encodes")
}

/// Every config limit off that the test is not about.
pub fn unlimited_rates() -> RelayServerConfig {
    RelayServerConfig {
        reservation_rate_limit_per_peer: None,
        reservation_rate_limit_per_ip: None,
        circuit_rate_limit_per_peer: None,
        circuit_rate_limit_per_ip: None,
        ..RelayServerConfig::default()
    }
}

/// The stream the one successful open in `calls` returned.
pub fn opened(calls: &[Call]) -> Option<StreamKey> {
    let mut opens = calls.iter().filter_map(|call| match call {
        Call::Open { opened, .. } => Some(*opened),
        _ => None,
    });
    let first = opens.next()?;
    assert!(opens.next().is_none(), "more than one open: {calls:?}");
    first
}

/// The chunks written on `stream`, in order.
pub fn sends_on(calls: &[Call], stream: StreamKey) -> Vec<Vec<u8>> {
    calls
        .iter()
        .filter_map(|call| match call {
            Call::Send {
                stream: s, data, ..
            } if *s == stream => Some(data.clone()),
            _ => None,
        })
        .collect()
}

/// Bytes acknowledged on `stream`.
pub fn acked(calls: &[Call], stream: StreamKey) -> usize {
    calls
        .iter()
        .filter_map(|call| match call {
            Call::Ack { stream: s, bytes } if *s == stream => Some(*bytes),
            _ => None,
        })
        .sum()
}

pub fn resets(calls: &[Call]) -> Vec<StreamKey> {
    calls
        .iter()
        .filter_map(|call| match call {
            Call::Reset { stream, .. } => Some(*stream),
            _ => None,
        })
        .collect()
}

pub fn closes(calls: &[Call]) -> Vec<StreamKey> {
    calls
        .iter()
        .filter_map(|call| match call {
            Call::Close { stream, .. } => Some(*stream),
            _ => None,
        })
        .collect()
}

/// `calls` without acknowledgements, for tests about the other commands.
pub fn without_acks(calls: Vec<Call>) -> Vec<Call> {
    calls
        .into_iter()
        .filter(|call| !matches!(call, Call::Ack { .. }))
        .collect()
}
