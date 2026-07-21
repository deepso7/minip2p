//! Shared protocol-faithful test fixtures for the minip2p workspace.
//!
//! This crate is `publish = false` and is used only through dev-dependencies.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;
use std::time::Duration;

use minip2p_core::{Multiaddr, PeerAddr, PeerId};
use minip2p_relay::{
    FrameDecode, HopMessage, HopMessageType, Peer, Reservation, Status, StopMessage,
    StopMessageType, decode_frame, encode_frame,
};
use minip2p_transport::{
    ConnectionEndpoint, ConnectionId, StreamId, Transport, TransportError, TransportEvent,
    WaitOutcome,
};

/// Deterministic, connected, in-memory implementation of the transport contract.
///
/// A pair transfers stream events directly into its partner's poll queue. It
/// is intentionally single-threaded and is meant for protocol wrapper tests.
pub struct InMemoryTransport {
    shared: Rc<RefCell<InMemoryLink>>,
    side: usize,
    connection: ConnectionId,
    local_addr: Multiaddr,
    remote_addr: Multiaddr,
}

struct InMemoryLink {
    queues: [VecDeque<TransportEvent>; 2],
    next_stream: [u64; 2],
    active: bool,
    streams: HashMap<StreamId, InMemoryStream>,
}

#[derive(Default)]
struct InMemoryStream {
    write_closed: [bool; 2],
    closed: bool,
    close_delivered: [bool; 2],
}

impl InMemoryTransport {
    /// Creates a connected pair and queues the normal inbound/connected events.
    pub fn pair(local_peer: PeerId, remote_peer: PeerId) -> (Self, Self) {
        let a_addr: Multiaddr = "/ip4/192.0.2.1/udp/4001/quic-v1"
            .parse()
            .expect("test multiaddr");
        let b_addr: Multiaddr = "/ip4/192.0.2.2/udp/4002/quic-v1"
            .parse()
            .expect("test multiaddr");
        let connection = ConnectionId::new(1);
        let mut queues = [VecDeque::new(), VecDeque::new()];
        queues[0].push_back(TransportEvent::Connected {
            id: connection,
            endpoint: ConnectionEndpoint::with_peer_id(b_addr.clone(), remote_peer),
        });
        queues[1].push_back(TransportEvent::IncomingConnection {
            id: connection,
            endpoint: ConnectionEndpoint::new(a_addr.clone()),
        });
        queues[1].push_back(TransportEvent::Connected {
            id: connection,
            endpoint: ConnectionEndpoint::with_peer_id(a_addr.clone(), local_peer),
        });
        let shared = Rc::new(RefCell::new(InMemoryLink {
            queues,
            next_stream: [1, 2],
            active: true,
            streams: HashMap::new(),
        }));
        (
            Self {
                shared: shared.clone(),
                side: 0,
                connection,
                local_addr: a_addr.clone(),
                remote_addr: b_addr.clone(),
            },
            Self {
                shared,
                side: 1,
                connection,
                local_addr: b_addr,
                remote_addr: a_addr,
            },
        )
    }

    /// Returns the sole local connection identifier.
    pub fn connection_id(&self) -> ConnectionId {
        self.connection
    }

    /// Queues a synthetic local event for deterministic wrapper edge cases.
    pub fn push_event(&mut self, event: TransportEvent) {
        self.shared.borrow_mut().queues[self.side].push_back(event);
    }

    fn ensure_connection(&self, id: ConnectionId) -> Result<(), TransportError> {
        if self.shared.borrow().active && id == self.connection {
            Ok(())
        } else {
            Err(TransportError::ConnectionNotFound { id })
        }
    }

    fn stream_not_found(&self, stream_id: StreamId) -> TransportError {
        TransportError::StreamNotFound {
            id: self.connection,
            stream_id,
        }
    }
}

impl Transport for InMemoryTransport {
    fn dial(&mut self, _addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        Err(TransportError::InvalidConfig {
            reason: "in-memory pair is already connected".into(),
        })
    }

    fn listen(&mut self, _addr: &Multiaddr) -> Result<Multiaddr, TransportError> {
        let addr = self.local_addr.clone();
        self.shared.borrow_mut().queues[self.side]
            .push_back(TransportEvent::Listening { addr: addr.clone() });
        Ok(addr)
    }

    fn open_stream(&mut self, id: ConnectionId) -> Result<StreamId, TransportError> {
        self.ensure_connection(id)?;
        let other = 1 - self.side;
        let mut shared = self.shared.borrow_mut();
        let stream_id = StreamId::new(shared.next_stream[self.side]);
        shared.next_stream[self.side] += 2;
        let previous = shared.streams.insert(stream_id, InMemoryStream::default());
        debug_assert!(previous.is_none(), "stream ids are unique within a pair");
        shared.queues[self.side].push_back(TransportEvent::StreamOpened { id, stream_id });
        shared.queues[other].push_back(TransportEvent::IncomingStream {
            id: self.connection,
            stream_id,
        });
        Ok(stream_id)
    }

    fn send_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Vec<u8>,
    ) -> Result<(), TransportError> {
        self.ensure_connection(id)?;
        let mut shared = self.shared.borrow_mut();
        let Some(stream) = shared.streams.get(&stream_id) else {
            return Err(self.stream_not_found(stream_id));
        };
        if stream.closed {
            return Err(self.stream_not_found(stream_id));
        }
        if stream.write_closed[self.side] {
            return Err(TransportError::StreamSendFailed {
                id,
                stream_id,
                reason: "write side is closed".into(),
            });
        }
        if data.is_empty() {
            return Ok(());
        }
        shared.queues[1 - self.side].push_back(TransportEvent::StreamData {
            id: self.connection,
            stream_id,
            data,
        });
        Ok(())
    }

    fn close_stream_write(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        self.ensure_connection(id)?;
        let other = 1 - self.side;
        let mut shared = self.shared.borrow_mut();
        let both_write_closed = {
            let Some(stream) = shared.streams.get_mut(&stream_id) else {
                return Err(self.stream_not_found(stream_id));
            };
            if stream.closed {
                return Err(self.stream_not_found(stream_id));
            }
            if stream.write_closed[self.side] {
                return Ok(());
            }
            stream.write_closed[self.side] = true;
            let both_write_closed = stream.write_closed[other];
            if both_write_closed {
                stream.closed = true;
            }
            both_write_closed
        };
        shared.queues[other].push_back(TransportEvent::StreamRemoteWriteClosed {
            id: self.connection,
            stream_id,
        });
        if both_write_closed {
            shared.queues[self.side].push_back(TransportEvent::StreamClosed { id, stream_id });
            shared.queues[other].push_back(TransportEvent::StreamClosed {
                id: self.connection,
                stream_id,
            });
        }
        Ok(())
    }

    fn reset_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        self.ensure_connection(id)?;
        let other = 1 - self.side;
        let mut shared = self.shared.borrow_mut();
        let Some(stream) = shared.streams.get_mut(&stream_id) else {
            return Err(self.stream_not_found(stream_id));
        };
        if stream.closed {
            return Ok(());
        }
        stream.closed = true;
        shared.queues[self.side].push_back(TransportEvent::StreamClosed { id, stream_id });
        shared.queues[other].push_back(TransportEvent::StreamClosed {
            id: self.connection,
            stream_id,
        });
        Ok(())
    }

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        self.ensure_connection(id)?;
        let other = 1 - self.side;
        let mut shared = self.shared.borrow_mut();
        shared.active = false;
        shared.streams.clear();
        shared.queues[self.side].push_back(TransportEvent::Closed { id });
        shared.queues[other].push_back(TransportEvent::Closed {
            id: self.connection,
        });
        Ok(())
    }

    fn poll(&mut self) -> Result<Vec<TransportEvent>, TransportError> {
        let mut shared = self.shared.borrow_mut();
        let events = shared.queues[self.side].drain(..).collect::<Vec<_>>();
        let mut fully_delivered = Vec::new();
        for event in &events {
            let stream_id = match event {
                TransportEvent::StreamClosed { id, stream_id } if *id == self.connection => {
                    *stream_id
                }
                _ => continue,
            };
            let Some(stream) = shared.streams.get_mut(&stream_id) else {
                continue;
            };
            if !stream.closed {
                continue;
            }
            stream.close_delivered[self.side] = true;
            if stream.close_delivered == [true, true] {
                fully_delivered.push(stream_id);
            }
        }
        for stream_id in fully_delivered {
            shared.streams.remove(&stream_id);
        }
        Ok(events)
    }

    fn next_timeout(&self) -> Option<Duration> {
        (!self.shared.borrow().queues[self.side].is_empty()).then_some(Duration::ZERO)
    }

    fn wait_for_input(&mut self, _timeout: Duration) -> WaitOutcome {
        if self.shared.borrow().queues[self.side].is_empty() {
            WaitOutcome::Unsupported
        } else {
            WaitOutcome::Ready
        }
    }

    fn local_addresses(&self) -> Vec<Multiaddr> {
        vec![self.local_addr.clone()]
    }

    fn active_inbound_connection_sources(&self) -> Vec<Multiaddr> {
        if self.side == 1 && self.shared.borrow().active {
            vec![self.remote_addr.clone()]
        } else {
            Vec::new()
        }
    }
}

/// Result of handling one HOP CONNECT request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectRequestOutcome {
    /// The target held a reservation and a STOP CONNECT was queued for it.
    Bridging {
        /// Opaque token tying the STOP response to this CONNECT request.
        pending_id: PendingConnectId,
        target: PeerId,
        /// Bytes pipelined behind the HOP CONNECT frame.
        trailing: Vec<u8>,
    },
    /// The target held no reservation and a refusal was queued for the
    /// initiator.
    Refused {
        /// Bytes pipelined behind the HOP CONNECT frame.
        trailing: Vec<u8>,
    },
}

/// Events retained by [`RelayEmulator`] for test assertions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayEvent {
    ReservationStored { peer: PeerId },
    ConnectBridgedBetween { initiator: PeerId, target: PeerId },
    StatusOkSentToInitiator,
}

/// Opaque identity for a HOP CONNECT awaiting its target's STOP response.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingConnectId(u64);

/// Minimal in-memory HOP/STOP relay used by protocol and NAT-agent tests.
///
/// It validates real framed relay messages, stores reservations, queues STOP
/// CONNECT requests, and turns an accepted STOP response into HOP STATUS:OK.
#[derive(Default)]
pub struct RelayEmulator {
    reservations: HashMap<PeerId, ReservationChannels>,
    pending_connects: HashMap<PendingConnectId, PendingConnect>,
    next_connect_id: u64,
    pub events: Vec<RelayEvent>,
}

struct PendingConnect {
    initiator: PeerId,
    target: PeerId,
}

#[derive(Default)]
struct ReservationChannels {
    hop_inbox: Vec<u8>,
    stop_inbox: Vec<u8>,
}

impl RelayEmulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Handles a complete HOP RESERVE frame and returns any bytes pipelined
    /// behind it.
    pub fn on_reserve_request(
        &mut self,
        reserver: &PeerId,
        bytes: &[u8],
    ) -> Result<Vec<u8>, RelayEmulatorError> {
        let (msg, consumed) = decode_hop_message(bytes)?;
        if msg.kind != HopMessageType::Reserve {
            return Err(RelayEmulatorError::Unexpected("expected RESERVE"));
        }

        let channels = self.reservations.entry(reserver.clone()).or_default();
        let response = HopMessage {
            kind: HopMessageType::Status,
            peer: None,
            reservation: Some(Reservation {
                expire: Some(9_999_999_999),
                addrs: Vec::new(),
                voucher: None,
            }),
            limit: None,
            status: Some(Status::Ok),
        };
        channels.hop_inbox.extend(encode_frame(&response.encode()));
        self.events.push(RelayEvent::ReservationStored {
            peer: reserver.clone(),
        });
        Ok(bytes[consumed..].to_vec())
    }

    pub fn drain_hop_bytes_for(&mut self, peer: &PeerId) -> Vec<u8> {
        self.reservations
            .get_mut(peer)
            .map(|channels| core::mem::take(&mut channels.hop_inbox))
            .unwrap_or_default()
    }

    pub fn drain_stop_bytes_for(&mut self, peer: &PeerId) -> Vec<u8> {
        self.reservations
            .get_mut(peer)
            .map(|channels| core::mem::take(&mut channels.stop_inbox))
            .unwrap_or_default()
    }

    /// Handles a complete HOP CONNECT frame. A reserved target receives a
    /// queued STOP CONNECT; an unreserved target produces a refusal in
    /// `initiator_inbox`.
    pub fn on_connect_request(
        &mut self,
        initiator: &PeerId,
        bytes: &[u8],
        initiator_inbox: &mut Vec<u8>,
    ) -> Result<ConnectRequestOutcome, RelayEmulatorError> {
        let (msg, consumed) = decode_hop_message(bytes)?;
        if msg.kind != HopMessageType::Connect {
            return Err(RelayEmulatorError::Unexpected("expected CONNECT"));
        }
        let target_bytes = msg
            .peer
            .as_ref()
            .map(|peer| peer.id.clone())
            .ok_or(RelayEmulatorError::Unexpected("missing peer field"))?;
        let target = PeerId::from_bytes(&target_bytes)
            .map_err(|_| RelayEmulatorError::Unexpected("invalid target peer id"))?;
        let trailing = bytes[consumed..].to_vec();

        let Some(channels) = self.reservations.get_mut(&target) else {
            let refusal = HopMessage {
                kind: HopMessageType::Status,
                peer: None,
                reservation: None,
                limit: None,
                status: Some(Status::NoReservation),
            };
            initiator_inbox.extend(encode_frame(&refusal.encode()));
            return Ok(ConnectRequestOutcome::Refused { trailing });
        };

        let stop_connect = StopMessage {
            kind: StopMessageType::Connect,
            peer: Some(Peer {
                id: initiator.to_bytes(),
                addrs: Vec::new(),
            }),
            limit: None,
            status: None,
        };
        channels
            .stop_inbox
            .extend(encode_frame(&stop_connect.encode()));
        let pending_id = PendingConnectId(self.next_connect_id);
        self.next_connect_id = self.next_connect_id.wrapping_add(1);
        self.pending_connects.insert(
            pending_id,
            PendingConnect {
                initiator: initiator.clone(),
                target: target.clone(),
            },
        );
        Ok(ConnectRequestOutcome::Bridging {
            pending_id,
            target,
            trailing,
        })
    }

    /// Handles the target's STOP response for one pending HOP CONNECT.
    ///
    /// The pending token and target must identify the same CONNECT. On a
    /// successful STOP STATUS:OK, this queues HOP STATUS:OK for the initiator
    /// and returns any bytes already belonging to the bridge.
    pub fn on_stop_ack_from_target(
        &mut self,
        pending_id: PendingConnectId,
        target: &PeerId,
        bytes: &[u8],
        initiator_inbox: &mut Vec<u8>,
    ) -> Result<Vec<u8>, RelayEmulatorError> {
        let (msg, consumed) = decode_stop_message(bytes)?;
        if msg.kind != StopMessageType::Status || msg.status != Some(Status::Ok) {
            return Err(RelayEmulatorError::Unexpected("expected STOP STATUS:OK"));
        }

        let pending =
            self.pending_connects
                .get(&pending_id)
                .ok_or(RelayEmulatorError::Unexpected(
                    "no matching pending CONNECT",
                ))?;
        if &pending.target != target {
            return Err(RelayEmulatorError::Unexpected(
                "STOP response target does not match pending CONNECT",
            ));
        }
        let pending = self
            .pending_connects
            .remove(&pending_id)
            .expect("pending CONNECT was checked above");

        let ok = HopMessage {
            kind: HopMessageType::Status,
            peer: None,
            reservation: None,
            limit: None,
            status: Some(Status::Ok),
        };
        initiator_inbox.extend(encode_frame(&ok.encode()));
        self.events.push(RelayEvent::ConnectBridgedBetween {
            initiator: pending.initiator,
            target: pending.target,
        });
        self.events.push(RelayEvent::StatusOkSentToInitiator);
        Ok(bytes[consumed..].to_vec())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayEmulatorError {
    Unexpected(&'static str),
}

impl core::fmt::Display for RelayEmulatorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unexpected(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for RelayEmulatorError {}

fn decode_hop_message(bytes: &[u8]) -> Result<(HopMessage, usize), RelayEmulatorError> {
    match decode_frame(bytes) {
        FrameDecode::Complete { payload, consumed } => HopMessage::decode(payload)
            .map(|message| (message, consumed))
            .map_err(|_| RelayEmulatorError::Unexpected("bad HOP")),
        _ => Err(RelayEmulatorError::Unexpected("incomplete HOP frame")),
    }
}

fn decode_stop_message(bytes: &[u8]) -> Result<(StopMessage, usize), RelayEmulatorError> {
    match decode_frame(bytes) {
        FrameDecode::Complete { payload, consumed } => StopMessage::decode(payload)
            .map(|message| (message, consumed))
            .map_err(|_| RelayEmulatorError::Unexpected("bad STOP")),
        _ => Err(RelayEmulatorError::Unexpected("incomplete STOP frame")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(tag: &[u8]) -> PeerId {
        PeerId::from_public_key_protobuf(tag)
    }

    fn transport_pair() -> (InMemoryTransport, InMemoryTransport) {
        InMemoryTransport::pair(peer(b"transport-a"), peer(b"transport-b"))
    }

    fn drain_startup(a: &mut InMemoryTransport, b: &mut InMemoryTransport) {
        assert!(matches!(
            a.poll().unwrap().as_slice(),
            [TransportEvent::Connected { .. }]
        ));
        assert!(matches!(
            b.poll().unwrap().as_slice(),
            [
                TransportEvent::IncomingConnection { .. },
                TransportEvent::Connected { .. }
            ]
        ));
    }

    #[test]
    fn in_memory_listen_emits_the_resolved_address() {
        let (mut transport, mut peer) = transport_pair();
        drain_startup(&mut transport, &mut peer);
        let requested: Multiaddr = "/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap();

        let resolved = transport.listen(&requested).unwrap();

        assert_eq!(
            transport.poll().unwrap(),
            [TransportEvent::Listening {
                addr: resolved.clone()
            }]
        );
        assert_eq!(resolved, transport.local_addr);
    }

    #[test]
    fn in_memory_rejects_unknown_stream_writes() {
        let (mut a, mut b) = transport_pair();
        drain_startup(&mut a, &mut b);
        let id = a.connection_id();
        let stream_id = StreamId::new(99);

        assert_eq!(
            a.send_stream(id, stream_id, vec![1, 2, 3]),
            Err(TransportError::StreamNotFound { id, stream_id })
        );
        assert!(b.poll().unwrap().is_empty());
    }

    #[test]
    fn in_memory_half_close_is_idempotent_and_closes_after_both_fins() {
        let (mut a, mut b) = transport_pair();
        drain_startup(&mut a, &mut b);
        let id = a.connection_id();
        let stream_id = a.open_stream(id).unwrap();
        a.poll().unwrap();
        b.poll().unwrap();

        a.close_stream_write(id, stream_id).unwrap();
        a.close_stream_write(id, stream_id).unwrap();
        assert_eq!(
            b.poll().unwrap(),
            [TransportEvent::StreamRemoteWriteClosed { id, stream_id }]
        );
        assert!(matches!(
            a.send_stream(id, stream_id, vec![1]),
            Err(TransportError::StreamSendFailed { .. })
        ));

        b.close_stream_write(id, stream_id).unwrap();
        assert_eq!(
            a.poll().unwrap(),
            [
                TransportEvent::StreamRemoteWriteClosed { id, stream_id },
                TransportEvent::StreamClosed { id, stream_id }
            ]
        );
        assert_eq!(
            b.poll().unwrap(),
            [TransportEvent::StreamClosed { id, stream_id }]
        );
        assert!(a.shared.borrow().streams.is_empty());
        assert_eq!(
            b.send_stream(id, stream_id, vec![1]),
            Err(TransportError::StreamNotFound { id, stream_id })
        );
    }

    #[test]
    fn in_memory_reset_is_idempotent_and_tombstones_the_stream() {
        let (mut a, mut b) = transport_pair();
        drain_startup(&mut a, &mut b);
        let id = a.connection_id();
        let stream_id = a.open_stream(id).unwrap();
        a.poll().unwrap();
        b.poll().unwrap();

        a.reset_stream(id, stream_id).unwrap();
        a.reset_stream(id, stream_id).unwrap();

        assert_eq!(
            a.poll().unwrap(),
            [TransportEvent::StreamClosed { id, stream_id }]
        );
        assert_eq!(
            b.poll().unwrap(),
            [TransportEvent::StreamClosed { id, stream_id }]
        );
        assert_eq!(
            a.send_stream(id, stream_id, vec![1]),
            Err(TransportError::StreamNotFound { id, stream_id })
        );
        assert_eq!(
            b.close_stream_write(id, stream_id),
            Err(TransportError::StreamNotFound { id, stream_id })
        );
    }

    #[test]
    fn in_memory_reclaims_terminal_streams_after_both_close_events_are_delivered() {
        let (mut a, mut b) = transport_pair();
        drain_startup(&mut a, &mut b);
        let id = a.connection_id();

        for _ in 0..128 {
            let stream_id = a.open_stream(id).unwrap();
            a.poll().unwrap();
            b.poll().unwrap();

            a.reset_stream(id, stream_id).unwrap();
            a.reset_stream(id, stream_id).unwrap();
            assert_eq!(a.shared.borrow().streams.len(), 1);

            assert_eq!(
                a.poll().unwrap(),
                [TransportEvent::StreamClosed { id, stream_id }]
            );
            assert_eq!(a.shared.borrow().streams.len(), 1);
            assert_eq!(
                b.poll().unwrap(),
                [TransportEvent::StreamClosed { id, stream_id }]
            );
            assert!(a.shared.borrow().streams.is_empty());
        }
    }

    #[test]
    fn in_memory_close_disables_both_endpoints_before_closed_is_polled() {
        let (mut a, mut b) = transport_pair();
        drain_startup(&mut a, &mut b);
        let id = a.connection_id();
        let stream_id = a.open_stream(id).unwrap();
        a.poll().unwrap();
        b.poll().unwrap();

        a.close(id).unwrap();

        assert!(a.shared.borrow().streams.is_empty());

        assert_eq!(
            b.open_stream(id),
            Err(TransportError::ConnectionNotFound { id })
        );
        assert_eq!(
            b.send_stream(id, stream_id, vec![1]),
            Err(TransportError::ConnectionNotFound { id })
        );
        assert_eq!(b.close(id), Err(TransportError::ConnectionNotFound { id }));
        assert!(b.active_inbound_connection_sources().is_empty());
        assert_eq!(a.poll().unwrap(), [TransportEvent::Closed { id }]);
        assert_eq!(b.poll().unwrap(), [TransportEvent::Closed { id }]);
        assert!(a.poll().unwrap().is_empty());
        assert!(b.poll().unwrap().is_empty());
    }

    fn reserve(relay: &mut RelayEmulator, target: &PeerId) {
        let request = HopMessage {
            kind: HopMessageType::Reserve,
            peer: None,
            reservation: None,
            limit: None,
            status: None,
        };
        relay
            .on_reserve_request(target, &encode_frame(&request.encode()))
            .unwrap();
        relay.events.clear();
    }

    fn connect(relay: &mut RelayEmulator, initiator: &PeerId, target: &PeerId) -> PendingConnectId {
        let request = HopMessage {
            kind: HopMessageType::Connect,
            peer: Some(Peer {
                id: target.to_bytes(),
                addrs: Vec::new(),
            }),
            reservation: None,
            limit: None,
            status: None,
        };
        let mut inbox = Vec::new();
        let outcome = relay
            .on_connect_request(initiator, &encode_frame(&request.encode()), &mut inbox)
            .unwrap();
        assert!(inbox.is_empty());
        match outcome {
            ConnectRequestOutcome::Bridging { pending_id, .. } => pending_id,
            ConnectRequestOutcome::Refused { .. } => panic!("reserved target was refused"),
        }
    }

    fn stop_ok() -> Vec<u8> {
        encode_frame(
            &StopMessage {
                kind: StopMessageType::Status,
                peer: None,
                limit: None,
                status: Some(Status::Ok),
            }
            .encode(),
        )
    }

    #[test]
    fn bridge_event_is_emitted_only_after_stop_accepts() {
        let initiator = peer(b"initiator");
        let target = peer(b"target");
        let mut relay = RelayEmulator::new();
        reserve(&mut relay, &target);

        let pending_id = connect(&mut relay, &initiator, &target);
        assert!(relay.events.is_empty(), "CONNECT is still pending STOP ACK");

        let mut inbox = Vec::new();
        relay
            .on_stop_ack_from_target(pending_id, &target, &stop_ok(), &mut inbox)
            .unwrap();
        assert!(!inbox.is_empty(), "initiator receives HOP STATUS:OK");
        assert_eq!(
            relay.events,
            [
                RelayEvent::ConnectBridgedBetween { initiator, target },
                RelayEvent::StatusOkSentToInitiator,
            ]
        );
    }

    #[test]
    fn stop_ack_must_match_pending_connect_context() {
        let initiator_a = peer(b"initiator-a");
        let initiator_b = peer(b"initiator-b");
        let target_a = peer(b"target-a");
        let target_b = peer(b"target-b");
        let mut relay = RelayEmulator::new();
        reserve(&mut relay, &target_a);
        reserve(&mut relay, &target_b);
        let pending_a = connect(&mut relay, &initiator_a, &target_a);
        let pending_b = connect(&mut relay, &initiator_b, &target_b);
        let ack = stop_ok();

        let mut inbox = Vec::new();
        let wrong_circuit = relay
            .on_stop_ack_from_target(pending_a, &target_b, &ack, &mut inbox)
            .unwrap_err();
        assert_eq!(
            wrong_circuit,
            RelayEmulatorError::Unexpected("STOP response target does not match pending CONNECT")
        );
        assert!(inbox.is_empty());
        assert!(relay.events.is_empty());

        relay
            .on_stop_ack_from_target(pending_a, &target_a, &ack, &mut inbox)
            .unwrap();
        inbox.clear();
        let already_consumed = relay
            .on_stop_ack_from_target(pending_a, &target_a, &ack, &mut inbox)
            .unwrap_err();
        assert_eq!(
            already_consumed,
            RelayEmulatorError::Unexpected("no matching pending CONNECT")
        );
        assert!(inbox.is_empty());

        relay
            .on_stop_ack_from_target(pending_b, &target_b, &ack, &mut inbox)
            .unwrap();
        assert!(relay.events.iter().any(|event| matches!(
            event,
            RelayEvent::ConnectBridgedBetween { initiator, target }
                if initiator == &initiator_b && target == &target_b
        )));
    }
}
