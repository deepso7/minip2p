//! Shared protocol-faithful test fixtures for the minip2p workspace.
//!
//! This crate is `publish = false` and is used only through dev-dependencies.

use std::collections::HashMap;

use minip2p_core::PeerId;
use minip2p_relay::{
    FrameDecode, HopMessage, HopMessageType, Peer, Reservation, Status, StopMessage,
    StopMessageType, decode_frame, encode_frame,
};

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
