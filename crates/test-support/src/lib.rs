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

/// Minimal in-memory HOP/STOP relay used by protocol and NAT-agent tests.
///
/// It validates real framed relay messages, stores reservations, queues STOP
/// CONNECT requests, and turns an accepted STOP response into HOP STATUS:OK.
#[derive(Default)]
pub struct RelayEmulator {
    reservations: HashMap<PeerId, ReservationChannels>,
    pub events: Vec<RelayEvent>,
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
        self.events.push(RelayEvent::ConnectBridgedBetween {
            initiator: initiator.clone(),
            target: target.clone(),
        });
        Ok(ConnectRequestOutcome::Bridging { target, trailing })
    }

    /// Handles a complete STOP STATUS:OK frame, queues HOP STATUS:OK for the
    /// initiator, and returns any bytes already belonging to the bridge.
    pub fn on_stop_ack_from_target(
        &mut self,
        bytes: &[u8],
        initiator_inbox: &mut Vec<u8>,
    ) -> Result<Vec<u8>, RelayEmulatorError> {
        let (msg, consumed) = decode_stop_message(bytes)?;
        if msg.kind != StopMessageType::Status || msg.status != Some(Status::Ok) {
            return Err(RelayEmulatorError::Unexpected("expected STOP STATUS:OK"));
        }

        let ok = HopMessage {
            kind: HopMessageType::Status,
            peer: None,
            reservation: None,
            limit: None,
            status: Some(Status::Ok),
        };
        initiator_inbox.extend(encode_frame(&ok.encode()));
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
