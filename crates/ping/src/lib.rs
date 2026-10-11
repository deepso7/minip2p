//! Sans-IO state machine for the `/ipfs/ping/1.0.0` protocol.
//!
//! Handles both dialer (send ping, measure RTT) and listener (echo payload)
//! roles. `no_std` + `alloc` compatible.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::PeerId;
use minip2p_transport::StreamId;
use thiserror::Error;

/// The ping protocol identifier.
pub const PING_PROTOCOL_ID: &str = "/ipfs/ping/1.0.0";
/// Required ping payload size in bytes.
pub const PING_PAYLOAD_LEN: usize = 32;
/// Most inbound ping streams accepted per peer before excess streams are
/// reset.
const MAX_INBOUND_STREAMS: usize = 2;

/// Configuration for the ping protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PingConfig {
    /// Maximum time in milliseconds to wait for a ping response before timing out.
    pub request_timeout_ms: u64,
}

impl Default for PingConfig {
    fn default() -> Self {
        Self {
            request_timeout_ms: 10_000,
        }
    }
}

/// Commands the host must execute on behalf of the ping protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PingAction {
    /// Send ping payload bytes on a stream.
    Send {
        peer_id: PeerId,
        stream_id: StreamId,
        data: [u8; PING_PAYLOAD_LEN],
    },
    /// Half-close the write side of a stream.
    CloseStreamWrite {
        peer_id: PeerId,
        stream_id: StreamId,
    },
    /// Abruptly reset a stream.
    ResetStream {
        peer_id: PeerId,
        stream_id: StreamId,
    },
}

/// Events emitted by the ping protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PingEvent {
    /// An outbound ping stream was registered for a peer.
    OutboundStreamRegistered {
        peer_id: PeerId,
        stream_id: StreamId,
    },
    /// An inbound ping stream was accepted.
    InboundStreamAccepted {
        peer_id: PeerId,
        stream_id: StreamId,
    },
    /// A ping round-trip completed successfully.
    RttMeasured {
        peer_id: PeerId,
        stream_id: StreamId,
        rtt_ms: u64,
    },
    /// A ping request timed out.
    Timeout {
        peer_id: PeerId,
        stream_id: StreamId,
        timeout_ms: u64,
    },
    /// The outbound ping stream was closed.
    OutboundStreamClosed {
        peer_id: PeerId,
        stream_id: StreamId,
    },
    /// A peer exceeded the maximum number of inbound streams.
    StreamLimitExceeded {
        peer_id: PeerId,
        stream_id: StreamId,
        limit: usize,
    },
    /// The remote peer violated the ping protocol.
    ProtocolViolation {
        peer_id: PeerId,
        stream_id: StreamId,
        reason: String,
    },
}

/// Outputs produced by [`PingProtocol::poll_output`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PingOutput {
    /// Command the host must execute.
    Action(PingAction),
    /// Application/protocol event.
    Event(PingEvent),
}

/// Errors returned by ping protocol operations.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PingError {
    #[error("peer {peer_id} already has outbound ping stream {existing_stream}")]
    OutboundStreamExists {
        peer_id: PeerId,
        existing_stream: StreamId,
    },
    #[error("peer {peer_id} has no outbound ping stream")]
    OutboundStreamMissing { peer_id: PeerId },
    #[error("peer {peer_id} already has ping request in flight on stream {stream_id}")]
    PingAlreadyInFlight {
        peer_id: PeerId,
        stream_id: StreamId,
    },
    #[error("invalid ping payload length {actual}; expected {PING_PAYLOAD_LEN}")]
    InvalidPayloadLength { actual: usize },
}

/// A ping request that has been sent and is awaiting a response.
#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingPing {
    /// The 32-byte payload that was sent.
    payload: [u8; PING_PAYLOAD_LEN],
    /// Timestamp (caller-provided) when the ping was sent.
    sent_at_ms: u64,
}

/// Per-peer state tracking for the ping protocol.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct PeerPingState {
    /// The single outbound stream used for sending pings to this peer.
    outbound_stream: Option<StreamId>,
    /// Inbound streams on which this peer sends pings to us.
    inbound_streams: BTreeSet<StreamId>,
    /// The in-flight outbound ping, if any.
    pending_ping: Option<PendingPing>,
    /// Per-stream receive buffers to handle fragmented data delivery.
    recv_bufs: BTreeMap<StreamId, Vec<u8>>,
}

/// The ping protocol state machine.
pub struct PingProtocol {
    /// Per-peer protocol state.
    peers: BTreeMap<PeerId, PeerPingState>,
    /// Events buffered for [`PingProtocol::poll_output`].
    pending_events: VecDeque<PingEvent>,
    /// Actions buffered for [`PingProtocol::poll_output`].
    pending_actions: VecDeque<PingAction>,
    /// Protocol configuration.
    config: PingConfig,
}

impl Default for PingProtocol {
    fn default() -> Self {
        Self::new(PingConfig::default())
    }
}

impl PingProtocol {
    /// Creates a new ping protocol instance with the given configuration.
    pub fn new(config: PingConfig) -> Self {
        Self {
            peers: BTreeMap::new(),
            pending_events: VecDeque::new(),
            pending_actions: VecDeque::new(),
            config,
        }
    }

    /// Registers a negotiated outbound stream for a peer.
    pub fn register_outbound_stream(
        &mut self,
        peer_id: PeerId,
        stream_id: StreamId,
    ) -> Result<(), PingError> {
        let peer = self.peers.entry(peer_id.clone()).or_default();

        if let Some(existing) = peer.outbound_stream {
            if existing != stream_id {
                return Err(PingError::OutboundStreamExists {
                    peer_id,
                    existing_stream: existing,
                });
            }

            // Already registered with this exact stream -- idempotent no-op.
            return Ok(());
        }

        peer.outbound_stream = Some(stream_id);
        self.pending_events
            .push_back(PingEvent::OutboundStreamRegistered { peer_id, stream_id });
        Ok(())
    }

    /// Returns the negotiated outbound ping stream for `peer_id`, if any.
    pub fn outbound_stream(&self, peer_id: &PeerId) -> Option<StreamId> {
        self.peers
            .get(peer_id)
            .and_then(|peer| peer.outbound_stream)
    }

    /// Returns the payload of the ping in flight to `peer_id`, if any.
    ///
    /// A host that hands the peer over to a new connection reads this before
    /// removing the peer, so it can re-send the same ping there.
    pub fn in_flight_payload(&self, peer_id: &PeerId) -> Option<[u8; PING_PAYLOAD_LEN]> {
        self.peers
            .get(peer_id)
            .and_then(|peer| peer.pending_ping.as_ref())
            .map(|pending| pending.payload)
    }

    /// Registers a negotiated inbound stream from a peer.
    pub fn register_inbound_stream(&mut self, peer_id: PeerId, stream_id: StreamId) {
        let peer = self.peers.entry(peer_id.clone()).or_default();
        if peer.inbound_streams.contains(&stream_id) {
            return;
        }

        if peer.inbound_streams.len() >= MAX_INBOUND_STREAMS {
            self.pending_events
                .push_back(PingEvent::StreamLimitExceeded {
                    peer_id: peer_id.clone(),
                    stream_id,
                    limit: MAX_INBOUND_STREAMS,
                });

            self.pending_actions
                .push_back(PingAction::ResetStream { peer_id, stream_id });
            return;
        }

        peer.inbound_streams.insert(stream_id);
        self.pending_events
            .push_back(PingEvent::InboundStreamAccepted { peer_id, stream_id });
    }

    /// Sends a ping with the given 32-byte payload, queuing the send action.
    pub fn send_ping(
        &mut self,
        peer_id: &PeerId,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<(), PingError> {
        if payload.len() != PING_PAYLOAD_LEN {
            return Err(PingError::InvalidPayloadLength {
                actual: payload.len(),
            });
        }

        let peer = self
            .peers
            .get_mut(peer_id)
            .ok_or_else(|| PingError::OutboundStreamMissing {
                peer_id: peer_id.clone(),
            })?;
        let stream_id = peer
            .outbound_stream
            .ok_or_else(|| PingError::OutboundStreamMissing {
                peer_id: peer_id.clone(),
            })?;

        if peer.pending_ping.is_some() {
            return Err(PingError::PingAlreadyInFlight {
                peer_id: peer_id.clone(),
                stream_id,
            });
        }

        let mut frame = [0u8; PING_PAYLOAD_LEN];
        frame.copy_from_slice(payload);
        peer.pending_ping = Some(PendingPing {
            payload: frame,
            sent_at_ms: now_ms,
        });

        self.pending_actions.push_back(PingAction::Send {
            peer_id: peer_id.clone(),
            stream_id,
            data: frame,
        });
        Ok(())
    }

    /// Half-closes the outbound stream. Fails if a ping is in flight.
    pub fn close_outbound_stream_write(&mut self, peer_id: &PeerId) -> Result<(), PingError> {
        let peer = self
            .peers
            .get_mut(peer_id)
            .ok_or_else(|| PingError::OutboundStreamMissing {
                peer_id: peer_id.clone(),
            })?;
        let stream_id = peer
            .outbound_stream
            .ok_or_else(|| PingError::OutboundStreamMissing {
                peer_id: peer_id.clone(),
            })?;

        if peer.pending_ping.is_some() {
            return Err(PingError::PingAlreadyInFlight {
                peer_id: peer_id.clone(),
                stream_id,
            });
        }

        self.pending_actions
            .push_back(PingAction::CloseStreamWrite {
                peer_id: peer_id.clone(),
                stream_id,
            });
        Ok(())
    }

    /// Feeds received stream data into the protocol, queuing any actions.
    pub fn on_stream_data(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
        data: &[u8],
        now_ms: u64,
    ) {
        // Check stream is known, collecting info before mutating.
        let is_known = self.peers.get(peer_id).is_some_and(|p| {
            p.outbound_stream == Some(stream_id) || p.inbound_streams.contains(&stream_id)
        });

        if !is_known {
            return self.protocol_violation(
                peer_id,
                stream_id,
                "ping data on unknown stream".into(),
            );
        }

        // Append data to the per-stream receive buffer and retain its length
        // while we hold the peer-state borrow.
        let buf_len = match self.peers.get_mut(peer_id) {
            Some(peer) => {
                let buf = peer.recv_bufs.entry(stream_id).or_default();
                buf.extend_from_slice(data);
                buf.len()
            }
            None => {
                return self.protocol_violation(
                    peer_id,
                    stream_id,
                    "ping peer state disappeared while receiving data".into(),
                );
            }
        };

        if buf_len > PING_PAYLOAD_LEN {
            if let Some(p) = self.peers.get_mut(peer_id) {
                p.recv_bufs.remove(&stream_id);
            }
            return self.protocol_violation(
                peer_id,
                stream_id,
                format!(
                    "recv buffer {} bytes exceeds payload size {}",
                    buf_len, PING_PAYLOAD_LEN
                ),
            );
        }

        if buf_len < PING_PAYLOAD_LEN {
            return;
        }

        // Exactly PING_PAYLOAD_LEN bytes -- extract payload and drop the buffer.
        let received = match self.peers.get_mut(peer_id) {
            Some(peer) => match peer.recv_bufs.remove(&stream_id) {
                Some(received) => received,
                None => {
                    return self.protocol_violation(
                        peer_id,
                        stream_id,
                        "ping receive buffer disappeared before processing".into(),
                    );
                }
            },
            None => {
                return self.protocol_violation(
                    peer_id,
                    stream_id,
                    "ping peer state disappeared before processing data".into(),
                );
            }
        };
        let Ok(payload) = received.try_into() else {
            return self.protocol_violation(
                peer_id,
                stream_id,
                "ping receive buffer changed size before processing".into(),
            );
        };

        self.process_complete_payload(peer_id, stream_id, payload, now_ms)
    }

    /// Handles a fully buffered 32-byte payload on either an outbound or inbound stream.
    fn process_complete_payload(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
        payload: [u8; PING_PAYLOAD_LEN],
        now_ms: u64,
    ) {
        let peer = self.peers.get_mut(peer_id).expect("peer exists");

        if peer.outbound_stream == Some(stream_id) {
            let Some(pending) = peer.pending_ping.take() else {
                return self.protocol_violation(
                    peer_id,
                    stream_id,
                    "received ping response with no in-flight request".into(),
                );
            };

            if pending.payload != payload {
                return self.protocol_violation(
                    peer_id,
                    stream_id,
                    "ping response payload mismatch".into(),
                );
            }

            let rtt_ms = now_ms.saturating_sub(pending.sent_at_ms);
            self.pending_events.push_back(PingEvent::RttMeasured {
                peer_id: peer_id.clone(),
                stream_id,
                rtt_ms,
            });
            return;
        }

        if peer.inbound_streams.contains(&stream_id) {
            self.pending_actions.push_back(PingAction::Send {
                peer_id: peer_id.clone(),
                stream_id,
                data: payload,
            });
        }
    }

    /// Notifies the protocol that the remote peer closed its write side.
    pub fn on_stream_remote_write_closed(&mut self, peer_id: &PeerId, stream_id: StreamId) {
        let Some(peer) = self.peers.get_mut(peer_id) else {
            return;
        };

        if peer.inbound_streams.remove(&stream_id) {
            peer.recv_bufs.remove(&stream_id);
            return;
        }

        if peer.outbound_stream == Some(stream_id) {
            if peer.pending_ping.is_some() {
                // Clear stale state before emitting the violation.
                peer.pending_ping = None;
                peer.outbound_stream = None;
                peer.recv_bufs.remove(&stream_id);
                return self.protocol_violation(
                    peer_id,
                    stream_id,
                    "outbound stream closed before ping response".into(),
                );
            }

            peer.outbound_stream = None;
            peer.recv_bufs.remove(&stream_id);
            self.pending_events
                .push_back(PingEvent::OutboundStreamClosed {
                    peer_id: peer_id.clone(),
                    stream_id,
                });
        }
    }

    /// Notifies the protocol that a stream was fully closed.
    pub fn on_stream_closed(&mut self, peer_id: &PeerId, stream_id: StreamId) {
        let Some(peer) = self.peers.get_mut(peer_id) else {
            return;
        };

        peer.inbound_streams.remove(&stream_id);
        peer.recv_bufs.remove(&stream_id);
        if peer.outbound_stream == Some(stream_id) {
            peer.outbound_stream = None;
            peer.pending_ping = None;
        }
    }

    /// Remove all state for a peer. Call this when the connection to a peer is
    /// closed to prevent unbounded memory growth.
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.peers.remove(peer_id);
    }

    /// Re-keys all state for `old_peer_id` to `new_peer_id`.
    ///
    /// Used when the swarm discovers a connection's real peer identity after
    /// initially registering the connection under a placeholder that is
    /// upgraded once the real identity is verified.
    ///
    /// Also rewrites any buffered events still referencing `old_peer_id` so
    /// the application only ever sees events under the real PeerId.
    ///
    /// If there is no state for `old_peer_id`, this is a no-op.
    pub fn migrate_peer(&mut self, old_peer_id: &PeerId, new_peer_id: &PeerId) {
        if old_peer_id == new_peer_id {
            return;
        }

        if let Some(state) = self.peers.remove(old_peer_id) {
            self.peers.insert(new_peer_id.clone(), state);
        }

        for event in &mut self.pending_events {
            match event {
                PingEvent::OutboundStreamRegistered { peer_id, .. }
                | PingEvent::InboundStreamAccepted { peer_id, .. }
                | PingEvent::RttMeasured { peer_id, .. }
                | PingEvent::Timeout { peer_id, .. }
                | PingEvent::OutboundStreamClosed { peer_id, .. }
                | PingEvent::StreamLimitExceeded { peer_id, .. }
                | PingEvent::ProtocolViolation { peer_id, .. } => {
                    if peer_id == old_peer_id {
                        *peer_id = new_peer_id.clone();
                    }
                }
            }
        }
    }

    /// Checks for timed-out ping requests. Call periodically.
    pub fn on_tick(&mut self, now_ms: u64) {
        for (peer_id, peer) in self.peers.iter_mut() {
            let Some(stream_id) = peer.outbound_stream else {
                continue;
            };
            let Some(pending) = peer.pending_ping.as_ref() else {
                continue;
            };

            let elapsed = now_ms.saturating_sub(pending.sent_at_ms);
            if elapsed > self.config.request_timeout_ms {
                peer.pending_ping = None;
                peer.outbound_stream = None;
                peer.recv_bufs.remove(&stream_id);
                self.pending_events.push_back(PingEvent::Timeout {
                    peer_id: peer_id.clone(),
                    stream_id,
                    timeout_ms: self.config.request_timeout_ms,
                });
                self.pending_events
                    .push_back(PingEvent::OutboundStreamClosed {
                        peer_id: peer_id.clone(),
                        stream_id,
                    });
                self.pending_actions.push_back(PingAction::ResetStream {
                    peer_id: peer_id.clone(),
                    stream_id,
                });
            }
        }
    }

    /// Emits a ProtocolViolation event and queues a ResetStream action.
    fn protocol_violation(&mut self, peer_id: &PeerId, stream_id: StreamId, reason: String) {
        self.pending_events.push_back(PingEvent::ProtocolViolation {
            peer_id: peer_id.clone(),
            stream_id,
            reason,
        });

        self.pending_actions.push_back(PingAction::ResetStream {
            peer_id: peer_id.clone(),
            stream_id,
        });
    }
}

impl PingProtocol {
    /// Returns the next pending output, if any: actions first, then events.
    ///
    /// Drain until `None` after every input, before waiting on the
    /// transport or timers again.
    pub fn poll_output(&mut self) -> Option<PingOutput> {
        if let Some(action) = self.pending_actions.pop_front() {
            return Some(PingOutput::Action(action));
        }
        self.pending_events.pop_front().map(PingOutput::Event)
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;

    impl PingProtocol {
        /// Drains and returns all pending events (test helper).
        fn poll_events(&mut self) -> Vec<PingEvent> {
            self.pending_events.drain(..).collect()
        }

        /// Drains and returns all pending actions (test helper).
        fn poll_actions(&mut self) -> Vec<PingAction> {
            self.pending_actions.drain(..).collect()
        }
    }

    fn peer(id: &str) -> PeerId {
        PeerId::from_str(id).expect("peer id")
    }

    fn test_peer() -> PeerId {
        peer("QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N")
    }

    #[test]
    fn outputs_drain_actions_before_events() {
        let mut ping = PingProtocol::default();
        let peer = test_peer();
        let stream_id = StreamId::new(1);

        ping.register_inbound_stream(peer.clone(), stream_id);
        let mut payload = [0u8; PING_PAYLOAD_LEN];
        payload[0] = 7;
        ping.on_stream_data(&peer, stream_id, &payload, 10);

        assert!(matches!(
            ping.poll_output(),
            Some(PingOutput::Action(PingAction::Send {
                peer_id: p,
                stream_id: sid,
                data,
            })) if p == peer && sid == stream_id && data == payload
        ));
        assert!(matches!(
            ping.poll_output(),
            Some(PingOutput::Event(PingEvent::InboundStreamAccepted {
                peer_id: p,
                stream_id: sid,
            })) if p == peer && sid == stream_id
        ));
        assert!(ping.poll_output().is_none());
    }

    #[test]
    fn outbound_ping_roundtrip_emits_rtt() {
        let mut ping = PingProtocol::default();
        let peer = test_peer();
        let stream = StreamId::new(0);

        ping.register_outbound_stream(peer.clone(), stream)
            .expect("register stream");

        let payload = [42u8; PING_PAYLOAD_LEN];
        ping.send_ping(&peer, &payload, 100)
            .expect("send ping action");
        assert!(matches!(
            ping.poll_actions().as_slice(),
            [PingAction::Send {
                stream_id,
                data,
                ..
            }] if *stream_id == stream && *data == payload
        ));

        ping.on_stream_data(&peer, stream, &payload, 135);
        let response_actions = ping.poll_actions();
        assert!(response_actions.is_empty());

        let events = ping.poll_events();
        assert!(events.iter().any(|event| {
            matches!(
                event,
                PingEvent::RttMeasured {
                    peer_id,
                    stream_id,
                    rtt_ms
                } if peer_id == &peer && *stream_id == stream && *rtt_ms == 35
            )
        }));
    }

    #[test]
    fn inbound_stream_limit_is_enforced() {
        let mut ping = PingProtocol::default();
        let peer = test_peer();

        ping.register_inbound_stream(peer.clone(), StreamId::new(1));
        let a = ping.poll_actions();
        ping.register_inbound_stream(peer.clone(), StreamId::new(5));
        let b = ping.poll_actions();
        ping.register_inbound_stream(peer.clone(), StreamId::new(9));
        let c = ping.poll_actions();

        assert!(a.is_empty());
        assert!(b.is_empty());
        assert_eq!(
            c,
            vec![PingAction::ResetStream {
                peer_id: peer.clone(),
                stream_id: StreamId::new(9),
            }]
        );

        let events = ping.poll_events();
        assert!(
            events
                .iter()
                .any(|event| matches!(event, PingEvent::StreamLimitExceeded { .. }))
        );
    }

    #[test]
    fn inbound_payload_is_echoed() {
        let mut ping = PingProtocol::default();
        let peer = test_peer();
        let stream = StreamId::new(3);

        ping.register_inbound_stream(peer.clone(), stream);
        let _ = ping.poll_actions();

        let payload = [7u8; PING_PAYLOAD_LEN];
        ping.on_stream_data(&peer, stream, &payload, 5);
        let out = ping.poll_actions();
        assert_eq!(
            out,
            vec![PingAction::Send {
                peer_id: peer,
                stream_id: stream,
                data: payload,
            }]
        );
    }

    #[test]
    fn timeout_emits_event_and_reset_action() {
        let mut ping = PingProtocol::new(PingConfig {
            request_timeout_ms: 10,
        });
        let peer = test_peer();
        let stream = StreamId::new(0);

        ping.register_outbound_stream(peer.clone(), stream)
            .expect("register stream");
        let payload = [1u8; PING_PAYLOAD_LEN];
        ping.send_ping(&peer, &payload, 100).expect("send ping");
        let _ = ping.poll_actions();

        ping.on_tick(111);
        let actions = ping.poll_actions();
        assert_eq!(
            actions,
            vec![PingAction::ResetStream {
                peer_id: peer.clone(),
                stream_id: stream,
            }]
        );

        let events = ping.poll_events();
        assert!(events.iter().any(|event| {
            matches!(
                event,
                PingEvent::Timeout {
                    peer_id,
                    stream_id,
                    timeout_ms
                } if peer_id == &peer && *stream_id == stream && *timeout_ms == 10
            )
        }));
        assert!(events.iter().any(|event| {
            matches!(
                event,
                PingEvent::OutboundStreamClosed {
                    peer_id,
                    stream_id,
                } if peer_id == &peer && *stream_id == stream
            )
        }));
    }

    #[test]
    fn fragmented_inbound_payload_is_buffered_then_echoed() {
        let mut ping = PingProtocol::default();
        let peer = test_peer();
        let stream = StreamId::new(3);

        ping.register_inbound_stream(peer.clone(), stream);
        let _ = ping.poll_actions();

        let payload = [7u8; PING_PAYLOAD_LEN];

        // Send first 16 bytes -- should buffer, no action yet.
        ping.on_stream_data(&peer, stream, &payload[..16], 5);
        let out = ping.poll_actions();
        assert!(out.is_empty());

        // Send remaining 16 bytes -- should now echo the full payload.
        ping.on_stream_data(&peer, stream, &payload[16..], 6);
        let out = ping.poll_actions();
        assert_eq!(
            out,
            vec![PingAction::Send {
                peer_id: peer,
                stream_id: stream,
                data: payload,
            }]
        );
    }

    #[test]
    fn fragmented_outbound_response_is_buffered_then_measures_rtt() {
        let mut ping = PingProtocol::default();
        let peer = test_peer();
        let stream = StreamId::new(0);

        ping.register_outbound_stream(peer.clone(), stream)
            .expect("register stream");

        let payload = [42u8; PING_PAYLOAD_LEN];
        ping.send_ping(&peer, &payload, 100).expect("send ping");
        let _ = ping.poll_actions();

        // Drain the OutboundStreamRegistered event from registration.
        let _ = ping.poll_events();

        // First chunk -- buffered.
        ping.on_stream_data(&peer, stream, &payload[..10], 120);
        let actions = ping.poll_actions();
        assert!(actions.is_empty());
        assert!(ping.poll_events().is_empty());

        // Second chunk -- completes the payload.
        ping.on_stream_data(&peer, stream, &payload[10..], 135);
        let actions = ping.poll_actions();
        assert!(actions.is_empty());

        let events = ping.poll_events();
        assert!(events.iter().any(|event| {
            matches!(
                event,
                PingEvent::RttMeasured {
                    peer_id,
                    stream_id,
                    rtt_ms
                } if peer_id == &peer && *stream_id == stream && *rtt_ms == 35
            )
        }));
    }

    #[test]
    fn oversized_buffer_is_protocol_violation() {
        let mut ping = PingProtocol::default();
        let peer = test_peer();
        let stream = StreamId::new(3);

        ping.register_inbound_stream(peer.clone(), stream);
        let _ = ping.poll_actions();

        // Send more than 32 bytes in one shot.
        let oversized = [0u8; PING_PAYLOAD_LEN + 1];
        ping.on_stream_data(&peer, stream, &oversized, 5);
        let actions = ping.poll_actions();
        assert_eq!(
            actions,
            vec![PingAction::ResetStream {
                peer_id: peer.clone(),
                stream_id: stream,
            }]
        );

        let events = ping.poll_events();
        assert!(
            events
                .iter()
                .any(|event| matches!(event, PingEvent::ProtocolViolation { .. }))
        );
    }

    #[test]
    fn close_outbound_write_rejected_while_ping_in_flight() {
        let mut ping = PingProtocol::default();
        let peer = test_peer();
        let stream = StreamId::new(0);

        ping.register_outbound_stream(peer.clone(), stream)
            .expect("register stream");

        let payload = [1u8; PING_PAYLOAD_LEN];
        ping.send_ping(&peer, &payload, 100).expect("send ping");
        let _ = ping.poll_actions();

        let result = ping.close_outbound_stream_write(&peer);
        assert!(matches!(result, Err(PingError::PingAlreadyInFlight { .. })));
    }

    #[test]
    fn remove_peer_clears_all_state() {
        let mut ping = PingProtocol::default();
        let peer = test_peer();
        let stream = StreamId::new(0);

        ping.register_outbound_stream(peer.clone(), stream)
            .expect("register stream");
        ping.register_inbound_stream(peer.clone(), StreamId::new(1));
        let _ = ping.poll_actions();

        let payload = [1u8; PING_PAYLOAD_LEN];
        ping.send_ping(&peer, &payload, 100).expect("send ping");
        let _ = ping.poll_actions();

        ping.remove_peer(&peer);

        // After removal, we can re-register everything fresh.
        ping.register_outbound_stream(peer.clone(), StreamId::new(10))
            .expect("re-register outbound stream after remove_peer");
        ping.register_inbound_stream(peer.clone(), StreamId::new(11));
        let actions = ping.poll_actions();
        assert!(actions.is_empty());
    }

    #[test]
    fn outbound_stream_ignores_inbound_streams() {
        let mut ping = PingProtocol::default();
        let peer = test_peer();

        ping.register_inbound_stream(peer.clone(), StreamId::new(1));
        assert_eq!(ping.outbound_stream(&peer), None);

        ping.register_outbound_stream(peer.clone(), StreamId::new(2))
            .expect("register outbound stream");
        assert_eq!(ping.outbound_stream(&peer), Some(StreamId::new(2)));
    }

    #[test]
    fn outbound_stream_closed_emitted_on_remote_write_close() {
        let mut ping = PingProtocol::default();
        let peer = test_peer();
        let stream = StreamId::new(0);

        ping.register_outbound_stream(peer.clone(), stream)
            .expect("register stream");

        // No ping in flight -- remote closes write side.
        ping.on_stream_remote_write_closed(&peer, stream);
        let actions = ping.poll_actions();
        assert!(actions.is_empty());

        let events = ping.poll_events();
        assert!(events.iter().any(|event| {
            matches!(
                event,
                PingEvent::OutboundStreamClosed {
                    peer_id,
                    stream_id,
                } if peer_id == &peer && *stream_id == stream
            )
        }));
    }
}
