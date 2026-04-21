//! Sans-IO state machine for the `/ipfs/id/1.0.0` identify protocol.
//!
//! After a connection is established, the *responder* (typically the listener
//! side) opens a stream, sends an [`IdentifyMessage`] and closes the write
//! side. The *initiator* (dialer side) reads the message.
//!
//! This crate handles both roles. `no_std` + `alloc` compatible.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod message;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use minip2p_core::{Multiaddr, PeerId};
use minip2p_transport::StreamId;
use thiserror::Error;

pub use message::{IdentifyMessage, IdentifyMessageError};

/// The identify protocol identifier.
pub const IDENTIFY_PROTOCOL_ID: &str = "/ipfs/id/1.0.0";

/// Maximum size for an incoming identify message (8 KiB).
///
/// Messages larger than this are rejected as a protocol violation.
const MAX_MESSAGE_SIZE: usize = 8192;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the identify protocol.
#[derive(Clone, Debug)]
pub struct IdentifyConfig {
    /// Protocol version string (e.g. `"ipfs/0.1.0"`).
    pub protocol_version: String,
    /// Agent version string (e.g. `"minip2p/0.1.0"`).
    pub agent_version: String,
    /// Protocols this node supports (e.g. `["/ipfs/ping/1.0.0"]`).
    pub protocols: Vec<String>,
    /// Addresses this node is listening on (multiaddr-encoded bytes).
    pub listen_addrs: Vec<Vec<u8>>,
    /// The local node's public key (protobuf-encoded).
    pub public_key: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Actions and events
// ---------------------------------------------------------------------------

/// Commands the host must execute on behalf of the identify protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentifyAction {
    /// Send data on a stream.
    Send {
        peer_id: PeerId,
        stream_id: StreamId,
        data: Vec<u8>,
    },
    /// Half-close the write side of a stream.
    CloseStreamWrite {
        peer_id: PeerId,
        stream_id: StreamId,
    },
}

/// Events emitted by the identify protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentifyEvent {
    /// Successfully received an identify message from a remote peer.
    Received {
        peer_id: PeerId,
        info: IdentifyMessage,
    },
    /// An error occurred while processing an identify stream.
    Error {
        peer_id: PeerId,
        stream_id: StreamId,
        error: String,
    },
}

/// Errors returned by identify protocol methods.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum IdentifyError {
    /// The peer already has an active identify exchange on this role.
    #[error("identify stream already registered for peer {peer_id}")]
    StreamAlreadyRegistered { peer_id: PeerId },
    /// No outbound identify stream registered for this peer.
    #[error("no outbound identify stream for peer {peer_id}")]
    NoOutboundStream { peer_id: PeerId },
}

// ---------------------------------------------------------------------------
// Per-peer state
// ---------------------------------------------------------------------------

/// State for a single peer's identify exchange.
#[derive(Clone, Debug, Default)]
struct PeerIdentifyState {
    /// Stream where we are the responder (sending our info).
    outbound_stream: Option<StreamId>,
    /// Streams where we are the initiator (receiving their info).
    inbound_streams: BTreeMap<StreamId, Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Protocol state machine
// ---------------------------------------------------------------------------

/// Sans-IO state machine for the identify protocol.
///
/// The host drives this by:
/// 1. Calling input methods (`on_stream_data`, etc.) when transport events arrive.
/// 2. Executing the returned [`IdentifyAction`] commands on the transport.
/// 3. Polling [`poll_events`] to collect [`IdentifyEvent`] notifications.
pub struct IdentifyProtocol {
    /// Per-peer identify state.
    peers: BTreeMap<PeerId, PeerIdentifyState>,
    /// Buffered events for the host to poll.
    events: Vec<IdentifyEvent>,
    /// Local identify info used when responding.
    config: IdentifyConfig,
}

impl IdentifyProtocol {
    /// Creates a new identify protocol handler.
    pub fn new(config: IdentifyConfig) -> Self {
        Self {
            peers: BTreeMap::new(),
            events: Vec::new(),
            config,
        }
    }

    /// Registers a stream where we are the **responder** (sending our info).
    ///
    /// Call this after multistream-select negotiates `/ipfs/id/1.0.0` on an
    /// inbound stream. `observed_addr` is the transport address we observed
    /// the remote dialing us from; pass `None` if the information is not
    /// available (the resulting identify message simply omits the
    /// `observedAddr` field).
    ///
    /// The returned actions send our identify message and close the write
    /// side.
    pub fn register_outbound_stream(
        &mut self,
        peer_id: PeerId,
        stream_id: StreamId,
        observed_addr: Option<Multiaddr>,
    ) -> Result<Vec<IdentifyAction>, IdentifyError> {
        let state = self.peers.entry(peer_id.clone()).or_default();

        if state.outbound_stream.is_some() {
            return Err(IdentifyError::StreamAlreadyRegistered {
                peer_id: peer_id.clone(),
            });
        }

        state.outbound_stream = Some(stream_id);

        // Encode the observed multiaddr as its string form bytes. This is
        // pragmatic rather than spec-pure: the libp2p identify spec calls
        // for a binary multiaddr encoding, but minip2p does not yet
        // implement multicodec-based binary serialization (see
        // `packages/core`). The string form is non-empty and round-trips
        // between minip2p peers; third-party libp2p peers will see it as
        // opaque bytes until we add binary encoding to the core crate.
        let observed_addr_bytes = observed_addr.map(|addr| addr.to_string().into_bytes());

        let msg = IdentifyMessage {
            protocol_version: Some(self.config.protocol_version.clone()),
            agent_version: Some(self.config.agent_version.clone()),
            public_key: Some(self.config.public_key.clone()),
            listen_addrs: self.config.listen_addrs.clone(),
            observed_addr: observed_addr_bytes,
            protocols: self.config.protocols.clone(),
        };

        let encoded = msg.encode();

        Ok(vec![
            IdentifyAction::Send {
                peer_id: peer_id.clone(),
                stream_id,
                data: encoded,
            },
            IdentifyAction::CloseStreamWrite {
                peer_id,
                stream_id,
            },
        ])
    }

    /// Registers a stream where we are the **initiator** (receiving their info).
    ///
    /// Call this after multistream-select negotiates `/ipfs/id/1.0.0` on an
    /// outbound stream. The protocol will buffer incoming data until the
    /// remote closes its write side.
    pub fn register_inbound_stream(
        &mut self,
        peer_id: PeerId,
        stream_id: StreamId,
    ) {
        let state = self.peers.entry(peer_id).or_default();
        state.inbound_streams.entry(stream_id).or_default();
    }

    /// Feed received stream data into the protocol.
    ///
    /// Returns actions the host must execute (none expected for the initiator
    /// side, but included for consistency).
    pub fn on_stream_data(
        &mut self,
        peer_id: PeerId,
        stream_id: StreamId,
        data: Vec<u8>,
    ) -> Vec<IdentifyAction> {
        let Some(state) = self.peers.get_mut(&peer_id) else {
            return Vec::new();
        };

        if let Some(buf) = state.inbound_streams.get_mut(&stream_id) {
            buf.extend_from_slice(&data);

            if buf.len() > MAX_MESSAGE_SIZE {
                self.events.push(IdentifyEvent::Error {
                    peer_id: peer_id.clone(),
                    stream_id,
                    error: alloc::format!(
                        "identify message exceeds maximum size ({} > {MAX_MESSAGE_SIZE})",
                        buf.len()
                    ),
                });
                state.inbound_streams.remove(&stream_id);
            }
        }

        Vec::new()
    }

    /// Notify that the remote peer closed its write side on a stream.
    ///
    /// For inbound identify streams (where we are the initiator), this
    /// signals the message is complete. The initiator closes its own write
    /// side in response so that the stream can reach the `Closed` state and
    /// have its transport-level and protocol-level state reclaimed.
    pub fn on_stream_remote_write_closed(
        &mut self,
        peer_id: PeerId,
        stream_id: StreamId,
    ) -> Vec<IdentifyAction> {
        let Some(state) = self.peers.get_mut(&peer_id) else {
            return Vec::new();
        };

        let Some(buf) = state.inbound_streams.remove(&stream_id) else {
            return Vec::new();
        };

        match IdentifyMessage::decode(&buf) {
            Ok(info) => {
                self.events.push(IdentifyEvent::Received {
                    peer_id: peer_id.clone(),
                    info,
                });
            }
            Err(e) => {
                self.events.push(IdentifyEvent::Error {
                    peer_id: peer_id.clone(),
                    stream_id,
                    error: alloc::format!("failed to decode identify message: {e}"),
                });
            }
        }

        // Close our own write side. We never send data on an initiator
        // identify stream, but multistream-select did, so the QUIC transport
        // still considers the local write side open. Without this FIN the
        // stream never transitions to `Closed` and both the swarm's
        // stream_owner entry and the transport's per-stream state leak for
        // the lifetime of the connection.
        vec![IdentifyAction::CloseStreamWrite {
            peer_id,
            stream_id,
        }]
    }

    /// Notify that a stream was fully closed.
    pub fn on_stream_closed(&mut self, peer_id: PeerId, stream_id: StreamId) {
        let Some(state) = self.peers.get_mut(&peer_id) else {
            return;
        };

        if state.outbound_stream == Some(stream_id) {
            state.outbound_stream = None;
        }

        state.inbound_streams.remove(&stream_id);

        if state.outbound_stream.is_none() && state.inbound_streams.is_empty() {
            self.peers.remove(&peer_id);
        }
    }

    /// Remove all state for a peer.
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.peers.remove(peer_id);
    }

    /// Re-keys all state for `old_peer_id` to `new_peer_id`.
    ///
    /// Used when the swarm discovers a connection's real peer identity after
    /// initially registering the connection under a placeholder. Any buffered
    /// events referencing `old_peer_id` are rewritten to `new_peer_id` so the
    /// application only ever sees events under the real peer identity.
    pub fn migrate_peer(&mut self, old_peer_id: &PeerId, new_peer_id: &PeerId) {
        if old_peer_id == new_peer_id {
            return;
        }

        if let Some(state) = self.peers.remove(old_peer_id) {
            self.peers.insert(new_peer_id.clone(), state);
        }

        for event in &mut self.events {
            match event {
                IdentifyEvent::Received { peer_id, .. }
                | IdentifyEvent::Error { peer_id, .. } => {
                    if peer_id == old_peer_id {
                        *peer_id = new_peer_id.clone();
                    }
                }
            }
        }
    }

    /// Drain buffered events.
    pub fn poll_events(&mut self) -> Vec<IdentifyEvent> {
        core::mem::take(&mut self.events)
    }
}
