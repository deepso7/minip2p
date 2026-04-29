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
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use minip2p_core::{Multiaddr, PeerId, VarintError, read_uvarint, write_uvarint};
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
///
/// Note: `listen_addrs` is **not** a field here -- the swarm driver
/// auto-populates it from the underlying transport's `local_addresses()`
/// at send time, so the advertised set always reflects what the peer
/// is actually listening on. See
/// [`IdentifyProtocol::register_outbound_stream`].
#[derive(Clone, Debug)]
pub struct IdentifyConfig {
    /// Protocol version string (e.g. `"ipfs/0.1.0"`).
    pub protocol_version: String,
    /// Agent version string (e.g. `"minip2p/0.1.0"`).
    pub agent_version: String,
    /// Protocols this node supports (e.g. `["/ipfs/ping/1.0.0"]`).
    pub protocols: Vec<String>,
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

    /// Adds a protocol id to future Identify responses if not already advertised.
    pub fn add_protocol(&mut self, protocol_id: impl Into<String>) {
        let id = protocol_id.into();
        if !self.config.protocols.iter().any(|p| p == &id) {
            self.config.protocols.push(id);
        }
    }

    /// Registers a stream where we are the **responder** (sending our info).
    ///
    /// Call this after multistream-select negotiates `/ipfs/id/1.0.0` on an
    /// inbound stream. `observed_addr` is the transport address we observed
    /// the remote dialing us from; pass `None` if the information is not
    /// available (the resulting identify message simply omits the
    /// `observedAddr` field). `listen_addrs` is our current listening
    /// set, typically snapshotted from the transport by the swarm
    /// driver so it stays in sync with what we're actually bound to.
    ///
    /// The returned actions send our identify message and close the write
    /// side.
    pub fn register_outbound_stream(
        &mut self,
        peer_id: PeerId,
        stream_id: StreamId,
        observed_addr: Option<Multiaddr>,
        listen_addrs: &[Multiaddr],
    ) -> Result<Vec<IdentifyAction>, IdentifyError> {
        let state = self.peers.entry(peer_id.clone()).or_default();

        if state.outbound_stream.is_some() {
            return Err(IdentifyError::StreamAlreadyRegistered {
                peer_id: peer_id.clone(),
            });
        }

        state.outbound_stream = Some(stream_id);

        // libp2p's Identify spec prescribes multicodec-based binary
        // encoding for observed_addr and listen_addrs (see
        // <https://github.com/multiformats/multiaddr>). `to_bytes()`
        // produces the on-wire shape foreign libp2p peers expect.
        let observed_addr_bytes = observed_addr.map(|addr| addr.to_bytes());
        let listen_addrs_bytes: Vec<Vec<u8>> =
            listen_addrs.iter().map(|addr| addr.to_bytes()).collect();

        // libp2p Identify is wire-framed as a varint length prefix
        // followed by the protobuf body (see
        // <https://github.com/libp2p/specs/blob/master/identify/README.md>).
        // Omitting the prefix causes remote decoders to interpret the
        // first bytes of the protobuf body as a length varint -- which
        // commonly lands on wire type 4 and is rejected as
        // "deprecated group".
        let msg = IdentifyMessage {
            protocol_version: Some(self.config.protocol_version.clone()),
            agent_version: Some(self.config.agent_version.clone()),
            public_key: Some(self.config.public_key.clone()),
            listen_addrs: listen_addrs_bytes,
            observed_addr: observed_addr_bytes,
            protocols: self.config.protocols.clone(),
        };

        let encoded = msg.encode();
        let data = encode_length_prefixed(&encoded);

        Ok(vec![
            IdentifyAction::Send {
                peer_id: peer_id.clone(),
                stream_id,
                data,
            },
            IdentifyAction::CloseStreamWrite { peer_id, stream_id },
        ])
    }

    /// Registers a stream where we are the **initiator** (receiving their info).
    ///
    /// Call this after multistream-select negotiates `/ipfs/id/1.0.0` on an
    /// outbound stream. The protocol will buffer incoming data until the
    /// remote closes its write side.
    pub fn register_inbound_stream(&mut self, peer_id: PeerId, stream_id: StreamId) {
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

        match decode_length_prefixed(&buf).and_then(IdentifyMessage::decode) {
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
        vec![IdentifyAction::CloseStreamWrite { peer_id, stream_id }]
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
                IdentifyEvent::Received { peer_id, .. } | IdentifyEvent::Error { peer_id, .. } => {
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

// ---------------------------------------------------------------------------
// Wire framing helpers
// ---------------------------------------------------------------------------

/// Prepends a varint length prefix to a protobuf-encoded Identify payload.
///
/// The libp2p Identify spec requires this framing on the wire; see the
/// call site in [`IdentifyProtocol::register_outbound_stream`] for why
/// omitting it breaks interop with third-party libp2p peers.
fn encode_length_prefixed(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + payload.len());
    write_uvarint(payload.len() as u64, &mut out);
    out.extend_from_slice(payload);
    out
}

/// Strips the varint length prefix from a framed Identify buffer and
/// returns a borrowed slice over the body.
///
/// Errors:
/// - `Varint` if the prefix itself is malformed.
/// - `FieldOverflow` if the prefix declares a length longer than the
///   bytes we have (the stream was truncated before the full message
///   arrived, or the peer lied about the length).
fn decode_length_prefixed(buf: &[u8]) -> Result<&[u8], message::IdentifyMessageError> {
    let (len, consumed) =
        read_uvarint(buf).map_err(|e: VarintError| message::IdentifyMessageError::from(e))?;
    let len = len as usize;
    let remaining = buf.len() - consumed;
    if len > remaining {
        return Err(message::IdentifyMessageError::FieldOverflow {
            offset: consumed,
            length: len as u64,
            remaining,
        });
    }
    Ok(&buf[consumed..consumed + len])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> IdentifyConfig {
        IdentifyConfig {
            protocol_version: "minip2p/test".into(),
            agent_version: "minip2p-test/0.0.1".into(),
            protocols: vec!["/ipfs/ping/1.0.0".into()],
            public_key: vec![1, 2, 3, 4],
        }
    }

    fn sample_peer() -> PeerId {
        // Deterministic peer id so test output is stable across runs.
        PeerId::from_public_key_protobuf(b"test-fixture-identify-lib")
    }

    #[test]
    fn length_prefix_round_trip() {
        let body = b"hello identify";
        let framed = encode_length_prefixed(body);
        assert_eq!(framed[0] as usize, body.len());
        let decoded = decode_length_prefixed(&framed).unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn length_prefix_decode_rejects_overshoot() {
        // Declare a 255-byte body but only ship 3 bytes: should fail.
        let mut framed = Vec::new();
        write_uvarint(255, &mut framed);
        framed.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        assert!(matches!(
            decode_length_prefixed(&framed),
            Err(message::IdentifyMessageError::FieldOverflow { .. })
        ));
    }

    #[test]
    fn register_outbound_stream_emits_length_prefixed_payload() {
        // Regression test for the rust-libp2p interop bug: the bytes
        // handed to the transport MUST begin with a varint whose value
        // equals the length of the remaining bytes -- otherwise remote
        // libp2p implementations reject the message as a malformed
        // protobuf (historically surfacing as "deprecated group" /
        // "unsupported wire type 4").
        let mut identify = IdentifyProtocol::new(sample_config());
        let peer = sample_peer();
        let stream = StreamId::new(1);

        let listen_addrs =
            [
                <Multiaddr as core::str::FromStr>::from_str("/ip4/127.0.0.1/udp/4001/quic-v1")
                    .unwrap(),
            ];
        let actions = identify
            .register_outbound_stream(peer.clone(), stream, None, &listen_addrs)
            .unwrap();

        let data = actions
            .iter()
            .find_map(|a| match a {
                IdentifyAction::Send { data, .. } => Some(data.clone()),
                _ => None,
            })
            .expect("expected a Send action");

        // The frame must decode as `<varint prefix><body>` and the body
        // must itself be a valid IdentifyMessage.
        let body = decode_length_prefixed(&data).expect("length-prefixed framing");
        let msg = IdentifyMessage::decode(body).expect("body decodes");
        assert_eq!(msg.agent_version.as_deref(), Some("minip2p-test/0.0.1"));
        assert_eq!(msg.protocol_version.as_deref(), Some("minip2p/test"));

        // listen_addrs are encoded as binary multicodec bytes, one per
        // multiaddr passed in -- the regression we're guarding against.
        assert_eq!(msg.listen_addrs.len(), 1);
        let decoded = Multiaddr::from_bytes(&msg.listen_addrs[0]).expect("listen_addr round-trips");
        assert_eq!(decoded, listen_addrs[0]);
    }

    #[test]
    fn on_stream_remote_write_closed_decodes_framed_payload() {
        // Round-trip via the whole protocol: one side sends its identify
        // through `register_outbound_stream` and the other side decodes
        // it via the initiator path (`register_inbound_stream` +
        // `on_stream_data` + `on_stream_remote_write_closed`). No wire
        // errors should surface.
        let mut responder = IdentifyProtocol::new(sample_config());
        let mut initiator = IdentifyProtocol::new(IdentifyConfig {
            protocol_version: "other".into(),
            agent_version: "other".into(),
            protocols: Vec::new(),
            public_key: Vec::new(),
        });
        let r_peer = sample_peer();
        let i_peer = PeerId::from_public_key_protobuf(b"initiator");
        let stream = StreamId::new(7);

        // Responder emits the framed bytes.
        let actions = responder
            .register_outbound_stream(i_peer.clone(), stream, None, &[])
            .unwrap();
        let mut framed = Vec::new();
        for action in actions {
            if let IdentifyAction::Send { data, .. } = action {
                framed.extend_from_slice(&data);
            }
        }

        // Initiator receives byte-for-byte and decodes after the remote
        // half-close.
        initiator.register_inbound_stream(r_peer.clone(), stream);
        let _ = initiator.on_stream_data(r_peer.clone(), stream, framed);
        let _ = initiator.on_stream_remote_write_closed(r_peer.clone(), stream);

        let events = initiator.poll_events();
        assert_eq!(events.len(), 1);
        match &events[0] {
            IdentifyEvent::Received { peer_id, info } => {
                assert_eq!(peer_id, &r_peer);
                assert_eq!(info.agent_version.as_deref(), Some("minip2p-test/0.0.1"));
            }
            IdentifyEvent::Error { error, .. } => panic!("unexpected error: {error}"),
        }
    }
}
