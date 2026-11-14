//! Wire codec for the relay-mesh directory and forward protocols.
//!
//! Each frame is `<uvarint length><protobuf payload>`, capped at
//! [`MAX_MESH_MESSAGE_SIZE`] like Circuit Relay v2 control frames. Field
//! framing uses `minip2p-core`'s shared protobuf vocabulary.
//!
//! ```text
//! message DirectoryMessage {
//!   Type type = 1;              // PRESENT=0 | GONE=1 | SYNCED=2
//!   bytes peer = 2;             // PRESENT, GONE
//!   uint64 expires_unix = 3;    // PRESENT
//! }
//! message ForwardMessage {
//!   Type type = 1;              // FORWARD=0 | STATUS=1
//!   bytes source = 2;           // FORWARD
//!   bytes destination = 3;      // FORWARD
//!   Limit limit = 4;            // FORWARD; Circuit Relay v2 `Limit`
//!   Status status = 5;          // STATUS; Circuit Relay v2 status codes
//! }
//! ```
//!
//! Unknown fields are skipped. Fields that a message type does not use are
//! ignored on decode and never encoded.

use alloc::vec::Vec;

use minip2p_core::{
    PeerId, WIRE_LEN, WIRE_VARINT, WireError, encode_bytes_field, encode_frame,
    encode_varint_field, read_len_delimited, read_tag, read_varint_value, skip_field,
};
use minip2p_relay::{Limit, RelayMessageError, Status};
use thiserror::Error;

/// Protocol id of the directory stream a mesh node pushes its local
/// reservations on.
pub const DIRECTORY_PROTOCOL_ID: &str = "/minip2p/relay-mesh/directory/1.0.0";

/// Protocol id of the stream an entry node forwards a CONNECT on.
pub const FORWARD_PROTOCOL_ID: &str = "/minip2p/relay-mesh/forward/1.0.0";

/// Largest protobuf payload of one mesh frame: 8 KiB, as for relay control
/// frames. A payload of exactly this size is accepted.
pub const MAX_MESH_MESSAGE_SIZE: usize = minip2p_relay::MAX_MESSAGE_SIZE;

/// One message on a directory stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectoryMessage {
    /// `peer` holds a reservation on the sending node until `expires_unix`
    /// (UTC UNIX seconds). Sent on commit, renewal, and connection move.
    Present {
        /// Reserved peer.
        peer: PeerId,
        /// Reservation expiry, UTC UNIX seconds.
        expires_unix: u64,
    },
    /// `peer` no longer holds a reservation on the sending node.
    Gone {
        /// Peer whose reservation ended.
        peer: PeerId,
    },
    /// The snapshot that opens the stream is complete.
    Synced,
}

/// One message on a forward stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForwardMessage {
    /// Entry node to holding node: open a circuit from `source` to the
    /// holding node's reservation for `destination`, under `limit`.
    Forward {
        /// The dialer, as it appears in STOP CONNECT.
        source: PeerId,
        /// The reserved peer the dialer asked for.
        destination: PeerId,
        /// The entry node's circuit limit; an absent field decodes as
        /// [`Limit::default`].
        limit: Limit,
    },
    /// Holding node to entry node: the outcome of a `Forward`, as a Circuit
    /// Relay v2 status code.
    Status(Status),
}

/// Why a mesh frame could not be decoded.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum MeshMessageError {
    /// The frame header declared a payload over [`MAX_MESH_MESSAGE_SIZE`].
    #[error("mesh frame length {len} exceeds the maximum of {MAX_MESH_MESSAGE_SIZE}")]
    FrameTooLarge {
        /// The declared payload length.
        len: u64,
    },
    /// A shared protobuf framing failure.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// The `type` field was missing.
    #[error("required `type` field missing")]
    MissingType,
    /// The `type` field had a value this message does not define.
    #[error("invalid message type value: {value}")]
    InvalidMessageType {
        /// The raw value.
        value: u64,
    },
    /// A field the message type requires was missing.
    #[error("required `{field}` field missing")]
    MissingField {
        /// The protobuf field name.
        field: &'static str,
    },
    /// A peer id field was not a valid peer id multihash.
    #[error("invalid peer id in `{field}` field")]
    InvalidPeerId {
        /// The protobuf field name.
        field: &'static str,
    },
}

impl From<RelayMessageError> for MeshMessageError {
    fn from(error: RelayMessageError) -> Self {
        match error {
            RelayMessageError::Wire(e) => Self::Wire(e),
            RelayMessageError::MissingType => Self::MissingType,
            RelayMessageError::InvalidMessageType { value } => Self::InvalidMessageType { value },
        }
    }
}

impl DirectoryMessage {
    /// Encodes the protobuf payload, without length prefix.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Present { peer, expires_unix } => {
                encode_varint_field(&mut out, 1, 0);
                encode_bytes_field(&mut out, 2, &peer.to_bytes());
                encode_varint_field(&mut out, 3, *expires_unix);
            }
            Self::Gone { peer } => {
                encode_varint_field(&mut out, 1, 1);
                encode_bytes_field(&mut out, 2, &peer.to_bytes());
            }
            Self::Synced => encode_varint_field(&mut out, 1, 2),
        }
        out
    }

    /// Encodes one length-prefixed frame. Every directory message fits well
    /// under [`MAX_MESH_MESSAGE_SIZE`].
    pub fn encode_frame(&self) -> Vec<u8> {
        encode_frame(&self.encode())
    }

    /// Decodes a protobuf payload, without length prefix.
    pub fn decode(input: &[u8]) -> Result<Self, MeshMessageError> {
        let mut kind = None;
        let mut peer = None;
        let mut expires_unix = None;
        let mut idx = 0;
        while let Some((field, wire_type)) = read_tag(input, &mut idx)? {
            match (field, wire_type) {
                (1, WIRE_VARINT) => kind = Some(read_varint_value(input, &mut idx)?),
                (2, WIRE_LEN) => peer = Some(read_len_delimited(input, &mut idx)?),
                (3, WIRE_VARINT) => expires_unix = Some(read_varint_value(input, &mut idx)?),
                _ => skip_field(input, &mut idx, wire_type)?,
            }
        }
        match kind.ok_or(MeshMessageError::MissingType)? {
            0 => Ok(Self::Present {
                peer: decode_peer(peer, "peer")?,
                expires_unix: expires_unix.ok_or(MeshMessageError::MissingField {
                    field: "expires_unix",
                })?,
            }),
            1 => Ok(Self::Gone {
                peer: decode_peer(peer, "peer")?,
            }),
            2 => Ok(Self::Synced),
            value => Err(MeshMessageError::InvalidMessageType { value }),
        }
    }
}

impl ForwardMessage {
    /// Encodes the protobuf payload, without length prefix.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Forward {
                source,
                destination,
                limit,
            } => {
                encode_varint_field(&mut out, 1, 0);
                encode_bytes_field(&mut out, 2, &source.to_bytes());
                encode_bytes_field(&mut out, 3, &destination.to_bytes());
                encode_bytes_field(&mut out, 4, &limit.encode());
            }
            Self::Status(status) => {
                encode_varint_field(&mut out, 1, 1);
                encode_varint_field(&mut out, 5, status.to_u64());
            }
        }
        out
    }

    /// Encodes one length-prefixed frame. Every forward message fits well
    /// under [`MAX_MESH_MESSAGE_SIZE`].
    pub fn encode_frame(&self) -> Vec<u8> {
        encode_frame(&self.encode())
    }

    /// Decodes a protobuf payload, without length prefix.
    pub fn decode(input: &[u8]) -> Result<Self, MeshMessageError> {
        let mut kind = None;
        let mut source = None;
        let mut destination = None;
        let mut limit = None;
        let mut status = None;
        let mut idx = 0;
        while let Some((field, wire_type)) = read_tag(input, &mut idx)? {
            match (field, wire_type) {
                (1, WIRE_VARINT) => kind = Some(read_varint_value(input, &mut idx)?),
                (2, WIRE_LEN) => source = Some(read_len_delimited(input, &mut idx)?),
                (3, WIRE_LEN) => destination = Some(read_len_delimited(input, &mut idx)?),
                (4, WIRE_LEN) => limit = Some(Limit::decode(read_len_delimited(input, &mut idx)?)?),
                (5, WIRE_VARINT) => {
                    status = Some(Status::from_u64(read_varint_value(input, &mut idx)?));
                }
                _ => skip_field(input, &mut idx, wire_type)?,
            }
        }
        match kind.ok_or(MeshMessageError::MissingType)? {
            0 => Ok(Self::Forward {
                source: decode_peer(source, "source")?,
                destination: decode_peer(destination, "destination")?,
                limit: limit.unwrap_or_default(),
            }),
            1 => Ok(Self::Status(
                status.ok_or(MeshMessageError::MissingField { field: "status" })?,
            )),
            value => Err(MeshMessageError::InvalidMessageType { value }),
        }
    }
}

/// Decodes one complete length-prefixed frame from the start of `input` with
/// `decode`, returning the message and the bytes it consumed, or `Ok(None)`
/// while the frame is incomplete.
///
/// For a one-shot buffer such as a forward stream's reply. A directory stream
/// is fed through [`super::Directory`], which keeps its own frame buffer.
pub fn decode_mesh_frame<T>(
    input: &[u8],
    decode: impl FnOnce(&[u8]) -> Result<T, MeshMessageError>,
) -> Result<Option<(T, usize)>, MeshMessageError> {
    match minip2p_core::decode_frame(input, MAX_MESH_MESSAGE_SIZE) {
        minip2p_core::FrameDecode::Complete { payload, consumed } => {
            Ok(Some((decode(payload)?, consumed)))
        }
        minip2p_core::FrameDecode::Incomplete => Ok(None),
        minip2p_core::FrameDecode::TooLarge { len } => Err(MeshMessageError::FrameTooLarge { len }),
        minip2p_core::FrameDecode::Error(e) => Err(MeshMessageError::Wire(e.into())),
    }
}

fn decode_peer(bytes: Option<&[u8]>, field: &'static str) -> Result<PeerId, MeshMessageError> {
    let bytes = bytes.ok_or(MeshMessageError::MissingField { field })?;
    #[expect(
        clippy::map_err_ignore,
        reason = "the field name is the actionable context; multihash internals are not"
    )]
    PeerId::from_bytes(bytes).map_err(|_| MeshMessageError::InvalidPeerId { field })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(seed: u8) -> PeerId {
        PeerId::from_public_key_protobuf(&[seed])
    }

    #[test]
    fn directory_messages_round_trip_through_frames() {
        for message in [
            DirectoryMessage::Present {
                peer: peer(1),
                expires_unix: 1_700_000_000,
            },
            DirectoryMessage::Gone { peer: peer(2) },
            DirectoryMessage::Synced,
        ] {
            let frame = message.encode_frame();
            let decoded = decode_mesh_frame(&frame, DirectoryMessage::decode)
                .expect("decodes")
                .expect("complete");
            assert_eq!(decoded, (message, frame.len()));
        }
    }

    #[test]
    fn forward_messages_round_trip_through_frames() {
        for message in [
            ForwardMessage::Forward {
                source: peer(1),
                destination: peer(2),
                limit: Limit {
                    duration: Some(120),
                    data: Some(1 << 17),
                },
            },
            ForwardMessage::Status(Status::NoReservation),
            ForwardMessage::Status(Status::Unknown(999)),
        ] {
            let frame = message.encode_frame();
            let decoded = decode_mesh_frame(&frame, ForwardMessage::decode)
                .expect("decodes")
                .expect("complete");
            assert_eq!(decoded, (message, frame.len()));
        }
    }

    #[test]
    fn unknown_fields_are_skipped() {
        let mut payload = DirectoryMessage::Gone { peer: peer(3) }.encode();
        encode_bytes_field(&mut payload, 9, b"future");
        assert_eq!(
            DirectoryMessage::decode(&payload),
            Ok(DirectoryMessage::Gone { peer: peer(3) })
        );
    }

    #[test]
    fn malformed_payloads_are_rejected() {
        let mut no_expiry = Vec::new();
        encode_varint_field(&mut no_expiry, 1, 0);
        encode_bytes_field(&mut no_expiry, 2, &peer(1).to_bytes());
        assert_eq!(
            DirectoryMessage::decode(&no_expiry),
            Err(MeshMessageError::MissingField {
                field: "expires_unix"
            })
        );

        let mut bad_peer = Vec::new();
        encode_varint_field(&mut bad_peer, 1, 1);
        encode_bytes_field(&mut bad_peer, 2, b"not a multihash");
        assert_eq!(
            DirectoryMessage::decode(&bad_peer),
            Err(MeshMessageError::InvalidPeerId { field: "peer" })
        );

        let mut bad_type = Vec::new();
        encode_varint_field(&mut bad_type, 1, 7);
        assert_eq!(
            ForwardMessage::decode(&bad_type),
            Err(MeshMessageError::InvalidMessageType { value: 7 })
        );

        let mut no_status = Vec::new();
        encode_varint_field(&mut no_status, 1, 1);
        assert_eq!(
            ForwardMessage::decode(&no_status),
            Err(MeshMessageError::MissingField { field: "status" })
        );

        assert_eq!(
            ForwardMessage::decode(&[]),
            Err(MeshMessageError::MissingType)
        );
        assert!(matches!(
            DirectoryMessage::decode(&[0x12, 0x05, 0x01]),
            Err(MeshMessageError::Wire(WireError::FieldOverflow { .. }))
        ));
    }

    #[test]
    fn frames_over_the_cap_are_refused_from_the_header() {
        let mut header = Vec::new();
        minip2p_core::write_uvarint(MAX_MESH_MESSAGE_SIZE as u64 + 1, &mut header);
        assert_eq!(
            decode_mesh_frame(&header, DirectoryMessage::decode),
            Err(MeshMessageError::FrameTooLarge {
                len: MAX_MESH_MESSAGE_SIZE as u64 + 1
            })
        );
        assert_eq!(
            decode_mesh_frame(&header[..1], DirectoryMessage::decode),
            Ok(None)
        );
    }
}
