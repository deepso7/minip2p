//! Sans-IO state machine for `/multistream/1.0.0` protocol negotiation.
//!
//! Messages use varint-length-prefixed framing per the libp2p spec.
//! `no_std` + `alloc` compatible.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use minip2p_core::{read_uvarint, uvarint_len, write_uvarint, VarintError};
use thiserror::Error;

/// The multistream-select protocol identifier.
pub const MULTISTREAM_PROTOCOL_ID: &str = "/multistream/1.0.0";
/// The "not available" response sent when a protocol is unsupported.
const NOT_AVAILABLE: &str = "na";
/// Maximum allowed message payload length in bytes.
const MAX_MESSAGE_LEN: usize = 1024;

/// Output produced by the negotiation state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MultistreamOutput {
    /// Bytes to send to the remote peer.
    OutboundData(Vec<u8>),
    /// Protocol negotiation succeeded.
    Negotiated { protocol: String },
    /// The remote peer does not support the requested protocol.
    NotAvailable,
    /// A protocol-level error occurred; negotiation is terminated.
    ProtocolError { reason: String },
}

/// Errors encountered during multistream-select framing or negotiation.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MultistreamError {
    #[error("message exceeds maximum length ({len} > {MAX_MESSAGE_LEN})")]
    MessageTooLong { len: usize },
    #[error("invalid varint in message frame: {0}")]
    InvalidVarint(VarintError),
    #[error("non-utf8 message payload")]
    NonUtf8,
    #[error("message missing trailing newline")]
    MissingNewline,
    #[error("empty protocol line")]
    EmptyProtocol,
    #[error("unexpected multistream header: {actual}")]
    UnexpectedHeader { actual: String },
    #[error("unexpected protocol response: {actual}")]
    UnexpectedProtocolResponse { actual: String },
}

/// Whether this side initiated (Dialer) or accepted (Listener) the negotiation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Role {
    Dialer,
    Listener,
}

/// Internal state machine states for the multistream-select handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    /// Expecting the remote's multistream protocol header.
    WaitingForRemoteHeader,
    /// Listener waiting for the dialer's protocol proposal.
    WaitingForProtocolRequest,
    /// Dialer waiting for the listener's protocol confirmation or rejection.
    WaitingForProtocolResponse,
    /// Negotiation finished (success or error).
    Done,
}

/// Multistream-select negotiation state machine.
pub struct MultistreamSelect {
    role: Role,
    state: State,
    desired_protocol: Option<String>,
    supported_protocols: BTreeSet<String>,
    recv_buf: Vec<u8>,
    started: bool,
}

impl MultistreamSelect {
    /// Creates a dialer that will propose `desired_protocol`.
    pub fn dialer(desired_protocol: impl Into<String>) -> Self {
        Self {
            role: Role::Dialer,
            state: State::WaitingForRemoteHeader,
            desired_protocol: Some(desired_protocol.into()),
            supported_protocols: BTreeSet::new(),
            recv_buf: Vec::new(),
            started: false,
        }
    }

    /// Creates a listener that accepts connections for the given protocols.
    pub fn listener(protocols: impl IntoIterator<Item = String>) -> Self {
        Self {
            role: Role::Listener,
            state: State::WaitingForRemoteHeader,
            desired_protocol: None,
            supported_protocols: protocols.into_iter().collect(),
            recv_buf: Vec::new(),
            started: false,
        }
    }

    /// Produces the initial multistream header to send. Idempotent.
    pub fn start(&mut self) -> Vec<MultistreamOutput> {
        if self.started {
            return Vec::new();
        }

        self.started = true;
        vec![MultistreamOutput::OutboundData(encode_message(
            MULTISTREAM_PROTOCOL_ID,
        ))]
    }

    /// Returns `true` if negotiation has completed (successfully or with an error).
    pub fn is_done(&self) -> bool {
        self.state == State::Done
    }

    /// Drains and returns any buffered bytes received after negotiation finished.
    ///
    /// If the remote pipelines protocol data into the same network packet that
    /// completes the multistream-select handshake, those extra bytes remain in
    /// the internal receive buffer. After detecting [`MultistreamOutput::Negotiated`],
    /// callers should drain these bytes and hand them to the negotiated
    /// protocol handler.
    pub fn take_remaining_buffer(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.recv_buf)
    }

    /// Feeds received bytes into the state machine and returns any outputs.
    pub fn receive(&mut self, bytes: &[u8]) -> Vec<MultistreamOutput> {
        if self.state == State::Done {
            return Vec::new();
        }

        self.recv_buf.extend_from_slice(bytes);
        let mut outputs = Vec::new();

        loop {
            if self.state == State::Done {
                break;
            }

            let (payload, consumed) = match decode_message(&self.recv_buf) {
                DecodeResult::Complete { payload, consumed } => {
                    (payload.to_string(), consumed)
                }
                DecodeResult::Incomplete => break,
                DecodeResult::Error(err) => {
                    outputs.extend(self.protocol_error(err));
                    break;
                }
            };
            self.recv_buf.drain(..consumed);
            outputs.extend(self.on_message(&payload));
        }

        outputs
    }

    /// Processes a single decoded protocol line and advances the state machine.
    fn on_message(&mut self, line: &str) -> Vec<MultistreamOutput> {
        match self.state {
            State::WaitingForRemoteHeader => {
                if line != MULTISTREAM_PROTOCOL_ID {
                    return self.protocol_error(MultistreamError::UnexpectedHeader {
                        actual: line.to_string(),
                    });
                }

                match self.role {
                    Role::Dialer => {
                        let desired = self
                            .desired_protocol
                            .as_ref()
                            .expect("dialer must have desired protocol");
                        self.state = State::WaitingForProtocolResponse;
                        vec![MultistreamOutput::OutboundData(encode_message(desired))]
                    }
                    Role::Listener => {
                        self.state = State::WaitingForProtocolRequest;
                        Vec::new()
                    }
                }
            }
            State::WaitingForProtocolRequest => {
                if self.supported_protocols.contains(line) {
                    self.state = State::Done;
                    vec![
                        MultistreamOutput::OutboundData(encode_message(line)),
                        MultistreamOutput::Negotiated {
                            protocol: line.to_string(),
                        },
                    ]
                } else {
                    self.state = State::Done;
                    vec![
                        MultistreamOutput::OutboundData(encode_message(NOT_AVAILABLE)),
                        MultistreamOutput::NotAvailable,
                    ]
                }
            }
            State::WaitingForProtocolResponse => {
                let desired = self
                    .desired_protocol
                    .as_ref()
                    .expect("dialer must have desired protocol");

                if line == desired {
                    self.state = State::Done;
                    vec![MultistreamOutput::Negotiated {
                        protocol: desired.clone(),
                    }]
                } else if line == NOT_AVAILABLE {
                    self.state = State::Done;
                    vec![MultistreamOutput::NotAvailable]
                } else {
                    self.protocol_error(MultistreamError::UnexpectedProtocolResponse {
                        actual: line.to_string(),
                    })
                }
            }
            State::Done => Vec::new(),
        }
    }

    /// Transitions to Done and returns a ProtocolError output.
    fn protocol_error(&mut self, error: MultistreamError) -> Vec<MultistreamOutput> {
        self.state = State::Done;
        vec![MultistreamOutput::ProtocolError {
            reason: error.to_string(),
        }]
    }
}

/// Encodes a protocol string as a varint-length-prefixed message.
///
/// Wire format: `<uvarint: len(payload + '\n')> <payload> <'\n'>`
fn encode_message(protocol: &str) -> Vec<u8> {
    let payload_len = protocol.len() + 1; // +1 for trailing '\n'
    let mut out = Vec::with_capacity(uvarint_len(payload_len as u64) + payload_len);
    write_uvarint(payload_len as u64, &mut out);
    out.extend_from_slice(protocol.as_bytes());
    out.push(b'\n');
    out
}

/// Result of attempting to decode a varint-framed message from the buffer.
enum DecodeResult<'a> {
    /// A complete message was decoded.
    Complete { payload: &'a str, consumed: usize },
    /// Not enough data yet.
    Incomplete,
    /// Framing or content error.
    Error(MultistreamError),
}

/// Attempts to decode one varint-length-prefixed message from the buffer.
fn decode_message(buf: &[u8]) -> DecodeResult<'_> {
    if buf.is_empty() {
        return DecodeResult::Incomplete;
    }

    let (msg_len, varint_bytes) = match read_uvarint(buf) {
        Ok(pair) => pair,
        Err(VarintError::BufferTooShort) => return DecodeResult::Incomplete,
        Err(e) => return DecodeResult::Error(MultistreamError::InvalidVarint(e)),
    };

    let msg_len = msg_len as usize;

    if msg_len > MAX_MESSAGE_LEN {
        return DecodeResult::Error(MultistreamError::MessageTooLong { len: msg_len });
    }

    let total = varint_bytes + msg_len;
    if buf.len() < total {
        return DecodeResult::Incomplete;
    }

    let msg_bytes = &buf[varint_bytes..total];

    // The message must end with '\n' per the spec.
    if msg_bytes.last() != Some(&b'\n') {
        return DecodeResult::Error(MultistreamError::MissingNewline);
    }

    // Strip the trailing newline to get the payload.
    let payload_bytes = &msg_bytes[..msg_bytes.len() - 1];

    let payload = match core::str::from_utf8(payload_bytes) {
        Ok(s) => s,
        Err(_) => return DecodeResult::Error(MultistreamError::NonUtf8),
    };

    if payload.is_empty() {
        return DecodeResult::Error(MultistreamError::EmptyProtocol);
    }

    DecodeResult::Complete {
        payload,
        consumed: total,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PING: &str = "/ipfs/ping/1.0.0";

    #[test]
    fn dialer_and_listener_negotiate_ping() {
        let mut dialer = MultistreamSelect::dialer(PING);
        let mut listener = MultistreamSelect::listener([PING.to_string()]);

        let listener_start = listener.start();
        let dialer_start = dialer.start();

        assert_eq!(
            listener_start,
            vec![MultistreamOutput::OutboundData(encode_message(
                MULTISTREAM_PROTOCOL_ID
            ))]
        );
        assert_eq!(
            dialer_start,
            vec![MultistreamOutput::OutboundData(encode_message(
                MULTISTREAM_PROTOCOL_ID
            ))]
        );

        let dialer_after_header = dialer.receive(&encode_message(MULTISTREAM_PROTOCOL_ID));
        assert_eq!(
            dialer_after_header,
            vec![MultistreamOutput::OutboundData(encode_message(PING))]
        );

        let listener_after_header = listener.receive(&encode_message(MULTISTREAM_PROTOCOL_ID));
        assert!(listener_after_header.is_empty());

        let listener_after_request = listener.receive(&encode_message(PING));
        assert_eq!(
            listener_after_request,
            vec![
                MultistreamOutput::OutboundData(encode_message(PING)),
                MultistreamOutput::Negotiated {
                    protocol: PING.to_string()
                }
            ]
        );

        let dialer_after_response = dialer.receive(&encode_message(PING));
        assert_eq!(
            dialer_after_response,
            vec![MultistreamOutput::Negotiated {
                protocol: PING.to_string()
            }]
        );
    }

    #[test]
    fn listener_rejects_unsupported_protocol() {
        let mut listener = MultistreamSelect::listener(["/ipfs/identify/1.0.0".to_string()]);
        let _ = listener.start();
        let _ = listener.receive(&encode_message(MULTISTREAM_PROTOCOL_ID));

        let out = listener.receive(&encode_message(PING));
        assert_eq!(
            out,
            vec![
                MultistreamOutput::OutboundData(encode_message("na")),
                MultistreamOutput::NotAvailable
            ]
        );
    }

    #[test]
    fn parses_chunked_input() {
        let mut dialer = MultistreamSelect::dialer(PING);
        let _ = dialer.start();

        let full = encode_message(MULTISTREAM_PROTOCOL_ID);
        let (a, b) = full.split_at(full.len() / 2);

        let out = dialer.receive(a);
        assert!(out.is_empty());

        let out = dialer.receive(b);
        assert_eq!(
            out,
            vec![MultistreamOutput::OutboundData(encode_message(PING))]
        );
    }

    #[test]
    fn errors_on_unexpected_header() {
        let mut dialer = MultistreamSelect::dialer(PING);
        let _ = dialer.start();

        let out = dialer.receive(&encode_message("/wrong/1.0.0"));
        assert!(matches!(
            out.as_slice(),
            [MultistreamOutput::ProtocolError { .. }]
        ));
    }

    #[test]
    fn encode_decode_roundtrip() {
        let encoded = encode_message("/ipfs/ping/1.0.0");

        // Verify wire format: varint + payload + newline
        let (msg_len, varint_bytes) = read_uvarint(&encoded).unwrap();
        assert_eq!(msg_len as usize, "/ipfs/ping/1.0.0".len() + 1); // +1 for '\n'
        assert_eq!(encoded.len(), varint_bytes + msg_len as usize);
        assert_eq!(encoded.last(), Some(&b'\n'));

        match decode_message(&encoded) {
            DecodeResult::Complete { payload, consumed } => {
                assert_eq!(payload, "/ipfs/ping/1.0.0");
                assert_eq!(consumed, encoded.len());
            }
            _ => panic!("expected Complete"),
        }
    }

    #[test]
    fn rejects_non_utf8_payload() {
        // Build a message with invalid UTF-8: varint(3) + [0xFF, 0xFE] + '\n'
        let mut msg = Vec::new();
        write_uvarint(3, &mut msg);
        msg.push(0xFF);
        msg.push(0xFE);
        msg.push(b'\n');

        let mut dialer = MultistreamSelect::dialer(PING);
        let _ = dialer.start();
        let out = dialer.receive(&msg);
        assert!(matches!(
            out.as_slice(),
            [MultistreamOutput::ProtocolError { .. }]
        ));
    }

    #[test]
    fn rejects_oversized_message() {
        let long_protocol = "x".repeat(MAX_MESSAGE_LEN + 1);
        let encoded = encode_message(&long_protocol);

        let mut dialer = MultistreamSelect::dialer(PING);
        let _ = dialer.start();
        let out = dialer.receive(&encoded);
        assert!(matches!(
            out.as_slice(),
            [MultistreamOutput::ProtocolError { .. }]
        ));
    }

    #[test]
    fn multiple_messages_in_one_receive() {
        let mut dialer = MultistreamSelect::dialer(PING);
        let _ = dialer.start();

        // Send header + protocol confirmation in a single buffer
        let mut combined = encode_message(MULTISTREAM_PROTOCOL_ID);
        combined.extend_from_slice(&encode_message(PING));

        let out = dialer.receive(&combined);
        assert_eq!(
            out,
            vec![
                MultistreamOutput::OutboundData(encode_message(PING)),
                MultistreamOutput::Negotiated {
                    protocol: PING.to_string()
                }
            ]
        );
    }

    #[test]
    fn dialer_receives_na() {
        let mut dialer = MultistreamSelect::dialer(PING);
        let _ = dialer.start();
        let _ = dialer.receive(&encode_message(MULTISTREAM_PROTOCOL_ID));

        let out = dialer.receive(&encode_message("na"));
        assert_eq!(out, vec![MultistreamOutput::NotAvailable]);
    }
}
