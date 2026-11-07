//! Sans-IO state machine for `/multistream/1.0.0` protocol negotiation.
//!
//! Messages use varint-length-prefixed framing per the libp2p spec.
//! `no_std` + `alloc` compatible.
//!
//! The dialer sends its header and its proposal together, as go-libp2p and
//! rust-libp2p do, so a negotiation takes one round trip. It still requires
//! the listener's header before the listener's answer.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::collections::{BTreeSet, VecDeque};
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use minip2p_core::{VarintError, read_uvarint, uvarint_len, write_uvarint};
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
    /// A protocol proposal was unavailable: either the listener rejected the
    /// dialer's proposal or the dialer received `na` from the listener.
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

/// Which side of the negotiation this is, with the data only that side needs.
enum Role {
    /// Initiated the stream and proposes one protocol.
    Dialer { desired: String },
    /// Accepted the stream and answers proposals from this set.
    Listener { supported: BTreeSet<String> },
}

/// Internal state machine states for the multistream-select handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    /// `start` has not run. Received bytes are buffered, not answered, so
    /// nothing goes out before this side's header.
    Unstarted,
    /// Expecting the remote's multistream protocol header. A started dialer
    /// has already sent its proposal too.
    WaitingForRemoteHeader,
    /// Header received: a listener waits for a proposal, a dialer for the
    /// answer to its own.
    Negotiating,
    /// Negotiation finished (success or error).
    Done,
}

/// Multistream-select negotiation state machine.
pub struct MultistreamSelect {
    role: Role,
    state: State,
    recv_buf: Vec<u8>,
    pending_outputs: VecDeque<MultistreamOutput>,
}

impl MultistreamSelect {
    /// Creates a dialer that will propose `desired_protocol`.
    pub fn dialer(desired_protocol: impl Into<String>) -> Self {
        Self::new(Role::Dialer {
            desired: desired_protocol.into(),
        })
    }

    /// Creates a listener that accepts connections for the given protocols.
    pub fn listener(protocols: impl IntoIterator<Item = String>) -> Self {
        Self::new(Role::Listener {
            supported: protocols.into_iter().collect(),
        })
    }

    fn new(role: Role) -> Self {
        Self {
            role,
            state: State::Unstarted,
            recv_buf: Vec::new(),
            pending_outputs: VecDeque::new(),
        }
    }

    /// Queues the initial write: the multistream header, and for a dialer its
    /// protocol proposal right after it in the same `OutboundData`. Then
    /// answers any bytes received before the start. Idempotent.
    pub fn start(&mut self) {
        if self.state != State::Unstarted {
            return;
        }

        self.state = State::WaitingForRemoteHeader;
        let mut first_write = encode_message(MULTISTREAM_PROTOCOL_ID);
        if let Role::Dialer { desired } = &self.role {
            first_write.extend_from_slice(&encode_message(desired));
        }
        self.pending_outputs
            .push_back(MultistreamOutput::OutboundData(first_write));
        self.process_buffer();
    }

    /// Returns `true` if negotiation has completed (successfully or with an error).
    #[cfg(test)]
    pub fn is_done(&self) -> bool {
        self.state == State::Done
    }

    /// Returns `true` while a dialer has drained its proposal and only reads
    /// the reply: it has nothing left to write. That holds from the moment
    /// `start`'s write is polled, before the remote header arrives.
    pub fn awaits_response(&self) -> bool {
        matches!(self.role, Role::Dialer { .. })
            && matches!(
                self.state,
                State::WaitingForRemoteHeader | State::Negotiating
            )
            && self.pending_outputs.is_empty()
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

    /// Feeds received bytes into the state machine, queuing any outputs.
    /// Bytes received before [`start`](Self::start) wait for it.
    pub fn on_data(&mut self, bytes: &[u8]) {
        if self.state == State::Done {
            return;
        }

        self.recv_buf.extend_from_slice(bytes);
        self.process_buffer();
    }

    /// Handles every complete message buffered so far.
    fn process_buffer(&mut self) {
        while matches!(
            self.state,
            State::WaitingForRemoteHeader | State::Negotiating
        ) {
            let (next_state, produced, consumed) = match decode_message(&self.recv_buf) {
                DecodeResult::Complete { payload, consumed } => {
                    let (next_state, produced) = handle_message(&self.role, self.state, payload);
                    (next_state, produced, consumed)
                }
                DecodeResult::Incomplete => break,
                DecodeResult::Error(err) => {
                    self.state = State::Done;
                    self.pending_outputs
                        .push_back(MultistreamOutput::ProtocolError {
                            reason: err.to_string(),
                        });
                    break;
                }
            };
            self.recv_buf.drain(..consumed);
            self.state = next_state;
            self.pending_outputs.extend(produced);
        }
    }

    /// Returns the next pending output, if any.
    ///
    /// Drain until `None` after every input, before waiting on the stream
    /// again.
    pub fn poll_output(&mut self) -> Option<MultistreamOutput> {
        self.pending_outputs.pop_front()
    }
}

/// Processes a single decoded protocol line.
fn handle_message(role: &Role, state: State, line: &str) -> (State, Vec<MultistreamOutput>) {
    match (state, role) {
        (State::WaitingForRemoteHeader, _) => {
            if line != MULTISTREAM_PROTOCOL_ID {
                return protocol_error(MultistreamError::UnexpectedHeader {
                    actual: line.to_string(),
                });
            }
            // The dialer's proposal went out with its header in `start`.
            (State::Negotiating, Vec::new())
        }
        (State::Negotiating, Role::Listener { supported }) => {
            if supported.contains(line) {
                (
                    State::Done,
                    vec![
                        MultistreamOutput::OutboundData(encode_message(line)),
                        MultistreamOutput::Negotiated {
                            protocol: line.to_string(),
                        },
                    ],
                )
            } else {
                (
                    // A dialer may propose another protocol on the same
                    // stream after `na` (for example rust-libp2p tries
                    // meshsub 1.2 before falling back to 1.1). Keep the
                    // listener alive for that next proposal.
                    State::Negotiating,
                    vec![
                        MultistreamOutput::OutboundData(encode_message(NOT_AVAILABLE)),
                        MultistreamOutput::NotAvailable,
                    ],
                )
            }
        }
        (State::Negotiating, Role::Dialer { desired }) => {
            if line == desired {
                (
                    State::Done,
                    vec![MultistreamOutput::Negotiated {
                        protocol: desired.clone(),
                    }],
                )
            } else if line == NOT_AVAILABLE {
                (State::Done, vec![MultistreamOutput::NotAvailable])
            } else {
                protocol_error(MultistreamError::UnexpectedProtocolResponse {
                    actual: line.to_string(),
                })
            }
        }
        // `process_buffer` only runs in the two states above.
        (State::Unstarted | State::Done, _) => (state, Vec::new()),
    }
}

fn protocol_error(error: MultistreamError) -> (State, Vec<MultistreamOutput>) {
    (
        State::Done,
        vec![MultistreamOutput::ProtocolError {
            reason: error.to_string(),
        }],
    )
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

    let msg_len = match usize::try_from(msg_len) {
        Ok(msg_len) => msg_len,
        Err(_) => {
            return DecodeResult::Error(MultistreamError::InvalidVarint(VarintError::Overflow));
        }
    };

    if msg_len > MAX_MESSAGE_LEN {
        return DecodeResult::Error(MultistreamError::MessageTooLong { len: msg_len });
    }

    let total = varint_bytes + msg_len;
    if buf.len() < total {
        return DecodeResult::Incomplete;
    }

    let Some(msg_bytes) = buf.get(varint_bytes..total) else {
        return DecodeResult::Incomplete;
    };

    // The message must end with '\n' per the spec. `split_last` also leaves
    // the payload without the terminator.
    let Some((&b'\n', payload_bytes)) = msg_bytes.split_last() else {
        return DecodeResult::Error(MultistreamError::MissingNewline);
    };

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

    impl MultistreamSelect {
        /// Starts and returns what the start queued (test helper).
        fn start_drained(&mut self) -> Vec<MultistreamOutput> {
            self.start();
            self.pending_outputs.drain(..).collect()
        }

        /// Feeds `bytes` and returns what they queued (test helper).
        fn receive(&mut self, bytes: &[u8]) -> Vec<MultistreamOutput> {
            self.on_data(bytes);
            self.pending_outputs.drain(..).collect()
        }
    }

    /// The dialer's header followed by its proposal, as one start queues them.
    fn header_and(protocol: &str) -> Vec<u8> {
        let mut bytes = encode_message(MULTISTREAM_PROTOCOL_ID);
        bytes.extend_from_slice(&encode_message(protocol));
        bytes
    }

    #[test]
    fn dialer_and_listener_negotiate_ping() {
        let mut dialer = MultistreamSelect::dialer(PING);
        let mut listener = MultistreamSelect::listener([PING.to_string()]);

        let listener_start = listener.start_drained();
        let dialer_start = dialer.start_drained();

        assert_eq!(
            listener_start,
            vec![MultistreamOutput::OutboundData(encode_message(
                MULTISTREAM_PROTOCOL_ID
            ))]
        );

        let listener_after_offer = listener.receive(&dialer_start_bytes(dialer_start));
        assert_eq!(
            listener_after_offer,
            vec![
                MultistreamOutput::OutboundData(encode_message(PING)),
                MultistreamOutput::Negotiated {
                    protocol: PING.to_string()
                }
            ]
        );

        assert!(
            dialer
                .receive(&encode_message(MULTISTREAM_PROTOCOL_ID))
                .is_empty()
        );
        assert_eq!(
            dialer.receive(&encode_message(PING)),
            vec![MultistreamOutput::Negotiated {
                protocol: PING.to_string()
            }]
        );
    }

    fn dialer_start_bytes(outputs: Vec<MultistreamOutput>) -> Vec<u8> {
        outputs
            .into_iter()
            .flat_map(|output| match output {
                MultistreamOutput::OutboundData(bytes) => bytes,
                other => panic!("dialer start queued {other:?}"),
            })
            .collect()
    }

    #[test]
    fn listener_rejects_unsupported_protocol() {
        let mut listener = MultistreamSelect::listener(["/ipfs/identify/1.0.0".to_string()]);
        let _ = listener.start_drained();
        let _ = listener.receive(&encode_message(MULTISTREAM_PROTOCOL_ID));

        let out = listener.receive(&encode_message(PING));
        assert_eq!(
            out,
            vec![
                MultistreamOutput::OutboundData(encode_message("na")),
                MultistreamOutput::NotAvailable
            ]
        );
        assert!(!listener.is_done());
    }

    #[test]
    fn listener_accepts_fallback_after_unsupported_proposal() {
        const MESHSUB_V1_2: &str = "/meshsub/1.2.0";
        const MESHSUB_V1_1: &str = "/meshsub/1.1.0";

        let mut listener = MultistreamSelect::listener([MESHSUB_V1_1.to_string()]);
        let _ = listener.start_drained();

        let mut pipelined = encode_message(MULTISTREAM_PROTOCOL_ID);
        pipelined.extend_from_slice(&encode_message(MESHSUB_V1_2));
        pipelined.extend_from_slice(&encode_message(MESHSUB_V1_1));

        assert_eq!(
            listener.receive(&pipelined),
            vec![
                MultistreamOutput::OutboundData(encode_message("na")),
                MultistreamOutput::NotAvailable,
                MultistreamOutput::OutboundData(encode_message(MESHSUB_V1_1)),
                MultistreamOutput::Negotiated {
                    protocol: MESHSUB_V1_1.to_string()
                }
            ]
        );
        assert!(listener.is_done());
    }

    #[test]
    fn parses_chunked_input() {
        let mut dialer = MultistreamSelect::dialer(PING);
        let _ = dialer.start_drained();

        let full = encode_message(MULTISTREAM_PROTOCOL_ID);
        let (a, b) = full.split_at(full.len() / 2);

        let out = dialer.receive(a);
        assert!(out.is_empty());

        let out = dialer.receive(b);
        assert!(out.is_empty(), "the proposal already went out with start");

        let full = encode_message(PING);
        let (a, b) = full.split_at(full.len() / 2);
        assert!(dialer.receive(a).is_empty());
        assert_eq!(
            dialer.receive(b),
            vec![MultistreamOutput::Negotiated {
                protocol: PING.to_string()
            }]
        );
    }

    #[test]
    fn errors_on_unexpected_header() {
        let mut dialer = MultistreamSelect::dialer(PING);
        let _ = dialer.start_drained();

        let out = dialer.receive(&encode_message("/wrong/1.0.0"));
        assert!(matches!(
            out.as_slice(),
            [MultistreamOutput::ProtocolError { .. }]
        ));
    }

    #[test]
    fn dialer_requires_header_before_the_echo() {
        // The proposal is already out, but the listener's answer still has
        // to come after its header.
        for first in [PING, NOT_AVAILABLE] {
            let mut dialer = MultistreamSelect::dialer(PING);
            let _ = dialer.start_drained();

            let out = dialer.receive(&encode_message(first));
            assert_eq!(
                out,
                vec![MultistreamOutput::ProtocolError {
                    reason: MultistreamError::UnexpectedHeader {
                        actual: first.to_string()
                    }
                    .to_string()
                }]
            );
            assert!(dialer.is_done());
        }
    }

    #[test]
    fn awaits_response_once_the_proposal_is_drained() {
        let mut dialer = MultistreamSelect::dialer(PING);
        assert!(!dialer.awaits_response(), "nothing sent before start");

        dialer.start();
        assert!(
            !dialer.awaits_response(),
            "header and proposal are still held unsent"
        );
        let _ = dialer.poll_output();
        assert!(
            dialer.awaits_response(),
            "proposal is out before the remote header arrives"
        );

        let _ = dialer.receive(&encode_message(MULTISTREAM_PROTOCOL_ID));
        assert!(dialer.awaits_response());

        let _ = dialer.receive(&encode_message(PING));
        assert!(!dialer.awaits_response(), "negotiation finished");

        let mut listener = MultistreamSelect::listener([PING.to_string()]);
        let _ = listener.start_drained();
        assert!(!listener.awaits_response());
    }

    #[test]
    fn data_before_start_is_answered_after_the_header() {
        let mut listener = MultistreamSelect::listener([PING.to_string()]);
        // Nothing may go out before the listener's own header.
        assert!(listener.receive(&header_and(PING)).is_empty());

        assert_eq!(
            listener.start_drained(),
            vec![
                MultistreamOutput::OutboundData(encode_message(MULTISTREAM_PROTOCOL_ID)),
                MultistreamOutput::OutboundData(encode_message(PING)),
                MultistreamOutput::Negotiated {
                    protocol: PING.to_string()
                }
            ]
        );
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
        let _ = dialer.start_drained();
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
        let _ = dialer.start_drained();
        let out = dialer.receive(&encoded);
        assert!(matches!(
            out.as_slice(),
            [MultistreamOutput::ProtocolError { .. }]
        ));
    }

    #[test]
    fn multiple_messages_in_one_receive() {
        let mut dialer = MultistreamSelect::dialer(PING);
        let _ = dialer.start_drained();

        // Send header + protocol confirmation in a single buffer
        let mut combined = encode_message(MULTISTREAM_PROTOCOL_ID);
        combined.extend_from_slice(&encode_message(PING));

        let out = dialer.receive(&combined);
        assert_eq!(
            out,
            vec![MultistreamOutput::Negotiated {
                protocol: PING.to_string()
            }]
        );
    }

    #[test]
    fn dialer_receives_na() {
        let mut dialer = MultistreamSelect::dialer(PING);
        let _ = dialer.start_drained();
        // `na` ends this dialer; a caller falls back with a fresh stream.
        let out = dialer.receive(&header_and(NOT_AVAILABLE));
        assert_eq!(out, vec![MultistreamOutput::NotAvailable]);
        assert!(dialer.is_done());
    }

    #[test]
    fn outputs_are_drained_through_poll_output() {
        let mut dialer = MultistreamSelect::dialer(PING);

        dialer.start();
        dialer.start();
        assert_eq!(
            dialer.poll_output(),
            Some(MultistreamOutput::OutboundData(header_and(PING))),
            "header and proposal leave in one write"
        );
        assert!(dialer.poll_output().is_none(), "start is idempotent");

        dialer.on_data(&header_and(PING));
        assert_eq!(
            dialer.poll_output(),
            Some(MultistreamOutput::Negotiated {
                protocol: PING.to_string()
            })
        );
    }
}
