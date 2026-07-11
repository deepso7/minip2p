//! Sans-IO state machines for DCUtR (Direct Connection Upgrade through Relay).
//!
//! Per the libp2p spec at
//! <https://github.com/libp2p/specs/blob/master/relay/DCUtR.md>, two peers
//! connected via a relay coordinate a simultaneous direct connection attempt
//! to escape NAT. The exchange uses a single message type (`HolePunch`) with
//! two kinds:
//!
//! - `CONNECT` (100) -- exchange of observed/predicted addresses.
//! - `SYNC` (300) -- synchronization signal to kick off the simultaneous dial.
//!
//! This crate models both roles:
//! - [`DcutrInitiator`] -- we want to upgrade the relay connection. Sends
//!   CONNECT first, measures RTT, then SYNC.
//! - [`DcutrResponder`] -- we received a CONNECT from a remote. Replies with
//!   our own CONNECT and waits for SYNC.
//!
//! For the QUIC transport, the spec defines the hole-punch timing as
//! asymmetric: the initiator (role `A` in the spec) dials immediately on
//! receiving `SYNC`; the responder (role `B`) waits RTT/2 and sends random
//! UDP packets to open its NAT mapping for inbound QUIC packets.
//!
//! `no_std` + `alloc` compatible.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod message;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::{Multiaddr, SansIoProtocol};

pub use message::{
    DcutrMessageError, FrameDecode, HolePunch, HolePunchType, decode_frame, encode_frame,
};

/// Protocol id for DCUtR.
pub const DCUTR_PROTOCOL_ID: &str = "/libp2p/dcutr";

/// Maximum size for a single DCUtR message (4 KiB, per spec).
pub const MAX_MESSAGE_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned by DCUtR state machines.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DcutrError {
    /// A message exceeded the maximum allowed size. This covers both
    /// incoming data and locally constructed outbound messages: a frame
    /// this crate's own decoder would reject is never queued for sending.
    #[error("DCUtR message exceeds maximum size ({len} > {MAX_MESSAGE_SIZE})")]
    MessageTooLarge { len: usize },
    /// The remote declared a frame length exceeding the maximum allowed size.
    #[error("DCUtR frame length exceeds maximum size ({len} > {MAX_MESSAGE_SIZE})")]
    FrameTooLarge { len: u64 },
    /// An incoming message failed to decode.
    #[error("malformed DCUtR message: {0}")]
    Malformed(#[from] DcutrMessageError),
    /// The remote sent a message type that is not valid for the current state.
    #[error("unexpected message: {0}")]
    UnexpectedMessage(String),
}

// ---------------------------------------------------------------------------
// DcutrInitiator: we initiate the hole punch
// ---------------------------------------------------------------------------

/// Sequence of actions the caller should take based on the initiator state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InitiatorOutcome {
    /// The remote has replied with their observed addresses. The caller
    /// should immediately dial these addresses.
    DialNow {
        /// Addresses observed by the remote. Entries that fail to parse
        /// as a valid [`Multiaddr`] are silently dropped; the raw bytes
        /// are still available via [`InitiatorOutcome::DialNow::remote_addr_bytes`].
        remote_addrs: Vec<Multiaddr>,
        /// Raw observed-address bytes as received on the wire, before
        /// parsing. Kept available so callers can surface diagnostics
        /// about malformed entries.
        remote_addr_bytes: Vec<Vec<u8>>,
        /// Measured relay RTT in milliseconds (wall clock between sending
        /// CONNECT and receiving the reply). Timing is the caller's
        /// responsibility; this is just the reported measurement.
        rtt_ms: u64,
    },
}

/// Input accepted by [`DcutrInitiator`] through [`SansIoProtocol`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DcutrInitiatorInput {
    /// Drain queued CONNECT or SYNC bytes into an output.
    Flush,
    /// Bytes received from the relay stream, with measured relay RTT.
    Data { bytes: Vec<u8>, rtt_ms: u64 },
    /// Remote write side closed.
    RemoteWriteClosed,
    /// Queue the SYNC frame after the caller has started direct dialing.
    SendSync,
}

/// Output produced by [`DcutrInitiator`] through [`SansIoProtocol`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DcutrInitiatorOutput {
    /// Bytes to write to the DCUtR stream.
    Outbound(Vec<u8>),
    /// Direct-dial instruction decoded from the remote CONNECT reply.
    Outcome(InitiatorOutcome),
}

/// Client-side (initiator) state machine.
///
/// Usage:
/// 1. Construct with [`DcutrInitiator::new`], passing our observed addresses.
/// 2. Drain [`DcutrInitiatorOutput::Outbound`] from
///    [`SansIoProtocol::poll_output`] and send the bytes.
/// 3. Record the send time; feed stream data with
///    [`DcutrInitiatorInput::Data`].
/// 4. When [`DcutrInitiatorOutput::Outcome`] returns `DialNow`, the caller:
///    - dials the returned addresses immediately,
///    - feeds [`DcutrInitiatorInput::SendSync`] to queue the SYNC frame,
///    - flushes the outbound bytes.
pub struct DcutrInitiator {
    outbound: Vec<u8>,
    recv_buf: Vec<u8>,
    state: InitiatorState,
    outcome: Option<InitiatorOutcome>,
    emitted_outcome: bool,
    /// Deferred construction error (oversized CONNECT), surfaced by the
    /// first [`SansIoProtocol::handle_input`] call.
    pending_error: Option<DcutrError>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InitiatorState {
    /// CONNECT queued but not yet taken by the caller.
    Pending,
    /// CONNECT sent; awaiting the remote's CONNECT reply.
    AwaitingConnectReply,
    /// Reply received; caller is expected to dial and then call send_sync().
    ReadyToSync,
    /// SYNC queued; awaiting caller to flush.
    SyncPending,
    /// SYNC sent; flow complete.
    Done,
}

impl DcutrInitiator {
    /// Creates a new initiator, queuing the outbound CONNECT message.
    ///
    /// `own_addrs` are our observed (and possibly predicted) multiaddrs.
    /// They are serialized via [`Multiaddr`]'s `Display` for the wire
    /// (see the crate-level note on binary vs string encoding).
    ///
    /// If the encoded CONNECT would exceed [`MAX_MESSAGE_SIZE`] -- a frame
    /// any spec-compliant peer (including this crate's own decoder) would
    /// reject -- no bytes are queued and the first
    /// [`SansIoProtocol::handle_input`] call fails with
    /// [`DcutrError::MessageTooLarge`].
    pub fn new(own_addrs: &[Multiaddr]) -> Self {
        let obs_addrs = own_addrs.iter().map(encode_multiaddr).collect();
        let msg = HolePunch {
            kind: HolePunchType::Connect,
            obs_addrs,
        };
        let (outbound, state, pending_error) = match checked_outbound_frame(&msg.encode()) {
            Ok(frame) => (frame, InitiatorState::Pending, None),
            Err(err) => (Vec::new(), InitiatorState::Done, Some(err)),
        };

        Self {
            outbound,
            recv_buf: Vec::new(),
            state,
            outcome: None,
            emitted_outcome: false,
            pending_error,
        }
    }

    /// Drains and returns any pending outbound bytes.
    fn take_outbound(&mut self) -> Vec<u8> {
        let bytes = core::mem::take(&mut self.outbound);
        self.state = match self.state {
            InitiatorState::Pending => InitiatorState::AwaitingConnectReply,
            InitiatorState::SyncPending => InitiatorState::Done,
            other => other,
        };
        bytes
    }

    /// Feeds incoming stream bytes.
    ///
    /// `rtt_ms` is the caller's measured RTT from when they sent CONNECT
    /// (via `take_outbound`) to now. It is passed through into the
    /// `DialNow` outcome so the caller can use it for SYNC timing.
    fn on_data(&mut self, data: &[u8], rtt_ms: u64) -> Result<(), DcutrError> {
        if matches!(
            self.state,
            InitiatorState::Done | InitiatorState::SyncPending
        ) {
            return Ok(());
        }

        self.recv_buf.extend_from_slice(data);
        self.try_decode_reply(rtt_ms)
    }

    /// Notifies the state machine that the remote closed its write side.
    fn on_remote_write_closed(&mut self) -> Result<(), DcutrError> {
        // No-op: the outcome is already resolved by the time we'd care.
        Ok(())
    }

    /// Returns the current outcome, if available.
    #[cfg(test)]
    fn outcome(&self) -> Option<&InitiatorOutcome> {
        self.outcome.as_ref()
    }

    /// Returns `true` if the flow has completed (SYNC was sent).
    pub fn is_done(&self) -> bool {
        self.state == InitiatorState::Done
    }

    /// Queues the SYNC message to be sent.
    ///
    /// Call this after you have initiated your simultaneous dial, per the
    /// spec. After feeding [`DcutrInitiatorInput::SendSync`], drain
    /// [`DcutrInitiatorOutput::Outbound`] to the stream.
    fn send_sync(&mut self) -> Result<(), DcutrError> {
        if self.state != InitiatorState::ReadyToSync {
            return Err(DcutrError::UnexpectedMessage(alloc::format!(
                "cannot send SYNC from state {:?}",
                self.state
            )));
        }

        let msg = HolePunch {
            kind: HolePunchType::Sync,
            obs_addrs: Vec::new(),
        };
        // SYNC carries no addresses and is structurally tiny; the size check
        // is kept for uniformity across all outbound frame constructions.
        self.outbound.extend(checked_outbound_frame(&msg.encode())?);
        self.state = InitiatorState::SyncPending;
        Ok(())
    }

    fn try_decode_reply(&mut self, rtt_ms: u64) -> Result<(), DcutrError> {
        if self.state != InitiatorState::AwaitingConnectReply {
            return Ok(());
        }

        let (reply, consumed) = match decode_frame(&self.recv_buf) {
            FrameDecode::Complete { payload, consumed } => {
                let reply = HolePunch::decode(payload).map_err(|e| {
                    self.state = InitiatorState::Done;
                    DcutrError::Malformed(e)
                })?;
                (reply, consumed)
            }
            // Only the incomplete remainder is bounded: a complete frame
            // decodes (and drains) regardless of what is coalesced behind
            // it, so the backstop can never reject a frame the decoder
            // would accept.
            FrameDecode::Incomplete => {
                enforce_max_size(&self.recv_buf).inspect_err(|_| {
                    self.state = InitiatorState::Done;
                })?;
                return Ok(());
            }
            FrameDecode::TooLarge { len } => {
                self.state = InitiatorState::Done;
                return Err(DcutrError::FrameTooLarge { len });
            }
            FrameDecode::Error(e) => {
                self.state = InitiatorState::Done;
                return Err(DcutrError::Malformed(DcutrMessageError::Varint(e)));
            }
        };
        self.recv_buf.drain(..consumed);

        if reply.kind != HolePunchType::Connect {
            self.state = InitiatorState::Done;
            return Err(DcutrError::UnexpectedMessage(alloc::format!(
                "expected HolePunch CONNECT but got {:?}",
                reply.kind
            )));
        }

        self.state = InitiatorState::ReadyToSync;
        let remote_addrs = decode_remote_addrs(&reply.obs_addrs);
        self.outcome = Some(InitiatorOutcome::DialNow {
            remote_addrs,
            remote_addr_bytes: reply.obs_addrs,
            rtt_ms,
        });
        self.emitted_outcome = false;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DcutrResponder: the remote is initiating; we reply and wait
// ---------------------------------------------------------------------------

/// Events the responder surfaces to its caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResponderEvent {
    /// The initiator has provided their observed addresses.
    ///
    /// We have already queued our own CONNECT reply via the constructor, but
    /// the caller now knows which addresses to NAT-punch towards.
    ConnectReceived {
        /// Decoded remote observed addresses. Malformed entries are
        /// dropped silently; the raw bytes remain in `remote_addr_bytes`
        /// for diagnostics.
        remote_addrs: Vec<Multiaddr>,
        /// Raw bytes of the observed addresses as received on the wire.
        remote_addr_bytes: Vec<Vec<u8>>,
    },
    /// The initiator has sent SYNC. Per the spec, the responder should wait
    /// RTT/2 and then start sending random UDP packets to the remote's
    /// addresses to open its NAT binding.
    SyncReceived,
}

/// Input accepted by [`DcutrResponder`] through [`SansIoProtocol`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DcutrResponderInput {
    /// Drain queued CONNECT reply bytes into an output.
    Flush,
    /// Bytes received from the relay stream.
    Data(Vec<u8>),
    /// Remote write side closed.
    RemoteWriteClosed,
}

/// Output produced by [`DcutrResponder`] through [`SansIoProtocol`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DcutrResponderOutput {
    /// Bytes to write to the DCUtR stream.
    Outbound(Vec<u8>),
    /// Responder event decoded from incoming messages.
    Event(ResponderEvent),
}

/// Server-side (responder) state machine.
///
/// Usage:
/// 1. Construct with [`DcutrResponder::new`], passing our observed addresses.
///    Our CONNECT reply is queued automatically.
/// 2. Feed incoming bytes with [`DcutrResponderInput::Data`].
/// 3. Drain [`DcutrResponderOutput`] values from
///    [`SansIoProtocol::poll_output`].
/// 4. Send [`DcutrResponderOutput::Outbound`] bytes back on the relay stream.
/// 5. On [`DcutrResponderOutput::Event`] with
///    [`ResponderEvent::SyncReceived`], start the responder-side dial timing /
///    UDP bombardment strategy.
pub struct DcutrResponder {
    /// Pre-encoded, size-validated CONNECT reply frame; queued (taken)
    /// when the initiator's CONNECT arrives.
    connect_reply: Vec<u8>,
    outbound: Vec<u8>,
    recv_buf: Vec<u8>,
    state: ResponderState,
    events: VecDeque<ResponderEvent>,
    /// Deferred construction error (oversized CONNECT reply), surfaced by
    /// the first [`SansIoProtocol::handle_input`] call.
    pending_error: Option<DcutrError>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponderState {
    /// Waiting for the initiator's CONNECT message.
    AwaitingConnect,
    /// Got CONNECT, sent our reply, waiting for SYNC.
    AwaitingSync,
    /// SYNC received; flow complete.
    Done,
}

impl DcutrResponder {
    /// Creates a new responder.
    ///
    /// `own_addrs` are the addresses we want the initiator to try dialing us
    /// on. The CONNECT reply is encoded (and size-validated) here, but only
    /// queued once we actually receive the initiator's CONNECT.
    ///
    /// If the encoded reply would exceed [`MAX_MESSAGE_SIZE`] -- a frame any
    /// spec-compliant peer (including this crate's own decoder) would
    /// reject -- the first [`SansIoProtocol::handle_input`] call fails with
    /// [`DcutrError::MessageTooLarge`].
    pub fn new(own_addrs: &[Multiaddr]) -> Self {
        let reply = HolePunch {
            kind: HolePunchType::Connect,
            obs_addrs: own_addrs.iter().map(encode_multiaddr).collect(),
        };
        let (connect_reply, state, pending_error) = match checked_outbound_frame(&reply.encode()) {
            Ok(frame) => (frame, ResponderState::AwaitingConnect, None),
            Err(err) => (Vec::new(), ResponderState::Done, Some(err)),
        };

        Self {
            connect_reply,
            outbound: Vec::new(),
            recv_buf: Vec::new(),
            state,
            events: VecDeque::new(),
            pending_error,
        }
    }

    /// Drains and returns any pending outbound bytes.
    fn take_outbound(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.outbound)
    }

    /// Feeds incoming stream bytes.
    fn on_data(&mut self, data: &[u8]) -> Result<(), DcutrError> {
        if self.state == ResponderState::Done {
            return Ok(());
        }

        self.recv_buf.extend_from_slice(data);
        self.try_decode()
    }

    /// Notifies the state machine that the remote closed its write side.
    fn on_remote_write_closed(&mut self) -> Result<(), DcutrError> {
        self.try_decode()
    }

    /// Drains buffered events.
    #[cfg(test)]
    fn poll_events(&mut self) -> Vec<ResponderEvent> {
        self.events.drain(..).collect()
    }

    /// Returns `true` if the flow has completed.
    pub fn is_done(&self) -> bool {
        self.state == ResponderState::Done
    }

    fn try_decode(&mut self) -> Result<(), DcutrError> {
        loop {
            if self.state == ResponderState::Done {
                return Ok(());
            }

            let (msg, consumed) = match decode_frame(&self.recv_buf) {
                FrameDecode::Complete { payload, consumed } => {
                    let msg = HolePunch::decode(payload).map_err(|e| {
                        self.state = ResponderState::Done;
                        DcutrError::Malformed(e)
                    })?;
                    (msg, consumed)
                }
                // Only the incomplete remainder is bounded: a complete
                // frame decodes (and drains) regardless of what is
                // coalesced behind it -- e.g. a maximal CONNECT pipelined
                // with SYNC -- so the backstop can never reject a frame
                // the decoder would accept.
                FrameDecode::Incomplete => {
                    enforce_max_size(&self.recv_buf).inspect_err(|_| {
                        self.state = ResponderState::Done;
                    })?;
                    return Ok(());
                }
                FrameDecode::TooLarge { len } => {
                    self.state = ResponderState::Done;
                    return Err(DcutrError::FrameTooLarge { len });
                }
                FrameDecode::Error(e) => {
                    self.state = ResponderState::Done;
                    return Err(DcutrError::Malformed(DcutrMessageError::Varint(e)));
                }
            };
            self.recv_buf.drain(..consumed);

            match (self.state, msg.kind) {
                (ResponderState::AwaitingConnect, HolePunchType::Connect) => {
                    // Queue our pre-encoded CONNECT reply (size-validated in
                    // `new`) and transition state.
                    self.outbound
                        .extend(core::mem::take(&mut self.connect_reply));

                    let remote_addr_bytes = msg.obs_addrs;
                    let remote_addrs = decode_remote_addrs(&remote_addr_bytes);
                    self.events.push_back(ResponderEvent::ConnectReceived {
                        remote_addrs,
                        remote_addr_bytes,
                    });
                    self.state = ResponderState::AwaitingSync;
                }
                (ResponderState::AwaitingSync, HolePunchType::Sync) => {
                    self.events.push_back(ResponderEvent::SyncReceived);
                    self.state = ResponderState::Done;
                }
                (current_state, actual_kind) => {
                    self.state = ResponderState::Done;
                    return Err(DcutrError::UnexpectedMessage(alloc::format!(
                        "unexpected {:?} in state {:?}",
                        actual_kind,
                        current_state
                    )));
                }
            }
        }
    }
}

impl SansIoProtocol for DcutrInitiator {
    type Input = DcutrInitiatorInput;
    type Output = DcutrInitiatorOutput;
    type Error = DcutrError;

    fn handle_input(&mut self, input: Self::Input) -> Result<(), Self::Error> {
        if let Some(err) = self.pending_error.take() {
            return Err(err);
        }
        match input {
            DcutrInitiatorInput::Flush => {}
            DcutrInitiatorInput::Data { bytes, rtt_ms } => self.on_data(&bytes, rtt_ms)?,
            DcutrInitiatorInput::RemoteWriteClosed => self.on_remote_write_closed()?,
            DcutrInitiatorInput::SendSync => self.send_sync()?,
        }
        Ok(())
    }

    fn poll_output(&mut self) -> Option<Self::Output> {
        let outbound = self.take_outbound();
        if !outbound.is_empty() {
            return Some(DcutrInitiatorOutput::Outbound(outbound));
        }
        if !self.emitted_outcome
            && let Some(outcome) = self.outcome.clone()
        {
            self.emitted_outcome = true;
            return Some(DcutrInitiatorOutput::Outcome(outcome));
        }
        None
    }

    fn is_idle(&self) -> bool {
        self.pending_error.is_none()
            && self.outbound.is_empty()
            && (self.emitted_outcome || self.outcome.is_none())
    }
}

impl SansIoProtocol for DcutrResponder {
    type Input = DcutrResponderInput;
    type Output = DcutrResponderOutput;
    type Error = DcutrError;

    fn handle_input(&mut self, input: Self::Input) -> Result<(), Self::Error> {
        if let Some(err) = self.pending_error.take() {
            return Err(err);
        }
        match input {
            DcutrResponderInput::Flush => {}
            DcutrResponderInput::Data(data) => self.on_data(&data)?,
            DcutrResponderInput::RemoteWriteClosed => self.on_remote_write_closed()?,
        }
        Ok(())
    }

    fn poll_output(&mut self) -> Option<Self::Output> {
        let outbound = self.take_outbound();
        if !outbound.is_empty() {
            return Some(DcutrResponderOutput::Outbound(outbound));
        }
        self.events.pop_front().map(DcutrResponderOutput::Event)
    }

    fn is_idle(&self) -> bool {
        self.pending_error.is_none() && self.outbound.is_empty() && self.events.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Longest length prefix a legal frame can carry: [`MAX_MESSAGE_SIZE`] is
/// below 2^14, so its uvarint prefix encodes in at most two bytes.
const MAX_FRAME_PREFIX_LEN: usize = 2;

/// Backstop bound on the receive buffer once decoding has stalled on an
/// incomplete frame.
///
/// Called only on [`FrameDecode::Incomplete`], after any complete frame
/// has been drained: a stalled buffer can legally hold at most one
/// partial frame (the payload bound is [`decode_frame`]'s `TooLarge`), so
/// this can never reject traffic the decoder would accept -- including a
/// maximal frame coalesced with pipelined trailing bytes.
fn enforce_max_size(buf: &[u8]) -> Result<(), DcutrError> {
    if buf.len() > MAX_MESSAGE_SIZE + MAX_FRAME_PREFIX_LEN {
        return Err(DcutrError::MessageTooLarge { len: buf.len() });
    }
    Ok(())
}

/// Encodes an outbound message payload as a length-prefixed frame,
/// rejecting payloads that exceed [`MAX_MESSAGE_SIZE`].
///
/// This mirrors the inbound limit enforced by [`decode_frame`]: the state
/// machines must never put a frame on the wire that a spec-compliant
/// receiver (including this crate's own decoder) would reject as oversized.
fn checked_outbound_frame(payload: &[u8]) -> Result<Vec<u8>, DcutrError> {
    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(DcutrError::MessageTooLarge { len: payload.len() });
    }
    Ok(encode_frame(payload))
}

/// Encodes a [`Multiaddr`] for transmission in a `HolePunch` `obs_addrs`
/// field using the libp2p-spec multicodec-based binary encoding.
fn encode_multiaddr(addr: &Multiaddr) -> Vec<u8> {
    addr.to_bytes()
}

/// Decodes a list of raw observed-address bytes into [`Multiaddr`]
/// values, dropping any entry that fails to decode as a well-formed
/// binary multiaddr.
///
/// The raw bytes remain available in the surrounding event/outcome so
/// callers can emit diagnostics for dropped entries if they care.
fn decode_remote_addrs(raw: &[Vec<u8>]) -> Vec<Multiaddr> {
    raw.iter()
        .filter_map(|bytes| Multiaddr::from_bytes(bytes).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(msg: HolePunch) -> Vec<u8> {
        encode_frame(&msg.encode())
    }

    fn addr(s: &str) -> Multiaddr {
        <Multiaddr as core::str::FromStr>::from_str(s).expect("test multiaddr")
    }

    #[test]
    fn initiator_sends_connect_then_dials_on_reply() {
        let own = [addr("/ip4/1.2.3.4/udp/1111/quic-v1")];
        let mut init = DcutrInitiator::new(&own);

        // Take the initial CONNECT.
        let outbound = init.take_outbound();
        let FrameDecode::Complete { payload, .. } = decode_frame(&outbound) else {
            panic!();
        };
        let req = HolePunch::decode(payload).unwrap();
        assert_eq!(req.kind, HolePunchType::Connect);
        assert_eq!(req.obs_addrs.len(), 1);

        // Remote replies with its own CONNECT.
        let remote_str = "/ip4/5.6.7.8/udp/2222/quic-v1";
        let remote_addr = addr(remote_str);
        let remote_bytes = vec![remote_addr.to_bytes()];
        let reply = frame(HolePunch {
            kind: HolePunchType::Connect,
            obs_addrs: remote_bytes.clone(),
        });
        init.on_data(&reply, 42).unwrap();

        match init.outcome() {
            Some(InitiatorOutcome::DialNow {
                remote_addrs,
                remote_addr_bytes,
                rtt_ms,
            }) => {
                assert_eq!(remote_addrs.len(), 1);
                assert_eq!(remote_addrs[0], remote_addr);
                assert_eq!(*remote_addr_bytes, remote_bytes);
                assert_eq!(*rtt_ms, 42);
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[test]
    fn initiator_send_sync_after_reply() {
        let mut init = DcutrInitiator::new(&[]);
        let _ = init.take_outbound();

        let reply = frame(HolePunch {
            kind: HolePunchType::Connect,
            obs_addrs: Vec::new(),
        });
        init.on_data(&reply, 50).unwrap();

        init.send_sync().unwrap();
        let sync_bytes = init.take_outbound();
        let FrameDecode::Complete { payload, .. } = decode_frame(&sync_bytes) else {
            panic!();
        };
        let sync = HolePunch::decode(payload).unwrap();
        assert_eq!(sync.kind, HolePunchType::Sync);
        assert!(init.is_done());
    }

    #[test]
    fn initiator_send_sync_before_reply_fails() {
        let mut init = DcutrInitiator::new(&[]);
        let _ = init.take_outbound();

        let err = init.send_sync().unwrap_err();
        assert!(matches!(err, DcutrError::UnexpectedMessage(_)));
    }

    #[test]
    fn initiator_rejects_sync_as_reply() {
        let mut init = DcutrInitiator::new(&[]);
        let _ = init.take_outbound();

        let wrong = frame(HolePunch {
            kind: HolePunchType::Sync,
            obs_addrs: Vec::new(),
        });
        let err = init.on_data(&wrong, 0).unwrap_err();
        assert!(matches!(err, DcutrError::UnexpectedMessage(_)));
    }

    #[test]
    fn initiator_handles_fragmented_reply() {
        let mut init = DcutrInitiator::new(&[]);
        let _ = init.take_outbound();

        let reply = frame(HolePunch {
            kind: HolePunchType::Connect,
            obs_addrs: vec![addr("/ip4/1.2.3.4/udp/1/quic-v1").to_bytes()],
        });
        for byte in &reply {
            init.on_data(&[*byte], 10).unwrap();
        }

        assert!(matches!(
            init.outcome(),
            Some(InitiatorOutcome::DialNow { .. })
        ));
    }

    #[test]
    fn initiator_drops_malformed_remote_addrs_but_keeps_bytes() {
        let mut init = DcutrInitiator::new(&[]);
        let _ = init.take_outbound();

        let reply = frame(HolePunch {
            kind: HolePunchType::Connect,
            obs_addrs: vec![
                addr("/ip4/1.2.3.4/udp/1/quic-v1").to_bytes(), // valid binary
                vec![0xFF, 0x7F, 0x00],                        // unknown code
                vec![0x04, 0x7F],                              // truncated ip4
            ],
        });
        init.on_data(&reply, 10).unwrap();

        match init.outcome() {
            Some(InitiatorOutcome::DialNow {
                remote_addrs,
                remote_addr_bytes,
                ..
            }) => {
                assert_eq!(remote_addrs.len(), 1);
                assert_eq!(remote_addr_bytes.len(), 3);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn responder_replies_on_connect_then_surfaces_sync() {
        let own = [addr("/ip4/10.0.0.1/udp/1234/quic-v1")];
        let mut resp = DcutrResponder::new(&own);

        // Feed initiator's CONNECT.
        let remote_str = "/ip4/5.5.5.5/udp/7000/quic-v1";
        let remote_addr = addr(remote_str);
        let remote_bytes = vec![remote_addr.to_bytes()];
        let connect = frame(HolePunch {
            kind: HolePunchType::Connect,
            obs_addrs: remote_bytes.clone(),
        });
        resp.on_data(&connect).unwrap();

        // Reply should be queued with our own addr (binary-encoded).
        let outbound = resp.take_outbound();
        let FrameDecode::Complete { payload, .. } = decode_frame(&outbound) else {
            panic!();
        };
        let reply = HolePunch::decode(payload).unwrap();
        assert_eq!(reply.kind, HolePunchType::Connect);
        assert_eq!(reply.obs_addrs, vec![own[0].to_bytes()]);

        // ConnectReceived event should surface parsed multiaddrs.
        let events = resp.poll_events();
        assert_eq!(events.len(), 1);
        match &events[0] {
            ResponderEvent::ConnectReceived {
                remote_addrs,
                remote_addr_bytes,
            } => {
                assert_eq!(remote_addrs.len(), 1);
                assert_eq!(remote_addrs[0], remote_addr);
                assert_eq!(*remote_addr_bytes, remote_bytes);
            }
            _ => panic!(),
        }

        // Feed SYNC.
        let sync = frame(HolePunch {
            kind: HolePunchType::Sync,
            obs_addrs: Vec::new(),
        });
        resp.on_data(&sync).unwrap();

        let events = resp.poll_events();
        assert!(matches!(events.as_slice(), [ResponderEvent::SyncReceived]));
        assert!(resp.is_done());
    }

    #[test]
    fn responder_handles_pipelined_connect_and_sync() {
        let mut resp = DcutrResponder::new(&[]);

        // Send CONNECT and SYNC in one packet (unusual but possible).
        let mut packet = frame(HolePunch {
            kind: HolePunchType::Connect,
            obs_addrs: Vec::new(),
        });
        packet.extend(frame(HolePunch {
            kind: HolePunchType::Sync,
            obs_addrs: Vec::new(),
        }));
        resp.on_data(&packet).unwrap();

        let events = resp.poll_events();
        assert!(matches!(
            events.as_slice(),
            [
                ResponderEvent::ConnectReceived { .. },
                ResponderEvent::SyncReceived
            ]
        ));
        assert!(resp.is_done());
    }

    #[test]
    fn responder_rejects_sync_before_connect() {
        let mut resp = DcutrResponder::new(&[]);
        let sync = frame(HolePunch {
            kind: HolePunchType::Sync,
            obs_addrs: Vec::new(),
        });
        let err = resp.on_data(&sync).unwrap_err();
        assert!(matches!(err, DcutrError::UnexpectedMessage(_)));
    }

    #[test]
    fn responder_rejects_duplicate_connect() {
        let mut resp = DcutrResponder::new(&[]);

        let connect = frame(HolePunch {
            kind: HolePunchType::Connect,
            obs_addrs: Vec::new(),
        });
        resp.on_data(&connect).unwrap();

        let err = resp.on_data(&connect).unwrap_err();
        assert!(matches!(err, DcutrError::UnexpectedMessage(_)));
    }

    #[test]
    fn receive_buffer_backstop_bounds_partial_frames() {
        // The backstop allows one maximal legal frame (payload + 2-byte
        // prefix) and rejects anything beyond it. It runs only on stalled
        // (incomplete) buffers, where `decode_frame`'s own bounds make it
        // unreachable from wire input -- a pure defense-in-depth check.
        assert!(enforce_max_size(&vec![0u8; MAX_MESSAGE_SIZE + MAX_FRAME_PREFIX_LEN]).is_ok());
        assert!(matches!(
            enforce_max_size(&vec![0u8; MAX_MESSAGE_SIZE + MAX_FRAME_PREFIX_LEN + 1]),
            Err(DcutrError::MessageTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_oversized_declared_frame_length() {
        // A tiny header declaring an impossible payload length must fail
        // immediately instead of stalling while waiting for more bytes.
        let mut resp = DcutrResponder::new(&[]);
        let mut header = Vec::new();
        minip2p_core::write_uvarint((MAX_MESSAGE_SIZE + 1) as u64, &mut header);
        let err = resp.on_data(&header).unwrap_err();
        assert!(matches!(err, DcutrError::FrameTooLarge { .. }));
        assert!(resp.is_done());
    }

    /// Enough addresses that the encoded CONNECT payload far exceeds
    /// [`MAX_MESSAGE_SIZE`] (each entry is ~25 bytes on the wire).
    fn oversized_own_addrs() -> Vec<Multiaddr> {
        vec![addr("/ip6/2001:db8::1/udp/4001/quic-v1"); 200]
    }

    #[test]
    fn initiator_rejects_oversized_outbound_connect() {
        let mut init = DcutrInitiator::new(&oversized_own_addrs());

        // The oversized frame must never be emitted...
        assert!(!init.is_idle());
        assert!(init.poll_output().is_none());
        // ...and the error surfaces on the first input.
        let err = init.handle_input(DcutrInitiatorInput::Flush).unwrap_err();
        assert!(matches!(err, DcutrError::MessageTooLarge { .. }));
        assert!(init.is_done());
        assert!(init.is_idle());
    }

    #[test]
    fn responder_rejects_oversized_outbound_connect_reply() {
        let mut resp = DcutrResponder::new(&oversized_own_addrs());

        assert!(!resp.is_idle());
        let connect = frame(HolePunch {
            kind: HolePunchType::Connect,
            obs_addrs: Vec::new(),
        });
        let err = resp
            .handle_input(DcutrResponderInput::Data(connect))
            .unwrap_err();
        assert!(matches!(err, DcutrError::MessageTooLarge { .. }));
        // No reply frame may leak out after the failure.
        assert!(resp.poll_output().is_none());
        assert!(resp.is_done());
    }

    #[test]
    fn outbound_frame_at_exact_max_size_still_encodes() {
        // Payload layout: 2 bytes type field + 1 tag + 2-byte length varint
        // + 4091 addr bytes = exactly MAX_MESSAGE_SIZE.
        let at_max = HolePunch {
            kind: HolePunchType::Connect,
            obs_addrs: vec![vec![0u8; 4091]],
        }
        .encode();
        assert_eq!(at_max.len(), MAX_MESSAGE_SIZE);

        let framed = checked_outbound_frame(&at_max).expect("exactly-max payload must encode");
        assert!(matches!(
            decode_frame(&framed),
            FrameDecode::Complete { .. }
        ));

        // The framed bytes (payload + 2-byte prefix) must also survive the
        // state machine's own receive path, not just decode_frame -- even
        // when a coalesced read pipelines the SYNC frame behind the
        // maximal CONNECT in the same input.
        let own = [addr("/ip4/10.0.0.1/udp/1234/quic-v1")];
        let mut resp = DcutrResponder::new(&own);
        let mut coalesced = framed;
        coalesced.extend(frame(HolePunch {
            kind: HolePunchType::Sync,
            obs_addrs: Vec::new(),
        }));
        resp.handle_input(DcutrResponderInput::Data(coalesced))
            .expect("exactly-max CONNECT + pipelined SYNC must be accepted");
        assert!(matches!(
            resp.poll_output(),
            Some(DcutrResponderOutput::Outbound(_))
        ));

        // One more byte and the frame must be refused.
        let over_max = HolePunch {
            kind: HolePunchType::Connect,
            obs_addrs: vec![vec![0u8; 4092]],
        }
        .encode();
        assert_eq!(over_max.len(), MAX_MESSAGE_SIZE + 1);
        assert!(matches!(
            checked_outbound_frame(&over_max),
            Err(DcutrError::MessageTooLarge { len }) if len == MAX_MESSAGE_SIZE + 1
        ));
    }

    #[test]
    fn initiator_and_responder_implement_sans_io_protocol() {
        let own = [addr("/ip4/10.0.0.1/udp/1234/quic-v1")];
        let mut init = DcutrInitiator::new(&own);
        let mut resp = DcutrResponder::new(&own);

        init.handle_input(DcutrInitiatorInput::Flush).unwrap();
        let Some(DcutrInitiatorOutput::Outbound(connect)) = init.poll_output() else {
            panic!("initiator should emit CONNECT");
        };

        resp.handle_input(DcutrResponderInput::Data(connect))
            .unwrap();
        let Some(DcutrResponderOutput::Outbound(reply)) = resp.poll_output() else {
            panic!("responder should emit CONNECT reply");
        };
        assert!(matches!(
            resp.poll_output(),
            Some(DcutrResponderOutput::Event(
                ResponderEvent::ConnectReceived { .. }
            ))
        ));

        init.handle_input(DcutrInitiatorInput::Data {
            bytes: reply,
            rtt_ms: 42,
        })
        .unwrap();
        assert!(matches!(
            init.poll_output(),
            Some(DcutrInitiatorOutput::Outcome(InitiatorOutcome::DialNow {
                rtt_ms: 42,
                ..
            }))
        ));
    }
}
