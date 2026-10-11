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

use minip2p_core::{FrameExchange, FrameFault, Multiaddr};

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

impl From<FrameFault> for DcutrError {
    fn from(fault: FrameFault) -> Self {
        match fault {
            FrameFault::TooLarge { len, .. } => Self::FrameTooLarge { len },
            FrameFault::Overflow { len, .. } => Self::MessageTooLarge { len },
            FrameFault::Wire(e) => Self::Malformed(e.into()),
        }
    }
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

/// Output produced by [`DcutrInitiator::poll_output`].
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
///    [`DcutrInitiator::poll_output`] and send the bytes.
/// 3. Record the send time; feed stream data with
///    [`DcutrInitiator::on_data`].
/// 4. When [`DcutrInitiatorOutput::Outcome`] returns `DialNow`, the caller:
///    - dials the returned addresses immediately,
///    - calls [`DcutrInitiator::send_sync`] to queue the SYNC frame,
///    - flushes the outbound bytes.
///
/// Bytes coalesced behind the CONNECT reply belong to the application and
/// are kept for [`DcutrInitiator::take_trailing_data`].
pub struct DcutrInitiator {
    frames: FrameExchange,
    state: InitiatorState,
    outcome: Option<InitiatorOutcome>,
    emitted_outcome: bool,
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
    /// SYNC sent, or the exchange failed; flow complete.
    Done,
}

impl DcutrInitiator {
    /// Creates a new initiator, queuing the outbound CONNECT message.
    ///
    /// `own_addrs` are our observed (and possibly predicted) multiaddrs,
    /// sent in their binary multiaddr encoding.
    ///
    /// Fails with [`DcutrError::MessageTooLarge`] if the encoded CONNECT
    /// would exceed [`MAX_MESSAGE_SIZE`] -- a frame any spec-compliant peer
    /// (including this crate's own decoder) would reject.
    pub fn new(own_addrs: &[Multiaddr]) -> Result<Self, DcutrError> {
        let msg = HolePunch {
            kind: HolePunchType::Connect,
            obs_addrs: own_addrs.iter().map(encode_multiaddr).collect(),
        };
        let mut frames = hole_punch_frames();
        queue_message(&mut frames, &msg.encode())?;

        Ok(Self {
            frames,
            state: InitiatorState::Pending,
            outcome: None,
            emitted_outcome: false,
        })
    }

    /// Feeds incoming stream bytes.
    ///
    /// `rtt_ms` is the caller's measured RTT from when they sent CONNECT
    /// (drained from [`poll_output`](Self::poll_output)) to now. It is passed
    /// through into the `DialNow` outcome so the caller can use it for SYNC
    /// timing. Any error ends the flow.
    pub fn on_data(&mut self, data: &[u8], rtt_ms: u64) -> Result<(), DcutrError> {
        // Once the CONNECT reply has been consumed the stream carries no
        // further DCUtR frames toward the initiator, so later bytes are
        // dropped rather than buffered -- including in `ReadyToSync`,
        // where the caller has not sent SYNC yet and a misbehaving peer
        // could otherwise grow the buffer without bound.
        if self.state != InitiatorState::AwaitingConnectReply {
            return Ok(());
        }
        let result = self
            .frames
            .push(data)
            .map_err(DcutrError::from)
            .and_then(|()| self.try_decode_reply(rtt_ms));
        if result.is_err() {
            // Terminate without retaining attacker-controlled protocol input
            // or its backing allocation.
            self.state = InitiatorState::Done;
            self.frames.take_buffered();
        }
        result
    }

    /// Queues the SYNC message to be sent.
    ///
    /// Call this after you have initiated your simultaneous dial, per the
    /// spec, then drain [`DcutrInitiatorOutput::Outbound`] to the stream.
    pub fn send_sync(&mut self) -> Result<(), DcutrError> {
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
        queue_message(&mut self.frames, &msg.encode())?;
        self.state = InitiatorState::SyncPending;
        Ok(())
    }

    /// Returns the next pending output, if any.
    ///
    /// Drain until `None` after construction and after every input, before
    /// waiting on the stream again.
    pub fn poll_output(&mut self) -> Option<DcutrInitiatorOutput> {
        if self.frames.has_outbound() {
            self.state = match self.state {
                InitiatorState::Pending => InitiatorState::AwaitingConnectReply,
                InitiatorState::SyncPending => InitiatorState::Done,
                other => other,
            };
            return Some(DcutrInitiatorOutput::Outbound(self.frames.take_outbound()));
        }
        if !self.emitted_outcome
            && let Some(outcome) = self.outcome.clone()
        {
            self.emitted_outcome = true;
            return Some(DcutrInitiatorOutput::Outcome(outcome));
        }
        None
    }

    /// Returns the current outcome, if available.
    #[cfg(test)]
    fn outcome(&self) -> Option<&InitiatorOutcome> {
        self.outcome.as_ref()
    }

    /// Returns `true` if the flow has completed (SYNC was sent) or failed.
    pub fn is_done(&self) -> bool {
        self.state == InitiatorState::Done
    }

    /// Returns bytes received after the CONNECT reply in the same stream
    /// read.
    ///
    /// Once DCUtR completes, the caller normally hands the relay stream to
    /// its application. Keeping this remainder available avoids dropping
    /// application data that was coalesced behind the reply by the
    /// transport. Returns `None` until SYNC has been flushed, leaving the
    /// active decode buffer untouched. After successful completion, the
    /// trailing bytes are returned (and drained) exactly once. Failed
    /// exchanges never expose buffered control-plane bytes as application
    /// data.
    pub fn take_trailing_data(&mut self) -> Option<Vec<u8>> {
        (self.state == InitiatorState::Done && self.outcome.is_some())
            .then(|| self.frames.take_buffered())
    }

    fn try_decode_reply(&mut self, rtt_ms: u64) -> Result<(), DcutrError> {
        let Some(reply) = self.frames.next_frame(decode_hole_punch)? else {
            return Ok(());
        };
        if reply.kind != HolePunchType::Connect {
            return Err(DcutrError::UnexpectedMessage(alloc::format!(
                "expected HolePunch CONNECT but got {:?}",
                reply.kind
            )));
        }

        self.state = InitiatorState::ReadyToSync;
        // Nothing further is expected inbound. Bytes coalesced behind the
        // reply belong to the application and remain available through
        // `take_trailing_data` after SYNC has been flushed.
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
    /// Our own CONNECT reply has been queued alongside this event, and the
    /// caller now knows which addresses to NAT-punch towards.
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

/// Output produced by [`DcutrResponder::poll_output`].
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
/// 2. Feed incoming bytes with [`DcutrResponder::on_data`].
/// 3. Drain [`DcutrResponderOutput`] values from
///    [`DcutrResponder::poll_output`].
/// 4. Send [`DcutrResponderOutput::Outbound`] bytes back on the relay stream.
/// 5. On [`DcutrResponderOutput::Event`] with
///    [`ResponderEvent::SyncReceived`], start the responder-side dial timing /
///    UDP bombardment strategy.
///
/// The initiator may pipeline SYNC behind its CONNECT. Bytes coalesced
/// behind SYNC belong to the application and are kept for
/// [`DcutrResponder::take_trailing_data`].
pub struct DcutrResponder {
    /// Encoded, size-validated CONNECT reply payload; queued (taken) when
    /// the initiator's CONNECT arrives.
    connect_reply: Vec<u8>,
    frames: FrameExchange,
    state: ResponderState,
    events: VecDeque<ResponderEvent>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponderState {
    /// Waiting for the initiator's CONNECT message.
    AwaitingConnect,
    /// Got CONNECT, sent our reply, waiting for SYNC.
    AwaitingSync,
    /// SYNC received; flow complete.
    Done,
    /// The exchange terminated with a protocol error.
    Failed,
}

impl DcutrResponder {
    /// Creates a new responder.
    ///
    /// `own_addrs` are the addresses we want the initiator to try dialing us
    /// on. The CONNECT reply is encoded (and size-validated) here, but only
    /// queued once we actually receive the initiator's CONNECT.
    ///
    /// Fails with [`DcutrError::MessageTooLarge`] if the encoded reply would
    /// exceed [`MAX_MESSAGE_SIZE`] -- a frame any spec-compliant peer
    /// (including this crate's own decoder) would reject.
    pub fn new(own_addrs: &[Multiaddr]) -> Result<Self, DcutrError> {
        let connect_reply = HolePunch {
            kind: HolePunchType::Connect,
            obs_addrs: own_addrs.iter().map(encode_multiaddr).collect(),
        }
        .encode();
        if connect_reply.len() > MAX_MESSAGE_SIZE {
            return Err(DcutrError::MessageTooLarge {
                len: connect_reply.len(),
            });
        }

        Ok(Self {
            connect_reply,
            frames: hole_punch_frames(),
            state: ResponderState::AwaitingConnect,
            events: VecDeque::new(),
        })
    }

    /// Feeds incoming stream bytes. Any error ends the flow.
    pub fn on_data(&mut self, data: &[u8]) -> Result<(), DcutrError> {
        if self.is_done() {
            return Ok(());
        }
        let result = self
            .frames
            .push(data)
            .map_err(DcutrError::from)
            .and_then(|()| self.try_decode());
        if result.is_err() {
            self.state = ResponderState::Failed;
        }
        result
    }

    /// Notifies the state machine that the remote closed its write side,
    /// decoding whatever whole frames are already buffered.
    pub fn on_remote_write_closed(&mut self) -> Result<(), DcutrError> {
        if self.is_done() {
            return Ok(());
        }
        let result = self.try_decode();
        if result.is_err() {
            self.state = ResponderState::Failed;
        }
        result
    }

    /// Returns the next pending output, if any.
    ///
    /// Drain until `None` after every input, before waiting on the stream
    /// again.
    pub fn poll_output(&mut self) -> Option<DcutrResponderOutput> {
        if self.frames.has_outbound() {
            return Some(DcutrResponderOutput::Outbound(self.frames.take_outbound()));
        }
        self.events.pop_front().map(DcutrResponderOutput::Event)
    }

    /// Drains buffered events.
    #[cfg(test)]
    fn poll_events(&mut self) -> Vec<ResponderEvent> {
        self.events.drain(..).collect()
    }

    /// Returns `true` if the flow completed or terminated with an error.
    pub fn is_done(&self) -> bool {
        matches!(self.state, ResponderState::Done | ResponderState::Failed)
    }

    /// Returns bytes received after the final SYNC frame in the same stream
    /// read.
    ///
    /// Once DCUtR completes, the caller normally hands the relay stream to
    /// its application. Keeping this remainder available avoids dropping
    /// application data that was coalesced behind SYNC by the transport.
    /// Returns `None` while the exchange is incomplete, leaving the active
    /// decode buffer untouched. After completion, the trailing bytes are
    /// returned (and drained) exactly once.
    pub fn take_trailing_data(&mut self) -> Option<Vec<u8>> {
        (self.state == ResponderState::Done).then(|| self.frames.take_buffered())
    }

    fn try_decode(&mut self) -> Result<(), DcutrError> {
        // Stop at SYNC: any bytes coalesced behind it belong to the
        // application, which drains them with `take_trailing_data`.
        while !self.is_done() {
            let Some(msg) = self.frames.next_frame(decode_hole_punch)? else {
                return Ok(());
            };
            match (self.state, msg.kind) {
                (ResponderState::AwaitingConnect, HolePunchType::Connect) => {
                    // Queue our CONNECT reply (size-validated in `new`).
                    queue_message(&mut self.frames, &core::mem::take(&mut self.connect_reply))?;

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
                    return Err(DcutrError::UnexpectedMessage(alloc::format!(
                        "unexpected {:?} in state {:?}",
                        actual_kind,
                        current_state
                    )));
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// The frame exchange both roles read through.
///
/// Bytes behind the final frame belong to the application, so the exchange
/// does not bound them: they arrive in the read that completes the frame,
/// and every later read is dropped once the exchange is over.
fn hole_punch_frames() -> FrameExchange {
    FrameExchange::with_trailing(MAX_MESSAGE_SIZE, usize::MAX)
}

fn decode_hole_punch(payload: &[u8]) -> Result<HolePunch, DcutrError> {
    HolePunch::decode(payload).map_err(DcutrError::Malformed)
}

/// Queues an outbound message, rejecting payloads that exceed
/// [`MAX_MESSAGE_SIZE`]: the state machines must never put a frame on the
/// wire that a spec-compliant receiver (including this crate's own decoder)
/// would reject as oversized.
fn queue_message(frames: &mut FrameExchange, payload: &[u8]) -> Result<(), DcutrError> {
    frames.queue(payload).map_err(|fault| match fault {
        FrameFault::TooLarge { .. } => DcutrError::MessageTooLarge { len: payload.len() },
        other => other.into(),
    })
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

    fn initiator_outbound(init: &mut DcutrInitiator) -> Vec<u8> {
        let Some(DcutrInitiatorOutput::Outbound(bytes)) = init.poll_output() else {
            panic!("expected queued bytes");
        };
        bytes
    }

    fn responder_outbound(resp: &mut DcutrResponder) -> Vec<u8> {
        let Some(DcutrResponderOutput::Outbound(bytes)) = resp.poll_output() else {
            panic!("expected queued bytes");
        };
        bytes
    }

    fn over_declared_header() -> Vec<u8> {
        let mut header = Vec::new();
        minip2p_core::write_uvarint((MAX_MESSAGE_SIZE + 1) as u64, &mut header);
        header
    }

    /// A CONNECT whose payload is exactly [`MAX_MESSAGE_SIZE`]: 2 bytes type
    /// field + 1 tag + 2-byte length varint + 4091 address bytes.
    fn max_size_connect() -> Vec<u8> {
        let at_max = HolePunch {
            kind: HolePunchType::Connect,
            obs_addrs: vec![vec![0u8; 4091]],
        }
        .encode();
        assert_eq!(at_max.len(), MAX_MESSAGE_SIZE);
        encode_frame(&at_max)
    }

    fn addr(s: &str) -> Multiaddr {
        <Multiaddr as core::str::FromStr>::from_str(s).expect("test multiaddr")
    }

    #[test]
    fn initiator_sends_connect_then_dials_on_reply() {
        let own = [addr("/ip4/1.2.3.4/udp/1111/quic-v1")];
        let mut init = DcutrInitiator::new(&own).unwrap();

        // Take the initial CONNECT.
        let outbound = initiator_outbound(&mut init);
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
    fn initiator_exposes_bytes_coalesced_after_reply_once_complete() {
        let mut init = DcutrInitiator::new(&[]).unwrap();
        let _ = initiator_outbound(&mut init);

        // Reply arrives coalesced with application bytes. They cannot be
        // handed over before the protocol finishes.
        let mut coalesced = frame(HolePunch {
            kind: HolePunchType::Connect,
            obs_addrs: Vec::new(),
        });
        coalesced.extend_from_slice(&[0xaa; 512]);
        init.on_data(&coalesced, 7).unwrap();
        assert!(matches!(
            init.outcome(),
            Some(InitiatorOutcome::DialNow { .. })
        ));
        assert_eq!(init.take_trailing_data(), None);

        // Before the caller sends SYNC (`ReadyToSync`), further peer bytes
        // must be dropped, not buffered without bound.
        init.on_data(&[0xbb; 1024], 7).unwrap();
        assert_eq!(init.take_trailing_data(), None);

        init.send_sync().unwrap();
        let _ = initiator_outbound(&mut init);
        assert!(init.is_done());
        assert_eq!(init.take_trailing_data(), Some(vec![0xaa; 512]));
        assert_eq!(init.take_trailing_data(), Some(Vec::new()));
    }

    #[test]
    fn initiator_does_not_expose_malformed_protocol_bytes_as_trailing_data() {
        let mut init = DcutrInitiator::new(&[]).unwrap();
        let _ = initiator_outbound(&mut init);

        let mut malformed = encode_frame(&[0xff]);
        malformed.extend_from_slice(&vec![0xaa; MAX_MESSAGE_SIZE * 2]);
        let err = init.on_data(&malformed, 0).unwrap_err();
        assert!(matches!(err, DcutrError::Malformed(_)));
        assert!(init.is_done());
        assert_eq!(init.take_trailing_data(), None);
        assert_eq!(init.frames.buffered().len(), 0);
    }

    #[test]
    fn initiator_does_not_expose_oversized_frame_as_trailing_data() {
        let mut init = DcutrInitiator::new(&[]).unwrap();
        let _ = initiator_outbound(&mut init);

        let mut header = Vec::new();
        minip2p_core::write_uvarint((MAX_MESSAGE_SIZE + 1) as u64, &mut header);
        let err = init.on_data(&header, 0).unwrap_err();
        assert!(matches!(err, DcutrError::FrameTooLarge { .. }));
        assert!(init.is_done());
        assert_eq!(init.take_trailing_data(), None);
        assert_eq!(init.frames.buffered().len(), 0);
    }

    #[test]
    fn responder_exposes_trailing_bytes_after_flow_completes() {
        let mut resp = DcutrResponder::new(&[]).unwrap();

        // CONNECT + SYNC + application bytes in one coalesced input: the
        // flow completes, but the caller must be able to hand those bytes to
        // the application with the released raw stream.
        let mut coalesced = frame(HolePunch {
            kind: HolePunchType::Connect,
            obs_addrs: Vec::new(),
        });
        coalesced.extend(frame(HolePunch {
            kind: HolePunchType::Sync,
            obs_addrs: Vec::new(),
        }));
        coalesced.extend_from_slice(&[0xcc; 512]);
        resp.on_data(&coalesced).unwrap();
        assert!(resp.is_done());
        assert_eq!(resp.take_trailing_data(), Some(vec![0xcc; 512]));
        assert_eq!(resp.take_trailing_data(), Some(Vec::new()));
    }

    #[test]
    fn responder_cannot_drain_protocol_bytes_before_completion() {
        let mut resp = DcutrResponder::new(&[]).unwrap();
        let connect = frame(HolePunch {
            kind: HolePunchType::Connect,
            obs_addrs: Vec::new(),
        });
        let split = connect.len() / 2;
        resp.on_data(&connect[..split]).unwrap();

        assert_eq!(resp.take_trailing_data(), None);
        resp.on_data(&connect[split..]).unwrap();
        assert!(matches!(
            resp.poll_events().as_slice(),
            [ResponderEvent::ConnectReceived { .. }]
        ));
    }

    #[test]
    fn initiator_send_sync_after_reply() {
        let mut init = DcutrInitiator::new(&[]).unwrap();
        let _ = initiator_outbound(&mut init);

        let reply = frame(HolePunch {
            kind: HolePunchType::Connect,
            obs_addrs: Vec::new(),
        });
        init.on_data(&reply, 50).unwrap();

        init.send_sync().unwrap();
        let sync_bytes = initiator_outbound(&mut init);
        let FrameDecode::Complete { payload, .. } = decode_frame(&sync_bytes) else {
            panic!();
        };
        let sync = HolePunch::decode(payload).unwrap();
        assert_eq!(sync.kind, HolePunchType::Sync);
        assert!(init.is_done());
    }

    #[test]
    fn initiator_send_sync_before_reply_fails() {
        let mut init = DcutrInitiator::new(&[]).unwrap();
        let _ = initiator_outbound(&mut init);

        let err = init.send_sync().unwrap_err();
        assert!(matches!(err, DcutrError::UnexpectedMessage(_)));
    }

    #[test]
    fn initiator_rejects_sync_as_reply() {
        let mut init = DcutrInitiator::new(&[]).unwrap();
        let _ = initiator_outbound(&mut init);

        let wrong = frame(HolePunch {
            kind: HolePunchType::Sync,
            obs_addrs: Vec::new(),
        });
        let err = init.on_data(&wrong, 0).unwrap_err();
        assert!(matches!(err, DcutrError::UnexpectedMessage(_)));
    }

    #[test]
    fn initiator_handles_fragmented_reply() {
        let mut init = DcutrInitiator::new(&[]).unwrap();
        let _ = initiator_outbound(&mut init);

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
        let mut init = DcutrInitiator::new(&[]).unwrap();
        let _ = initiator_outbound(&mut init);

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
        let mut resp = DcutrResponder::new(&own).unwrap();

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
        let outbound = responder_outbound(&mut resp);
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
        let mut resp = DcutrResponder::new(&[]).unwrap();

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
        let mut resp = DcutrResponder::new(&[]).unwrap();
        let sync = frame(HolePunch {
            kind: HolePunchType::Sync,
            obs_addrs: Vec::new(),
        });
        let err = resp.on_data(&sync).unwrap_err();
        assert!(matches!(err, DcutrError::UnexpectedMessage(_)));
        assert_eq!(resp.take_trailing_data(), None);
    }

    #[test]
    fn responder_rejects_duplicate_connect() {
        let mut resp = DcutrResponder::new(&[]).unwrap();

        let connect = frame(HolePunch {
            kind: HolePunchType::Connect,
            obs_addrs: Vec::new(),
        });
        resp.on_data(&connect).unwrap();

        let err = resp.on_data(&connect).unwrap_err();
        assert!(matches!(err, DcutrError::UnexpectedMessage(_)));
    }

    #[test]
    fn responder_rejects_oversized_declared_frame_length() {
        // A tiny header declaring an impossible payload length must fail
        // immediately instead of stalling while waiting for more bytes.
        let mut resp = DcutrResponder::new(&[]).unwrap();
        let err = resp.on_data(&over_declared_header()).unwrap_err();
        assert!(matches!(err, DcutrError::FrameTooLarge { .. }));
        assert!(resp.is_done());
    }

    /// Enough addresses that the encoded CONNECT payload far exceeds
    /// [`MAX_MESSAGE_SIZE`] (each entry is ~25 bytes on the wire).
    fn oversized_own_addrs() -> Vec<Multiaddr> {
        vec![addr("/ip6/2001:db8::1/udp/4001/quic-v1"); 200]
    }

    #[test]
    fn constructors_refuse_an_oversized_outbound_connect() {
        // The oversized frame is never built: the caller learns at
        // construction, with no input needed to surface the error.
        assert!(matches!(
            DcutrInitiator::new(&oversized_own_addrs()),
            Err(DcutrError::MessageTooLarge { len }) if len > MAX_MESSAGE_SIZE
        ));
        assert!(matches!(
            DcutrResponder::new(&oversized_own_addrs()),
            Err(DcutrError::MessageTooLarge { len }) if len > MAX_MESSAGE_SIZE
        ));
    }

    #[test]
    fn outbound_message_at_exact_max_size_still_encodes() {
        let mut frames = hole_punch_frames();
        let at_max = vec![0u8; MAX_MESSAGE_SIZE];
        queue_message(&mut frames, &at_max).expect("exactly-max payload must encode");
        assert!(matches!(
            decode_frame(&frames.take_outbound()),
            FrameDecode::Complete { payload, .. } if payload.len() == MAX_MESSAGE_SIZE
        ));

        // One more byte and the payload must be refused.
        assert_eq!(
            queue_message(&mut frames, &[0u8; MAX_MESSAGE_SIZE + 1]),
            Err(DcutrError::MessageTooLarge {
                len: MAX_MESSAGE_SIZE + 1
            })
        );
        assert!(!frames.has_outbound());
    }

    #[test]
    fn initiator_accepts_an_exactly_max_reply() {
        let mut init = DcutrInitiator::new(&[]).unwrap();
        let _ = initiator_outbound(&mut init);

        init.on_data(&max_size_connect(), 1).unwrap();
        assert!(matches!(
            init.outcome(),
            Some(InitiatorOutcome::DialNow { .. })
        ));
    }

    #[test]
    fn responder_accepts_an_exactly_max_connect_with_pipelined_sync() {
        // A coalesced read can pipeline SYNC behind a maximal CONNECT.
        let own = [addr("/ip4/10.0.0.1/udp/1234/quic-v1")];
        let mut resp = DcutrResponder::new(&own).unwrap();
        let mut coalesced = max_size_connect();
        coalesced.extend(frame(HolePunch {
            kind: HolePunchType::Sync,
            obs_addrs: Vec::new(),
        }));
        resp.on_data(&coalesced)
            .expect("exactly-max CONNECT + pipelined SYNC must be accepted");
        assert!(matches!(
            resp.poll_output(),
            Some(DcutrResponderOutput::Outbound(_))
        ));
        assert!(resp.is_done());
    }

    #[test]
    fn initiator_and_responder_drive_each_other() {
        let own = [addr("/ip4/10.0.0.1/udp/1234/quic-v1")];
        let mut init = DcutrInitiator::new(&own).unwrap();
        let mut resp = DcutrResponder::new(&own).unwrap();

        let connect = initiator_outbound(&mut init);
        resp.on_data(&connect).unwrap();
        let reply = responder_outbound(&mut resp);
        assert!(matches!(
            resp.poll_output(),
            Some(DcutrResponderOutput::Event(
                ResponderEvent::ConnectReceived { .. }
            ))
        ));

        init.on_data(&reply, 42).unwrap();
        assert!(matches!(
            init.poll_output(),
            Some(DcutrInitiatorOutput::Outcome(InitiatorOutcome::DialNow {
                rtt_ms: 42,
                ..
            }))
        ));
        init.send_sync().unwrap();
        resp.on_data(&initiator_outbound(&mut init)).unwrap();
        assert_eq!(
            resp.poll_output(),
            Some(DcutrResponderOutput::Event(ResponderEvent::SyncReceived))
        );
        assert!(init.is_done() && resp.is_done());
    }
}
