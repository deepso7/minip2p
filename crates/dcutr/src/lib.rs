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

use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::Multiaddr;

pub use message::{
    decode_frame, encode_frame, DcutrMessageError, FrameDecode, HolePunch, HolePunchType,
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
    /// The incoming message exceeded the maximum allowed size.
    #[error("DCUtR message exceeds maximum size ({len} > {MAX_MESSAGE_SIZE})")]
    MessageTooLarge { len: usize },
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

/// Client-side (initiator) state machine.
///
/// Usage:
/// 1. Construct with [`DcutrInitiator::new`], passing our observed addresses.
/// 2. Call [`DcutrInitiator::take_outbound`] and send the bytes.
/// 3. Record the send time; feed stream data via [`DcutrInitiator::on_data`].
/// 4. When [`DcutrInitiator::outcome`] returns `DialNow`, the caller:
///    - dials the returned addresses immediately,
///    - calls [`DcutrInitiator::send_sync`] to queue the SYNC frame,
///    - flushes the outbound bytes.
pub struct DcutrInitiator {
    outbound: Vec<u8>,
    recv_buf: Vec<u8>,
    state: InitiatorState,
    outcome: Option<InitiatorOutcome>,
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
    pub fn new(own_addrs: &[Multiaddr]) -> Self {
        let obs_addrs = own_addrs.iter().map(encode_multiaddr).collect();
        let msg = HolePunch {
            kind: HolePunchType::Connect,
            obs_addrs,
        };
        let outbound = encode_frame(&msg.encode());

        Self {
            outbound,
            recv_buf: Vec::new(),
            state: InitiatorState::Pending,
            outcome: None,
        }
    }

    /// Drains and returns any pending outbound bytes.
    pub fn take_outbound(&mut self) -> Vec<u8> {
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
    pub fn on_data(&mut self, data: &[u8], rtt_ms: u64) -> Result<(), DcutrError> {
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
    pub fn on_remote_write_closed(&mut self) -> Result<(), DcutrError> {
        // No-op: the outcome is already resolved by the time we'd care.
        Ok(())
    }

    /// Returns the current outcome, if available.
    pub fn outcome(&self) -> Option<&InitiatorOutcome> {
        self.outcome.as_ref()
    }

    /// Returns `true` if the flow has completed (SYNC was sent).
    pub fn is_done(&self) -> bool {
        self.state == InitiatorState::Done
    }

    /// Queues the SYNC message to be sent.
    ///
    /// Call this after you have initiated your simultaneous dial, per the
    /// spec. After calling, flush [`take_outbound`] to the stream.
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
        self.outbound.extend(encode_frame(&msg.encode()));
        self.state = InitiatorState::SyncPending;
        Ok(())
    }

    fn try_decode_reply(&mut self, rtt_ms: u64) -> Result<(), DcutrError> {
        if self.state != InitiatorState::AwaitingConnectReply {
            return Ok(());
        }

        enforce_max_size(&self.recv_buf).map_err(|e| {
            self.state = InitiatorState::Done;
            e
        })?;

        let (payload, consumed) = match decode_frame(&self.recv_buf) {
            FrameDecode::Complete { payload, consumed } => (payload.to_vec(), consumed),
            FrameDecode::Incomplete => return Ok(()),
            FrameDecode::Error(e) => {
                self.state = InitiatorState::Done;
                return Err(DcutrError::Malformed(DcutrMessageError::Varint(e)));
            }
        };
        self.recv_buf.drain(..consumed);

        let reply = HolePunch::decode(&payload).map_err(|e| {
            self.state = InitiatorState::Done;
            DcutrError::Malformed(e)
        })?;

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

/// Server-side (responder) state machine.
///
/// Usage:
/// 1. Construct with [`DcutrResponder::new`], passing our observed addresses.
///    Our CONNECT reply is queued automatically.
/// 2. Feed incoming bytes via [`DcutrResponder::on_data`].
/// 3. Poll [`DcutrResponder::poll_events`] to collect [`ResponderEvent`]s.
/// 4. Flush [`DcutrResponder::take_outbound`] to the stream.
pub struct DcutrResponder {
    own_addrs: Vec<Vec<u8>>,
    outbound: Vec<u8>,
    recv_buf: Vec<u8>,
    state: ResponderState,
    events: Vec<ResponderEvent>,
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
    /// on. The CONNECT reply is lazily queued once we actually receive the
    /// initiator's CONNECT.
    pub fn new(own_addrs: &[Multiaddr]) -> Self {
        Self {
            own_addrs: own_addrs.iter().map(encode_multiaddr).collect(),
            outbound: Vec::new(),
            recv_buf: Vec::new(),
            state: ResponderState::AwaitingConnect,
            events: Vec::new(),
        }
    }

    /// Drains and returns any pending outbound bytes.
    pub fn take_outbound(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.outbound)
    }

    /// Feeds incoming stream bytes.
    pub fn on_data(&mut self, data: &[u8]) -> Result<(), DcutrError> {
        if self.state == ResponderState::Done {
            return Ok(());
        }

        self.recv_buf.extend_from_slice(data);
        self.try_decode()
    }

    /// Notifies the state machine that the remote closed its write side.
    pub fn on_remote_write_closed(&mut self) -> Result<(), DcutrError> {
        self.try_decode()
    }

    /// Drains buffered events.
    pub fn poll_events(&mut self) -> Vec<ResponderEvent> {
        core::mem::take(&mut self.events)
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

            enforce_max_size(&self.recv_buf).map_err(|e| {
                self.state = ResponderState::Done;
                e
            })?;

            let (payload, consumed) = match decode_frame(&self.recv_buf) {
                FrameDecode::Complete { payload, consumed } => (payload.to_vec(), consumed),
                FrameDecode::Incomplete => return Ok(()),
                FrameDecode::Error(e) => {
                    self.state = ResponderState::Done;
                    return Err(DcutrError::Malformed(DcutrMessageError::Varint(e)));
                }
            };
            self.recv_buf.drain(..consumed);

            let msg = HolePunch::decode(&payload).map_err(|e| {
                self.state = ResponderState::Done;
                DcutrError::Malformed(e)
            })?;

            match (self.state, msg.kind) {
                (ResponderState::AwaitingConnect, HolePunchType::Connect) => {
                    // Queue our own CONNECT reply and transition state.
                    let reply = HolePunch {
                        kind: HolePunchType::Connect,
                        obs_addrs: self.own_addrs.clone(),
                    };
                    self.outbound.extend(encode_frame(&reply.encode()));

                    let remote_addr_bytes = msg.obs_addrs;
                    let remote_addrs = decode_remote_addrs(&remote_addr_bytes);
                    self.events.push(ResponderEvent::ConnectReceived {
                        remote_addrs,
                        remote_addr_bytes,
                    });
                    self.state = ResponderState::AwaitingSync;
                }
                (ResponderState::AwaitingSync, HolePunchType::Sync) => {
                    self.events.push(ResponderEvent::SyncReceived);
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

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn enforce_max_size(buf: &[u8]) -> Result<(), DcutrError> {
    if buf.len() > MAX_MESSAGE_SIZE {
        return Err(DcutrError::MessageTooLarge { len: buf.len() });
    }
    Ok(())
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
    fn rejects_oversized_message() {
        let mut resp = DcutrResponder::new(&[]);
        let large = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let err = resp.on_data(&large).unwrap_err();
        assert!(matches!(err, DcutrError::MessageTooLarge { .. }));
    }
}
