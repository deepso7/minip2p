//! End-to-end integration test for the relay + DCUtR state machines.
//!
//! This test validates the **protocol logic** of the hole-punching flow by
//! driving the client-side state machines against a minimal in-memory relay
//! emulator. No QUIC, no multistream-select, no UDP — just bytes on pipes.
//!
//! Flow exercised:
//!
//! ```text
//! Peer B (target)                Relay R                 Peer A (initiator)
//!   |                              |                          |
//!   |------ HOP RESERVE ---------->|                          |
//!   |<----- HOP STATUS:OK ---------|                          |
//!   |      (reservation stored)    |                          |
//!   |                              |<------- HOP CONNECT -----|
//!   |<------ STOP CONNECT ---------|                          |
//!   |------- STOP STATUS:OK ------>|------ HOP STATUS:OK ---->|
//!   |                 (bridge established)                    |
//!   |<--------------------- DCUtR CONNECT --------------------|
//!   |--------------------- DCUtR CONNECT (reply) ------------>|
//!   |<---------------------- DCUtR SYNC ----------------------|
//!   |   (both peers ready to dial each other directly)        |
//! ```

use std::collections::{HashMap, VecDeque};
use std::str::FromStr;

use minip2p_core::{Multiaddr, PeerId};
use minip2p_dcutr::{
    decode_frame as dcutr_decode_frame, DcutrInitiator, DcutrResponder, InitiatorOutcome,
    ResponderEvent,
};
use minip2p_identity::Ed25519Keypair;
use minip2p_relay::{
    decode_frame as relay_decode_frame, encode_frame as relay_encode_frame, FrameDecode,
    HopConnect, HopMessage, HopMessageType, HopReservation, Peer, Reservation,
    ReservationOutcome, Status, StopMessage, StopMessageType, StopResponder,
};

// ---------------------------------------------------------------------------
// In-memory relay emulator (the absolute minimum needed to bridge the test)
// ---------------------------------------------------------------------------

/// A minimal in-memory relay that handles RESERVE and CONNECT over HOP, plus
/// the paired STOP exchange. It owns a per-peer inbox of bytes the client
/// would receive on their HOP stream.
struct RelayEmulator {
    /// HOP -> reserved peer id.
    reservations: HashMap<PeerId, ReservationChannels>,
    /// Events observed during processing, for test assertions.
    events: Vec<RelayEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RelayEvent {
    ReservationStored { peer: PeerId },
    ConnectBridgedBetween { initiator: PeerId, target: PeerId },
    StatusOkSentToInitiator,
}

/// Channels representing a reserved peer's HOP stream (for STATUS replies)
/// and an optional STOP stream we will open toward them on CONNECT.
struct ReservationChannels {
    /// Bytes the relay sends back to the reserving peer on its HOP stream.
    hop_inbox: Vec<u8>,
    /// Bytes the relay sends to the reserving peer on the STOP stream opened
    /// when another peer requests a CONNECT targeting this peer.
    stop_inbox: Vec<u8>,
}

impl RelayEmulator {
    fn new() -> Self {
        Self {
            reservations: HashMap::new(),
            events: Vec::new(),
        }
    }

    /// The reserving peer sends raw bytes on its HOP stream. We parse them
    /// and queue the appropriate response to the peer's HOP inbox.
    fn on_reserve_request(
        &mut self,
        reserver: &PeerId,
        bytes: &[u8],
    ) -> Result<(), RelayEmulatorError> {
        let msg = decode_hop_message(bytes)?;
        if msg.kind != HopMessageType::Reserve {
            return Err(RelayEmulatorError::Unexpected("expected RESERVE"));
        }

        // Prepare the reservation.
        let channels = self
            .reservations
            .entry(reserver.clone())
            .or_insert_with(|| ReservationChannels {
                hop_inbox: Vec::new(),
                stop_inbox: Vec::new(),
            });

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
        channels.hop_inbox.extend(relay_encode_frame(&response.encode()));
        self.events.push(RelayEvent::ReservationStored {
            peer: reserver.clone(),
        });
        Ok(())
    }

    /// Drain queued HOP bytes for a reserved peer.
    fn drain_hop_bytes_for(&mut self, peer: &PeerId) -> Vec<u8> {
        self.reservations
            .get_mut(peer)
            .map(|r| core::mem::take(&mut r.hop_inbox))
            .unwrap_or_default()
    }

    /// Drain queued STOP bytes for a reserved peer.
    fn drain_stop_bytes_for(&mut self, peer: &PeerId) -> Vec<u8> {
        self.reservations
            .get_mut(peer)
            .map(|r| core::mem::take(&mut r.stop_inbox))
            .unwrap_or_default()
    }

    /// An initiator peer sends a HOP CONNECT targeting `target`. We verify
    /// the target is reserved, then open a virtual STOP stream to them and
    /// forward a STOP CONNECT message.
    ///
    /// The initiator's responses (STATUS after the target acks) are tracked
    /// via `pending_initiator_responses`.
    fn on_connect_request(
        &mut self,
        initiator: &PeerId,
        bytes: &[u8],
        pending_initiator_responses: &mut Vec<u8>,
    ) -> Result<(), RelayEmulatorError> {
        let msg = decode_hop_message(bytes)?;
        if msg.kind != HopMessageType::Connect {
            return Err(RelayEmulatorError::Unexpected("expected CONNECT"));
        }
        let target_bytes = msg
            .peer
            .as_ref()
            .map(|p| p.id.clone())
            .ok_or(RelayEmulatorError::Unexpected("missing peer field"))?;

        let target = PeerId::from_bytes(&target_bytes)
            .map_err(|_| RelayEmulatorError::Unexpected("invalid target peer id"))?;

        if !self.reservations.contains_key(&target) {
            let refusal = HopMessage {
                kind: HopMessageType::Status,
                peer: None,
                reservation: None,
                limit: None,
                status: Some(Status::NoReservation),
            };
            pending_initiator_responses.extend(relay_encode_frame(&refusal.encode()));
            return Ok(());
        }

        // Open a STOP stream to the target: queue a STOP CONNECT with the
        // initiator's peer id as the source.
        let stop_connect = StopMessage {
            kind: StopMessageType::Connect,
            peer: Some(Peer {
                id: initiator.to_bytes(),
                addrs: Vec::new(),
            }),
            limit: None,
            status: None,
        };
        self.reservations
            .get_mut(&target)
            .expect("checked above")
            .stop_inbox
            .extend(relay_encode_frame(&stop_connect.encode()));

        self.events.push(RelayEvent::ConnectBridgedBetween {
            initiator: initiator.clone(),
            target,
        });

        Ok(())
    }

    /// The target peer replies on its STOP stream with STATUS:OK. We forward
    /// a HOP STATUS:OK to the initiator.
    fn on_stop_ack_from_target(
        &mut self,
        bytes: &[u8],
        initiator_inbox: &mut Vec<u8>,
    ) -> Result<(), RelayEmulatorError> {
        let msg = decode_stop_message(bytes)?;
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
        initiator_inbox.extend(relay_encode_frame(&ok.encode()));
        self.events.push(RelayEvent::StatusOkSentToInitiator);
        Ok(())
    }
}

#[derive(Debug)]
#[allow(dead_code)] // the &'static str is only for diagnostic messages surfaced via Debug.
enum RelayEmulatorError {
    Unexpected(&'static str),
}

/// Parse a single HOP frame from the front of `bytes` and return the decoded message.
fn decode_hop_message(bytes: &[u8]) -> Result<HopMessage, RelayEmulatorError> {
    match relay_decode_frame(bytes) {
        FrameDecode::Complete { payload, .. } => {
            HopMessage::decode(payload).map_err(|_| RelayEmulatorError::Unexpected("bad HOP"))
        }
        _ => Err(RelayEmulatorError::Unexpected("incomplete HOP frame")),
    }
}

/// Parse a single STOP frame from the front of `bytes` and return the decoded message.
fn decode_stop_message(bytes: &[u8]) -> Result<StopMessage, RelayEmulatorError> {
    match relay_decode_frame(bytes) {
        FrameDecode::Complete { payload, .. } => {
            StopMessage::decode(payload).map_err(|_| RelayEmulatorError::Unexpected("bad STOP"))
        }
        _ => Err(RelayEmulatorError::Unexpected("incomplete STOP frame")),
    }
}

// ---------------------------------------------------------------------------
// The actual test
// ---------------------------------------------------------------------------

#[test]
fn full_relay_plus_hole_punch_flow_succeeds() {
    // Peer identities (PeerIds) for A and B.
    let peer_a_key = Ed25519Keypair::generate();
    let peer_b_key = Ed25519Keypair::generate();
    let peer_a = peer_a_key.peer_id();
    let peer_b = peer_b_key.peer_id();

    let mut relay = RelayEmulator::new();

    // ---- Step 1: B reserves on the relay ----------------------------------

    let mut b_reservation = HopReservation::new();

    // B sends RESERVE. Relay stores reservation and responds with STATUS:OK.
    let reserve_bytes = b_reservation.take_outbound();
    relay.on_reserve_request(&peer_b, &reserve_bytes).unwrap();

    // B receives the relay's response on its HOP stream.
    let relay_to_b = relay.drain_hop_bytes_for(&peer_b);
    b_reservation.on_data(&relay_to_b).unwrap();
    assert!(b_reservation.is_done());
    assert!(matches!(
        b_reservation.outcome(),
        Some(ReservationOutcome::Accepted { .. })
    ));
    assert_eq!(
        relay.events[0],
        RelayEvent::ReservationStored {
            peer: peer_b.clone()
        }
    );

    // ---- Step 2: A asks the relay to CONNECT it to B ----------------------

    let mut a_connect = HopConnect::new(peer_b.to_bytes());

    // A sends HOP CONNECT(peer=B).
    let connect_bytes = a_connect.take_outbound();

    // The relay forwards a STOP CONNECT to B and remembers to send A a
    // STATUS:OK once B acks.
    let mut initiator_inbox: Vec<u8> = Vec::new();
    relay
        .on_connect_request(&peer_a, &connect_bytes, &mut initiator_inbox)
        .unwrap();
    assert_eq!(initiator_inbox, Vec::<u8>::new(), "no refusal expected");

    // ---- Step 3: B receives STOP CONNECT, accepts, relay bridges ---------

    let mut b_stop = StopResponder::new();
    let stop_to_b = relay.drain_stop_bytes_for(&peer_b);
    b_stop.on_data(&stop_to_b).unwrap();

    let b_stop_request = b_stop.request().expect("CONNECT received");
    // The source peer id in the STOP CONNECT must be A.
    assert_eq!(b_stop_request.source_peer_id, peer_a.to_bytes());

    // B accepts; outbound STATUS:OK goes back to the relay.
    b_stop.accept().unwrap();
    let b_stop_ok = b_stop.take_outbound();

    // Relay forwards the ack to A as HOP STATUS:OK.
    relay
        .on_stop_ack_from_target(&b_stop_ok, &mut initiator_inbox)
        .unwrap();

    // A receives the HOP STATUS:OK: the stream is now bridged.
    a_connect.on_data(&initiator_inbox).unwrap();
    assert!(a_connect.is_done());
    assert!(matches!(
        a_connect.outcome(),
        Some(minip2p_relay::ConnectOutcome::Bridged { .. })
    ));

    // Sanity check: the relay recorded both the CONNECT bridge and the final
    // STATUS:OK forward.
    assert!(relay
        .events
        .iter()
        .any(|e| matches!(e, RelayEvent::ConnectBridgedBetween { initiator, target }
            if initiator == &peer_a && target == &peer_b)));
    assert!(relay
        .events
        .contains(&RelayEvent::StatusOkSentToInitiator));

    // ---- Step 4: Over the bridge, A (initiator) runs DCUtR ---------------

    // Represent "the bridge" as two byte pipes between A and B.
    let mut a_to_b: VecDeque<u8> = VecDeque::new();
    let mut b_to_a: VecDeque<u8> = VecDeque::new();

    // A advertises its observed addresses; B advertises its own.
    let a_observed: Vec<Multiaddr> = vec![
        Multiaddr::from_str("/ip4/203.0.113.1/udp/12345/quic-v1").unwrap(),
    ];
    let b_observed: Vec<Multiaddr> = vec![
        Multiaddr::from_str("/ip4/198.51.100.2/udp/54321/quic-v1").unwrap(),
    ];

    let mut dcutr_a = DcutrInitiator::new(&a_observed);
    let mut dcutr_b = DcutrResponder::new(&b_observed);

    // A sends CONNECT over the bridge.
    push_bytes(&mut a_to_b, &dcutr_a.take_outbound());

    // B receives CONNECT, queues a reply, emits ConnectReceived event.
    let bytes = drain_pipe(&mut a_to_b);
    dcutr_b.on_data(&bytes).unwrap();

    let events_b = dcutr_b.poll_events();
    assert!(matches!(
        events_b.first(),
        Some(ResponderEvent::ConnectReceived { remote_addrs, .. })
            if *remote_addrs == a_observed
    ));

    // B flushes its CONNECT reply toward A.
    push_bytes(&mut b_to_a, &dcutr_b.take_outbound());

    // A receives CONNECT reply, records remote addrs and RTT.
    let bytes = drain_pipe(&mut b_to_a);
    let simulated_rtt_ms = 42;
    dcutr_a.on_data(&bytes, simulated_rtt_ms).unwrap();

    match dcutr_a.outcome() {
        Some(InitiatorOutcome::DialNow {
            remote_addrs,
            rtt_ms,
            ..
        }) => {
            assert_eq!(*remote_addrs, b_observed);
            assert_eq!(*rtt_ms, simulated_rtt_ms);
        }
        other => panic!("unexpected initiator outcome: {other:?}"),
    }

    // A sends SYNC over the bridge and (in a real system) immediately dials
    // B's observed addresses directly.
    dcutr_a.send_sync().unwrap();
    push_bytes(&mut a_to_b, &dcutr_a.take_outbound());
    assert!(dcutr_a.is_done());

    // B receives SYNC: in a real system it would now send random UDP to A's
    // addresses after an RTT/2 delay.
    let bytes = drain_pipe(&mut a_to_b);
    dcutr_b.on_data(&bytes).unwrap();
    let events_b = dcutr_b.poll_events();
    assert_eq!(events_b.as_slice(), [ResponderEvent::SyncReceived]);
    assert!(dcutr_b.is_done());

    // Both state machines are complete. A would now dial B directly on
    // b_observed; B would open its NAT binding by sending random UDP to
    // a_observed. That final step is out of scope for this in-memory test
    // but is covered by the CLI example.
}

// ---------------------------------------------------------------------------
// Additional focused scenarios
// ---------------------------------------------------------------------------

#[test]
fn connect_refused_when_target_not_reserved() {
    let peer_a = Ed25519Keypair::generate().peer_id();
    let target = Ed25519Keypair::generate().peer_id();

    let mut relay = RelayEmulator::new();

    let mut a_connect = HopConnect::new(target.to_bytes());
    let connect_bytes = a_connect.take_outbound();

    let mut initiator_inbox: Vec<u8> = Vec::new();
    relay
        .on_connect_request(&peer_a, &connect_bytes, &mut initiator_inbox)
        .unwrap();

    a_connect.on_data(&initiator_inbox).unwrap();

    match a_connect.outcome() {
        Some(minip2p_relay::ConnectOutcome::Refused { status, .. }) => {
            assert_eq!(*status, Status::NoReservation);
        }
        other => panic!("expected refusal, got {other:?}"),
    }
}

#[test]
fn dcutr_rtt_is_reported_back_to_initiator() {
    let mut a = DcutrInitiator::new(&[
        Multiaddr::from_str("/ip4/1.2.3.4/udp/1/quic-v1").unwrap(),
    ]);
    let mut b = DcutrResponder::new(&[
        Multiaddr::from_str("/ip4/5.6.7.8/udp/2/quic-v1").unwrap(),
    ]);

    let connect_from_a = a.take_outbound();
    b.on_data(&connect_from_a).unwrap();
    let _ = b.poll_events();

    let reply_from_b = b.take_outbound();
    a.on_data(&reply_from_b, 123).unwrap();

    match a.outcome() {
        Some(InitiatorOutcome::DialNow { rtt_ms, .. }) => assert_eq!(*rtt_ms, 123),
        _ => panic!("expected DialNow"),
    }
}

// ---------------------------------------------------------------------------
// Byte-pipe helpers
// ---------------------------------------------------------------------------

fn push_bytes(pipe: &mut VecDeque<u8>, bytes: &[u8]) {
    pipe.extend(bytes.iter().copied());
}

fn drain_pipe(pipe: &mut VecDeque<u8>) -> Vec<u8> {
    pipe.drain(..).collect()
}

/// Sanity test: the DCUtR frame decoder is the same across the encode/decode
/// path used in this integration test.
#[test]
fn dcutr_frame_decode_round_trips() {
    // Just asserting the crate's own helpers are in scope and work here.
    use minip2p_dcutr::{encode_frame, HolePunch, HolePunchType};
    let msg = HolePunch {
        kind: HolePunchType::Sync,
        obs_addrs: Vec::new(),
    };
    let framed = encode_frame(&msg.encode());
    match dcutr_decode_frame(&framed) {
        minip2p_dcutr::FrameDecode::Complete { payload, .. } => {
            let decoded = HolePunch::decode(payload).unwrap();
            assert_eq!(decoded, msg);
        }
        _ => panic!("expected complete frame"),
    }
}
