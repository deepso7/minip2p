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

use std::collections::VecDeque;
use std::str::FromStr;

use minip2p_core::{Multiaddr, SansIoProtocol};
use minip2p_dcutr::{
    DcutrInitiator, DcutrInitiatorInput, DcutrInitiatorOutput, DcutrResponder, DcutrResponderInput,
    DcutrResponderOutput, InitiatorOutcome, ResponderEvent, decode_frame as dcutr_decode_frame,
};
use minip2p_identity::Ed25519Keypair;
use minip2p_relay::{
    HopConnect, HopConnectInput, HopConnectOutput, HopReservation, HopReservationInput,
    HopReservationOutput, ReservationOutcome, Status, StopResponder, StopResponderInput,
    StopResponderOutput,
};
use minip2p_test_support::{ConnectRequestOutcome, RelayEmulator, RelayEvent};

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
    let reserve_bytes = reserve_flush(&mut b_reservation);
    assert!(
        relay
            .on_reserve_request(&peer_b, &reserve_bytes)
            .unwrap()
            .is_empty()
    );

    // B receives the relay's response on its HOP stream.
    let relay_to_b = relay.drain_hop_bytes_for(&peer_b);
    let reservation_outcome = reserve_feed(&mut b_reservation, relay_to_b);
    assert!(b_reservation.is_done());
    assert!(matches!(
        reservation_outcome,
        ReservationOutcome::Accepted { .. }
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
    let connect_bytes = connect_flush(&mut a_connect);

    // The relay forwards a STOP CONNECT to B and remembers to send A a
    // STATUS:OK once B acks.
    let mut initiator_inbox: Vec<u8> = Vec::new();
    let connect_request = relay
        .on_connect_request(&peer_a, &connect_bytes, &mut initiator_inbox)
        .unwrap();
    assert!(matches!(
        &connect_request,
        ConnectRequestOutcome::Bridging { target, trailing, .. }
            if target == &peer_b && trailing.is_empty()
    ));
    assert_eq!(initiator_inbox, Vec::<u8>::new(), "no refusal expected");

    // ---- Step 3: B receives STOP CONNECT, accepts, relay bridges ---------

    let mut b_stop = StopResponder::new();
    let stop_to_b = relay.drain_stop_bytes_for(&peer_b);
    let b_stop_request = stop_feed(&mut b_stop, stop_to_b);
    // The source peer id in the STOP CONNECT must be A.
    assert_eq!(b_stop_request.source_peer_id, peer_a.to_bytes());

    // B accepts; outbound STATUS:OK goes back to the relay.
    let b_stop_ok = stop_accept_flush(&mut b_stop);

    // Relay forwards the ack to A as HOP STATUS:OK.
    let ConnectRequestOutcome::Bridging { pending_id, .. } = connect_request else {
        unreachable!("CONNECT was checked as bridging above")
    };
    let stop_trailing = relay
        .on_stop_ack_from_target(pending_id, &peer_b, &b_stop_ok, &mut initiator_inbox)
        .unwrap();
    assert!(stop_trailing.is_empty());

    // A receives the HOP STATUS:OK: the stream is now bridged.
    let connect_outcome = connect_feed(&mut a_connect, initiator_inbox);
    assert!(a_connect.is_done());
    assert!(matches!(
        connect_outcome,
        minip2p_relay::ConnectOutcome::Bridged { .. }
    ));

    // Sanity check: the relay recorded both the CONNECT bridge and the final
    // STATUS:OK forward.
    assert!(relay.events.iter().any(
        |e| matches!(e, RelayEvent::ConnectBridgedBetween { initiator, target }
            if initiator == &peer_a && target == &peer_b)
    ));
    assert!(relay.events.contains(&RelayEvent::StatusOkSentToInitiator));

    // ---- Step 4: Over the bridge, A (initiator) runs DCUtR ---------------

    // Represent "the bridge" as two byte pipes between A and B.
    let mut a_to_b: VecDeque<u8> = VecDeque::new();
    let mut b_to_a: VecDeque<u8> = VecDeque::new();

    // A advertises its observed addresses; B advertises its own.
    let a_observed: Vec<Multiaddr> =
        vec![Multiaddr::from_str("/ip4/203.0.113.1/udp/12345/quic-v1").unwrap()];
    let b_observed: Vec<Multiaddr> =
        vec![Multiaddr::from_str("/ip4/198.51.100.2/udp/54321/quic-v1").unwrap()];

    let mut dcutr_a = DcutrInitiator::new(&a_observed);
    let mut dcutr_b = DcutrResponder::new(&b_observed);

    // A sends CONNECT over the bridge.
    push_bytes(&mut a_to_b, &dcutr_initiator_flush(&mut dcutr_a));

    // B receives CONNECT, queues a reply, emits ConnectReceived event.
    let bytes = drain_pipe(&mut a_to_b);
    dcutr_responder_feed(&mut dcutr_b, bytes);

    // B flushes its CONNECT reply toward A.
    push_bytes(&mut b_to_a, &dcutr_responder_flush(&mut dcutr_b));

    let events_b = dcutr_responder_events(&mut dcutr_b);
    assert!(matches!(
        events_b.first(),
        Some(ResponderEvent::ConnectReceived { remote_addrs, .. })
            if *remote_addrs == a_observed
    ));

    // A receives CONNECT reply, records remote addrs and RTT.
    let bytes = drain_pipe(&mut b_to_a);
    let simulated_rtt_ms = 42;
    let initiator_outcome = dcutr_initiator_feed(&mut dcutr_a, bytes, simulated_rtt_ms);

    match initiator_outcome {
        InitiatorOutcome::DialNow {
            remote_addrs,
            rtt_ms,
            ..
        } => {
            assert_eq!(remote_addrs, b_observed);
            assert_eq!(rtt_ms, simulated_rtt_ms);
        }
    }

    // A sends SYNC over the bridge and (in a real system) immediately dials
    // B's observed addresses directly.
    push_bytes(&mut a_to_b, &dcutr_send_sync_flush(&mut dcutr_a));
    assert!(dcutr_a.is_done());

    // B receives SYNC: in a real system it would now send random UDP to A's
    // addresses after an RTT/2 delay.
    let bytes = drain_pipe(&mut a_to_b);
    dcutr_responder_feed(&mut dcutr_b, bytes);
    let events_b = dcutr_responder_events(&mut dcutr_b);
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
    let connect_bytes = connect_flush(&mut a_connect);

    let mut initiator_inbox: Vec<u8> = Vec::new();
    let connect_request = relay
        .on_connect_request(&peer_a, &connect_bytes, &mut initiator_inbox)
        .unwrap();
    assert!(matches!(
        connect_request,
        ConnectRequestOutcome::Refused { trailing } if trailing.is_empty()
    ));

    let outcome = connect_feed(&mut a_connect, initiator_inbox);

    match outcome {
        minip2p_relay::ConnectOutcome::Refused { status, .. } => {
            assert_eq!(status, Status::NoReservation);
        }
        other => panic!("expected refusal, got {other:?}"),
    }
}

#[test]
fn dcutr_rtt_is_reported_back_to_initiator() {
    let mut a = DcutrInitiator::new(&[Multiaddr::from_str("/ip4/1.2.3.4/udp/1/quic-v1").unwrap()]);
    let mut b = DcutrResponder::new(&[Multiaddr::from_str("/ip4/5.6.7.8/udp/2/quic-v1").unwrap()]);

    let connect_from_a = dcutr_initiator_flush(&mut a);
    dcutr_responder_feed(&mut b, connect_from_a);
    let reply_from_b = dcutr_responder_flush(&mut b);
    let _ = dcutr_responder_events(&mut b);
    let outcome = dcutr_initiator_feed(&mut a, reply_from_b, 123);

    match outcome {
        InitiatorOutcome::DialNow { rtt_ms, .. } => assert_eq!(rtt_ms, 123),
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

fn reserve_flush(flow: &mut HopReservation) -> Vec<u8> {
    flow.handle_input(HopReservationInput::Flush).unwrap();
    match flow.poll_output() {
        Some(HopReservationOutput::Outbound(bytes)) => bytes,
        other => panic!("expected reservation outbound, got {other:?}"),
    }
}

fn reserve_feed(flow: &mut HopReservation, bytes: Vec<u8>) -> ReservationOutcome {
    flow.handle_input(HopReservationInput::Data(bytes)).unwrap();
    match flow.poll_output() {
        Some(HopReservationOutput::Outcome(outcome)) => outcome,
        other => panic!("expected reservation outcome, got {other:?}"),
    }
}

fn connect_flush(flow: &mut HopConnect) -> Vec<u8> {
    flow.handle_input(HopConnectInput::Flush).unwrap();
    match flow.poll_output() {
        Some(HopConnectOutput::Outbound(bytes)) => bytes,
        other => panic!("expected connect outbound, got {other:?}"),
    }
}

fn connect_feed(flow: &mut HopConnect, bytes: Vec<u8>) -> minip2p_relay::ConnectOutcome {
    flow.handle_input(HopConnectInput::Data(bytes)).unwrap();
    match flow.poll_output() {
        Some(HopConnectOutput::Outcome(outcome)) => outcome,
        other => panic!("expected connect outcome, got {other:?}"),
    }
}

fn stop_feed(flow: &mut StopResponder, bytes: Vec<u8>) -> minip2p_relay::StopConnectRequest {
    flow.handle_input(StopResponderInput::Data(bytes)).unwrap();
    match flow.poll_output() {
        Some(StopResponderOutput::Request(request)) => request,
        other => panic!("expected stop request, got {other:?}"),
    }
}

fn stop_accept_flush(flow: &mut StopResponder) -> Vec<u8> {
    flow.handle_input(StopResponderInput::Accept).unwrap();
    match flow.poll_output() {
        Some(StopResponderOutput::Outbound(bytes)) => bytes,
        other => panic!("expected stop outbound, got {other:?}"),
    }
}

fn dcutr_initiator_flush(flow: &mut DcutrInitiator) -> Vec<u8> {
    flow.handle_input(DcutrInitiatorInput::Flush).unwrap();
    match flow.poll_output() {
        Some(DcutrInitiatorOutput::Outbound(bytes)) => bytes,
        other => panic!("expected dcutr initiator outbound, got {other:?}"),
    }
}

fn dcutr_initiator_feed(
    flow: &mut DcutrInitiator,
    bytes: Vec<u8>,
    rtt_ms: u64,
) -> InitiatorOutcome {
    flow.handle_input(DcutrInitiatorInput::Data { bytes, rtt_ms })
        .unwrap();
    match flow.poll_output() {
        Some(DcutrInitiatorOutput::Outcome(outcome)) => outcome,
        other => panic!("expected dcutr initiator outcome, got {other:?}"),
    }
}

fn dcutr_send_sync_flush(flow: &mut DcutrInitiator) -> Vec<u8> {
    flow.handle_input(DcutrInitiatorInput::SendSync).unwrap();
    dcutr_initiator_flush(flow)
}

fn dcutr_responder_feed(flow: &mut DcutrResponder, bytes: Vec<u8>) {
    flow.handle_input(DcutrResponderInput::Data(bytes)).unwrap();
}

fn dcutr_responder_flush(flow: &mut DcutrResponder) -> Vec<u8> {
    flow.handle_input(DcutrResponderInput::Flush).unwrap();
    match flow.poll_output() {
        Some(DcutrResponderOutput::Outbound(bytes)) => bytes,
        other => panic!("expected dcutr responder outbound, got {other:?}"),
    }
}

fn dcutr_responder_events(flow: &mut DcutrResponder) -> Vec<ResponderEvent> {
    let mut events = Vec::new();
    while let Some(output) = flow.poll_output() {
        if let DcutrResponderOutput::Event(event) = output {
            events.push(event);
        }
    }
    events
}

/// Sanity test: the DCUtR frame decoder is the same across the encode/decode
/// path used in this integration test.
#[test]
fn dcutr_frame_decode_round_trips() {
    // Just asserting the crate's own helpers are in scope and work here.
    use minip2p_dcutr::{HolePunch, HolePunchType, encode_frame};
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
