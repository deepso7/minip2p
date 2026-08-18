use core::str::FromStr;

use minip2p_core::{PeerId, SansIoProtocol};
use minip2p_relay::{
    HopMessage, HopMessageType, HopRequest, HopResponder, HopResponderInput, HopResponderOutput,
    Limit, MAX_MESSAGE_SIZE, MAX_PENDING_BRIDGE_SIZE, Peer, RelayError, RelayMessageError,
    Reservation, Status, StopInitiator, StopInitiatorInput, StopInitiatorOutcome,
    StopInitiatorOutput, StopMessage, StopMessageType, StopResponder, StopResponderInput,
    StopResponderOutput, decode_frame, encode_frame,
};

fn peer() -> PeerId {
    PeerId::from_str("QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N").unwrap()
}

fn decode_hop_frame(frame: &[u8]) -> HopMessage {
    let minip2p_relay::FrameDecode::Complete { payload, .. } = decode_frame(frame) else {
        panic!("expected complete HOP frame");
    };
    HopMessage::decode(payload).unwrap()
}

#[test]
fn decoder_preserves_an_unknown_status_value() {
    // Hop STATUS (type=2), status=777. This literal is independent of the
    // encoder so an accidental proto3-default mapping cannot satisfy it.
    let decoded = HopMessage::decode(&[0x08, 0x02, 0x28, 0x89, 0x06]).unwrap();

    assert_eq!(decoded.status, Some(Status::Unknown(777)));
    assert_eq!(decoded.encode(), [0x08, 0x02, 0x28, 0x89, 0x06]);
}

#[test]
fn decoder_distinguishes_absent_and_invalid_types_and_connect_peers() {
    assert_eq!(HopMessage::decode(&[]), Err(RelayMessageError::MissingType));
    assert_eq!(
        HopMessage::decode(&[0x08, 99]),
        Err(RelayMessageError::InvalidMessageType { value: 99 })
    );

    let missing_peer = HopMessage::decode(&[0x08, 0x01]).unwrap();
    let invalid_peer = HopMessage::decode(&[0x08, 0x01, 0x12, 0x03, 0x0a, 0x01, 0xff]).unwrap();
    assert_eq!(missing_peer.peer, None);
    assert_eq!(invalid_peer.peer.unwrap().id, [0xff]);

    assert_eq!(
        StopMessage::decode(&[]),
        Err(RelayMessageError::MissingType)
    );
    assert_eq!(
        StopMessage::decode(&[0x08, 99]),
        Err(RelayMessageError::InvalidMessageType { value: 99 })
    );
}

fn hop_frame(message: HopMessage) -> Vec<u8> {
    encode_frame(&message.encode())
}

fn stop_frame(message: StopMessage) -> Vec<u8> {
    encode_frame(&message.encode())
}

fn decode_stop_frame(frame: &[u8]) -> StopMessage {
    let minip2p_relay::FrameDecode::Complete { payload, .. } = decode_frame(frame) else {
        panic!("expected complete STOP frame");
    };
    StopMessage::decode(payload).unwrap()
}

#[test]
fn hop_responder_replies_to_a_wrong_message_kind_then_closes_write() {
    let request = HopMessage {
        kind: HopMessageType::Status,
        peer: None,
        reservation: None,
        limit: None,
        status: Some(Status::Ok),
    };
    let mut responder = HopResponder::new();

    responder
        .handle_input(HopResponderInput::Data(hop_frame(request)))
        .unwrap();

    let Some(HopResponderOutput::Outbound(frame)) = responder.poll_output() else {
        panic!("expected an UNEXPECTED_MESSAGE response");
    };
    assert_eq!(
        decode_hop_frame(&frame).status,
        Some(Status::UnexpectedMessage)
    );
    assert_eq!(
        responder.poll_output(),
        Some(HopResponderOutput::CloseWrite)
    );
    assert!(responder.is_done());
}

#[test]
fn hop_responder_exposes_connect_before_accepting_a_decision() {
    let destination = peer();
    let request = HopMessage {
        kind: HopMessageType::Connect,
        peer: Some(Peer {
            id: destination.to_bytes(),
            addrs: Vec::new(),
        }),
        reservation: None,
        limit: None,
        status: None,
    };
    let mut responder = HopResponder::new();

    responder
        .handle_input(HopResponderInput::Data(hop_frame(request)))
        .unwrap();

    assert_eq!(
        responder.poll_output(),
        Some(HopResponderOutput::Request(HopRequest::Connect {
            destination_peer_id: destination,
        }))
    );
    assert!(responder.poll_output().is_none());
}

#[test]
fn hop_connect_acceptance_emits_status_before_pipelined_payload() {
    let destination = peer();
    let mut bytes = hop_frame(HopMessage {
        kind: HopMessageType::Connect,
        peer: Some(Peer {
            id: destination.to_bytes(),
            addrs: Vec::new(),
        }),
        reservation: None,
        limit: None,
        status: None,
    });
    bytes.extend_from_slice(b"source payload");
    let limit = Limit {
        duration: Some(120),
        data: Some(131_072),
    };
    let mut responder = HopResponder::new();

    responder
        .handle_input(HopResponderInput::Data(bytes))
        .unwrap();
    responder
        .handle_input(HopResponderInput::AcceptConnect {
            limit: Some(limit.clone()),
        })
        .unwrap();

    assert!(matches!(
        responder.poll_output(),
        Some(HopResponderOutput::Request(HopRequest::Connect { .. }))
    ));
    let Some(HopResponderOutput::Outbound(frame)) = responder.poll_output() else {
        panic!("expected acceptance frame after request");
    };
    let response = decode_hop_frame(&frame);
    assert_eq!(response.status, Some(Status::Ok));
    assert_eq!(response.limit, Some(limit));
    assert_eq!(
        responder.poll_output(),
        Some(HopResponderOutput::BridgeData(b"source payload".to_vec()))
    );
    assert!(responder.is_done());
}

#[test]
fn hop_connect_backpressures_new_data_while_the_decision_is_pending() {
    let destination = peer();
    let mut request = hop_frame(HopMessage {
        kind: HopMessageType::Connect,
        peer: Some(Peer {
            id: destination.to_bytes(),
            addrs: Vec::new(),
        }),
        reservation: None,
        limit: None,
        status: None,
    });
    request.extend_from_slice(b"coalesced payload");
    let mut responder = HopResponder::new();

    responder
        .handle_input(HopResponderInput::Data(request))
        .unwrap();
    assert!(matches!(
        responder.poll_output(),
        Some(HopResponderOutput::Request(HopRequest::Connect { .. }))
    ));
    assert_eq!(
        responder.handle_input(HopResponderInput::Data(b"later payload".to_vec())),
        Err(RelayError::DecisionPending)
    );

    responder
        .handle_input(HopResponderInput::AcceptConnect { limit: None })
        .unwrap();
    assert!(matches!(
        responder.poll_output(),
        Some(HopResponderOutput::Outbound(_))
    ));
    assert_eq!(
        responder.poll_output(),
        Some(HopResponderOutput::BridgeData(
            b"coalesced payload".to_vec()
        ))
    );
    assert!(responder.poll_output().is_none());
}

#[test]
fn hop_connect_bounds_only_pre_authorization_pipelined_data() {
    let connect_frame = || {
        hop_frame(HopMessage {
            kind: HopMessageType::Connect,
            peer: Some(Peer {
                id: peer().to_bytes(),
                addrs: Vec::new(),
            }),
            reservation: None,
            limit: None,
            status: None,
        })
    };

    let mut oversized_input = connect_frame();
    oversized_input.resize(oversized_input.len() + MAX_PENDING_BRIDGE_SIZE + 1, 0xaa);
    let mut oversized = HopResponder::new();
    oversized
        .handle_input(HopResponderInput::Data(oversized_input))
        .unwrap();
    assert_eq!(oversized.poll_output(), Some(HopResponderOutput::Reset));
    assert!(oversized.poll_output().is_none());

    let mut exact_input = connect_frame();
    exact_input.resize(exact_input.len() + MAX_PENDING_BRIDGE_SIZE, 0xbb);
    let mut exact = HopResponder::new();
    exact
        .handle_input(HopResponderInput::Data(exact_input))
        .unwrap();
    assert!(matches!(
        exact.poll_output(),
        Some(HopResponderOutput::Request(HopRequest::Connect { .. }))
    ));
    exact
        .handle_input(HopResponderInput::AcceptConnect { limit: None })
        .unwrap();
    assert!(matches!(
        exact.poll_output(),
        Some(HopResponderOutput::Outbound(_))
    ));
    assert!(matches!(
        exact.poll_output(),
        Some(HopResponderOutput::BridgeData(data))
            if data.len() == MAX_PENDING_BRIDGE_SIZE
    ));

    let live_data = vec![0xcc; MAX_PENDING_BRIDGE_SIZE + 1];
    exact
        .handle_input(HopResponderInput::Data(live_data.clone()))
        .unwrap();
    assert_eq!(
        exact.poll_output(),
        Some(HopResponderOutput::BridgeData(live_data))
    );

    let mut malformed_input = hop_frame(HopMessage {
        kind: HopMessageType::Connect,
        peer: None,
        reservation: None,
        limit: None,
        status: None,
    });
    malformed_input.resize(malformed_input.len() + MAX_PENDING_BRIDGE_SIZE + 1, 0xdd);
    let mut malformed = HopResponder::new();
    malformed
        .handle_input(HopResponderInput::Data(malformed_input))
        .unwrap();
    assert_eq!(malformed.poll_output(), Some(HopResponderOutput::Reset));
    assert!(malformed.poll_output().is_none());
}

#[test]
fn hop_responder_rejects_invalid_local_decisions() {
    let reserve = || {
        hop_frame(HopMessage {
            kind: HopMessageType::Reserve,
            peer: None,
            reservation: None,
            limit: None,
            status: None,
        })
    };

    for status in [Status::Ok, Status::Unused] {
        let mut responder = HopResponder::new();
        responder
            .handle_input(HopResponderInput::Data(reserve()))
            .unwrap();
        assert_eq!(
            responder.poll_output(),
            Some(HopResponderOutput::Request(HopRequest::Reserve))
        );
        responder
            .handle_input(HopResponderInput::Reject(status))
            .unwrap();
        assert_eq!(responder.poll_output(), Some(HopResponderOutput::Reset));
        assert!(responder.poll_output().is_none());
    }

    let mut idle_connect = HopResponder::new();
    assert!(matches!(
        idle_connect.handle_input(HopResponderInput::AcceptConnect { limit: None }),
        Err(RelayError::UnexpectedMessage(_))
    ));
    assert!(idle_connect.poll_output().is_none());

    let mut idle_reservation = HopResponder::new();
    assert!(matches!(
        idle_reservation.handle_input(HopResponderInput::AcceptReservation {
            reservation: Reservation {
                expire: None,
                addrs: Vec::new(),
                voucher: None,
            },
            limit: None,
        }),
        Err(RelayError::UnexpectedMessage(_))
    ));
    assert!(idle_reservation.poll_output().is_none());

    let mut idle_reject = HopResponder::new();
    assert!(matches!(
        idle_reject.handle_input(HopResponderInput::Reject(Status::ReservationRefused)),
        Err(RelayError::UnexpectedMessage(_))
    ));
    assert!(idle_reject.poll_output().is_none());

    let mut wrong_kind = HopResponder::new();
    wrong_kind
        .handle_input(HopResponderInput::Data(reserve()))
        .unwrap();
    assert_eq!(
        wrong_kind.poll_output(),
        Some(HopResponderOutput::Request(HopRequest::Reserve))
    );
    assert!(matches!(
        wrong_kind.handle_input(HopResponderInput::AcceptConnect { limit: None }),
        Err(RelayError::UnexpectedMessage(_))
    ));
    assert!(wrong_kind.poll_output().is_none());
}

#[test]
fn stop_initiator_sends_connect_then_accepts_with_pipelined_payload() {
    let source = peer();
    let limit = Limit {
        duration: Some(120),
        data: Some(131_072),
    };
    let mut initiator = StopInitiator::new(source.clone(), Some(limit.clone()));

    let Some(StopInitiatorOutput::Outbound(frame)) = initiator.poll_output() else {
        panic!("expected STOP CONNECT");
    };
    let minip2p_relay::FrameDecode::Complete { payload, .. } = decode_frame(&frame) else {
        panic!("expected complete STOP frame");
    };
    let connect = StopMessage::decode(payload).unwrap();
    assert_eq!(connect.kind, StopMessageType::Connect);
    assert_eq!(connect.peer.unwrap().id, source.to_bytes());
    assert_eq!(connect.limit, Some(limit));

    let mut response = stop_frame(StopMessage {
        kind: StopMessageType::Status,
        peer: None,
        limit: None,
        status: Some(Status::Ok),
    });
    response.extend_from_slice(b"destination payload");
    initiator
        .handle_input(StopInitiatorInput::Data(response))
        .unwrap();

    assert_eq!(
        initiator.poll_output(),
        Some(StopInitiatorOutput::Outcome(StopInitiatorOutcome::Accepted))
    );
    assert_eq!(
        initiator.poll_output(),
        Some(StopInitiatorOutput::BridgeData(
            b"destination payload".to_vec()
        ))
    );
    assert!(initiator.is_done());
}

#[test]
fn stop_responder_bounds_and_backpressures_pre_authorization_payload() {
    let connect_frame = || {
        stop_frame(StopMessage {
            kind: StopMessageType::Connect,
            peer: Some(Peer {
                id: peer().to_bytes(),
                addrs: Vec::new(),
            }),
            limit: None,
            status: None,
        })
    };

    let mut pending = StopResponder::new();
    pending
        .handle_input(StopResponderInput::Data(connect_frame()))
        .unwrap();
    assert!(matches!(
        pending.poll_output(),
        Some(StopResponderOutput::Request(_))
    ));
    assert_eq!(
        pending.handle_input(StopResponderInput::Data(b"later payload".to_vec())),
        Err(RelayError::DecisionPending)
    );
    pending.handle_input(StopResponderInput::Accept).unwrap();
    assert!(matches!(
        pending.poll_output(),
        Some(StopResponderOutput::Outbound(_))
    ));
    assert!(pending.poll_output().is_none());
    let live_data = vec![0xcc; MAX_PENDING_BRIDGE_SIZE + 1];
    pending
        .handle_input(StopResponderInput::Data(live_data.clone()))
        .unwrap();
    assert_eq!(
        pending.poll_output(),
        Some(StopResponderOutput::BridgeData(live_data))
    );

    let mut oversized_input = connect_frame();
    oversized_input.resize(oversized_input.len() + MAX_PENDING_BRIDGE_SIZE + 1, 0xaa);
    let mut oversized = StopResponder::new();
    assert_eq!(
        oversized.handle_input(StopResponderInput::Data(oversized_input)),
        Err(RelayError::PendingBridgeTooLarge {
            len: MAX_PENDING_BRIDGE_SIZE + 1
        })
    );
    assert!(oversized.is_done());
    assert!(oversized.poll_output().is_none());

    let mut exact_input = connect_frame();
    exact_input.resize(exact_input.len() + MAX_PENDING_BRIDGE_SIZE, 0xbb);
    let mut exact = StopResponder::new();
    exact
        .handle_input(StopResponderInput::Data(exact_input))
        .unwrap();
    assert!(matches!(
        exact.poll_output(),
        Some(StopResponderOutput::Request(_))
    ));
    exact.handle_input(StopResponderInput::Accept).unwrap();
    assert!(matches!(
        exact.poll_output(),
        Some(StopResponderOutput::Outbound(_))
    ));
    assert!(matches!(
        exact.poll_output(),
        Some(StopResponderOutput::BridgeData(data))
            if data.len() == MAX_PENDING_BRIDGE_SIZE
    ));
}

#[test]
fn hop_reservation_acceptance_carries_metadata_then_closes_write() {
    let mut responder = HopResponder::new();
    responder
        .handle_input(HopResponderInput::Data(hop_frame(HopMessage {
            kind: HopMessageType::Reserve,
            peer: None,
            reservation: None,
            limit: None,
            status: None,
        })))
        .unwrap();
    let reservation = Reservation {
        expire: Some(2_000_000_000),
        addrs: vec![vec![1, 2, 3]],
        voucher: Some(b"must not be issued".to_vec()),
    };
    let limit = Limit {
        duration: Some(120),
        data: Some(131_072),
    };

    responder
        .handle_input(HopResponderInput::AcceptReservation {
            reservation: reservation.clone(),
            limit: Some(limit.clone()),
        })
        .unwrap();

    assert_eq!(
        responder.poll_output(),
        Some(HopResponderOutput::Request(HopRequest::Reserve))
    );
    let Some(HopResponderOutput::Outbound(frame)) = responder.poll_output() else {
        panic!("expected reservation acceptance");
    };
    let response = decode_hop_frame(&frame);
    assert_eq!(response.status, Some(Status::Ok));
    assert_eq!(
        response.reservation,
        Some(Reservation {
            voucher: None,
            ..reservation
        })
    );
    assert_eq!(response.limit, Some(limit));
    assert_eq!(
        responder.poll_output(),
        Some(HopResponderOutput::CloseWrite)
    );
}

#[test]
fn hop_semantic_errors_receive_status_while_bad_framing_resets() {
    let cases = [
        (
            // CONNECT with no peer field.
            hop_frame(HopMessage {
                kind: HopMessageType::Connect,
                peer: None,
                reservation: None,
                limit: None,
                status: None,
            }),
            Status::MalformedMessage,
        ),
        (
            // CONNECT with a present but invalid peer id.
            hop_frame(HopMessage {
                kind: HopMessageType::Connect,
                peer: Some(Peer {
                    id: vec![0xff],
                    addrs: Vec::new(),
                }),
                reservation: None,
                limit: None,
                status: None,
            }),
            Status::MalformedMessage,
        ),
        (
            // A well-framed body with an absent type field.
            encode_frame(&[]),
            Status::MalformedMessage,
        ),
        (
            // A well-framed body with type=99.
            encode_frame(&[0x08, 99]),
            Status::MalformedMessage,
        ),
    ];

    for (input, expected) in cases {
        let mut responder = HopResponder::new();
        responder
            .handle_input(HopResponderInput::Data(input))
            .unwrap();
        let Some(HopResponderOutput::Outbound(frame)) = responder.poll_output() else {
            panic!("semantic error should receive a status");
        };
        assert_eq!(decode_hop_frame(&frame).status, Some(expected));
        assert_eq!(
            responder.poll_output(),
            Some(HopResponderOutput::CloseWrite)
        );
    }

    let mut invalid_varint = HopResponder::new();
    invalid_varint
        .handle_input(HopResponderInput::Data(vec![0x80; 10]))
        .unwrap();
    assert_eq!(
        invalid_varint.poll_output(),
        Some(HopResponderOutput::Reset)
    );

    let mut oversized = HopResponder::new();
    oversized
        .handle_input(HopResponderInput::Data(vec![0x81, 0x40]))
        .unwrap();
    assert_eq!(oversized.poll_output(), Some(HopResponderOutput::Reset));
}

#[test]
fn hop_responder_accepts_fragmented_and_exact_limit_frames() {
    let reserve = hop_frame(HopMessage {
        kind: HopMessageType::Reserve,
        peer: None,
        reservation: None,
        limit: None,
        status: None,
    });
    let mut fragmented = HopResponder::new();
    for byte in reserve {
        fragmented
            .handle_input(HopResponderInput::Data(vec![byte]))
            .unwrap();
    }
    assert_eq!(
        fragmented.poll_output(),
        Some(HopResponderOutput::Request(HopRequest::Reserve))
    );

    // RESERVE plus an unknown length-delimited field fills an exact 8 KiB
    // protobuf body without relying on the decoder under test for the size.
    let mut body = vec![0x08, 0x00, 0x4a, 0xfb, 0x3f];
    body.resize(MAX_MESSAGE_SIZE, 0xab);
    assert_eq!(body.len(), 8192);
    let mut exact = HopResponder::new();
    exact
        .handle_input(HopResponderInput::Data(encode_frame(&body)))
        .unwrap();
    assert_eq!(
        exact.poll_output(),
        Some(HopResponderOutput::Request(HopRequest::Reserve))
    );
}

#[test]
fn stop_refusal_preserves_exact_status_and_maps_unexpected_codes_for_hop() {
    for (stop_status, hop_status) in [
        (Status::Unknown(777), Status::UnexpectedMessage),
        (Status::ResourceLimitExceeded, Status::ResourceLimitExceeded),
        (Status::PermissionDenied, Status::PermissionDenied),
        (Status::ConnectionFailed, Status::UnexpectedMessage),
        (Status::NoReservation, Status::UnexpectedMessage),
    ] {
        let mut initiator = StopInitiator::new(peer(), None);
        let _ = initiator.poll_output();
        initiator
            .handle_input(StopInitiatorInput::Data(stop_frame(StopMessage {
                kind: StopMessageType::Status,
                peer: None,
                limit: None,
                status: Some(stop_status),
            })))
            .unwrap();
        let Some(StopInitiatorOutput::Outcome(outcome)) = initiator.poll_output() else {
            panic!("expected refusal outcome");
        };
        assert_eq!(
            outcome,
            StopInitiatorOutcome::Refused {
                status: stop_status,
            }
        );
        assert_eq!(outcome.hop_status(), hop_status);
    }
}

#[test]
fn stop_semantic_error_sends_status_and_closes_while_bad_framing_resets() {
    let mut missing_status = StopInitiator::new(peer(), None);
    let _ = missing_status.poll_output();
    missing_status
        .handle_input(StopInitiatorInput::Data(stop_frame(StopMessage {
            kind: StopMessageType::Status,
            peer: None,
            limit: None,
            status: None,
        })))
        .unwrap();
    let Some(StopInitiatorOutput::Outbound(frame)) = missing_status.poll_output() else {
        panic!("expected MALFORMED_MESSAGE response");
    };
    assert_eq!(
        decode_stop_frame(&frame).status,
        Some(Status::MalformedMessage)
    );
    assert_eq!(
        missing_status.poll_output(),
        Some(StopInitiatorOutput::CloseWrite)
    );
    let Some(StopInitiatorOutput::Outcome(outcome)) = missing_status.poll_output() else {
        panic!("expected protocol outcome");
    };
    assert_eq!(outcome.hop_status(), Status::MalformedMessage);

    let mut wrong_kind = StopInitiator::new(peer(), None);
    let _ = wrong_kind.poll_output();
    wrong_kind
        .handle_input(StopInitiatorInput::Data(stop_frame(StopMessage {
            kind: StopMessageType::Connect,
            peer: None,
            limit: None,
            status: None,
        })))
        .unwrap();
    let Some(StopInitiatorOutput::Outbound(frame)) = wrong_kind.poll_output() else {
        panic!("expected UNEXPECTED_MESSAGE response");
    };
    assert_eq!(
        decode_stop_frame(&frame).status,
        Some(Status::UnexpectedMessage)
    );
    assert_eq!(
        wrong_kind.poll_output(),
        Some(StopInitiatorOutput::CloseWrite)
    );
    assert_eq!(
        wrong_kind.poll_output(),
        Some(StopInitiatorOutput::Outcome(
            StopInitiatorOutcome::ProtocolError {
                status: Status::UnexpectedMessage,
            }
        ))
    );

    let mut invalid = StopInitiator::new(peer(), None);
    let _ = invalid.poll_output();
    invalid
        .handle_input(StopInitiatorInput::Data(vec![0x81, 0x40]))
        .unwrap();
    assert_eq!(invalid.poll_output(), Some(StopInitiatorOutput::Reset));
    assert_eq!(
        invalid.poll_output(),
        Some(StopInitiatorOutput::Outcome(
            StopInitiatorOutcome::ProtocolError {
                status: Status::MalformedMessage,
            }
        ))
    );

    let mut missing_type = StopInitiator::new(peer(), None);
    let _ = missing_type.poll_output();
    missing_type
        .handle_input(StopInitiatorInput::Data(encode_frame(&[])))
        .unwrap();
    let Some(StopInitiatorOutput::Outbound(frame)) = missing_type.poll_output() else {
        panic!("expected MALFORMED_MESSAGE response");
    };
    assert_eq!(
        decode_stop_frame(&frame).status,
        Some(Status::MalformedMessage)
    );
    assert_eq!(
        missing_type.poll_output(),
        Some(StopInitiatorOutput::CloseWrite)
    );
    assert_eq!(
        missing_type.poll_output(),
        Some(StopInitiatorOutput::Outcome(
            StopInitiatorOutcome::ProtocolError {
                status: Status::MalformedMessage,
            }
        ))
    );

    let mut invalid_varint = StopInitiator::new(peer(), None);
    let _ = invalid_varint.poll_output();
    invalid_varint
        .handle_input(StopInitiatorInput::Data(vec![0x80; 10]))
        .unwrap();
    assert_eq!(
        invalid_varint.poll_output(),
        Some(StopInitiatorOutput::Reset)
    );
    assert_eq!(
        invalid_varint.poll_output(),
        Some(StopInitiatorOutput::Outcome(
            StopInitiatorOutcome::ProtocolError {
                status: Status::MalformedMessage,
            }
        ))
    );
}

#[test]
fn remote_close_and_reset_make_both_machines_terminal() {
    let mut hop_closed = HopResponder::new();
    hop_closed
        .handle_input(HopResponderInput::RemoteWriteClosed)
        .unwrap();
    assert!(hop_closed.is_done());
    assert!(hop_closed.poll_output().is_none());

    let mut hop_reset = HopResponder::new();
    hop_reset
        .handle_input(HopResponderInput::RemoteReset)
        .unwrap();
    assert!(hop_reset.is_done());
    assert!(hop_reset.poll_output().is_none());

    let mut stop_closed = StopInitiator::new(peer(), None);
    let _ = stop_closed.poll_output();
    stop_closed
        .handle_input(StopInitiatorInput::RemoteWriteClosed)
        .unwrap();
    assert_eq!(
        stop_closed.poll_output(),
        Some(StopInitiatorOutput::Outcome(
            StopInitiatorOutcome::RemoteWriteClosed
        ))
    );

    let mut stop_reset = StopInitiator::new(peer(), None);
    let _ = stop_reset.poll_output();
    stop_reset
        .handle_input(StopInitiatorInput::RemoteReset)
        .unwrap();
    assert_eq!(
        stop_reset.poll_output(),
        Some(StopInitiatorOutput::Outcome(
            StopInitiatorOutcome::RemoteReset
        ))
    );
    assert_eq!(
        StopInitiatorOutcome::RemoteReset.hop_status(),
        Status::ConnectionFailed
    );
}

#[test]
fn hop_remote_reset_discards_queued_and_future_data() {
    let request = hop_frame(HopMessage {
        kind: HopMessageType::Connect,
        peer: Some(Peer {
            id: peer().to_bytes(),
            addrs: Vec::new(),
        }),
        reservation: None,
        limit: None,
        status: None,
    });
    let mut hop = HopResponder::new();
    hop.handle_input(HopResponderInput::Data(request)).unwrap();
    hop.handle_input(HopResponderInput::AcceptConnect { limit: None })
        .unwrap();
    hop.handle_input(HopResponderInput::RemoteReset).unwrap();
    hop.handle_input(HopResponderInput::Data(b"stale".to_vec()))
        .unwrap();
    assert!(hop.poll_output().is_none());

    let mut pending_stop = StopInitiator::new(peer(), None);
    pending_stop
        .handle_input(StopInitiatorInput::RemoteReset)
        .unwrap();
    assert_eq!(
        pending_stop.poll_output(),
        Some(StopInitiatorOutput::Outcome(
            StopInitiatorOutcome::RemoteReset
        ))
    );
    assert!(pending_stop.poll_output().is_none());
}

#[test]
fn hop_remote_write_close_preserves_pending_request_and_payload() {
    let mut request = hop_frame(HopMessage {
        kind: HopMessageType::Connect,
        peer: Some(Peer {
            id: peer().to_bytes(),
            addrs: Vec::new(),
        }),
        reservation: None,
        limit: None,
        status: None,
    });
    request.extend_from_slice(b"source payload");
    let mut hop = HopResponder::new();
    hop.handle_input(HopResponderInput::Data(request)).unwrap();
    hop.handle_input(HopResponderInput::RemoteWriteClosed)
        .unwrap();
    assert!(matches!(
        hop.poll_output(),
        Some(HopResponderOutput::Request(HopRequest::Connect { .. }))
    ));
    hop.handle_input(HopResponderInput::AcceptConnect { limit: None })
        .unwrap();
    assert!(matches!(
        hop.poll_output(),
        Some(HopResponderOutput::Outbound(_))
    ));
    assert_eq!(
        hop.poll_output(),
        Some(HopResponderOutput::BridgeData(b"source payload".to_vec()))
    );
    hop.handle_input(HopResponderInput::Data(b"after eof".to_vec()))
        .unwrap();
    assert!(hop.poll_output().is_none());

    let mut accepted = HopResponder::new();
    accepted
        .handle_input(HopResponderInput::Data(hop_frame(HopMessage {
            kind: HopMessageType::Connect,
            peer: Some(Peer {
                id: peer().to_bytes(),
                addrs: Vec::new(),
            }),
            reservation: None,
            limit: None,
            status: None,
        })))
        .unwrap();
    accepted
        .handle_input(HopResponderInput::AcceptConnect { limit: None })
        .unwrap();
    accepted
        .handle_input(HopResponderInput::RemoteWriteClosed)
        .unwrap();
    assert!(matches!(
        accepted.poll_output(),
        Some(HopResponderOutput::Request(HopRequest::Connect { .. }))
    ));
    assert!(matches!(
        accepted.poll_output(),
        Some(HopResponderOutput::Outbound(_))
    ));
    assert!(accepted.poll_output().is_none());
}

#[test]
fn stop_remote_terminal_after_response_preserves_completed_outputs() {
    for terminal in [
        StopInitiatorInput::RemoteWriteClosed,
        StopInitiatorInput::RemoteReset,
    ] {
        let mut stop = StopInitiator::new(peer(), None);
        let _ = stop.poll_output();
        let mut response = stop_frame(StopMessage {
            kind: StopMessageType::Status,
            peer: None,
            limit: None,
            status: Some(Status::Ok),
        });
        response.extend_from_slice(b"destination payload");
        stop.handle_input(StopInitiatorInput::Data(response))
            .unwrap();
        stop.handle_input(terminal).unwrap();
        assert_eq!(
            stop.poll_output(),
            Some(StopInitiatorOutput::Outcome(StopInitiatorOutcome::Accepted))
        );
        assert_eq!(
            stop.poll_output(),
            Some(StopInitiatorOutput::BridgeData(
                b"destination payload".to_vec()
            ))
        );
        assert!(stop.poll_output().is_none());
    }

    let mut malformed = StopInitiator::new(peer(), None);
    let _ = malformed.poll_output();
    malformed
        .handle_input(StopInitiatorInput::Data(encode_frame(&[])))
        .unwrap();
    malformed
        .handle_input(StopInitiatorInput::RemoteWriteClosed)
        .unwrap();
    assert!(matches!(
        malformed.poll_output(),
        Some(StopInitiatorOutput::Outbound(_))
    ));
    assert_eq!(
        malformed.poll_output(),
        Some(StopInitiatorOutput::CloseWrite)
    );
    assert_eq!(
        malformed.poll_output(),
        Some(StopInitiatorOutput::Outcome(
            StopInitiatorOutcome::ProtocolError {
                status: Status::MalformedMessage,
            }
        ))
    );

    let mut invalid_then_reset = StopInitiator::new(peer(), None);
    let _ = invalid_then_reset.poll_output();
    invalid_then_reset
        .handle_input(StopInitiatorInput::Data(vec![0x80; 10]))
        .unwrap();
    invalid_then_reset
        .handle_input(StopInitiatorInput::RemoteReset)
        .unwrap();
    assert_eq!(
        invalid_then_reset.poll_output(),
        Some(StopInitiatorOutput::Outcome(
            StopInitiatorOutcome::ProtocolError {
                status: Status::MalformedMessage,
            }
        ))
    );
    assert!(invalid_then_reset.poll_output().is_none());

    let mut wrong_kind_then_reset = StopInitiator::new(peer(), None);
    let _ = wrong_kind_then_reset.poll_output();
    wrong_kind_then_reset
        .handle_input(StopInitiatorInput::Data(stop_frame(StopMessage {
            kind: StopMessageType::Connect,
            peer: None,
            limit: None,
            status: None,
        })))
        .unwrap();
    wrong_kind_then_reset
        .handle_input(StopInitiatorInput::RemoteReset)
        .unwrap();
    assert_eq!(
        wrong_kind_then_reset.poll_output(),
        Some(StopInitiatorOutput::Outcome(
            StopInitiatorOutcome::ProtocolError {
                status: Status::UnexpectedMessage,
            }
        ))
    );
    assert!(wrong_kind_then_reset.poll_output().is_none());
}

#[test]
fn hop_rejection_closes_and_unencodable_acceptance_resets() {
    let request = hop_frame(HopMessage {
        kind: HopMessageType::Reserve,
        peer: None,
        reservation: None,
        limit: None,
        status: None,
    });
    let mut rejected = HopResponder::new();
    rejected
        .handle_input(HopResponderInput::Data(request.clone()))
        .unwrap();
    rejected
        .handle_input(HopResponderInput::Reject(Status::ReservationRefused))
        .unwrap();
    assert!(matches!(
        rejected.poll_output(),
        Some(HopResponderOutput::Request(HopRequest::Reserve))
    ));
    let Some(HopResponderOutput::Outbound(frame)) = rejected.poll_output() else {
        panic!("expected refusal");
    };
    assert_eq!(
        decode_hop_frame(&frame).status,
        Some(Status::ReservationRefused)
    );
    assert_eq!(rejected.poll_output(), Some(HopResponderOutput::CloseWrite));

    let mut oversized = HopResponder::new();
    oversized
        .handle_input(HopResponderInput::Data(request))
        .unwrap();
    oversized
        .handle_input(HopResponderInput::AcceptReservation {
            reservation: Reservation {
                expire: None,
                addrs: vec![vec![0; MAX_MESSAGE_SIZE]],
                voucher: None,
            },
            limit: None,
        })
        .unwrap();
    assert!(matches!(
        oversized.poll_output(),
        Some(HopResponderOutput::Request(HopRequest::Reserve))
    ));
    assert_eq!(oversized.poll_output(), Some(HopResponderOutput::Reset));
}

#[test]
fn stop_initiator_accepts_fragmented_and_exact_limit_responses() {
    let response = stop_frame(StopMessage {
        kind: StopMessageType::Status,
        peer: None,
        limit: None,
        status: Some(Status::Ok),
    });
    let mut fragmented = StopInitiator::new(peer(), None);
    let _ = fragmented.poll_output();
    for byte in response {
        fragmented
            .handle_input(StopInitiatorInput::Data(vec![byte]))
            .unwrap();
    }
    assert_eq!(
        fragmented.poll_output(),
        Some(StopInitiatorOutput::Outcome(StopInitiatorOutcome::Accepted))
    );

    // STOP STATUS:OK plus one unknown field fills an exact 8 KiB body.
    let mut body = vec![0x08, 0x01, 0x20, 0x64, 0x4a, 0xf9, 0x3f];
    body.resize(MAX_MESSAGE_SIZE, 0xcd);
    let mut exact = StopInitiator::new(peer(), None);
    let _ = exact.poll_output();
    exact
        .handle_input(StopInitiatorInput::Data(encode_frame(&body)))
        .unwrap();
    assert_eq!(
        exact.poll_output(),
        Some(StopInitiatorOutput::Outcome(StopInitiatorOutcome::Accepted))
    );
}
