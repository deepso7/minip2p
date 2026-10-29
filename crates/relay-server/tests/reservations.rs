//! Reservation lifecycle, HOP stream admission, address selection, and the
//! admission limits that apply to reservations.

mod common;

use common::{
    Call, Node, at, closes, connect_request, key, maddr, peer, reserve_request, resets, sends_on,
    unlimited_rates, without_acks,
};
use minip2p_core::platform::{Deadline, Now};
use minip2p_core::{Multiaddr, PeerId, Protocol};
use minip2p_relay::{FrameDecode, HopMessage, MAX_MESSAGE_SIZE, decode_frame};
use minip2p_relay_server::{
    RateLimit, RelayServerAddrSource, RelayServerAddressError, RelayServerConfig, RelayServerEvent,
    RelayServerRuntimeError, RelayServerRuntimeErrorKind, ReservationCloseReason, Status,
    StreamKey,
};
use minip2p_transport::ConnectionId;

fn no_rate_limits() -> RelayServerConfig {
    RelayServerConfig {
        reservation_rate_limit_per_peer: None,
        reservation_rate_limit_per_ip: None,
        ..RelayServerConfig::default()
    }
}

/// The HOP message in the one reply written on `stream`.
#[expect(clippy::panic, reason = "the helper requires one framed HOP reply")]
fn reply_on(calls: &[Call], stream: StreamKey) -> HopMessage {
    let sends = sends_on(calls, stream);
    let [send] = &sends[..] else {
        panic!("one reply on {stream:?}: {calls:?}");
    };
    let FrameDecode::Complete { payload, consumed } = decode_frame(send) else {
        panic!("a framed HOP reply");
    };
    assert!(payload.len() <= MAX_MESSAGE_SIZE && consumed == send.len());
    HopMessage::decode(payload).expect("a HOP message")
}

#[test]
fn a_reservation_commits_once_its_success_reply_is_taken() {
    let remote = peer(b"client");
    let stream = key(1, 2);
    let mut node = Node::new(RelayServerConfig::default());
    let now = Now::new(10, 1_000);
    node.handle_event(
        &minip2p_swarm::SwarmEvent::ConnectionEstablished {
            peer_id: remote.clone(),
            conn_id: stream.conn_id,
        },
        false,
        now,
    );
    node.hop_ready(&remote, stream, now);
    let request = minip2p_relay::encode_frame(&reserve_request().encode());
    node.data(&remote, stream, &request, now);

    let reply = reply_on(&node.calls(), stream);
    assert_eq!(reply.status, Some(Status::Ok));
    assert!(matches!(
        node.events()[..],
        [RelayServerEvent::ReservationAccepted {
            ref peer_id,
            renewed: false,
            expires_unix_secs: Some(4_600),
        }] if *peer_id == remote
    ));
    assert_eq!(node.reservation_connection(&remote), Some(stream.conn_id));
}

#[test]
fn a_failed_reply_creates_no_reservation_and_resets_without_a_fin() {
    let remote = peer(b"client-failed-response");
    let stream = key(31, 1);
    let mut node = Node::new(no_rate_limits());
    node.establish(&remote, stream.conn_id);
    node.swarm.failing_sends.insert(stream);
    node.feed_hop(&remote, stream, reserve_request(), &[]);

    assert_eq!(node.reservation_count(), 0);
    assert!(matches!(
        node.events()[..],
        [RelayServerEvent::Error(RelayServerRuntimeError {
            kind: RelayServerRuntimeErrorKind::SendStream,
            ..
        })]
    ));
    let calls = node.calls();
    assert_eq!(resets(&calls), [stream]);
    assert!(closes(&calls).is_empty(), "{calls:?}");
    // The stream stays the relay's until it closes.
    assert!(node.owns_stream(stream));
    assert!(node.stream_closed(&remote, stream, at(1)));
    assert!(!node.owns_stream(stream));
}

/// A reply the stream takes only part of is reset, never half-closed, and
/// the responder's FIN queued behind it never runs: the peer must not read a
/// truncated reply as complete.
#[test]
fn a_partly_written_control_reply_resets_instead_of_finishing() {
    let remote = peer(b"client-full-response");
    let stream = key(31, 1);
    let mut node = Node::new(RelayServerConfig::default());
    node.establish(&remote, stream.conn_id);
    node.swarm.credit.insert(stream, 1);
    // CONNECT to a peer with no reservation: the reply is a rejection
    // followed by a half-close.
    node.feed_hop(&remote, stream, connect_request(&peer(b"absent")), &[]);

    let calls = without_acks(node.calls());
    assert!(
        matches!(
            calls[..],
            [Call::Send { stream: sent, accepted: 1, .. }, Call::Reset { stream: reset, .. }]
                if sent == stream && reset == stream
        ),
        "a truncated reply must not end in a clean FIN: {calls:?}"
    );
    // Later reads are claimed and consumed, and drive nothing.
    assert!(node.data(&remote, stream, b"late", at(1)));
    assert_eq!(node.calls(), [Call::Ack { stream, bytes: 4 }]);
}

#[test]
fn reservation_expires_at_exact_monotonic_deadline_once() {
    let remote = peer(b"client-expiry");
    let mut node = Node::new(RelayServerConfig {
        reservation_duration_secs: 1,
        ..no_rate_limits()
    });
    node.reserve(&remote, key(32, 1));

    node.handle_tick(at(999));
    assert!(node.reservation_connection(&remote).is_some());
    node.handle_tick(at(1_000));
    assert!(matches!(
        node.events()[..],
        [RelayServerEvent::ReservationClosed {
            ref peer_id,
            reason: ReservationCloseReason::Expired,
        }] if *peer_id == remote
    ));
    node.handle_tick(at(2_000));
    assert!(node.events().is_empty());
}

#[test]
fn same_time_events_expire_control_streams_before_the_first_event() {
    let remote = peer(b"peer-same-timeout");
    let mut node = Node::new(RelayServerConfig {
        control_stream_timeout_ms: 5,
        ..RelayServerConfig::default()
    });
    let stream = key(34, 1);
    node.establish(&remote, stream.conn_id);
    node.hop_ready(&remote, stream, at(0));

    let first = minip2p_swarm::SwarmEvent::ConnectionEstablished {
        peer_id: peer(b"first-at-deadline"),
        conn_id: ConnectionId::new(35),
    };
    let second = minip2p_swarm::SwarmEvent::ConnectionEstablished {
        peer_id: peer(b"second-at-deadline"),
        conn_id: ConnectionId::new(36),
    };
    node.handle_event(&first, false, at(5));
    assert!(!node.owns_stream(stream));
    node.handle_event(&second, false, at(5));

    assert_eq!(resets(&node.calls()), [stream]);
}

#[test]
fn paused_reservation_is_denied_without_consuming_capacity() {
    let remote = peer(b"client-paused");
    let mut node = Node::new(RelayServerConfig::default());
    node.set_accepting(false);
    let stream = key(33, 1);
    node.establish(&remote, stream.conn_id);
    node.feed_hop(&remote, stream, reserve_request(), &[]);

    assert!(matches!(
        node.events()[..],
        [RelayServerEvent::ReservationDenied {
            ref peer_id,
            status: Status::ReservationRefused,
        }] if *peer_id == remote
    ));
    assert_eq!(node.reservation_count(), 0);
}

/// A renewal whose reply fails keeps the reservation it would have
/// replaced, even at full capacity.
#[test]
fn a_failed_renewal_keeps_the_reservation_at_full_capacity() {
    let remote = peer(b"client-renewal");
    let mut node = Node::new(RelayServerConfig {
        max_reservations: 1,
        ..no_rate_limits()
    });
    node.reserve(&remote, key(34, 1));
    let renewal = key(34, 2);
    node.swarm.failing_sends.insert(renewal);
    node.feed_hop(&remote, renewal, reserve_request(), &[]);

    assert_eq!(node.reservation_connection(&remote), Some(renewal.conn_id));
    assert_eq!(node.reservation_count(), 1);
}

#[test]
fn renewal_spends_no_rate_token() {
    let remote = peer(b"client-renewal-token");
    let mut node = Node::new(RelayServerConfig {
        reservation_rate_limit_per_peer: Some(RateLimit {
            capacity: 1,
            refill_interval_ms: 1_000_000,
        }),
        reservation_rate_limit_per_ip: None,
        ..RelayServerConfig::default()
    });
    node.reserve(&remote, key(343, 1));
    for stream_id in [2, 3] {
        node.feed_hop(&remote, key(343, stream_id), reserve_request(), &[]);
        assert!(matches!(
            node.events()[..],
            [RelayServerEvent::ReservationAccepted { renewed: true, .. }]
        ));
    }
}

/// A RESERVE refused because the relay is full spends no rate-limit token:
/// once there is room, the same peer is admitted.
#[test]
fn a_reservation_refused_for_capacity_spends_no_rate_token() {
    let mut node = Node::new(RelayServerConfig {
        max_reservations: 1,
        reservation_rate_limit_per_peer: Some(RateLimit {
            capacity: 1,
            refill_interval_ms: 1_000_000,
        }),
        reservation_rate_limit_per_ip: None,
        ..RelayServerConfig::default()
    });
    let holder = peer(b"holder-full-token");
    let holder_conn = ConnectionId::new(350);
    node.reserve(&holder, key(350, 1));

    let waiter = peer(b"waiter-full-token");
    node.establish(&waiter, ConnectionId::new(351));
    node.feed_hop(&waiter, key(351, 1), reserve_request(), &[]);
    assert!(matches!(
        node.events()[..],
        [RelayServerEvent::ReservationDenied {
            status: Status::ResourceLimitExceeded,
            ..
        }]
    ));

    // The holder leaves, freeing the only slot.
    node.close_connection(&holder, holder_conn, 0);
    node.events();
    node.feed_hop(&waiter, key(351, 2), reserve_request(), &[]);
    let events = node.events();
    assert!(
        matches!(events[..], [RelayServerEvent::ReservationAccepted { .. }]),
        "the waiter still holds its token: {events:?}"
    );
}

#[test]
fn direct_replacement_rebinds_reservation_with_its_original_expiry() {
    let remote = peer(b"client-replace");
    let mut node = Node::new(RelayServerConfig {
        reservation_duration_secs: 1,
        ..no_rate_limits()
    });
    node.reserve(&remote, key(35, 1));
    let new = ConnectionId::new(36);
    node.replace(&remote, ConnectionId::new(35), new, false, 500);
    assert_eq!(node.reservation_connection(&remote), Some(new));
    assert!(node.events().is_empty());

    // A stale close for the old connection cannot touch the rebound reservation.
    node.close_connection(&remote, ConnectionId::new(35), 500);
    assert_eq!(node.reservation_connection(&remote), Some(new));

    node.handle_tick(at(1_000));
    assert!(matches!(
        node.events()[..],
        [RelayServerEvent::ReservationClosed {
            reason: ReservationCloseReason::Expired,
            ..
        }]
    ));
}

#[test]
fn circuit_replacement_closes_reservation() {
    let remote = peer(b"client-replace");
    let mut node = Node::new(no_rate_limits());
    node.reserve(&remote, key(35, 1));
    node.replace(
        &remote,
        ConnectionId::new(35),
        ConnectionId::new(36),
        true,
        1,
    );
    assert_eq!(node.reservation_count(), 0);
    assert!(matches!(
        node.events()[..],
        [RelayServerEvent::ReservationClosed {
            ref peer_id,
            reason: ReservationCloseReason::ConnectionClosed,
        }] if *peer_id == remote
    ));
}

#[test]
fn address_sources_use_first_non_empty_and_invalid_replacement_is_atomic() {
    let mut node = Node::unannounced(RelayServerConfig::default());
    let listener = maddr("/ip4/192.0.2.1/tcp/1");
    let confirmed = maddr("/ip4/192.0.2.2/tcp/2");
    let explicit = maddr("/ip4/192.0.2.3/tcp/3");
    node.set_listener_addrs(vec![listener.clone()]).unwrap();
    assert_eq!(node.selected_addrs(), [listener]);
    node.set_confirmed_addrs(vec![confirmed.clone()]).unwrap();
    assert_eq!(node.selected_addrs(), core::slice::from_ref(&confirmed));
    node.replace_announce_addrs(vec![explicit.clone()]).unwrap();
    assert_eq!(node.selected_addrs(), core::slice::from_ref(&explicit));

    assert!(
        node.replace_announce_addrs(vec![maddr("/ip4/0.0.0.0/tcp/9")])
            .is_err()
    );
    assert_eq!(node.selected_addrs(), [explicit]);
    node.replace_announce_addrs(Vec::new()).unwrap();
    assert_eq!(node.selected_addrs(), [confirmed]);
}

/// Refreshes `source` with one address, returning its rejection.
fn refresh(
    node: &mut Node,
    source: RelayServerAddrSource,
    addr: &str,
) -> Option<RelayServerAddressError> {
    let addrs = vec![maddr(addr)];
    match source {
        RelayServerAddrSource::Listener => node.set_listener_addrs(addrs),
        RelayServerAddrSource::Confirmed => node.set_confirmed_addrs(addrs),
    }
    .err()
}

#[test]
fn rejected_refresh_keeps_prior_addrs_and_reports_failure_transitions() {
    for source in [
        RelayServerAddrSource::Listener,
        RelayServerAddrSource::Confirmed,
    ] {
        let mut node = Node::unannounced(RelayServerConfig::default());
        let good = maddr("/ip4/192.0.2.1/tcp/1");
        assert_eq!(refresh(&mut node, source, "/ip4/192.0.2.1/tcp/1"), None);
        assert!(node.events().is_empty());

        let error = refresh(&mut node, source, "/ip4/0.0.0.0/tcp/9").unwrap();
        assert_eq!(node.selected_addrs(), core::slice::from_ref(&good));
        assert_eq!(
            node.events(),
            [RelayServerEvent::AddrsRejected { source, error }]
        );
        refresh(&mut node, source, "/ip4/0.0.0.0/tcp/9").unwrap();
        assert!(node.events().is_empty());

        // A different error while failing is news.
        let error = refresh(&mut node, source, "/ip4/192.0.2.1/udp/1").unwrap();
        assert_eq!(
            node.events(),
            [RelayServerEvent::AddrsRejected { source, error }]
        );
        assert_eq!(node.selected_addrs(), core::slice::from_ref(&good));

        assert_eq!(refresh(&mut node, source, "/ip4/192.0.2.2/tcp/2"), None);
        assert_eq!(node.events(), [RelayServerEvent::AddrsRestored { source }]);
        assert_eq!(refresh(&mut node, source, "/ip4/192.0.2.3/tcp/3"), None);
        assert!(node.events().is_empty());
    }
}

#[test]
fn address_sources_fail_and_restore_independently() {
    use RelayServerAddrSource::{Confirmed, Listener};
    let mut node = Node::unannounced(RelayServerConfig::default());
    refresh(&mut node, Listener, "/ip4/0.0.0.0/tcp/1").unwrap();
    assert_eq!(refresh(&mut node, Confirmed, "/ip4/192.0.2.2/tcp/2"), None);
    assert!(matches!(
        node.events()[..],
        [RelayServerEvent::AddrsRejected {
            source: Listener,
            ..
        }]
    ));

    refresh(&mut node, Confirmed, "/ip4/0.0.0.0/tcp/2").unwrap();
    assert_eq!(refresh(&mut node, Listener, "/ip4/192.0.2.1/tcp/1"), None);
    refresh(&mut node, Confirmed, "/ip4/0.0.0.0/tcp/2").unwrap();
    assert!(matches!(
        node.events()[..],
        [
            RelayServerEvent::AddrsRejected {
                source: Confirmed,
                ..
            },
            RelayServerEvent::AddrsRestored { source: Listener },
        ]
    ));
}

#[test]
fn hop_over_circuit_negotiates_then_denies_with_permission_status() {
    let remote = peer(b"client-circuit-hop");
    let stream = key(37, 1);
    let mut node = Node::new(RelayServerConfig::default());
    node.establish_as(&remote, stream.conn_id, true);
    node.feed_hop(&remote, stream, reserve_request(), &[]);

    assert!(matches!(
        node.events()[..],
        [RelayServerEvent::ReservationDenied {
            ref peer_id,
            status: Status::PermissionDenied,
        }] if *peer_id == remote
    ));
    assert_eq!(
        reply_on(&node.calls(), stream).status,
        Some(Status::PermissionDenied)
    );
}

#[test]
fn finished_hop_streams_left_open_still_count_against_the_connection_cap() {
    let remote = peer(b"client-hop-leak");
    let conn_id = ConnectionId::new(39);
    let mut node = Node::new(RelayServerConfig {
        max_pending_hop_requests_per_connection: 2,
        ..RelayServerConfig::default()
    });
    node.establish(&remote, conn_id);

    // Two HOP exchanges run to completion, and the peer never closes either
    // stream, so both workers stay to claim their streams' events.
    for stream_id in [1, 2] {
        let stream = key(39, stream_id);
        node.feed_hop(&remote, stream, reserve_request(), &[]);
        assert!(node.owns_stream(stream));
    }
    node.calls();

    // A third must be refused. Counting only the workers still waiting on a
    // reply would let a peer that never closes its streams open one per
    // muxer slot, on every connection it holds.
    let third = key(39, 3);
    assert!(node.hop_ready(&remote, third, at(0)));
    assert_eq!(resets(&node.calls()), [third]);
}

#[test]
fn hop_cap_stream_is_owned_until_its_terminal_event() {
    let remote = peer(b"client-hop-cap");
    let stream = key(38, 1);
    let mut node = Node::new(RelayServerConfig {
        max_pending_hop_requests_per_connection: 0,
        ..RelayServerConfig::default()
    });
    node.establish(&remote, stream.conn_id);

    assert!(node.hop_ready(&remote, stream, at(0)));
    assert!(node.owns_stream(stream));
    assert_eq!(resets(&node.calls()), [stream]);

    assert!(node.stream_closed(&remote, stream, at(1)));
    assert!(!node.owns_stream(stream));
}

#[test]
fn accepted_reservation_disarms_its_hop_control_timeout() {
    let remote = peer(b"client-disarm");
    let mut node = Node::new(RelayServerConfig {
        control_stream_timeout_ms: 5,
        ..no_rate_limits()
    });
    node.reserve(&remote, key(39, 1));

    node.handle_tick(at(5));

    assert!(node.reservation_connection(&remote).is_some());
    assert!(node.calls().is_empty());
    assert!(node.events().is_empty());
}

/// Connects `peer` on `conn_id` from `address` and sends RESERVE. Returns
/// whether the relay committed it, or the denial status.
#[expect(
    clippy::panic,
    clippy::panic_in_result_fn,
    reason = "a test helper whose Err is the relay's denial, not a failure"
)]
fn request_reservation(
    node: &mut Node,
    peer: &PeerId,
    conn_id: ConnectionId,
    address: &str,
) -> Result<(), Status> {
    node.establish_from(peer, conn_id, address);
    node.feed_hop(peer, key(conn_id.as_u64(), 1), reserve_request(), &[]);
    node.calls();
    match &node.events()[..] {
        [RelayServerEvent::ReservationAccepted { .. }] => Ok(()),
        [RelayServerEvent::ReservationDenied { status, .. }] => Err(*status),
        other => panic!("expected a decision for {address}, got {other:?}"),
    }
}

#[test]
fn reservation_ip_limit_uses_the_first_ip_on_the_exact_connection() {
    let mut node = Node::new(RelayServerConfig {
        reservation_rate_limit_per_peer: None,
        reservation_rate_limit_per_ip: Some(RateLimit {
            capacity: 1,
            refill_interval_ms: 1_000,
        }),
        ..RelayServerConfig::default()
    });
    for (index, tail) in [[198, 51, 100, 1], [198, 51, 100, 2]]
        .into_iter()
        .enumerate()
    {
        let address = Multiaddr::from_protocols(vec![
            Protocol::Ip4([203, 0, 113, 9]),
            Protocol::Tcp(4001),
            Protocol::Ip4(tail),
        ]);
        let result = request_reservation(
            &mut node,
            &peer(&[b'p', index as u8]),
            ConnectionId::new(90 + index as u64),
            &address.to_string(),
        );
        if index == 0 {
            assert_eq!(result, Ok(()), "the first IP's token admits");
        } else {
            assert_eq!(result, Err(Status::ResourceLimitExceeded));
        }
    }
}

#[test]
fn ipv4_mapped_ipv6_shares_the_ipv4_rate_limit_bucket() {
    let mut node = Node::new(RelayServerConfig {
        reservation_rate_limit_per_peer: None,
        reservation_rate_limit_per_ip: Some(RateLimit {
            capacity: 1,
            refill_interval_ms: 1_000,
        }),
        ..RelayServerConfig::default()
    });
    let addresses = ["/ip4/203.0.113.9/tcp/1", "/ip6/::ffff:203.0.113.9/tcp/1"];
    for (index, address) in addresses.into_iter().enumerate() {
        let result = request_reservation(
            &mut node,
            &peer(&[b'm', index as u8]),
            ConnectionId::new(95 + index as u64),
            address,
        );
        if index == 0 {
            assert_eq!(result, Ok(()), "the IPv4 request is admitted");
        } else {
            assert_eq!(result, Err(Status::ResourceLimitExceeded));
        }
    }
}

#[test]
fn reservation_addresses_truncate_to_a_wire_prefix_and_empty_refuses() {
    let local = peer(b"relay");
    let addrs: Vec<_> = (0..160)
        .map(|index| {
            maddr(&format!(
                "/dns4/{index}.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example/tcp/4001"
            ))
        })
        .collect();
    let mut node = Node::unannounced(no_rate_limits());
    node.replace_announce_addrs(addrs.clone()).unwrap();
    let remote = peer(b"truncated-address-client");
    let stream = key(99, 1);
    node.establish(&remote, stream.conn_id);
    node.feed_hop(&remote, stream, reserve_request(), &[]);
    let reservation = reply_on(&node.calls(), stream)
        .reservation
        .expect("a reservation");
    assert!(!reservation.addrs.is_empty());
    assert!(reservation.addrs.len() < addrs.len());
    assert_eq!(reservation.voucher, None);
    let expected: Vec<_> = addrs
        .iter()
        .take(reservation.addrs.len())
        .map(|address| {
            let mut address = address.clone();
            address.push(Protocol::P2p(local.clone()));
            address.to_bytes()
        })
        .collect();
    assert_eq!(reservation.addrs, expected);

    let remote = peer(b"empty-address-client");
    let stream = key(100, 1);
    let mut empty = Node::unannounced(RelayServerConfig::default());
    empty.establish(&remote, stream.conn_id);
    empty.feed_hop(&remote, stream, reserve_request(), &[]);
    assert!(matches!(
        empty.events()[..],
        [RelayServerEvent::ReservationDenied {
            status: Status::ReservationRefused,
            ..
        }]
    ));
}

#[test]
fn zero_circuit_limits_are_advertised_as_zero() {
    let mut node = Node::new(RelayServerConfig {
        max_circuit_duration_secs: 0,
        max_circuit_bytes: 0,
        ..no_rate_limits()
    });
    let remote = peer(b"zero-limit-client");
    let stream = key(101, 1);
    node.establish(&remote, stream.conn_id);
    node.feed_hop(&remote, stream, reserve_request(), &[]);
    let limit = reply_on(&node.calls(), stream).limit.expect("a limit");
    assert_eq!(limit.duration, Some(0));
    assert_eq!(limit.data, Some(0));
}

#[test]
fn next_deadline_reports_the_absolute_reservation_expiry() {
    let mut node = Node::new(RelayServerConfig {
        reservation_duration_secs: 1,
        ..RelayServerConfig::default()
    });
    assert_eq!(node.next_deadline(at(0)), None);

    let remote = peer(b"client-deadline");
    node.reserve(&remote, key(350, 1));
    let due = Deadline::from_millis(1_000);
    assert_eq!(node.next_deadline(at(0)), Some(due));
    assert!(due.is_expired_at(at(1_000)));

    let overdue = at(5_000);
    assert_eq!(
        node.next_deadline(overdue),
        Some(due),
        "an overdue timer keeps its past due time"
    );
    node.handle_tick(overdue);
    assert_eq!(node.reservation_count(), 0);
}

#[test]
fn a_failed_renewal_keeps_the_old_deadline() {
    let mut node = Node::new(RelayServerConfig {
        reservation_duration_secs: 1,
        ..RelayServerConfig::default()
    });
    let remote = peer(b"client-renewal-failed");
    node.reserve(&remote, key(352, 1));
    let renewal = key(352, 2);
    node.swarm.failing_sends.insert(renewal);
    node.hop_ready(&remote, renewal, at(500));
    node.data(
        &remote,
        renewal,
        &minip2p_relay::encode_frame(&reserve_request().encode()),
        at(500),
    );
    assert!(matches!(
        node.events()[..],
        [RelayServerEvent::Error(RelayServerRuntimeError {
            kind: RelayServerRuntimeErrorKind::SendStream,
            ..
        })]
    ));

    node.handle_tick(at(1_000));
    assert!(matches!(
        node.events()[..],
        [RelayServerEvent::ReservationClosed {
            reason: ReservationCloseReason::Expired,
            ..
        }]
    ));
    assert_eq!(node.reservation_count(), 0);
}

#[test]
fn ninth_reservation_from_one_ipv4_address_or_ipv6_slash_64_is_refused() {
    let cases = [
        ("/ip4/198.51.100.7/tcp/{}", "/ip4/198.51.100.8/tcp/1"),
        ("/ip6/2001:db8:1:2::{}/tcp/1", "/ip6/2001:db8:1:3::1/tcp/1"),
    ];
    for (shared, other) in cases {
        let mut node = Node::new(unlimited_rates());
        for index in 0..8u8 {
            let address = shared.replace("{}", &(index + 1).to_string());
            request_reservation(
                &mut node,
                &peer(&[b'r', index]),
                ConnectionId::new(index.into()),
                &address,
            )
            .expect("within the per-IP cap");
        }
        let address = shared.replace("{}", "9");
        assert_eq!(
            request_reservation(&mut node, &peer(b"ninth"), ConnectionId::new(9), &address),
            Err(Status::ResourceLimitExceeded),
            "{shared}"
        );
        request_reservation(&mut node, &peer(b"elsewhere"), ConnectionId::new(10), other)
            .expect("another key keeps its own slots");
    }
}

#[test]
fn a_full_rate_limiter_map_refuses_a_new_peer() {
    let mut node = Node::new(RelayServerConfig {
        max_rate_limit_entries: 1,
        ..RelayServerConfig::default()
    });
    let address = "/ip4/198.51.100.7/tcp/1";
    request_reservation(&mut node, &peer(b"first"), ConnectionId::new(1), address)
        .expect("admitted");
    assert_eq!(
        request_reservation(&mut node, &peer(b"second"), ConnectionId::new(2), address),
        Err(Status::ResourceLimitExceeded)
    );
}
