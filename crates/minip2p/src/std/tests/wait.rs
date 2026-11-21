use super::*;

#[test]
fn wait_reports_deadline_without_swallowing_control_outcomes() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind loopback endpoint");

    assert!(matches!(
        endpoint.wait(Duration::ZERO).expect("wait endpoint"),
        EndpointWaitOutcome::Deadline
    ));
}

/// An `Instant` that has already passed.
fn past_instant() -> std::time::Instant {
    let now = std::time::Instant::now();
    now.checked_sub(Duration::from_secs(1)).unwrap_or(now)
}

#[test]
fn wait_with_a_passed_instant_delivers_a_queued_event() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind loopback endpoint");
    let peer = Ed25519Keypair::generate().peer_id();
    endpoint
        .engine
        .events
        .push_back(EndpointEvent::ConnectionClosed {
            peer_id: peer,
            conn_id: ConnectionId::new(1),
            reason: ConnectionCloseReason::Local,
        });
    assert!(matches!(
        endpoint.wait(past_instant()).expect("wait past deadline"),
        EndpointWaitOutcome::Event(EndpointEvent::ConnectionClosed { peer_id, .. })
            if peer_id == peer
    ));
}

#[test]
fn wait_with_a_passed_instant_drives_a_connect_to_settlement() {
    let mut listener = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind listener");
    let listen_addr = listener.listen().expect("listen");
    let mut dialer = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind dialer");
    let _listener = Driven::new(listener);

    let connect_id = dialer.connect(&listen_addr).expect("connect");
    let stale = past_instant();
    let give_up = std::time::Instant::now() + Duration::from_secs(10);
    let outcome = loop {
        assert!(
            std::time::Instant::now() < give_up,
            "a stale deadline must not stop the connect from settling"
        );
        if let EndpointWaitOutcome::Event(EndpointEvent::ConnectSettled {
            connect_id: settled,
            outcome,
            ..
        }) = dialer.wait(stale).expect("wait past deadline")
            && settled == connect_id
        {
            break outcome;
        }
    };
    assert!(
        matches!(outcome, ConnectOutcome::Connected { .. }),
        "got {outcome:?}"
    );
}

#[test]
fn a_caller_clock_check_ends_a_fixed_deadline_loop_while_events_keep_arriving() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind loopback endpoint");
    let peer = Ed25519Keypair::generate().peer_id();
    let arrive = |endpoint: &mut Endpoint| {
        endpoint
            .engine
            .events
            .push_back(EndpointEvent::ConnectionClosed {
                peer_id: peer,
                conn_id: ConnectionId::new(1),
                reason: ConnectionCloseReason::Local,
            });
    };
    let deadline = std::time::Instant::now() + Duration::from_millis(50);
    loop {
        if std::time::Instant::now() >= deadline {
            break;
        }
        arrive(&mut endpoint);
        assert!(matches!(
            endpoint.wait(deadline).expect("wait"),
            EndpointWaitOutcome::Event(_)
        ));
    }
    assert!(std::time::Instant::now() < deadline + Duration::from_secs(1));
    arrive(&mut endpoint);
    assert!(matches!(
        endpoint.wait(deadline).expect("wait past deadline"),
        EndpointWaitOutcome::Event(_)
    ));
}

#[test]
fn a_pending_interrupt_is_reported_once_even_past_the_deadline() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind loopback endpoint");
    endpoint.wait_handle().interrupt();
    endpoint.wait_handle().interrupt();

    assert!(matches!(
        endpoint.wait(past_instant()).expect("wait past deadline"),
        EndpointWaitOutcome::Interrupted
    ));
    assert!(matches!(
        endpoint.wait(past_instant()).expect("wait past deadline"),
        EndpointWaitOutcome::Deadline
    ));
}

/// A steady stream of host wakes cannot hold a wait past its deadline:
/// it runs at most one batch for them, and newer wakes stay pending.
#[test]
fn a_stream_of_wakes_does_not_hold_a_wait_past_its_deadline() {
    let mut endpoint = quic_endpoint();
    let wake = endpoint.platform.poll.wake_handle();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sent = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let waker = {
        let (stop, sent) = (std::sync::Arc::clone(&stop), std::sync::Arc::clone(&sent));
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                wake.wake();
                sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                std::thread::yield_now();
            }
        })
    };
    while sent.load(std::sync::atomic::Ordering::Relaxed) < 100 {
        std::thread::yield_now();
    }
    let passes = endpoint.engine.stats.capability_passes;
    let outcome = endpoint.wait(past_instant()).expect("wait past deadline");
    let batches = endpoint.engine.stats.capability_passes - passes;
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    waker.join().expect("waker thread");
    assert!(
        matches!(outcome, EndpointWaitOutcome::Deadline),
        "{outcome:?}"
    );
    assert!(batches <= 2, "ran {batches} batches past the deadline");
}

#[cfg(feature = "relay")]
#[test]
fn wait_with_duration_zero_still_drains_queued_events() {
    let mut endpoint = Endpoint::builder()
        .nat_config(super::nat_tests::idle_nat_config())
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind loopback endpoint");
    let peer = Ed25519Keypair::generate().peer_id();
    endpoint
        .engine
        .events
        .push_back(EndpointEvent::ConnectionClosed {
            peer_id: peer,
            conn_id: ConnectionId::new(1),
            reason: ConnectionCloseReason::Local,
        });
    assert!(matches!(
        endpoint.wait(Duration::ZERO).expect("zero-duration drain"),
        EndpointWaitOutcome::Event(EndpointEvent::ConnectionClosed { peer_id, .. })
            if peer_id == peer
    ));
    assert!(
        endpoint.engine.events.is_empty(),
        "Duration::ZERO must drain queued events"
    );
}

#[test]
fn wait_reports_interrupt_without_swallowing_it() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind loopback endpoint");
    endpoint.wait_handle().interrupt();

    assert!(matches!(
        endpoint.wait(WaitDeadline::NEVER).expect("wait endpoint"),
        EndpointWaitOutcome::Interrupted
    ));
}

#[test]
fn wait_delivers_connection_events_once_through_the_endpoint_stream() {
    let mut listener = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind listener");
    let listen_addr = listener.listen().expect("listen");
    let mut dialer = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind dialer");
    let _listener = Driven::new(listener);

    dialer.connect(&listen_addr).expect("connect");
    let peer = *listen_addr.peer_id();

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut established_count = 0u32;
    let mut conn_id = None;
    let mut saw_peer_ready = false;
    while std::time::Instant::now() < deadline {
        match dialer.wait(deadline).expect("wait") {
            EndpointWaitOutcome::Event(EndpointEvent::ConnectionEstablished {
                peer_id,
                conn_id: id,
            }) if peer_id == peer => {
                established_count += 1;
                conn_id = Some(id);
            }
            EndpointWaitOutcome::Event(EndpointEvent::PeerReady { peer_id, .. })
                if peer_id == peer =>
            {
                saw_peer_ready = true;
                break;
            }
            EndpointWaitOutcome::Event(_) | EndpointWaitOutcome::Interrupted => {}
            EndpointWaitOutcome::Deadline => break,
        }
    }
    assert_eq!(
        established_count, 1,
        "ConnectionEstablished must appear exactly once before PeerReady"
    );
    let conn_id = conn_id.expect("dialer saw ConnectionEstablished");
    assert!(saw_peer_ready, "PeerReady follows the single establishment");
    assert_eq!(dialer.connection_id(&peer), Some(conn_id));
    assert!(dialer.connected_peers().contains(&peer));
}

#[test]
fn wait_delivers_peer_ready_through_the_endpoint_stream() {
    let mut listener = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind listener");
    let listen_addr = listener.listen().expect("listen");
    let mut dialer = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind dialer");
    let _listener = Driven::new(listener);

    dialer.connect(&listen_addr).expect("connect");
    let peer = *listen_addr.peer_id();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut ready = false;
    while std::time::Instant::now() < deadline {
        match dialer.wait(deadline).expect("wait") {
            EndpointWaitOutcome::Event(EndpointEvent::PeerReady { peer_id, .. })
                if peer_id == peer =>
            {
                ready = true;
                break;
            }
            EndpointWaitOutcome::Event(_) | EndpointWaitOutcome::Interrupted => {}
            EndpointWaitOutcome::Deadline => break,
        }
    }
    assert!(ready, "PeerReady arrives once through Endpoint::wait");
    assert!(dialer.is_peer_ready(&peer));
    assert!(dialer.peer_info(&peer).is_some());
}

#[test]
fn state_getters_expose_bound_addresses_and_connection_without_driving() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind loopback endpoint");
    let before = endpoint.bound_addresses();
    assert!(
        !before.is_empty(),
        "bound transport addresses are visible before listen/drive"
    );
    let listened = endpoint.listen_all().expect("listen");
    assert_eq!(endpoint.bound_addresses(), before);
    assert_eq!(endpoint.connected_peers(), Vec::<PeerId>::new());
    assert!(endpoint.connection_id(listened[0].peer_id()).is_none());
    assert!(endpoint.peer_info(listened[0].peer_id()).is_none());
    assert!(!endpoint.is_peer_ready(listened[0].peer_id()));
}

#[cfg(feature = "relay")]
#[test]
fn wait_delivers_queued_nat_events_once() {
    let mut endpoint = Endpoint::builder()
        .nat_config(super::nat_tests::idle_nat_config())
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind NAT endpoint");
    endpoint
        .engine
        .nat
        .as_mut()
        .expect("NAT configured")
        .push_event(NatEvent::ReachabilityChanged {
            old: ReachabilityState::Unknown,
            new: ReachabilityState::Private,
            confirmed_addrs: Vec::new(),
        });

    assert!(matches!(
        endpoint.wait(Duration::ZERO).expect("wait"),
        EndpointWaitOutcome::Event(EndpointEvent::Nat(NatEvent::ReachabilityChanged { .. }))
    ));
    assert!(matches!(
        endpoint.wait(Duration::ZERO).expect("wait"),
        EndpointWaitOutcome::Deadline
    ));
}

#[cfg(feature = "pubsub")]
#[test]
fn wait_delivers_queued_gossipsub_events_as_endpoint_events() {
    let mut endpoint = Endpoint::builder()
        .gossipsub()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind pubsub endpoint");
    let peer = Ed25519Keypair::generate().peer_id();
    endpoint
        .engine
        .gossipsub
        .as_mut()
        .expect("pubsub configured")
        .events
        .push_back(GossipsubEvent::PeerSubscribed {
            peer,
            topic: "test".into(),
        });

    assert!(matches!(
        endpoint.wait(Duration::ZERO).expect("wait"),
        EndpointWaitOutcome::Event(EndpointEvent::Gossipsub(GossipsubEvent::PeerSubscribed {
            peer: returned,
            topic,
        })) if returned == peer && topic == "test"
    ));
}

#[cfg(all(feature = "relay", feature = "pubsub", feature = "relay-server"))]
#[test]
fn capability_events_leave_once_in_endpoint_order() {
    let mut endpoint = Endpoint::builder()
        .nat_config(super::nat_tests::idle_nat_config())
        .gossipsub()
        .relay_server()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind capability endpoint");
    let peer = Ed25519Keypair::generate().peer_id();
    endpoint
        .engine
        .gossipsub
        .as_mut()
        .unwrap()
        .events
        .push_back(GossipsubEvent::PeerSubscribed {
            peer,
            topic: "test".into(),
        });
    let nat = endpoint.engine.nat.as_mut().unwrap();
    nat.push_event(NatEvent::FellBackToRelay {
        connect_id: ConnectId::from_u64(99),
        peer,
        reason: minip2p_nat::UpgradeStop::PunchFailed { rounds: 3 },
    });
    nat.push_event(NatEvent::ReachabilityChanged {
        old: ReachabilityState::Unknown,
        new: ReachabilityState::Private,
        confirmed_addrs: Vec::new(),
    });
    endpoint
        .engine
        .relay_server
        .as_mut()
        .unwrap()
        .events
        .push_back(RelayServerEvent::Error(RelayServerRuntimeError {
            kind: RelayServerRuntimeErrorKind::InternalInvariant,
            peer_id: None,
            detail: "test diagnostic".into(),
        }));

    let settled_id = endpoint
        .connect(Ed25519Keypair::generate().peer_id())
        .expect("admit route-less connect");

    let events = endpoint.poll().expect("poll");
    let order: Vec<&str> = events
        .iter()
        .filter_map(|event| match event {
            EndpointEvent::RelayServer(_) => Some("relay-server"),
            EndpointEvent::Nat(_) => Some("nat"),
            EndpointEvent::Gossipsub(_) => Some("gossipsub"),
            EndpointEvent::ConnectSettled { connect_id, .. } if *connect_id == settled_id => {
                Some("settled")
            }
            _ => None,
        })
        .collect();
    assert_eq!(order, ["relay-server", "nat", "gossipsub", "settled"]);
}

#[cfg(feature = "relay")]
#[test]
fn wait_honors_expired_deadline_with_active_driver() {
    let mut endpoint = Endpoint::builder()
        .nat_config(super::nat_tests::idle_nat_config())
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind NAT endpoint");

    assert!(matches!(
        endpoint.wait(Duration::ZERO).expect("expired wait"),
        EndpointWaitOutcome::Deadline
    ));
}

#[cfg(feature = "relay")]
#[test]
fn wait_returns_application_event_produced_during_driver_poll() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let mut endpoint = Endpoint::builder()
        .nat_config(super::nat_tests::idle_nat_config())
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind driven endpoint");
    let mut remote = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind remote endpoint");
    endpoint.listen().expect("driven endpoint listens");
    let remote_addr = remote.listen().expect("remote listens");

    let stop = Arc::new(AtomicBool::new(false));
    let remote_stop = Arc::clone(&stop);
    let remote_thread = std::thread::spawn(move || {
        while !remote_stop.load(Ordering::Relaxed) {
            remote
                .next_event(Duration::from_millis(20))
                .expect("drive remote");
        }
    });

    endpoint.connect(&remote_addr).expect("connect to remote");
    let wake = endpoint
        .wait(Duration::from_secs(5))
        .expect("wait for application event");
    stop.store(true, Ordering::Relaxed);
    remote_thread.join().expect("remote driver exits");

    assert!(matches!(
        wake,
        EndpointWaitOutcome::Event(EndpointEvent::ConnectionEstablished { peer_id, .. })
            if peer_id == *remote_addr.peer_id()
    ));
}

/// A step's first event is often `ConnectionEstablished`, with the NAT
/// path and `ConnectSettled` behind it. `wait` must hand them out in that
/// order: the terminal never overtakes the connection it reports.
#[cfg(feature = "relay")]
#[test]
fn nat_path_and_connect_settled_follow_connection_established() {
    let mut endpoint = Endpoint::builder()
        .nat_config(super::nat_tests::idle_nat_config())
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind NAT endpoint");
    let mut remote = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind remote endpoint");
    endpoint.listen().expect("NAT endpoint listens");
    let remote_addr = remote.listen().expect("remote listens");
    let _remote = Driven::new(remote);

    let connect_id = endpoint.connect(&remote_addr).expect("connect");
    let mut events = Vec::new();
    wait_for(&mut endpoint, "connect settled", |event| {
        events.push(format!("{event:?}"));
        matches!(event, EndpointEvent::ConnectSettled { connect_id: id, .. } if *id == connect_id)
    });
    let position = |needle: &str| events.iter().position(|event| event.contains(needle));
    match (
        position("ConnectionEstablished"),
        position("PathEstablished"),
        position("ConnectSettled"),
    ) {
        (Some(established), Some(path), Some(settled)) => assert!(
            established < path && path < settled,
            "expected ConnectionEstablished, PathEstablished, ConnectSettled: {events:?}"
        ),
        _ => panic!("missing connection, path, or terminal event: {events:?}"),
    }
}

#[cfg(feature = "relay")]
#[test]
fn wait_delivers_connect_timeout_with_an_active_driver() {
    use std::net::{IpAddr, Ipv4Addr};

    let mut endpoint = Endpoint::builder()
        .connect_deadline(Duration::from_millis(20))
        .nat_config(super::nat_tests::idle_nat_config())
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind NAT endpoint");
    let unreachable = PeerAddr::quic_v1(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        9,
        Ed25519Keypair::generate().peer_id(),
    );
    let id = endpoint.connect(&unreachable).expect("start timed connect");

    let wake = endpoint
        .wait(Duration::from_secs(1))
        .expect("wait for connect deadline");
    match wake {
        EndpointWaitOutcome::Event(EndpointEvent::ConnectSettled {
            connect_id,
            outcome: ConnectOutcome::Failed(ConnectFailure::Timeout { .. }),
            ..
        }) => assert_eq!(connect_id, id),
        other => panic!("expected ConnectSettled Timeout, got {other:?}"),
    }
}
