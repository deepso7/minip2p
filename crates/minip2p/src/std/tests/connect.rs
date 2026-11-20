use super::*;

#[test]
fn connect_races_quic_and_tcp_candidates_on_a_quic_only_endpoint() {
    let mut listener = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind listener");
    let quic_addr = listener.listen().expect("listen");
    let tcp_addr = tcp_peer_addr(*quic_addr.peer_id(), 9);
    let _driver = Driven::new(listener);
    let mut dialer = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind dialer");
    let id = dialer
        .connect(vec![quic_addr.clone(), tcp_addr.clone()])
        .expect("connect");
    let ConnectOutcome::Connected { conn_id, .. } = connect_outcome(&mut dialer, id) else {
        panic!("expected connected");
    };
    let remote = dialer
        .connection_remote_addr(conn_id)
        .expect("remote addr")
        .clone();
    assert!(
        remote == *quic_addr.transport() || remote == *tcp_addr.transport(),
        "remote {remote} must be one of the candidates"
    );
}

#[test]
fn connect_without_a_transport_for_the_address_is_no_usable_route() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind");
    let target = tcp_peer_addr(Ed25519Keypair::generate().peer_id(), 9);
    let id = endpoint.connect(target.clone()).expect("admitted");
    match connect_outcome(&mut endpoint, id) {
        ConnectOutcome::Failed(ConnectFailure::NoUsableRoute { candidates, .. }) => {
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].addr, target);
            assert!(
                candidates[0].reason.contains("Tcp transport"),
                "{}",
                candidates[0].reason
            );
        }
        other => panic!("expected NoUsableRoute, got {other:?}"),
    }
}

#[test]
fn cancel_connect_before_handshake_settles_cancelled() {
    let mut listener = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind listener");
    let addr = listener.listen().expect("listen");
    let _driver = Driven::new(listener);
    let mut dialer = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind dialer");
    let id = dialer.connect(addr).expect("connect");
    dialer.cancel_connect(id);
    assert!(matches!(
        connect_outcome(&mut dialer, id),
        ConnectOutcome::Cancelled
    ));
    assert!(dialer.connected_peers().is_empty());
}

/// A lookup that reports each name it is asked for on `started` and
/// then blocks until the test sends it an answer (or drops the sender).
fn stalling_lookup() -> (
    dial::Lookup,
    std::sync::mpsc::Receiver<String>,
    std::sync::mpsc::Sender<crate::names::Answer>,
) {
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (answer_tx, answer_rx) = std::sync::mpsc::channel::<crate::names::Answer>();
    let answer_rx = std::sync::Mutex::new(answer_rx);
    let lookup: dial::Lookup = Arc::new(move |host: &str| {
        drop(started_tx.send(host.to_string()));
        let answer = answer_rx.lock().expect("lookup lock").recv();
        answer.unwrap_or_else(|_| Err("test ended".to_string()))
    });
    (lookup, started_rx, answer_tx)
}

fn with_lookup(endpoint: &mut Endpoint, lookup: dial::Lookup) {
    let wake = endpoint.platform.poll.wake_handle();
    endpoint.platform.resolver = dial::Resolver::with_lookup(move || wake.wake(), lookup);
}

/// `addr` with its host swapped for the name `host`.
fn named(addr: &PeerAddr, host: &str) -> PeerAddr {
    let mut protocols = addr.transport().protocols().to_vec();
    *protocols.first_mut().expect("a host") = Protocol::Dns(host.to_string());
    PeerAddr::new(Multiaddr::from_protocols(protocols), *addr.peer_id()).expect("named peer addr")
}

#[test]
fn a_stalled_lookup_does_not_hold_up_other_attempts() {
    let mut listener = quic_endpoint();
    let addr = listener.listen().expect("listen");
    let _driver = Driven::new(listener);
    let mut dialer = quic_endpoint();
    let (lookup, started, _answer) = stalling_lookup();
    with_lookup(&mut dialer, lookup);

    let stalled_peer = Ed25519Keypair::generate().peer_id();
    let stalled = dialer
        .connect(named(
            &PeerAddr::new(addr.transport().clone(), stalled_peer).expect("addr"),
            "stalled.invalid",
        ))
        .expect("connect returns without waiting for the lookup");
    assert_eq!(started.recv().expect("lookup started"), "stalled.invalid");

    let id = dialer.connect(addr).expect("connect");
    assert!(matches!(
        connect_outcome(&mut dialer, id),
        ConnectOutcome::Connected { .. }
    ));
    assert!(
        dialer.engine.connect.is_pending(stalled),
        "the stalled attempt is still waiting on its lookup"
    );
}

#[test]
fn an_ip_candidate_dials_while_a_name_in_the_same_attempt_resolves() {
    let mut listener = quic_endpoint();
    let addr = listener.listen().expect("listen");
    let _driver = Driven::new(listener);
    let mut dialer = quic_endpoint();
    let (lookup, _started, _answer) = stalling_lookup();
    with_lookup(&mut dialer, lookup);

    let id = dialer
        .connect(vec![named(&addr, "stalled.invalid"), addr.clone()])
        .expect("connect");
    let ConnectOutcome::Connected { conn_id, .. } = connect_outcome(&mut dialer, id) else {
        panic!("the /ip4 candidate must not wait for the name");
    };
    assert_eq!(
        dialer.connection_remote_addr(conn_id),
        Some(addr.transport())
    );
}

#[test]
fn attempts_naming_one_host_share_a_lookup_and_its_failure() {
    let mut dialer = quic_endpoint();
    let (lookup, started, answer) = stalling_lookup();
    with_lookup(&mut dialer, lookup);
    let peer = Ed25519Keypair::generate().peer_id();
    let target = |text: &str| PeerAddr::new(text.parse().expect("addr"), peer).expect("peer addr");

    let first = dialer
        .connect(target("/dns/gone.invalid/udp/4001/quic-v1"))
        .expect("connect");
    let second = dialer
        .connect(target("/dns4/gone.invalid/udp/4002/quic-v1"))
        .expect("connect");
    assert_eq!(started.recv().expect("lookup started"), "gone.invalid");
    assert!(
        started.recv_timeout(Duration::from_millis(200)).is_err(),
        "the second attempt joined the first lookup"
    );
    answer
        .send(Err("NXDOMAIN".to_string()))
        .expect("lookup waiting");

    // The lookup thread wakes the driver; that is not the caller's
    // interrupt, so `wait` keeps going instead of surfacing it.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut unsettled = vec![first, second];
    while !unsettled.is_empty() {
        match dialer.wait(deadline).expect("wait") {
            EndpointWaitOutcome::Event(EndpointEvent::ConnectSettled {
                connect_id,
                outcome,
                ..
            }) => {
                let ConnectOutcome::Failed(ConnectFailure::NoUsableRoute { candidates, .. }) =
                    outcome
                else {
                    panic!("expected NoUsableRoute, got {outcome:?}");
                };
                assert!(
                    candidates[0].reason.contains("gone.invalid")
                        && candidates[0].reason.contains("NXDOMAIN"),
                    "the reason names the host: {}",
                    candidates[0].reason
                );
                unsettled.retain(|id| *id != connect_id);
            }
            EndpointWaitOutcome::Event(_) => {}
            other => panic!("expected both attempts to settle, got {other:?}"),
        }
    }
}

/// A lookup's wake and an event queued in the same batch both arrive:
/// the event is returned first, the wake stays pending behind it, and
/// neither is lost or reported as the caller's interrupt.
#[test]
fn a_resolver_wake_and_a_queued_event_in_one_batch_both_arrive() {
    let mut dialer = quic_endpoint();
    let (lookup, started, answer) = stalling_lookup();
    with_lookup(&mut dialer, lookup);
    let peer = Ed25519Keypair::generate().peer_id();
    let named_target = PeerAddr::new(
        "/dns/gone.invalid/udp/4001/quic-v1".parse().expect("addr"),
        peer,
    )
    .expect("peer addr");
    let connect_id = dialer.connect(named_target).expect("connect");
    assert_eq!(started.recv().expect("lookup started"), "gone.invalid");

    answer
        .send(Err("NXDOMAIN".to_string()))
        .expect("lookup waiting");
    // Let the lookup thread queue its answer and wake the poll.
    std::thread::sleep(Duration::from_millis(100));
    let other = Ed25519Keypair::generate().peer_id();
    dialer.engine.events.push_back(EndpointEvent::PingFailed {
        peer_id: other,
        conn_id: ConnectionId::new(1),
        cause: minip2p_swarm::PingFailure::TimedOut,
    });

    let (mut settled, mut queued) = (false, false);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !(settled && queued) {
        match dialer.wait(deadline).expect("wait") {
            EndpointWaitOutcome::Event(EndpointEvent::ConnectSettled {
                connect_id: id, ..
            }) if id == connect_id => settled = true,
            EndpointWaitOutcome::Event(EndpointEvent::PingFailed { peer_id, .. })
                if peer_id == other =>
            {
                queued = true;
            }
            EndpointWaitOutcome::Event(_) => {}
            other => panic!("lost something: settled {settled}, queued {queued}: {other:?}"),
        }
    }
}

#[test]
fn cancelling_a_resolving_attempt_is_immediate_and_the_late_answer_is_dropped() {
    let mut listener = quic_endpoint();
    let addr = listener.listen().expect("listen");
    let _driver = Driven::new(listener);
    let mut dialer = quic_endpoint();
    let (lookup, started, answer) = stalling_lookup();
    with_lookup(&mut dialer, lookup);

    let id = dialer
        .connect(named(&addr, "late.invalid"))
        .expect("connect");
    started.recv().expect("lookup started");
    dialer.cancel_connect(id);
    assert!(matches!(
        dialer.poll().expect("poll").as_slice(),
        [EndpointEvent::ConnectSettled {
            connect_id,
            outcome: ConnectOutcome::Cancelled,
            ..
        }] if *connect_id == id
    ));

    // An answer that would reach the live listener, had anything kept it.
    answer
        .send(Ok(vec![std::net::Ipv4Addr::LOCALHOST.into()]))
        .expect("lookup waiting");
    let until = std::time::Instant::now() + Duration::from_millis(500);
    while let Some(event) = dialer.next_event(until).expect("drive") {
        assert!(
            !matches!(
                event,
                EndpointEvent::ConnectSettled { .. } | EndpointEvent::ConnectionEstablished { .. }
            ),
            "the late answer must have no effect, got {event:?}"
        );
    }
    assert!(dialer.connected_peers().is_empty());
}

#[test]
fn an_answer_after_the_deadline_leaves_the_attempt_timed_out() {
    let mut dialer = Endpoint::builder()
        .connect_deadline(Duration::from_millis(50))
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind");
    let (lookup, started, answer) = stalling_lookup();
    with_lookup(&mut dialer, lookup);
    let target = PeerAddr::new(
        "/dns/slow.invalid/udp/4001/quic-v1".parse().expect("addr"),
        Ed25519Keypair::generate().peer_id(),
    )
    .expect("peer addr");

    let id = dialer.connect(target).expect("connect");
    started.recv().expect("lookup started");
    // The answer lands past the deadline but before the next poll: the
    // attempt already ran out of time, so the answer must not decide it.
    std::thread::sleep(Duration::from_millis(100));
    answer
        .send(Err("NXDOMAIN".to_string()))
        .expect("lookup waiting");
    // Give the lookup thread time to queue its answer.
    std::thread::sleep(Duration::from_millis(50));
    match connect_outcome(&mut dialer, id) {
        ConnectOutcome::Failed(ConnectFailure::Timeout { candidates, .. }) => {
            assert!(candidates[0].reason.contains("resolving"), "{candidates:?}");
        }
        other => panic!("expected Timeout, got {other:?}"),
    }
}

#[test]
fn a_dns_candidate_connects_through_the_system_resolver() {
    let mut listener = quic_endpoint();
    let addr = listener.listen().expect("listen");
    let _driver = Driven::new(listener);
    let mut dialer = quic_endpoint();

    let mut protocols = addr.transport().protocols().to_vec();
    *protocols.first_mut().expect("a host") = Protocol::Dns4("localhost".to_string());
    let target = PeerAddr::new(Multiaddr::from_protocols(protocols), *addr.peer_id())
        .expect("named peer addr");
    let id = dialer.connect(target).expect("connect");
    let ConnectOutcome::Connected { conn_id, .. } = connect_outcome(&mut dialer, id) else {
        panic!("localhost must resolve and connect");
    };
    assert_eq!(
        dialer.connection_remote_addr(conn_id),
        Some(addr.transport())
    );
}

#[cfg(feature = "tcp")]
#[test]
fn connect_reaches_quic_when_the_tcp_candidate_is_closed() {
    let mut listener = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind listener");
    let quic_addr = listener.listen().expect("listen");
    let tcp_addr = tcp_peer_addr(*quic_addr.peer_id(), 9);
    let _driver = Driven::new(listener);
    let mut dialer = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic")
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp")
        .bind()
        .expect("bind both");
    let id = dialer
        .connect(vec![quic_addr.clone(), tcp_addr])
        .expect("connect");
    let ConnectOutcome::Connected { conn_id, .. } = connect_outcome(&mut dialer, id) else {
        panic!("expected connected");
    };
    let remote = dialer.connection_remote_addr(conn_id).expect("remote");
    assert_eq!(remote, quic_addr.transport());
}

#[test]
fn wait_delivers_connect_timeout_before_the_caller_deadline() {
    let mut listener = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind listener");
    let addr = listener.listen().expect("listen");
    // Leave the listener undriven so the handshake hangs past the
    // attempt deadline instead of failing immediately.
    let mut dialer = Endpoint::builder()
        .connect_deadline(Duration::from_millis(80))
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind dialer");
    let id = dialer.connect(addr).expect("connect");
    let caller = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match dialer.wait(caller).expect("wait") {
            EndpointWaitOutcome::Event(EndpointEvent::ConnectSettled {
                connect_id,
                outcome: ConnectOutcome::Failed(ConnectFailure::Timeout { .. }),
                ..
            }) if connect_id == id => return,
            EndpointWaitOutcome::Event(_) => {}
            EndpointWaitOutcome::Deadline => {
                panic!("caller deadline beat the connect timeout")
            }
            EndpointWaitOutcome::Interrupted => {}
        }
    }
}
