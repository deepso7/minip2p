use super::*;

/// A transport with nothing to do whose `poll` fails while `fail` is set.
struct FlakyPollTransport {
    fail: Arc<AtomicBool>,
}

impl Transport for FlakyPollTransport {
    fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
        Err(TransportError::Unsupported { operation: "dial" })
    }
    fn listen(&mut self, _: &Multiaddr) -> Result<Multiaddr, TransportError> {
        Err(TransportError::Unsupported {
            operation: "listen",
        })
    }
    fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
        Err(TransportError::Unsupported {
            operation: "open stream",
        })
    }
    fn send_stream(
        &mut self,
        _: ConnectionId,
        _: StreamId,
        _: Bytes,
    ) -> Result<(), TransportError> {
        Err(TransportError::Unsupported {
            operation: "send stream",
        })
    }
    fn close_stream_write(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Err(TransportError::Unsupported {
            operation: "close stream write",
        })
    }
    fn reset_stream(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Err(TransportError::Unsupported {
            operation: "reset stream",
        })
    }
    fn ack_stream(&mut self, _: ConnectionId, _: StreamId, _: usize) -> Result<(), TransportError> {
        Ok(())
    }
    fn close(&mut self, _: ConnectionId) -> Result<(), TransportError> {
        Err(TransportError::Unsupported {
            operation: "close connection",
        })
    }
    fn poll(
        &mut self,
        _: minip2p_core::platform::Now,
    ) -> Result<Vec<minip2p_transport::TransportEvent>, TransportError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(TransportError::PollError {
                reason: "injected".into(),
            });
        }
        Ok(Vec::new())
    }
}

impl minip2p_transport::PollSource for FlakyPollTransport {
    fn attach(
        &mut self,
        _: minip2p_transport::mio::Registry,
        _: minip2p_transport::TokenSpace,
        _: std::sync::Arc<minip2p_transport::mio::Waker>,
    ) -> std::io::Result<()> {
        Ok(())
    }

    fn dispatch(&mut self, _: &minip2p_transport::mio::event::Event) {}
}

/// Events already queued survive a `poll` that fails, and come out of the
/// next one.
#[test]
fn a_failed_poll_keeps_queued_events_for_the_next() {
    let fail = Arc::new(AtomicBool::new(false));
    let mut set = TransportSet::new();
    insert_member(
        &mut set,
        TransportKind::Tcp,
        [ConnectionNamespace::TCP_IPV4],
        FlakyPollTransport {
            fail: Arc::clone(&fail),
        },
    )
    .expect("insert transport");
    let mut endpoint = Endpoint::builder().bind_over(set).expect("build");
    let peer = Ed25519Keypair::generate().peer_id();
    endpoint
        .engine
        .events
        .push_back(EndpointEvent::ConnectionClosed {
            peer_id: peer,
            conn_id: ConnectionId::new(1),
            reason: ConnectionCloseReason::Local,
        });

    fail.store(true, Ordering::SeqCst);
    endpoint.poll().expect_err("injected poll failure");
    fail.store(false, Ordering::SeqCst);

    let events = endpoint.poll().expect("poll");
    assert!(
        events.iter().any(|event| matches!(
            event,
            EndpointEvent::ConnectionClosed { peer_id, .. } if peer_id == &peer
        )),
        "the queued event must survive the failed poll: {events:?}"
    );
}

/// A close whose drain fails still returns the events queued before it,
/// alongside the error.
#[test]
fn close_reports_queued_events_with_a_drain_failure() {
    let fail = Arc::new(AtomicBool::new(true));
    let mut set = TransportSet::new();
    insert_member(
        &mut set,
        TransportKind::Tcp,
        [ConnectionNamespace::TCP_IPV4],
        FlakyPollTransport { fail },
    )
    .expect("insert transport");
    let mut endpoint = Endpoint::builder().bind_over(set).expect("build");
    let peer = Ed25519Keypair::generate().peer_id();
    endpoint
        .engine
        .events
        .push_back(EndpointEvent::ConnectionClosed {
            peer_id: peer,
            conn_id: ConnectionId::new(1),
            reason: ConnectionCloseReason::Local,
        });

    let report = endpoint.close();
    assert!(
        matches!(
            report.events.as_slice(),
            [EndpointEvent::ConnectionClosed { peer_id, .. }] if peer_id == &peer
        ),
        "{:?}",
        report.events
    );
    assert_eq!(report.errors.len(), 1, "{:?}", report.errors);
    assert_eq!(report.outcome, CloseOutcome::Failed);
}

#[test]
fn closing_an_idle_endpoint_drains_with_nothing_unfinished() {
    let endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind");

    let report = endpoint.close();
    assert_eq!(report.outcome, CloseOutcome::Drained);
    assert!(report.unfinished.is_empty(), "{:?}", report.unfinished);
    assert!(report.errors.is_empty(), "{:?}", report.errors);
}

/// A zero deadline tears down at once and names the live connection it
/// did not wait for.
#[test]
fn closing_within_zero_reports_the_live_connection_unfinished() {
    let mut listener = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind listener");
    let addr = listener.listen().expect("listen");
    let _listener = Driven::new(listener);
    let mut dialer = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind dialer");
    dialer.connect(addr.clone()).expect("connect");
    let EndpointEvent::ConnectionEstablished { conn_id, .. } =
        wait_for(&mut dialer, "connection", |event| {
            matches!(event, EndpointEvent::ConnectionEstablished { .. })
        })
    else {
        panic!("the connection predicate returned an unrelated event")
    };

    let report = dialer.close_within(Duration::ZERO);
    assert_eq!(report.outcome, CloseOutcome::DeadlineExpired);
    assert_eq!(report.unfinished, [(conn_id, Some(*addr.peer_id()))]);
}

/// A dial the transport still holds is unfinished teardown, not a drain.
#[test]
fn closing_within_zero_reports_a_pending_dial_unfinished() {
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind silent socket");
    let port = silent.local_addr().expect("silent addr").port();
    let peer = Ed25519Keypair::generate().peer_id();
    let target = PeerAddr::new(
        format!("/ip4/127.0.0.1/udp/{port}/quic-v1")
            .parse()
            .expect("addr"),
        peer,
    )
    .expect("peer addr");
    let mut dialer = quic_endpoint();
    dialer.connect(target).expect("connect");

    let report = dialer.close_within(Duration::ZERO);
    assert_eq!(report.outcome, CloseOutcome::DeadlineExpired);
    assert!(
        matches!(report.unfinished.as_slice(), [(_, Some(unfinished))] if *unfinished == peer),
        "{:?}",
        report.unfinished
    );
}
