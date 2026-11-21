use super::*;
use std::sync::atomic::AtomicUsize;

struct NoopDoorbell;

impl EventDoorbell for NoopDoorbell {
    fn on_events_ready(&self) {}
}

#[derive(Default)]
struct RecordingDoorbell {
    rings: AtomicUsize,
}

impl EventDoorbell for RecordingDoorbell {
    fn on_events_ready(&self) {
        self.rings.fetch_add(1, Ordering::AcqRel);
    }
}

struct DropTrackingDoorbell {
    callbacks: Arc<AtomicUsize>,
    dropped: Arc<AtomicBool>,
}

impl EventDoorbell for DropTrackingDoorbell {
    fn on_events_ready(&self) {
        self.callbacks.fetch_add(1, Ordering::AcqRel);
    }
}

impl Drop for DropTrackingDoorbell {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}

struct WaitingDoorbell {
    endpoint: std::sync::Weak<P2pEndpoint>,
    result: Mutex<Option<bool>>,
}

struct DropThreadDoorbell(SyncSender<std::thread::ThreadId>);

impl EventDoorbell for DropThreadDoorbell {
    fn on_events_ready(&self) {}
}

impl Drop for DropThreadDoorbell {
    fn drop(&mut self) {
        // The receiver may already be gone while the test tears down.
        match self.0.send(std::thread::current().id()) {
            Ok(()) | Err(_) => {}
        }
    }
}

struct PanickingDoorbell(Arc<AtomicUsize>);

impl EventDoorbell for PanickingDoorbell {
    fn on_events_ready(&self) {
        self.0.fetch_add(1, Ordering::AcqRel);
        panic!("injected doorbell panic");
    }
}

impl EventDoorbell for WaitingDoorbell {
    fn on_events_ready(&self) {
        let result = self
            .endpoint
            .upgrade()
            .expect("endpoint")
            .wait_stopped(60_000);
        *self.result.lock().unwrap_or_else(PoisonError::into_inner) = Some(result);
    }
}

fn config() -> EndpointConfig {
    EndpointConfig {
        agent_version: None,
        relays: Vec::new(),
        autonat_servers: Vec::new(),
        listen: Some(vec!["/ip4/127.0.0.1/udp/0/quic-v1".into()]),
        force_relay: false,
        allow_unsigned: false,
        protocols: Vec::new(),
        inbound_stream_limits: Default::default(),
        discovery: None,
        mdns: None,
        limits: None,
        timeouts: None,
    }
}

#[test]
fn drain_is_bounded_and_preserves_order() {
    let endpoint = endpoint(config()).expect("endpoint");
    {
        let mut events = endpoint.shared.lock_events();
        events.carry.carry.push(P2pEvent::PingFailed {
            peer_id: "a".into(),
            conn_id: 1,
            cause: crate::PingFailure::TimedOut,
        });
        events.carry.carry.push(P2pEvent::PingFailed {
            peer_id: "b".into(),
            conn_id: 1,
            cause: crate::PingFailure::TimedOut,
        });
    }

    assert_eq!(
        endpoint.drain_events(1),
        vec![P2pEvent::PingFailed {
            peer_id: "a".into(),
            conn_id: 1,
            cause: crate::PingFailure::TimedOut,
        }]
    );
    assert_eq!(
        endpoint.drain_events(1),
        vec![P2pEvent::PingFailed {
            peer_id: "b".into(),
            conn_id: 1,
            cause: crate::PingFailure::TimedOut,
        }]
    );
    assert!(endpoint.drain_events(1).is_empty());
    assert!(endpoint.drain_events(u32::MAX).is_empty());
}

#[test]
fn inbound_stream_limits_reject_zero_and_register_additional_protocols() {
    let mut invalid = config();
    invalid.inbound_stream_limits.insert("/limited/1".into(), 0);
    assert!(matches!(endpoint(invalid), Err(FfiError::InvalidConfig {
        capability: crate::ConfigCapability::Options, detail,
    }) if detail.contains("inboundStreamLimits") && detail.contains("/limited/1") && detail.contains("positive")));

    let mut valid = config();
    valid.inbound_stream_limits.insert("/limited/1".into(), 4);
    let endpoint = endpoint(valid).expect("positive cap registers an additional protocol");
    assert!(
        endpoint
            .shared
            .lock_state()
            .lifecycle
            .accepting()
            .unwrap()
            .protocol_id("/limited/1")
            .is_some()
    );
}

#[test]
fn inbound_limits_reject_finite_quic_connection_credit_as_invalid_config() {
    let mut invalid = config();
    invalid.inbound_stream_limits.insert("/limited/1".into(), 1);
    invalid.limits = Some(crate::LimitsOptions {
        quic: Some(crate::QuicLimitsOptions {
            connection_receive_window: Some(crate::WindowLimit::Bounded { bytes: 1024 }),
            ..Default::default()
        }),
        ..Default::default()
    });
    assert!(matches!(endpoint(invalid), Err(FfiError::InvalidConfig {
        capability: crate::ConfigCapability::Options, detail,
    }) if detail.contains("connectionReceiveWindow") && detail.contains("inboundStreamLimits") && detail.contains("must be unlimited")));
}

#[test]
fn an_interrupted_driver_resumes_once_commands_end() {
    let endpoint = endpoint(config()).expect("endpoint");
    let pending = PendingCommand::new(&endpoint.shared);
    let shared = Arc::clone(&endpoint.shared);
    let (resumed_tx, resumed_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        shared.wait_for_commands();
        resumed_tx.send(()).expect("signal resume");
    });
    assert!(
        resumed_rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "held back while a command is pending"
    );
    drop(pending);
    resumed_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("resumes after the last command ends");
}

#[test]
fn draining_neither_waits_for_nor_interrupts_the_driver() {
    let endpoint = endpoint(config()).expect("endpoint");
    let ping = P2pEvent::PingFailed {
        peer_id: "a".into(),
        conn_id: 1,
        cause: crate::PingFailure::TimedOut,
    };
    endpoint.shared.lock_events().carry.carry.push(ping.clone());
    // A driver parked in `wait` holds the state lock.
    let mut parked = endpoint.shared.lock_state();
    let (drained_tx, drained_rx) = std::sync::mpsc::channel();
    let drainer = Arc::clone(&endpoint);
    std::thread::spawn(move || drained_tx.send(drainer.drain_events(8)));
    assert_eq!(
        drained_rx.recv_timeout(Duration::from_secs(5)),
        Ok(vec![ping]),
        "drain completes while the driver holds the state lock"
    );
    let outcome = parked
        .lifecycle
        .accepting()
        .expect("endpoint")
        .wait(Duration::from_millis(20))
        .expect("wait");
    assert!(
        !matches!(outcome, minip2p::EndpointWaitOutcome::Interrupted),
        "drain latched no interrupt"
    );
}

#[test]
fn cancelling_an_unsettled_attempt_emits_exactly_one_connect_cancelled() {
    let a = endpoint(config()).expect("endpoint a");
    a.start(Arc::new(NoopDoorbell)).expect("start a");

    let black_hole_peer = minip2p::Ed25519Keypair::from_secret_key_bytes([8; 32])
        .peer_id()
        .to_base58();
    let connect_id = a
        .connect(crate::ConnectTarget::Addresses {
            addresses: vec![format!(
                "/ip4/127.0.0.1/udp/1/quic-v1/p2p/{black_hole_peer}"
            )],
        })
        .expect("connect");
    a.cancel_connect(connect_id).expect("cancel");

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut drained = Vec::new();
    while Instant::now() < deadline {
        drained.extend(a.drain_events(4_096));
        if drained
            .iter()
            .any(|event| crate::carry::terminal_connect_id(event) == Some(connect_id))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    let terminals: Vec<&P2pEvent> = drained
        .iter()
        .filter(|event| crate::carry::terminal_connect_id(event) == Some(connect_id))
        .collect();
    assert_eq!(
        terminals,
        [&P2pEvent::ConnectCancelled {
            connect_id,
            peer_id: black_hole_peer,
        }]
        .as_slice(),
        "exactly one ConnectCancelled terminal: {drained:#?}"
    );

    a.cancel_connect(connect_id).expect("idempotent cancel");
    let quiet = Instant::now() + Duration::from_millis(200);
    while Instant::now() < quiet {
        drained.extend(a.drain_events(4_096));
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        drained
            .iter()
            .filter(|event| crate::carry::terminal_connect_id(event) == Some(connect_id))
            .count(),
        1,
        "no further terminal after the first cancel: {drained:#?}"
    );

    a.stop(0);
    assert!(a.wait_stopped(5_000));
}

#[test]
fn cancelling_a_settled_attempt_is_a_no_op_and_the_terminal_is_delivered_once() {
    let a = endpoint(config()).expect("endpoint a");
    let b = endpoint(config()).expect("endpoint b");
    a.start(Arc::new(NoopDoorbell)).expect("start a");
    b.start(Arc::new(NoopDoorbell)).expect("start b");

    let connect_id = a
        .connect(crate::ConnectTarget::Addresses {
            addresses: vec![b.listen_addrs()[0].clone()],
        })
        .expect("connect");
    let deadline = Instant::now() + Duration::from_secs(5);
    while a.path(b.peer_id()).expect("path").is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(a.path(b.peer_id()).expect("path").is_some());

    a.cancel_connect(connect_id).expect("cancel after settle");

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut drained = Vec::new();
    while Instant::now() < deadline {
        drained.extend(a.drain_events(4_096));
        if drained
            .iter()
            .any(|event| crate::carry::terminal_connect_id(event) == Some(connect_id))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    // Let the driver run a little longer so a duplicate terminal could
    // not still be in flight.
    let quiet = Instant::now() + Duration::from_millis(200);
    while Instant::now() < quiet {
        drained.extend(a.drain_events(4_096));
        std::thread::sleep(Duration::from_millis(10));
    }

    let terminals: Vec<&P2pEvent> = drained
        .iter()
        .filter(|event| crate::carry::terminal_connect_id(event) == Some(connect_id))
        .collect();
    assert_eq!(
        terminals.len(),
        1,
        "exactly one terminal event for connect id {connect_id}: {drained:#?}"
    );
    assert!(
        matches!(terminals[0], P2pEvent::PathEstablished { .. }),
        "settled attempt keeps its PathEstablished terminal: {terminals:#?}"
    );

    a.stop(0);
    b.stop(0);
    assert!(a.wait_stopped(5_000));
    assert!(b.wait_stopped(5_000));
}

#[test]
fn connect_admits_addresses_and_settles_once() {
    let a = endpoint(config()).expect("endpoint a");
    let b = endpoint(config()).expect("endpoint b");
    a.start(Arc::new(NoopDoorbell)).expect("start a");
    b.start(Arc::new(NoopDoorbell)).expect("start b");

    let connect_id = a
        .connect(crate::ConnectTarget::Addresses {
            addresses: vec![b.listen_addrs()[0].clone()],
        })
        .expect("connect");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut drained = Vec::new();
    while Instant::now() < deadline {
        drained.extend(a.drain_events(4_096));
        if drained.iter().any(|event| {
            matches!(event, P2pEvent::PathEstablished { connect_id: id, .. } if *id == connect_id)
        }) {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    let terminals: Vec<&P2pEvent> = drained
        .iter()
        .filter(|event| crate::carry::terminal_connect_id(event) == Some(connect_id))
        .collect();
    assert_eq!(
        terminals.len(),
        1,
        "exactly one terminal event for connect id {connect_id}: {drained:#?}"
    );
    let P2pEvent::PathEstablished { conn_id, .. } = terminals[0] else {
        panic!("terminal must be PathEstablished: {terminals:#?}");
    };

    let info = a
        .connection_info(b.peer_id())
        .expect("connection info")
        .expect("connected peer has a transport connection");
    assert_eq!(info.conn_id, *conn_id);
    assert_eq!(info.peer_id, b.peer_id());
    assert_eq!(info.path, crate::PathKind::Direct);
    assert!(
        info.remote_addr.contains("/quic-v1"),
        "remote addr records the transport: {info:?}"
    );
    assert!(matches!(
        a.connection_info("not-a-peer-id".into()),
        Err(FfiError::InvalidPeerId { .. })
    ));
    let stranger = minip2p::Ed25519Keypair::from_secret_key_bytes([7; 32])
        .peer_id()
        .to_base58();
    assert_eq!(a.connection_info(stranger).expect("connection info"), None);

    a.stop(0);
    b.stop(0);
    assert!(a.wait_stopped(5_000));
    assert!(b.wait_stopped(5_000));
}

fn endpoint(config: EndpointConfig) -> Result<Arc<P2pEndpoint>, FfiError> {
    P2pEndpoint::new(vec![9; 32], config)
}

#[test]
fn constructs_a_real_loopback_endpoint() {
    let endpoint = endpoint(config()).expect("endpoint");

    assert!(!endpoint.peer_id().is_empty());
    assert_eq!(endpoint.listen_addrs().len(), 1);
}

#[test]
fn force_relay_requires_a_relay_before_binding() {
    let mut config = config();
    config.force_relay = true;

    assert!(matches!(
        endpoint(config),
        Err(FfiError::InvalidConfig {
            capability: ConfigCapability::Options,
            ..
        })
    ));
}

#[test]
fn constructor_rejects_bad_key_relay_and_listen_address() {
    let bad_key = config();
    let mut bad_secret = vec![9; 32];
    bad_secret.pop();
    assert!(matches!(
        P2pEndpoint::new(bad_secret, bad_key),
        Err(FfiError::InvalidKey { .. })
    ));

    let mut bad_relay = config();
    bad_relay.relays.push("not-a-peer-address".into());
    assert!(matches!(
        endpoint(bad_relay),
        Err(FfiError::InvalidAddress { .. })
    ));

    let mut bad_listen = config();
    bad_listen.listen = Some(vec!["not-a-multiaddr".into()]);
    assert!(matches!(
        endpoint(bad_listen),
        Err(FfiError::InvalidAddress { .. })
    ));
}

#[test]
fn constructor_validates_discovery_before_binding() {
    let mut invalid_topic = config();
    invalid_topic.discovery = Some(crate::DiscoveryOptions {
        topic: String::new(),
        beacon_interval_ms: 10_000,
        peer_ttl_ms: 35_000,
        auto_dial: true,
    });
    assert!(matches!(
        endpoint(invalid_topic),
        Err(FfiError::InvalidConfig {
            capability: ConfigCapability::Discovery,
            ..
        })
    ));

    let mut invalid_ttl = config();
    invalid_ttl.discovery = Some(crate::DiscoveryOptions {
        topic: "room".into(),
        beacon_interval_ms: 10_000,
        peer_ttl_ms: 0,
        auto_dial: true,
    });
    assert!(matches!(
        endpoint(invalid_ttl),
        Err(FfiError::InvalidConfig {
            capability: ConfigCapability::Discovery,
            ..
        })
    ));
}

#[test]
fn immutable_queries_reflect_the_constructed_endpoint() {
    let expected_peer = minip2p::Ed25519Keypair::from_secret_key_bytes([9; 32])
        .peer_id()
        .to_base58();
    let endpoint = endpoint(config()).expect("endpoint");

    assert_eq!(endpoint.peer_id(), expected_peer);
    assert!(endpoint.listen_addrs()[0].starts_with("/ip4/127.0.0.1/udp/"));
    assert!(
        endpoint
            .connected_peers()
            .expect("running endpoint")
            .is_empty()
    );
}

#[test]
fn endpoint_config_contains_no_secret_material() {
    let debug = format!("{:?}", config());

    assert!(!debug.contains("9, 9, 9"));
}

#[test]
fn poisoned_endpoint_lock_recovers() {
    let endpoint = endpoint(config()).expect("endpoint");
    let endpoint_for_panic = Arc::clone(&endpoint);
    let result = std::thread::spawn(move || {
        let _guard = endpoint_for_panic.shared.state.lock().expect("lock");
        panic!("poison endpoint lock");
    })
    .join();
    assert!(result.is_err(), "the lock-poisoning worker must panic");

    assert!(matches!(
        endpoint.shared.lock_state().lifecycle,
        Lifecycle::Created(_)
    ));
}

#[test]
fn constructor_uses_quic_dual_stack_defaults_without_listen() {
    let mut config = config();
    config.listen = None;

    let endpoint = endpoint(config).expect("default endpoint");

    assert!(!endpoint.listen_addrs().is_empty());
    assert!(
        endpoint
            .listen_addrs()
            .iter()
            .all(|address| address.contains("/quic-v1"))
    );
}

#[test]
fn constructor_infers_each_transport_from_the_listen_address() {
    let mut config = config();
    config.listen = Some(vec![
        "/ip4/127.0.0.1/udp/0/quic-v1".into(),
        "/ip6/::1/udp/0/quic-v1".into(),
        "/ip4/127.0.0.1/tcp/0".into(),
    ]);

    let endpoint = endpoint(config).expect("address-shaped listen");
    let addresses = endpoint.listen_addrs();
    assert_eq!(addresses.len(), 3);
    assert!(
        addresses
            .iter()
            .any(|address| address.starts_with("/ip6/::1/") && address.contains("/quic-v1"))
    );
    assert!(addresses.iter().any(|address| address.contains("/tcp/")));
}

#[test]
fn constructor_rejects_empty_and_duplicate_family_listen() {
    let mut empty = config();
    empty.listen = Some(Vec::new());
    assert!(matches!(
        endpoint(empty),
        Err(FfiError::InvalidConfig {
            capability: ConfigCapability::Options,
            ..
        })
    ));

    let mut duplicate_quic_family = config();
    duplicate_quic_family.listen = Some(vec![
        "/ip4/127.0.0.1/udp/0/quic-v1".into(),
        "/ip4/0.0.0.0/udp/0/quic-v1".into(),
    ]);
    assert!(matches!(
        endpoint(duplicate_quic_family),
        Err(FfiError::InvalidConfig {
            capability: ConfigCapability::Options,
            ..
        })
    ));
}

#[test]
fn constructor_accepts_valid_discovery_configuration() {
    let mut config = config();
    config.discovery = Some(crate::DiscoveryOptions {
        topic: "room".into(),
        beacon_interval_ms: 10_000,
        peer_ttl_ms: 35_000,
        auto_dial: true,
    });

    endpoint(config).expect("discovery endpoint");
}

#[test]
fn constructor_accepts_mdns_configuration() {
    let mut config = config();
    config.mdns = Some(crate::MdnsOptions {
        enable_ipv6: false,
        ttl_ms: 120_000,
        query_interval_ms: 300_000,
        max_packet_bytes: 1_400,
        max_announced_addrs: 16,
        interface_refresh_ms: 10_000,
        auto_dial: true,
    });

    endpoint(config).expect("mDNS endpoint");
}

#[test]
fn constructor_rejects_invalid_mdns_configuration() {
    let mut config = config();
    config.mdns = Some(crate::MdnsOptions {
        enable_ipv6: false,
        ttl_ms: 0,
        query_interval_ms: 300_000,
        max_packet_bytes: 1_400,
        max_announced_addrs: 16,
        interface_refresh_ms: 10_000,
        auto_dial: true,
    });

    assert!(matches!(
        endpoint(config),
        Err(FfiError::InvalidConfig {
            capability: ConfigCapability::Mdns,
            ..
        })
    ));
}

#[test]
fn constructor_rejects_non_quic_and_circuit_relays() {
    let relay = minip2p::Ed25519Keypair::from_secret_key_bytes([8; 32]).peer_id();

    for address in [
        format!("/ip4/127.0.0.1/udp/4001/p2p/{relay}"),
        format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p-circuit/p2p/{relay}"),
        format!("/ip4/0.0.0.0/udp/4001/quic-v1/p2p/{relay}"),
    ] {
        let mut config = config();
        config.relays.push(address);
        assert!(matches!(
            endpoint(config),
            Err(FfiError::InvalidAddress { .. })
        ));
    }
}

#[test]
fn connected_peers_follows_connect_and_disconnect() {
    let a = P2pEndpoint::new(vec![1; 32], config()).expect("endpoint a");
    let b = P2pEndpoint::new(vec![2; 32], config()).expect("endpoint b");
    a.start(Arc::new(NoopDoorbell)).expect("start a");
    b.start(Arc::new(NoopDoorbell)).expect("start b");
    let reaches = |expected: &[String]| {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if a.connected_peers().expect("running endpoint") == expected {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    };

    a.connect(crate::ConnectTarget::Addresses {
        addresses: vec![b.listen_addrs()[0].clone()],
    })
    .expect("connect");
    assert!(reaches(&[b.peer_id()]), "lists the peer once connected");
    a.disconnect(b.peer_id()).expect("disconnect");
    assert!(reaches(&[]), "drops the peer once closed");

    a.stop(0);
    assert!(
        matches!(a.connected_peers(), Err(FfiError::Stopped)),
        "reports stopped as soon as stop returns"
    );
    b.stop(0);
    assert!(a.wait_stopped(5_000));
    assert!(b.wait_stopped(5_000));
}

#[test]
fn connected_peers_neither_waits_for_nor_interrupts_the_driver() {
    let endpoint = endpoint(config()).expect("endpoint");
    // A driver parked in `wait` holds the state lock.
    let mut parked = endpoint.shared.lock_state();
    let (peers_tx, peers_rx) = std::sync::mpsc::channel();
    let querier = Arc::clone(&endpoint);
    std::thread::spawn(move || peers_tx.send(querier.connected_peers()));
    let peers = peers_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("query completes while the driver holds the state lock");
    assert!(peers.expect("created endpoint").is_empty());
    let outcome = parked
        .lifecycle
        .accepting()
        .expect("endpoint")
        .wait(Duration::from_millis(20))
        .expect("wait");
    assert!(!matches!(
        outcome,
        minip2p::EndpointWaitOutcome::Interrupted
    ));
}

#[test]
fn connected_peers_reports_a_stopped_endpoint() {
    let endpoint = endpoint(config()).expect("endpoint");
    endpoint.stop(0);

    assert!(matches!(endpoint.connected_peers(), Err(FfiError::Stopped)));
}

#[test]
fn a_socket_the_platform_refuses_is_a_transport_failure() {
    // TEST-NET-1 is never a local address, so the bind itself fails.
    let mut unbindable = config();
    unbindable.listen = Some(vec!["/ip4/192.0.2.1/udp/0/quic-v1".into()]);
    assert!(matches!(
        endpoint(unbindable),
        Err(FfiError::Transport { .. })
    ));
}

#[test]
fn bind_failures_route_by_what_failed() {
    let limit = BindError::Quic(QuicBindError::InvalidLimit {
        field: "idle_timeout_ms",
        requirement: "must be greater than zero",
    });
    assert!(matches!(
        map_bind_error(limit),
        FfiError::InvalidConfig {
            capability: ConfigCapability::Transport,
            ..
        }
    ));
    let listen = BindError::Listen(TransportError::ResourceExhausted { resource: "socket" });
    assert!(matches!(map_bind_error(listen), FfiError::Transport { .. }));
    let invariant = BindError::Invariant { reason: "test" };
    assert!(matches!(
        map_bind_error(invariant),
        FfiError::Internal { .. }
    ));
}

#[test]
fn a_zero_timeout_is_an_options_config_error_naming_the_field() {
    let mut zeroed = config();
    zeroed.timeouts = Some(crate::TimeoutsOptions {
        ping_ms: Some(0),
        ..crate::TimeoutsOptions::default()
    });
    match endpoint(zeroed) {
        Err(FfiError::InvalidConfig {
            capability: ConfigCapability::Options,
            detail,
        }) => assert!(detail.contains("ping_ms"), "{detail}"),
        Err(error) => panic!("expected an Options InvalidConfig, got {error:?}"),
        Ok(_) => panic!("a zero deadline must not build"),
    }

    let mut raised = config();
    raised.timeouts = Some(crate::TimeoutsOptions {
        identify_ms: Some(60_000),
        ..crate::TimeoutsOptions::default()
    });
    endpoint(raised).expect("a partial override keeps the other defaults");
}

/// A loopback QUIC + TCP config with `limits`.
fn limited(limits: crate::LimitsOptions) -> EndpointConfig {
    let mut config = config();
    config.listen = Some(vec![
        "/ip4/127.0.0.1/udp/0/quic-v1".into(),
        "/ip4/127.0.0.1/tcp/0".into(),
    ]);
    config.limits = Some(limits);
    config
}

fn small_yamux_window() -> crate::YamuxOptions {
    crate::YamuxOptions {
        receive_window: Some(1024),
        ..crate::YamuxOptions::default()
    }
}

/// The `detail` of a Transport `InvalidConfig`, failing on anything else.
fn transport_config_detail(result: Result<Arc<P2pEndpoint>, FfiError>) -> String {
    match result {
        Err(FfiError::InvalidConfig {
            capability: ConfigCapability::Transport,
            detail,
        }) => detail,
        Err(error) => panic!("expected a Transport InvalidConfig, got {error:?}"),
        Ok(_) => panic!("expected a Transport InvalidConfig, got an endpoint"),
    }
}

#[test]
fn invalid_limits_are_transport_config_errors_naming_the_field() {
    let quic = transport_config_detail(endpoint(limited(crate::LimitsOptions {
        quic: Some(crate::QuicLimitsOptions {
            idle_timeout_ms: Some(0),
            ..crate::QuicLimitsOptions::default()
        }),
        ..crate::LimitsOptions::default()
    })));
    assert!(quic.contains("idle_timeout_ms"), "{quic}");

    let tcp = transport_config_detail(endpoint(limited(crate::LimitsOptions {
        tcp: Some(crate::TcpLimitsOptions {
            yamux: Some(small_yamux_window()),
            ..crate::TcpLimitsOptions::default()
        }),
        ..crate::LimitsOptions::default()
    })));
    assert!(tcp.contains("TcpConfig::yamux"), "{tcp}");
    assert!(tcp.contains("receive_window"), "{tcp}");

    let circuit = transport_config_detail(endpoint(limited(crate::LimitsOptions {
        circuit: Some(small_yamux_window()),
        ..crate::LimitsOptions::default()
    })));
    assert!(circuit.contains("CircuitLimits::yamux"), "{circuit}");

    let send_cap = transport_config_detail(endpoint(limited(crate::LimitsOptions {
        circuit: Some(crate::YamuxOptions {
            max_buffered_send: Some(0),
            ..crate::YamuxOptions::default()
        }),
        ..crate::LimitsOptions::default()
    })));
    assert!(send_cap.contains("max_buffered_send"), "{send_cap}");
}

#[test]
fn limits_of_an_unbound_transport_are_ignored() {
    // QUIC-only listen: no TCP transport is bound to validate against.
    let mut quic_only = config();
    quic_only.limits = Some(crate::LimitsOptions {
        tcp: Some(crate::TcpLimitsOptions {
            yamux: Some(small_yamux_window()),
            ..crate::TcpLimitsOptions::default()
        }),
        ..crate::LimitsOptions::default()
    });
    endpoint(quic_only).expect("QUIC-only endpoint");

    let mut tcp_only = config();
    tcp_only.listen = Some(vec!["/ip4/127.0.0.1/tcp/0".into()]);
    tcp_only.limits = Some(crate::LimitsOptions {
        quic: Some(crate::QuicLimitsOptions {
            idle_timeout_ms: Some(0),
            ..crate::QuicLimitsOptions::default()
        }),
        ..crate::LimitsOptions::default()
    });
    endpoint(tcp_only).expect("TCP-only endpoint");
}

#[test]
fn valid_limits_bind() {
    endpoint(limited(crate::LimitsOptions {
        quic: Some(crate::QuicLimitsOptions {
            stream_receive_window: Some(4_000_000),
            connection_receive_window: Some(crate::WindowLimit::Unlimited),
            ..crate::QuicLimitsOptions::default()
        }),
        tcp: Some(crate::TcpLimitsOptions {
            handshake_timeout_ms: Some(crate::TimeoutLimit::Never),
            ..crate::TcpLimitsOptions::default()
        }),
        max_circuits: Some(0),
        ..crate::LimitsOptions::default()
    }))
    .expect("endpoint");
}

#[test]
fn created_endpoint_requires_stop_before_wait_stopped() {
    let endpoint = endpoint(config()).expect("endpoint");

    assert!(!endpoint.is_running());
    assert!(!endpoint.wait_stopped(0));
    endpoint.stop(0);
    assert!(endpoint.wait_stopped(100));
    assert!(!endpoint.is_running());
}

#[test]
fn stop_is_idempotent_in_created_and_stopped_states() {
    let endpoint = endpoint(config()).expect("endpoint");

    endpoint.stop(0);
    endpoint.stop(0);

    assert!(endpoint.wait_stopped(0));
    let state = endpoint.shared.lock_state();
    assert!(matches!(state.lifecycle, Lifecycle::Stopped));
}

#[test]
fn stop_finishes_a_running_driver() {
    let endpoint = endpoint(config()).expect("endpoint");
    endpoint.start(Arc::new(NoopDoorbell)).expect("start");
    assert!(endpoint.is_running());

    endpoint.stop(0);

    assert!(endpoint.wait_stopped(1_000));
    assert!(!endpoint.is_running());
    assert!(matches!(
        endpoint.shared.lock_state().lifecycle,
        Lifecycle::Stopped
    ));
}

/// The last event drained once `endpoint` has stopped.
fn last_event_after_stop(endpoint: &P2pEndpoint) -> Option<P2pEvent> {
    assert!(endpoint.wait_stopped(5_000));
    endpoint.drain_events(u32::MAX).pop()
}

#[test]
fn stopping_an_idle_driver_reports_a_drained_close_last() {
    let endpoint = endpoint(config()).expect("endpoint");
    endpoint.start(Arc::new(NoopDoorbell)).expect("start");

    endpoint.stop(DEFAULT_STOP_TIMEOUT_MS);

    assert_eq!(
        last_event_after_stop(&endpoint),
        Some(P2pEvent::EndpointClosed {
            outcome: crate::CloseOutcome::Drained,
            unfinished: Vec::new(),
        })
    );
}

/// `stop(0)` reaches `close_within(ZERO)`, which does not wait for the
/// live connection.
#[test]
fn stopping_within_zero_reports_the_live_connection_unfinished() {
    let a = endpoint(config()).expect("endpoint a");
    let b = endpoint(config()).expect("endpoint b");
    a.start(Arc::new(NoopDoorbell)).expect("start a");
    b.start(Arc::new(NoopDoorbell)).expect("start b");
    a.connect(crate::ConnectTarget::Addresses {
        addresses: vec![b.listen_addrs()[0].clone()],
    })
    .expect("connect");
    let deadline = Instant::now() + Duration::from_secs(5);
    let conn_id = loop {
        if let Some(info) = a.connection_info(b.peer_id()).expect("connection info") {
            break info.conn_id;
        }
        assert!(Instant::now() < deadline, "a never connected to b");
        std::thread::sleep(Duration::from_millis(10));
    };

    a.stop(0);

    assert_eq!(
        last_event_after_stop(&a),
        Some(P2pEvent::EndpointClosed {
            outcome: crate::CloseOutcome::DeadlineExpired,
            unfinished: vec![crate::UnfinishedConnection {
                conn_id,
                peer_id: Some(b.peer_id()),
            }],
        })
    );
    b.stop(0);
}

/// The drain's `ConnectionClosed` reaches the binding before the
/// `EndpointClosed` that reports the drain.
#[test]
fn stopping_delivers_the_drained_connection_close_before_endpoint_closed() {
    let a = endpoint(config()).expect("endpoint a");
    let b = endpoint(config()).expect("endpoint b");
    a.start(Arc::new(NoopDoorbell)).expect("start a");
    b.start(Arc::new(NoopDoorbell)).expect("start b");
    a.connect(crate::ConnectTarget::Addresses {
        addresses: vec![b.listen_addrs()[0].clone()],
    })
    .expect("connect");
    // The binding takes the connection's events, so the carry keeps its end.
    let deadline = Instant::now() + Duration::from_secs(5);
    let conn_id = loop {
        let established = a
            .drain_events(u32::MAX)
            .into_iter()
            .find_map(|event| match event {
                P2pEvent::ConnectionEstablished { conn_id, .. } => Some(conn_id),
                _ => None,
            });
        if let Some(conn_id) = established {
            break conn_id;
        }
        assert!(Instant::now() < deadline, "a never connected to b");
        std::thread::sleep(Duration::from_millis(10));
    };

    a.stop(5_000);

    assert!(a.wait_stopped(10_000));
    let events = a.drain_events(u32::MAX);
    let closed_at = events
        .iter()
        .position(|event| {
            matches!(event, P2pEvent::ConnectionClosed { conn_id: closed, .. } if *closed == conn_id)
        })
        .unwrap_or_else(|| panic!("no ConnectionClosed in {events:?}"));
    assert!(closed_at < events.len() - 1, "{events:?}");
    assert_eq!(
        events.last(),
        Some(&P2pEvent::EndpointClosed {
            outcome: crate::CloseOutcome::Drained,
            unfinished: Vec::new(),
        })
    );
    b.stop(0);
}

#[test]
fn an_idle_driver_sleeps_until_a_caller_wakes_it() {
    let endpoint = endpoint(config()).expect("endpoint");
    endpoint.start(Arc::new(NoopDoorbell)).expect("start");
    // Long enough for any fixed polling cadence to show.
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(
        endpoint.driver_stats().iterations,
        0,
        "an endpoint with nothing due must not cycle its driver"
    );

    // The parked driver holds the endpoint lock with no deadline, so each
    // of these would block forever if it failed to wake it.
    let (done, finished) = std::sync::mpsc::channel();
    let caller = Arc::clone(&endpoint);
    std::thread::spawn(move || {
        assert!(!caller.wait_stopped(20), "nothing has stopped it yet");
        assert!(matches!(
            caller.start(Arc::new(NoopDoorbell)),
            Err(FfiError::AlreadyStarted)
        ));
        assert_eq!(
            caller.driver_stats().iterations,
            0,
            "an interrupt alone is no cycle"
        );
        assert!(caller.subscribe("room".into()).expect("subscribe"));
        caller.stop(0);
        done.send(caller.wait_stopped(60_000)).expect("report");
    });
    assert_eq!(
        finished.recv_timeout(Duration::from_secs(30)),
        Ok(true),
        "queries, commands and stop must each wake an idle driver"
    );
}

#[test]
fn start_rejects_double_start_and_restart_after_stop() {
    let endpoint = endpoint(config()).expect("endpoint");
    endpoint.start(Arc::new(NoopDoorbell)).expect("start");

    assert!(matches!(
        endpoint.start(Arc::new(NoopDoorbell)),
        Err(FfiError::AlreadyStarted)
    ));
    endpoint.stop(0);
    assert!(endpoint.wait_stopped(1_000));
    assert!(matches!(
        endpoint.start(Arc::new(NoopDoorbell)),
        Err(FfiError::Stopped)
    ));
}

#[test]
fn rejected_start_does_not_spawn_an_orphan_doorbell() {
    let endpoint = endpoint(config()).expect("endpoint");
    endpoint.start(Arc::new(NoopDoorbell)).expect("start");
    let caller = std::thread::current().id();
    let (dropped, received) = sync_channel(1);
    assert!(matches!(
        endpoint.start(Arc::new(DropThreadDoorbell(dropped))),
        Err(FfiError::AlreadyStarted)
    ));
    assert_eq!(received.recv_timeout(Duration::from_secs(1)), Ok(caller));
    endpoint.stop(0);
    assert!(endpoint.wait_stopped(1_000));
}

#[test]
fn repeated_doorbell_panics_do_not_block_shutdown() {
    let a = endpoint(config()).expect("endpoint a");
    let b = endpoint(config()).expect("endpoint b");
    let callbacks = Arc::new(AtomicUsize::new(0));
    a.start(Arc::new(PanickingDoorbell(Arc::clone(&callbacks))))
        .expect("start a");
    b.start(Arc::new(NoopDoorbell)).expect("start b");
    a.connect(crate::ConnectTarget::Addresses {
        addresses: vec![b.listen_addrs()[0].clone()],
    })
    .expect("connect");

    let deadline = Instant::now() + Duration::from_secs(5);
    while callbacks.load(Ordering::Acquire) == 0 && Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert!(callbacks.load(Ordering::Acquire) > 0);

    a.stop(0);
    assert!(a.wait_stopped(1_000));
    b.stop(0);
    assert!(b.wait_stopped(1_000));
}

#[test]
fn spawn_failure_stops_and_releases_endpoint() {
    let endpoint = endpoint(config()).expect("endpoint");

    let error = endpoint
        .start_with(Arc::new(NoopDoorbell), |_, _| {
            Err(std::io::Error::other("injected spawn failure"))
        })
        .expect_err("spawn must fail");

    assert!(matches!(error, FfiError::Internal { .. }));
    assert!(endpoint.wait_stopped(0));
    assert!(matches!(endpoint.connected_peers(), Err(FfiError::Stopped)));
    let state = endpoint.shared.lock_state();
    assert!(matches!(state.lifecycle, Lifecycle::Stopped));
}

#[test]
fn wait_stopped_releases_doorbell_before_returning() {
    let endpoint = endpoint(config()).expect("endpoint");
    let callbacks = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    endpoint
        .start(Arc::new(DropTrackingDoorbell {
            callbacks: Arc::clone(&callbacks),
            dropped: Arc::clone(&dropped),
        }))
        .expect("start");

    endpoint.stop(0);
    assert!(endpoint.wait_stopped(1_000));

    assert!(dropped.load(Ordering::Acquire));
}

#[test]
fn drop_without_explicit_stop_releases_doorbell() {
    let endpoint = endpoint(config()).expect("endpoint");
    let callbacks = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    endpoint
        .start(Arc::new(DropTrackingDoorbell {
            callbacks,
            dropped: Arc::clone(&dropped),
        }))
        .expect("start");

    drop(endpoint);

    let deadline = Instant::now() + Duration::from_secs(1);
    while !dropped.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert!(dropped.load(Ordering::Acquire));
}

#[test]
fn concurrent_commands_queries_and_stop_complete() {
    let endpoint = endpoint(config()).expect("endpoint");
    endpoint.start(Arc::new(NoopDoorbell)).expect("start");
    let mut workers = Vec::new();

    for worker in 0..4 {
        let endpoint = Arc::clone(&endpoint);
        workers.push(std::thread::spawn(move || {
            for index in 0_u8..250 {
                match worker {
                    0 => {
                        drop(endpoint.connected_peers());
                    }
                    1 => endpoint.set_active(index % 2 == 0),
                    2 => {
                        drop(endpoint.publish("room".into(), vec![index]));
                    }
                    _ => {
                        drop(endpoint.cancel_connect(u64::MAX));
                    }
                }
            }
        }));
    }

    std::thread::yield_now();
    endpoint.stop(0);
    for worker in workers {
        worker.join().expect("worker must not panic");
    }

    assert!(endpoint.wait_stopped(5_000));
    assert!(!endpoint.is_running());
}

#[test]
fn fatal_driver_panic_is_reported_before_stopped() {
    let endpoint = endpoint(config()).expect("endpoint");
    let listener = Arc::new(RecordingDoorbell::default());
    endpoint
        .start_with(Arc::new(NoopDoorbell), |_, _| {
            Ok(std::thread::spawn(|| {}).thread().id())
        })
        .expect("mark running");

    // Panics holding `state`, as a panic inside `pump` would, so the
    // driver's cleanup runs over a poisoned lock.
    let shared = Arc::clone(&endpoint.shared);
    crate::driver::run_with(
        Arc::clone(&endpoint.shared),
        Arc::clone(&listener) as Arc<dyn EventDoorbell>,
        move |_| {
            let _state = shared.lock_state();
            panic!("injected driver panic")
        },
    );

    assert!(matches!(
        endpoint.drain_events(10).as_slice(),
        [
            crate::P2pEvent::DriverFailed {
                kind: crate::DriverFailureKind::Panic,
                ..
            },
            crate::P2pEvent::EndpointClosed {
                outcome: crate::CloseOutcome::Failed,
                unfinished,
            },
        ] if unfinished.is_empty()
    ));
    assert!(matches!(endpoint.connected_peers(), Err(FfiError::Stopped)));
    assert!(endpoint.wait_stopped(0));
}

#[test]
fn wait_stopped_from_driver_callback_returns_immediately() {
    let endpoint = endpoint(config()).expect("endpoint");
    let listener = Arc::new(WaitingDoorbell {
        endpoint: Arc::downgrade(&endpoint),
        result: Mutex::new(None),
    });
    endpoint
        .start_with(Arc::new(NoopDoorbell), |_, _| {
            Ok(std::thread::spawn(|| {}).thread().id())
        })
        .expect("mark running");

    let started = Instant::now();
    crate::driver::run_with(
        Arc::clone(&endpoint.shared),
        Arc::clone(&listener) as Arc<dyn EventDoorbell>,
        |_| panic!("injected driver panic"),
    );

    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(
        *listener
            .result
            .lock()
            .unwrap_or_else(PoisonError::into_inner),
        Some(false)
    );
}

#[test]
fn pending_command_interrupts_a_waiter_and_balances_the_counter() {
    let endpoint = endpoint(config()).expect("endpoint");
    let shared = Arc::clone(&endpoint.shared);
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn(move || {
        let mut state = shared.lock_state();
        entered_tx.send(()).expect("signal waiter");
        let outcome = state
            .lifecycle
            .accepting()
            .expect("endpoint")
            .wait(Duration::from_secs(5))
            .expect("wait");
        assert!(matches!(outcome, minip2p::EndpointWaitOutcome::Interrupted));
    });
    entered_rx.recv().expect("waiter entered");
    std::thread::sleep(Duration::from_millis(20));

    {
        let _pending = PendingCommand::new(&endpoint.shared);
        assert_eq!(endpoint.shared.pending_commands.load(Ordering::Acquire), 1);
    }
    waiter.join().expect("waiter exits after interrupt");
    assert_eq!(endpoint.shared.pending_commands.load(Ordering::Acquire), 0);
}

#[test]
fn pre_start_commands_and_queries_are_deterministic() {
    let endpoint = endpoint(config()).expect("endpoint");
    let remote = minip2p::Ed25519Keypair::from_secret_key_bytes([7; 32]).peer_id();

    assert!(endpoint.subscribe("room".into()).expect("subscribe"));
    assert!(!endpoint.subscribe("room".into()).expect("idempotent"));
    endpoint
        .publish("room".into(), b"hello".to_vec())
        .expect("publish");
    assert!(endpoint.unsubscribe("room".into()).expect("unsubscribe"));
    assert!(endpoint.connected_peers().expect("peers").is_empty());
    assert!(endpoint.known_peers().expect("known peers").is_empty());
    assert_eq!(
        endpoint.reachability().expect("reachability"),
        crate::Reachability::Unknown
    );
    assert!(
        endpoint
            .active_reservation()
            .expect("reservation")
            .is_none()
    );
    let connect_id = endpoint
        .connect(crate::ConnectTarget::Peer {
            peer_id: remote.to_base58(),
        })
        .expect("connection attempt");
    endpoint.cancel_connect(connect_id).expect("known cancel");
    endpoint
        .cancel_connect(connect_id)
        .expect("settled cancel is a no-op");
    endpoint.cancel_connect(u64::MAX).expect("unknown cancel");
}

#[test]
fn disconnect_validates_the_peer_id() {
    let endpoint = endpoint(config()).expect("endpoint");

    assert!(matches!(
        endpoint.disconnect("not-a-peer-id".into()),
        Err(FfiError::InvalidPeerId { .. })
    ));
}

#[test]
fn command_inputs_and_stopped_state_are_typed() {
    let endpoint = endpoint(config()).expect("endpoint");

    assert!(matches!(
        endpoint.subscribe(String::new()),
        Err(FfiError::InvalidTopic { .. })
    ));
    assert!(matches!(
        endpoint.connect(crate::ConnectTarget::Peer {
            peer_id: "not-a-peer".into()
        }),
        Err(FfiError::InvalidPeerId { .. })
    ));
    assert!(matches!(
        endpoint.connect(crate::ConnectTarget::Addresses {
            addresses: vec!["not-an-address".into()]
        }),
        Err(FfiError::InvalidAddress { .. })
    ));

    endpoint.stop(0);
    assert!(matches!(
        endpoint.publish("room".into(), Vec::new()),
        Err(FfiError::Stopped)
    ));
    assert!(matches!(endpoint.known_peers(), Err(FfiError::Stopped)));
}

#[test]
fn source_age_uses_saturating_discovery_clock_math() {
    assert_eq!(age(Some(100), Some(40)), Some(60));
    assert_eq!(age(Some(40), Some(100)), Some(0));
    assert_eq!(age(None, Some(10)), None);
    assert_eq!(age(Some(10), None), None);
}

#[test]
fn commands_reject_stopping_and_oversized_payloads() {
    let endpoint = endpoint(config()).expect("endpoint");
    assert!(matches!(
        endpoint.publish("room".into(), vec![0; minip2p_pubsub::MAX_RPC_SIZE + 1]),
        Err(FfiError::MessageTooLarge)
    ));

    endpoint.shared.lock_state().lifecycle = Lifecycle::Stopping {
        live: None,
        close_timeout: Duration::ZERO,
    };
    assert!(matches!(
        endpoint.subscribe("room".into()),
        Err(FfiError::Stopped)
    ));
    assert!(matches!(
        endpoint.publish("room".into(), Vec::new()),
        Err(FfiError::Stopped)
    ));
    assert!(matches!(endpoint.cancel_connect(0), Err(FfiError::Stopped)));
}

#[test]
fn gossipsub_and_transport_errors_map_by_context() {
    let mut discovery = config();
    discovery.discovery = Some(crate::DiscoveryOptions {
        topic: "presence".into(),
        beacon_interval_ms: 10_000,
        peer_ttl_ms: 35_000,
        auto_dial: false,
    });
    let endpoint = endpoint(discovery).expect("endpoint");
    assert!(matches!(
        endpoint.unsubscribe("presence".into()),
        Err(FfiError::NotPermitted { .. })
    ));

    assert!(matches!(
        map_gossipsub_error(minip2p::GossipsubError::Publish(
            minip2p::PublishError::TooLarge
        )),
        FfiError::MessageTooLarge
    ));
    assert!(matches!(
        map_gossipsub_error(minip2p::GossipsubError::Publish(
            minip2p::PublishError::Backpressure
        )),
        FfiError::Backpressure
    ));
    assert!(matches!(
        map_driver_error(
            TransportError::PollError {
                reason: "test".into()
            }
            .into()
        ),
        FfiError::Transport { .. }
    ));
}

#[test]
fn listen_addrs_follow_listen_set_changes_only() {
    let endpoint = endpoint(config()).expect("endpoint");
    let bound = endpoint.listen_addrs();
    assert_eq!(bound.len(), 1, "{bound:?}");

    let public = P2pEvent::PublicAddressesChanged {
        addrs: vec!["/ip4/203.0.113.9/udp/1/quic-v1".into()],
    };
    endpoint.shared.lock_events().ingest(vec![public]);
    assert_eq!(endpoint.listen_addrs(), bound);

    let rotated = vec![format!("{}/rotated", bound[0])];
    let changed = P2pEvent::ListenAddressesChanged {
        addrs: rotated.clone(),
    };
    endpoint.shared.lock_events().ingest(vec![changed.clone()]);
    assert_eq!(endpoint.listen_addrs(), rotated);
    assert!(endpoint.drain_events(8).contains(&changed));
}
