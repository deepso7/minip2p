use super::*;

const PROTOCOL: &str = "/myapp/1.0.0";

#[test]
fn dial_only_quic_rejects_finite_credit_with_inbound_caps() {
    let mut transport = minip2p_transport::TransportSet::new();
    let quic =
        minip2p_quic::QuicTransport::dual_stack(minip2p_quic::QuicNodeConfig::generate()).unwrap();
    transport
        .insert(TransportKind::Quic, quic.namespaces(), Box::new(quic))
        .unwrap();
    let result = Endpoint::builder()
        .protocol_with_inbound_limit(PROTOCOL, std::num::NonZeroUsize::new(1).unwrap())
        .quic_limits(QuicLimits {
            connection_receive_window: 1024,
            ..QuicLimits::default()
        })
        .bind_over(transport);
    assert!(matches!(
        result,
        Err(BindError::Options(
            EndpointOptionsError::InboundLimitWithFiniteQuicWindow
        ))
    ));
}

#[test]
fn builder_protocol_registers_for_stream_routing() {
    let mut endpoint = Endpoint::builder()
        .protocol(PROTOCOL)
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind loopback endpoint");

    // A registered protocol fails with NotConnected for an unknown
    // peer, not ProtocolNotRegistered -- proving the builder wired the
    // protocol into user-stream routing.
    let peer_id = Ed25519Keypair::generate().peer_id();
    assert!(matches!(
        endpoint.open_stream(&peer_id, PROTOCOL),
        Err(Error::Swarm(SwarmError::NotConnected { .. }))
    ));
    assert!(matches!(
        endpoint.open_stream(&peer_id, "/other/1.0.0"),
        Err(Error::Swarm(SwarmError::ProtocolNotRegistered { .. }))
    ));
}

/// Every bind failure names what failed and carries its typed cause.
#[test]
fn bind_errors_name_what_failed() {
    let quic = || {
        Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
    };
    let limits = QuicLimits {
        idle_timeout_ms: 0,
        ..QuicLimits::default()
    };
    assert!(matches!(
        quic().quic_limits(limits).bind().err(),
        Some(BindError::Quic(minip2p_quic::QuicBindError::InvalidLimit {
            field: "idle_timeout_ms",
            ..
        }))
    ));
    assert!(matches!(
        Endpoint::builder().bind().err(),
        Some(BindError::Options(EndpointOptionsError::NoTransport))
    ));
    #[cfg(feature = "pubsub")]
    assert!(matches!(
        quic()
            .gossipsub_config(crate::GossipsubConfig {
                heartbeat_interval_ms: 0,
                ..crate::GossipsubConfig::default()
            })
            .bind()
            .err(),
        Some(BindError::Gossipsub(crate::GossipsubConfigError {
            field: "heartbeat_interval_ms",
            ..
        }))
    ));
    #[cfg(feature = "relay-server")]
    {
        let announce: Multiaddr = format!(
            "/ip4/198.51.100.7/udp/4001/quic-v1/p2p/{}",
            Ed25519Keypair::generate().peer_id()
        )
        .parse()
        .expect("announce address");
        assert!(matches!(
            quic()
                .relay_server_announce_addrs(vec![announce.clone()])
                .expect("valid for the peer it names")
                .bind()
                .err(),
            Some(BindError::Options(
                EndpointOptionsError::RelayAnnounceWithoutServer
            ))
        ));
        // Valid for the peer it names, but this endpoint is another one.
        let Some(BindError::RelayServerAnnounce(error)) = quic()
            .relay_server()
            .relay_server_announce_addrs(vec![announce])
            .expect("valid for the peer it names")
            .bind()
            .err()
        else {
            panic!("a foreign announce address must fail the bind");
        };
        assert!(matches!(
            error.reason,
            minip2p_relay_server::RelayServerAddressErrorKind::ConflictingPeerId { .. }
        ));
    }
}

#[test]
fn builder_rejects_reserved_protocol_ids() {
    for reserved in RESERVED_PROTOCOL_IDS {
        let error = Endpoint::builder()
            .protocol(reserved)
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .err()
            .expect("reserved ids must fail the build");
        assert!(matches!(
            error,
            BindError::Swarm(SwarmError::ReservedProtocol { .. })
        ));
    }
}

#[test]
fn builder_rejects_reserved_protocol_ids_before_binding() {
    // An unbindable address must not mask the configuration error:
    // validation happens before any socket is allocated.
    let error = Endpoint::builder()
        .protocol(RESERVED_PROTOCOL_IDS[0])
        // TEST-NET-1 is never a local address, so this bind would fail.
        .listen_on("/ip4/192.0.2.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .err()
        .expect("reserved ids must fail the build");
    assert!(matches!(
        error,
        BindError::Swarm(SwarmError::ReservedProtocol { .. })
    ));
}

#[test]
fn builder_rejects_a_zero_timeout_before_binding() {
    let error = Endpoint::builder()
        .timeouts(SwarmTimeouts {
            identify_ms: 0,
            ..SwarmTimeouts::default()
        })
        // TEST-NET-1 is never a local address, so this bind would fail.
        .listen_on("/ip4/192.0.2.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .err()
        .expect("a zero deadline must fail the build");
    assert!(matches!(
        error,
        BindError::Swarm(SwarmError::ZeroTimeout {
            field: "identify_ms"
        })
    ));
}

#[test]
fn add_protocol_rejects_reserved_protocol_ids() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind loopback endpoint");
    let error = endpoint
        .add_protocol(RESERVED_PROTOCOL_IDS[0])
        .expect_err("reserved ids must be rejected");
    assert!(matches!(
        error,
        Error::Swarm(SwarmError::ReservedProtocol { .. })
    ));
    endpoint
        .add_protocol(PROTOCOL)
        .expect("application ids must be accepted");
}

#[cfg(feature = "relay-server")]
#[test]
fn relay_mesh_is_checked_before_any_socket_opens() {
    let public = Ed25519Keypair::generate();
    let quic: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();
    let member = |transport: &str| {
        PeerAddr::new(
            transport.parse().unwrap(),
            Ed25519Keypair::generate().peer_id(),
        )
        .unwrap()
    };
    let mesh = |identity: &Ed25519Keypair, members| RelayMeshConfig {
        identity: identity.clone(),
        listen: vec![quic.clone()],
        members,
    };
    let bind = |builder: EndpointBuilder| match builder
        .identity(public.clone())
        .listen_on_multiaddr(&quic)
        .unwrap()
        .bind()
    {
        Err(BindError::Options(error)) => error,
        Err(other) => panic!("expected an options error, got {other:?}"),
        Ok(_) => panic!("bound despite an invalid relay mesh"),
    };
    let backbone = Ed25519Keypair::generate();

    let error = bind(Endpoint::builder().relay_mesh(mesh(&backbone, Vec::new())));
    assert_eq!(error, EndpointOptionsError::RelayMeshWithoutServer);
    let error = bind(
        Endpoint::builder()
            .relay_server()
            .relay_mesh(mesh(&public, Vec::new())),
    );
    assert_eq!(error, EndpointOptionsError::RelayMeshPublicIdentity);
    // Backbone transports take `/ip4|ip6` QUIC only: no names, no TCP.
    for transport in [
        "/dns4/relay.example/udp/19877/quic-v1",
        "/ip4/127.0.0.1/tcp/19877",
    ] {
        let bad = member(transport);
        let error = bind(
            Endpoint::builder()
                .relay_server()
                .relay_mesh(mesh(&backbone, vec![bad.clone()])),
        );
        assert_eq!(error, EndpointOptionsError::RelayMeshMember { addr: bad });
    }
    let error = bind(
        Endpoint::builder()
            .relay_server()
            .relay_mesh(RelayMeshConfig {
                listen: vec!["/ip4/127.0.0.1/udp/0/quic-v1/webtransport".parse().unwrap()],
                ..mesh(&backbone, Vec::new())
            }),
    );
    assert!(matches!(
        error,
        EndpointOptionsError::UnsupportedListenShape { .. }
    ));
}

#[cfg(all(feature = "relay-server", feature = "tcp"))]
#[test]
fn relay_server_builder_is_order_independent_and_announce_does_not_enable() {
    let announce = vec!["/ip4/127.0.0.1/tcp/4001".parse().unwrap()];
    let endpoint = Endpoint::builder()
        .relay_server_announce_addrs(announce.clone())
        .expect("valid announce address")
        .relay_server()
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
        .expect("enabled relay server binds");
    assert!(endpoint.engine.relay_server.is_some());

    let result = Endpoint::builder()
        .relay_server_announce_addrs(announce)
        .expect("valid announce address")
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind();
    let error = match result {
        Ok(_) => panic!("announce addresses alone must not enable the service"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("relay server is not enabled"));
}

#[cfg(feature = "relay-server")]
#[test]
fn relay_server_builder_rejects_structurally_invalid_addresses_immediately() {
    let wildcard = "/ip4/0.0.0.0/tcp/4001".parse().unwrap();
    let error = match Endpoint::builder().relay_server_announce_addrs(vec![wildcard]) {
        Ok(_) => panic!("wildcards are not announceable"),
        Err(RelayServerAnnounceError::Address(error)) => error,
        Err(RelayServerAnnounceError::Config(error)) => {
            panic!("default validator configuration is valid: {error}")
        }
    };
    assert_eq!(error.index, 0);
    assert_eq!(error.reason, RelayServerAddressErrorKind::Wildcard);
}

#[cfg(feature = "relay-server")]
#[test]
fn relay_server_builder_checks_announce_peer_against_fixed_identity_immediately() {
    let identity = Ed25519Keypair::from_secret_key_bytes([91; 32]);
    let other = Ed25519Keypair::from_secret_key_bytes([92; 32]).peer_id();
    let address = format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{other}")
        .parse()
        .unwrap();
    let error = match Endpoint::builder()
        .identity(identity.clone())
        .relay_server_announce_addrs(vec![address])
    {
        Ok(_) => panic!("conflicting peer id must fail immediately"),
        Err(RelayServerAnnounceError::Address(error)) => error,
        Err(RelayServerAnnounceError::Config(error)) => {
            panic!("default validator configuration is valid: {error}")
        }
    };
    assert!(matches!(
        error.reason,
        RelayServerAddressErrorKind::ConflictingPeerId { expected, found }
            if expected == identity.peer_id() && found == other
    ));
}

#[cfg(feature = "relay-server")]
#[test]
fn relay_server_runtime_controls_are_typed_and_address_replacement_is_atomic() {
    let mut absent = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind endpoint");
    assert!(matches!(
        absent.set_relay_server_accepting(false),
        Err(RelayServerControlError::NotConfigured)
    ));

    let original: Multiaddr = "/ip4/127.0.0.1/udp/4001/quic-v1".parse().unwrap();
    let mut endpoint = Endpoint::builder()
        .relay_server()
        .relay_server_announce_addrs(vec![original.clone()])
        .expect("valid initial address")
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind relay server");
    let invalid = "/ip4/0.0.0.0/udp/4002/quic-v1".parse().unwrap();
    let error = endpoint
        .set_relay_server_announce_addrs(vec![invalid])
        .expect_err("invalid replacement");
    assert!(matches!(
        error,
        RelayServerControlError::InvalidAddress(RelayServerAddressError {
            index: 0,
            reason: RelayServerAddressErrorKind::Wildcard,
            ..
        })
    ));
    assert_eq!(
        endpoint
            .engine
            .relay_server
            .as_ref()
            .unwrap()
            .agent
            .selected_addrs(),
        core::slice::from_ref(&original)
    );
    endpoint
        .set_relay_server_announce_addrs(Vec::new())
        .expect("empty replacement clears override");
    let selected = endpoint
        .engine
        .relay_server
        .as_ref()
        .unwrap()
        .agent
        .selected_addrs();
    assert!(!selected.is_empty());
    assert_ne!(selected, [original]);
}

#[cfg(feature = "relay-server")]
#[test]
fn wildcard_listener_binds_without_becoming_a_relay_announce_address() {
    let endpoint = Endpoint::builder()
        .relay_server()
        .listen_on("/ip4/0.0.0.0/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("wildcard listener may host once a usable address source appears");
    assert!(
        endpoint
            .engine
            .relay_server
            .as_ref()
            .unwrap()
            .agent
            .selected_addrs()
            .is_empty()
    );
}

#[cfg(all(feature = "relay-server", feature = "quic"))]
#[test]
fn relay_server_webtransport_announces_follow_the_certificate_mode() {
    let hash_free: Multiaddr = "/dns/relay.example/udp/4001/quic-v1/webtransport"
        .parse()
        .unwrap();
    let hashed: Multiaddr =
        format!("{hash_free}/certhash/uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g")
            .parse()
            .unwrap();
    // Announce addresses are set before the certificate: the mode is
    // checked at bind, once every option is in.
    let relay = |announce: &Multiaddr, ca: bool| {
        let builder = Endpoint::builder()
            .relay_server()
            .relay_server_announce_addrs(vec![announce.clone()])
            .expect("well-shaped announce address")
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1/webtransport")
            .expect("WebTransport");
        if ca {
            builder
                .webtransport_certificate_pem(CA_LEAF, CA_KEY)
                .expect("fixture PEM")
        } else {
            builder
        }
        .bind()
    };
    let reason = |result: Result<Endpoint, BindError>| match result {
        Err(BindError::RelayServerAnnounce(error)) => error.reason,
        Err(error) => panic!("unexpected bind error: {error}"),
        Ok(_) => panic!("the announce address must be refused"),
    };
    assert_eq!(
        reason(relay(&hash_free, false)),
        RelayServerAddressErrorKind::MissingCerthash
    );
    assert_eq!(
        reason(relay(&hashed, true)),
        RelayServerAddressErrorKind::UnexpectedCerthash
    );

    // At runtime too, and a refused replacement keeps the override.
    let mut ca = relay(&hash_free, true).expect("CA mode announces hash-free");
    let error = ca
        .set_relay_server_announce_addrs(vec![hashed.clone()])
        .expect_err("CA mode refuses a certhash");
    assert!(matches!(
        error,
        RelayServerControlError::InvalidAddress(RelayServerAddressError {
            index: 0,
            reason: RelayServerAddressErrorKind::UnexpectedCerthash,
            ..
        })
    ));
    let selected = ca
        .engine
        .relay_server
        .as_ref()
        .unwrap()
        .agent
        .selected_addrs();
    assert_eq!(selected, core::slice::from_ref(&hash_free));

    let mut derived = relay(&hashed, false).expect("derived mode announces a certhash");
    let error = derived
        .set_relay_server_announce_addrs(vec![hash_free])
        .expect_err("derived mode needs a certhash");
    assert!(matches!(
        error,
        RelayServerControlError::InvalidAddress(RelayServerAddressError {
            reason: RelayServerAddressErrorKind::MissingCerthash,
            ..
        })
    ));
}

#[cfg(feature = "relay-server")]
#[test]
fn wait_delivers_relay_server_events() {
    let mut endpoint = Endpoint::builder()
        .relay_server()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind relay server");
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
    assert!(matches!(
        endpoint.wait(Duration::ZERO).expect("queue wait"),
        EndpointWaitOutcome::Event(EndpointEvent::RelayServer(RelayServerEvent::Error(_)))
    ));
    assert!(matches!(
        endpoint.wait(Duration::ZERO).expect("drained wait"),
        EndpointWaitOutcome::Deadline
    ));
}

#[cfg(all(feature = "relay", feature = "relay-server"))]
#[test]
fn nat_and_relay_address_contributions_form_a_stable_first_wins_union() {
    let mut endpoint = Endpoint::builder()
        .nat_config(super::nat_tests::idle_nat_config())
        .relay_server()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind combined endpoint");
    let nat_only: Multiaddr = "/ip4/203.0.113.1/udp/4001/quic-v1".parse().unwrap();
    let duplicate: Multiaddr = "/ip4/203.0.113.2/udp/4002/quic-v1".parse().unwrap();
    let relay_only: Multiaddr = "/ip4/203.0.113.3/udp/4003/quic-v1".parse().unwrap();
    endpoint
        .engine
        .nat
        .as_mut()
        .unwrap()
        .set_test_public_addrs(vec![nat_only.clone(), duplicate.clone()]);
    endpoint
        .engine
        .relay_server
        .as_mut()
        .unwrap()
        .agent
        .replace_announce_addrs(vec![duplicate.clone(), relay_only.clone()])
        .unwrap();
    // One batch merges the contributions; the next advertises them.
    endpoint.poll().expect("merge address contributions");
    endpoint.poll().expect("refresh identify snapshot");
    let advertised = endpoint.core().local_addresses();
    let nat_index = advertised
        .iter()
        .position(|addr| addr == &nat_only)
        .unwrap();
    let duplicate_indices: Vec<_> = advertised
        .iter()
        .enumerate()
        .filter_map(|(index, addr)| (addr == &duplicate).then_some(index))
        .collect();
    let relay_index = advertised
        .iter()
        .position(|addr| addr == &relay_only)
        .unwrap();
    assert_eq!(duplicate_indices.len(), 1);
    assert!(nat_index < duplicate_indices[0] && duplicate_indices[0] < relay_index);
}

#[cfg(feature = "relay-server")]
#[test]
fn relay_refresh_preserves_caller_owned_swarm_external_addresses() {
    let mut endpoint = Endpoint::builder()
        .relay_server()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind relay endpoint");
    let caller_owned: Multiaddr = "/ip4/203.0.113.8/udp/4008/quic-v1".parse().unwrap();
    let relay_owned: Multiaddr = "/ip4/203.0.113.9/udp/4009/quic-v1".parse().unwrap();
    endpoint.set_external_addresses(vec![caller_owned.clone()]);
    endpoint
        .set_relay_server_announce_addrs(vec![relay_owned.clone()])
        .expect("replace relay addresses");
    endpoint.raw_poll().expect("refresh identify snapshot");

    let advertised = endpoint.core().local_addresses();
    assert!(advertised.contains(&caller_owned));
    assert!(advertised.contains(&relay_owned));
}

#[cfg(feature = "relay-server")]
#[test]
fn caller_keeps_an_address_after_the_matching_driver_contribution_clears() {
    let mut endpoint = Endpoint::builder()
        .relay_server()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind relay endpoint");
    let shared: Multiaddr = "/ip4/203.0.113.10/udp/4010/quic-v1".parse().unwrap();
    endpoint
        .set_relay_server_announce_addrs(vec![shared.clone()])
        .expect("set relay contribution");
    endpoint.set_external_addresses(vec![shared.clone()]);

    endpoint
        .set_relay_server_announce_addrs(Vec::new())
        .expect("clear relay contribution");
    endpoint.raw_poll().expect("refresh identify snapshot");

    assert!(endpoint.core().local_addresses().contains(&shared));
}

#[test]
fn default_agent_version_matches_package_version() {
    assert_eq!(
        DEFAULT_AGENT_VERSION,
        format!("minip2p/{}", env!("CARGO_PKG_VERSION"))
    );
}
