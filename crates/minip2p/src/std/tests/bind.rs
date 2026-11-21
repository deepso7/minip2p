use super::*;

#[cfg(feature = "discovery")]
#[test]
fn discovery_config_is_rejected_before_binding() {
    let config = BeaconConfig {
        beacon_interval_ms: 0,
        ..BeaconConfig::default()
    };
    assert!(matches!(
        Endpoint::builder()
            .discovery_config(config)
            .listen_on(UNBINDABLE_QUIC)
            .expect("quic listen address")
            .bind()
            .err(),
        Some(BindError::Discovery(
            crate::DiscoveryConfigError::ZeroBeaconInterval
        ))
    ));
}

#[test]
fn an_endpoint_with_nothing_to_bind_is_refused() {
    let Err(error) = Endpoint::builder().bind() else {
        panic!("an endpoint with no transport must not build");
    };
    assert!(
        format!("{error}").contains("at least one transport"),
        "got {error}"
    );
}

#[test]
fn listen_configures_a_quic_multiaddr() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("listen accepts QUIC")
        .bind()
        .expect("bind");
    let addrs = endpoint.listen_all().expect("listen_all");
    assert_eq!(addrs.len(), 1);
    assert!(
        addrs[0]
            .transport()
            .to_string()
            .starts_with("/ip4/127.0.0.1/udp/"),
        "{addrs:?}"
    );
    assert!(
        addrs[0].transport().to_string().ends_with("/quic-v1"),
        "{addrs:?}"
    );
}

#[cfg(feature = "tcp")]
#[test]
fn listen_configures_a_tcp_multiaddr() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("listen accepts TCP")
        .bind()
        .expect("bind");
    let addrs = endpoint.listen_all().expect("listen_all");
    assert_eq!(addrs.len(), 1);
    assert!(
        addrs[0]
            .transport()
            .to_string()
            .starts_with("/ip4/127.0.0.1/tcp/"),
        "{addrs:?}"
    );
}

#[test]
fn listen_groups_ipv4_and_ipv6_quic_without_duplicating_transports() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("ipv4")
        .listen_on("/ip6/::1/udp/0/quic-v1")
        .expect("ipv6")
        .bind()
        .expect("bind dual");
    let addrs = endpoint.listen_all().expect("listen_all");
    assert_eq!(addrs.len(), 2, "{addrs:?}");
    assert!(
        addrs
            .iter()
            .any(|a| a.transport().to_string().contains("/ip4/"))
    );
    assert!(
        addrs
            .iter()
            .any(|a| a.transport().to_string().contains("/ip6/"))
    );
}

#[cfg(feature = "tcp")]
#[test]
fn listen_composes_quic_and_tcp() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic")
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp")
        .bind()
        .expect("bind both");
    let reported: Vec<String> = endpoint
        .listen_all()
        .expect("listen_all")
        .iter()
        .map(|addr| addr.transport().to_string())
        .collect();
    assert_eq!(reported.len(), 2, "{reported:?}");
    assert!(reported.iter().any(|addr| addr.contains("/quic-v1")));
    assert!(reported.iter().any(|addr| addr.contains("/tcp/")));
}

#[test]
fn listen_rejects_unsupported_and_contradictory_shapes() {
    let Err(dns) = Endpoint::builder().listen_on("/dns/example.com/udp/0/quic-v1") else {
        panic!("DNS listen must fail");
    };
    assert!(
        matches!(
            &dns,
            EndpointOptionsError::UnsupportedListenShape { expected, .. }
                if expected.contains("DNS")
        ),
        "{dns}"
    );

    let Err(circuit) = Endpoint::builder().listen_on("/ip4/127.0.0.1/udp/0/quic-v1/p2p-circuit")
    else {
        panic!("circuit listen must fail");
    };
    assert!(
        matches!(
            &circuit,
            EndpointOptionsError::UnsupportedListenShape { expected, .. }
                if expected.contains("p2p-circuit")
        ),
        "{circuit}"
    );

    let Err(duplicate) = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("first")
        .listen_on("/ip4/0.0.0.0/udp/0/quic-v1")
    else {
        panic!("duplicate IPv4 QUIC must fail");
    };
    assert!(
        matches!(
            &duplicate,
            EndpointOptionsError::DuplicateQuicFamily {
                family: IpFamily::Ipv4,
                ..
            }
        ),
        "{duplicate}"
    );
}

#[test]
fn webtransport_listens_share_the_quic_socket_of_their_family() {
    let builder = || {
        Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic-v1")
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1/webtransport")
            .expect("WebTransport on the same socket")
    };
    for rejected in [
        "/ip4/127.0.0.1/udp/4001/quic-v1/webtransport",
        "/ip4/127.0.0.1/udp/0/quic-v1/webtransport",
    ] {
        let Err(error) = builder().listen_on(rejected) else {
            panic!("{rejected} must be refused");
        };
        assert!(
            matches!(error, EndpointOptionsError::DuplicateQuicFamily { .. }),
            "{rejected}: {error}"
        );
    }
    let Err(certhash) = Endpoint::builder().listen_on(
        "/ip4/127.0.0.1/udp/0/quic-v1/webtransport/certhash/uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g",
    ) else {
        panic!("a listen certhash must be refused");
    };
    assert!(
        matches!(
            &certhash,
            EndpointOptionsError::UnsupportedListenShape { expected, .. }
                if expected.contains("without /certhash")
        ),
        "{certhash}"
    );
}

#[cfg(feature = "quic")]
#[test]
fn webtransport_certificate_pem_names_what_is_missing() {
    let two_keys = [CA_KEY, CA_KEY].concat();
    for (chain, key, expected) in [
        (CA_KEY, CA_KEY, "no `BEGIN CERTIFICATE`"),
        (CA_LEAF, CA_LEAF, "no `BEGIN PRIVATE KEY`"),
        (CA_LEAF, two_keys.as_slice(), "2 private keys"),
    ] {
        let Err(error) = Endpoint::builder().webtransport_certificate_pem(chain, key) else {
            panic!("{expected}: the PEM must be refused");
        };
        assert!(
            matches!(
                &error,
                EndpointOptionsError::WebTransportCertificatePem { problem }
                    if problem.contains(expected)
            ),
            "{expected}: {error}"
        );
    }
}

#[cfg(feature = "quic")]
#[test]
fn webtransport_certificate_without_a_webtransport_listener_fails_bind() {
    let result = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic-v1")
        .webtransport_certificate_pem(CA_LEAF, CA_KEY)
        .expect("fixture PEM")
        .bind();
    assert!(matches!(
        result,
        Err(BindError::Options(
            EndpointOptionsError::WebTransportCertificateWithoutListener
        ))
    ));
}

#[cfg(feature = "quic")]
#[test]
fn ca_webtransport_listener_reports_a_hash_free_address() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1/webtransport")
        .expect("WebTransport")
        .webtransport_certificate_pem(CA_LEAF, CA_KEY)
        .expect("fixture PEM")
        .bind()
        .expect("bind with the fixture certificate");
    let addrs = endpoint.listen_all().expect("listen_all");
    assert!(
        matches!(
            addrs.as_slice(),
            [addr] if addr.transport().is_webtransport()
                && addr.transport().certhashes().next().is_none()
        ),
        "{addrs:?}"
    );
}

#[cfg(feature = "quic")]
#[test]
fn set_webtransport_certificate_pem_needs_ca_mode_and_a_matching_key() {
    const CHAIN: &[u8] =
        include_bytes!("../../../../../transports/quic/tests/fixtures/ca/chain.pem");
    const CHAIN_KEY: &[u8] =
        include_bytes!("../../../../../transports/quic/tests/fixtures/ca/chain.key");
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1/webtransport")
        .expect("WebTransport")
        .webtransport_certificate_pem(CA_LEAF, CA_KEY)
        .expect("fixture PEM")
        .bind()
        .expect("bind with the fixture certificate");
    endpoint
        .set_webtransport_certificate_pem(CHAIN, CHAIN_KEY)
        .expect("replace");
    assert!(matches!(
        endpoint.set_webtransport_certificate_pem(CA_LEAF, CHAIN_KEY),
        Err(SetWebTransportCertificateError::Invalid { reason })
            if reason.contains("does not match")
    ));

    let mut derived = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1/webtransport")
        .expect("WebTransport")
        .bind()
        .expect("bind");
    assert_eq!(
        derived.set_webtransport_certificate_pem(CHAIN, CHAIN_KEY),
        Err(SetWebTransportCertificateError::NotConfigured)
    );
}

#[test]
fn listen_default_binds_dual_stack_quic() {
    let mut endpoint = Endpoint::builder()
        .listen_default()
        .expect("default listen")
        .bind()
        .expect("default dual-stack");
    let addrs = endpoint.listen_all().expect("listen_all");
    assert_eq!(
        addrs.len(),
        2,
        "dual-stack default binds both families: {addrs:?}"
    );
    assert!(
        addrs
            .iter()
            .all(|addr| addr.transport().to_string().contains("/quic-v1")),
        "{addrs:?}"
    );
    let has_v4 = addrs
        .iter()
        .any(|addr| addr.transport().to_string().contains("/ip4/"));
    let has_v6 = addrs
        .iter()
        .any(|addr| addr.transport().to_string().contains("/ip6/"));
    assert!(
        has_v4 && has_v6,
        "default listen binds IPv4 and IPv6: {addrs:?}"
    );
}

#[test]
fn listen_default_rejects_duplicate_quic_family() {
    let ipv4 = "/ip4/127.0.0.1/udp/0/quic-v1".parse().expect("ipv4");
    let Err(error) = Endpoint::builder()
        .listen_on_multiaddr(&ipv4)
        .expect("listen ipv4")
        .listen_default()
    else {
        panic!("listen_default after IPv4 QUIC must fail");
    };
    assert!(
        matches!(
            &error,
            EndpointOptionsError::DuplicateQuicFamily {
                family: IpFamily::Ipv4,
                ..
            }
        ),
        "{error}"
    );
}

#[cfg(feature = "tcp")]
#[test]
fn a_tcp_endpoint_reports_the_port_it_was_given() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
        .expect("bind tcp endpoint");

    let addrs = endpoint.listen_all().expect("listen");
    assert_eq!(addrs.len(), 1, "one transport, one address: {addrs:?}");
    let port = tcp_port(&addrs[0]);
    assert_ne!(
        port, 0,
        "an ephemeral bind reports the port it actually got"
    );
    assert_eq!(
        addrs[0].transport().to_string(),
        format!("/ip4/127.0.0.1/tcp/{port}"),
        "the host asked for is the host reported, and nothing is added to it"
    );
    assert_eq!(addrs[0].peer_id(), endpoint.peer_id());
}

#[cfg(feature = "tcp")]
#[test]
fn every_bound_transport_reports_where_it_listens() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
        .expect("bind both");

    let reported: Vec<String> = endpoint
        .listen_all()
        .expect("listen")
        .iter()
        .map(|addr| addr.transport().to_string())
        .collect();
    assert_eq!(reported.len(), 2, "one per transport: {reported:?}");
    assert!(
        reported.iter().any(|addr| addr.contains("/quic-v1")),
        "{reported:?}"
    );
    assert!(
        reported.iter().any(|addr| addr.contains("/tcp/")),
        "{reported:?}"
    );
}

#[cfg(feature = "tcp")]
#[test]
fn a_second_tcp_address_joins_the_transport_that_already_serves_tcp() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
        .expect("both tcp addresses bind");
    let addrs = endpoint.listen_all().expect("listen");
    assert_eq!(addrs.len(), 2, "both addresses are listening: {addrs:?}");
    assert_ne!(
        tcp_port(&addrs[0]),
        tcp_port(&addrs[1]),
        "two binds, two sockets"
    );

    let second = addrs[1].clone();
    let _driver = Driven::new(endpoint);
    let mut dialer = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
        .expect("bind dialer");
    dialer
        .connect(second.clone())
        .expect("connect to the second address");
    wait_for(
        &mut dialer,
        "connection",
        |event| matches!(event, EndpointEvent::ConnectionEstablished { peer_id, .. } if peer_id == second.peer_id()),
    );
}

#[cfg(feature = "tcp")]
#[test]
fn listening_arms_every_bound_transport_not_just_the_first() {
    let mut listener = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind both");
    let bound = listener
        .core()
        .transport()
        .local_addresses()
        .into_iter()
        .find(|addr| addr.to_string().contains("quic"))
        .expect("a bound quic socket");
    let quic_addr = PeerAddr::new(bound, *listener.peer_id()).expect("target");
    let first = listener.listen().expect("listen returns the first address");
    assert!(
        first.transport().to_string().contains("/tcp/"),
        "the returned address is the first bound one: {first:?}"
    );
    let _driver = Driven::new(listener);

    let mut dialer = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind dialer");
    dialer.connect(&quic_addr).expect("connect");
    wait_for(
        &mut dialer,
        "connection",
        |event| matches!(event, EndpointEvent::ConnectionEstablished { peer_id, .. } if peer_id == quic_addr.peer_id()),
    );
}

#[cfg(feature = "tcp")]
#[test]
fn a_peer_is_reached_over_the_transport_its_address_names() {
    let mut over_tcp = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
        .expect("bind tcp peer");
    let mut over_quic = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind quic peer");
    let tcp_addr = over_tcp.listen().expect("tcp peer listens");
    let quic_addr = over_quic.listen().expect("quic peer listens");

    let mut dialer = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
        .expect("bind dialer");
    let _drivers = (Driven::new(over_tcp), Driven::new(over_quic));

    for (addr, expected) in [
        (&tcp_addr, ConnectionNamespace::TCP_IPV4),
        (&quic_addr, ConnectionNamespace::QUIC_IPV4),
    ] {
        dialer.connect(addr).expect("connect");
        let event = wait_for(
            &mut dialer,
            "connection",
            |event| matches!(event, EndpointEvent::ConnectionEstablished { peer_id, .. } if peer_id == addr.peer_id()),
        );
        let EndpointEvent::ConnectionEstablished { conn_id, .. } = event else {
            panic!("the connection predicate returned an unrelated event")
        };
        assert_eq!(
            conn_id.namespace(),
            expected,
            "{} should have been carried by {expected}",
            addr.transport()
        );
    }
}

#[cfg(feature = "tcp")]
#[test]
fn tcp_limits_and_namespace_reach_the_transport() {
    let mut endpoint = Endpoint::builder()
        .tcp_config(TcpConfig {
            namespace: ConnectionNamespace::TCP_IPV6,
            ..TcpConfig::default()
        })
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
        .expect("bind tcp endpoint");
    let target = PeerAddr::new(
        "/ip4/127.0.0.1/tcp/1".parse().expect("address"),
        Ed25519Keypair::generate().peer_id(),
    )
    .expect("target");

    let id = endpoint.core_mut().dial(&target).expect("the dial starts");
    assert_eq!(id.namespace(), ConnectionNamespace::TCP_IPV6);
}

#[cfg(feature = "tcp")]
#[test]
fn a_tcp_config_that_breaks_the_yamux_invariants_is_refused_at_bind() {
    let mut config = TcpConfig::default();
    config.yamux.max_frame_len = 0;
    let Err(error) = Endpoint::builder()
        .tcp_config(config)
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
    else {
        panic!("a zero frame length cannot work");
    };
    assert!(
        matches!(
            error,
            BindError::Options(EndpointOptionsError::InvalidLimit(InvalidLimit {
                field: "TcpConfig::yamux",
                ..
            }))
        ),
        "got {error}"
    );
}

#[cfg(all(feature = "relay", feature = "quic"))]
#[test]
fn circuit_limits_that_break_the_yamux_invariants_are_refused_at_bind() {
    let mut limits = CircuitLimits::default();
    limits.yamux.max_frame_len = 0;
    let Err(error) = Endpoint::builder()
        .circuit_limits(limits)
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
    else {
        panic!("a zero frame length cannot work");
    };
    assert!(
        matches!(
            error,
            BindError::Options(EndpointOptionsError::InvalidLimit(InvalidLimit {
                field: "CircuitLimits::yamux",
                ..
            }))
        ),
        "got {error}"
    );
}

#[cfg(feature = "tcp")]
#[test]
fn a_tcp_transport_tagged_for_another_carrier_is_refused() {
    let Err(error) = Endpoint::builder()
        .tcp_config(TcpConfig {
            namespace: ConnectionNamespace::QUIC_IPV4,
            ..TcpConfig::default()
        })
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
    else {
        panic!("a tcp transport must not claim another transport's ids");
    };
    assert!(
        matches!(
            error,
            BindError::Options(EndpointOptionsError::TcpNamespace {
                namespace: ConnectionNamespace::QUIC_IPV4
            })
        ),
        "got {error}"
    );
}
