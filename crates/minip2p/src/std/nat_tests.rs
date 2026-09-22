//! Standard Endpoint NAT regression tests.
use minip2p_core::Multiaddr;
use minip2p_nat::{NatAction, NatAgent, NatEvent, Now, Path};
use minip2p_platform::StdEntropy;
use minip2p_swarm::SwarmEvent;
use minip2p_transport::Transport;
use minip2p_transport::{ConnectionId, StreamId};
use std::time::Instant;
type NatDriver = crate::nat::NatDriver<StdEntropy>;
#[cfg(all(feature = "quic", feature = "relay-server"))]
use crate::QuicLimits;
use crate::{Ed25519Keypair, Endpoint, Event, NatConfig, ReachabilityState};
use minip2p_nat::{NatToken, ReservationPolicy};
use minip2p_relay::{HOP_PROTOCOL_ID, HopMessage, HopMessageType, Status, encode_frame};

struct BridgePair {
    local: Endpoint,
    relay: Endpoint,
    local_addr: minip2p_core::PeerAddr,
    relay_addr: minip2p_core::PeerAddr,
    inner_conn: ConnectionId,
    relay_conn: ConnectionId,
    stream: StreamId,
}

fn negotiated_bridge() -> BridgePair {
    let mut relay = Endpoint::builder()
        .identity(Ed25519Keypair::from_secret_key_bytes([72; 32]))
        .protocol(HOP_PROTOCOL_ID)
        .bind_quic("127.0.0.1:0")
        .expect("bind relay");
    let relay_addr = relay.listen().expect("relay listens");
    let mut local = Endpoint::builder()
        .identity(Ed25519Keypair::from_secret_key_bytes([71; 32]))
        .protocol(HOP_PROTOCOL_ID)
        .bind_quic("127.0.0.1:0")
        .expect("bind local");
    let local_addr = local.listen().expect("local listens");
    local.dial(&relay_addr).expect("dial relay");

    let deadline = Instant::now() + std::time::Duration::from_secs(5);
    let mut inner_conn = None;
    let mut relay_conn = None;
    let mut local_ready = false;
    let mut relay_ready = false;
    while !local_ready || !relay_ready {
        assert!(
            Instant::now() < deadline,
            "relay session did not become ready"
        );
        if let Some(event) = local
            .next_event(std::time::Duration::from_millis(10))
            .expect("drive local")
        {
            match event {
                Event::ConnectionEstablished { peer_id, conn_id }
                    if peer_id == *relay_addr.peer_id() =>
                {
                    inner_conn = Some(conn_id);
                }
                Event::PeerReady { peer_id, .. } if peer_id == *relay_addr.peer_id() => {
                    local_ready = true;
                }
                _ => {}
            }
        }
        if let Some(event) = relay
            .next_event(std::time::Duration::from_millis(10))
            .expect("drive relay")
        {
            match event {
                Event::ConnectionEstablished { peer_id, conn_id }
                    if peer_id == *local.peer_id() =>
                {
                    relay_conn = Some(conn_id);
                }
                Event::PeerReady { peer_id, .. } if peer_id == *local.peer_id() => {
                    relay_ready = true;
                }
                _ => {}
            }
        }
    }
    let inner_conn = inner_conn.expect("local connection id");
    let relay_conn = relay_conn.expect("relay connection id");
    let stream = local
        .open_stream(relay_addr.peer_id(), HOP_PROTOCOL_ID)
        .expect("open bridge stream");
    let mut local_stream_ready = false;
    let mut relay_stream_ready = false;
    while !local_stream_ready || !relay_stream_ready {
        assert!(Instant::now() < deadline, "bridge stream did not negotiate");
        if let Some(Event::StreamReady { stream_id, .. }) = local
            .next_event(std::time::Duration::from_millis(10))
            .expect("drive local stream")
            && stream_id == stream
        {
            local_stream_ready = true;
        }
        if let Some(Event::StreamReady { stream_id, .. }) = relay
            .next_event(std::time::Duration::from_millis(10))
            .expect("drive relay stream")
            && stream_id == stream
        {
            relay_stream_ready = true;
        }
    }
    BridgePair {
        local,
        relay,
        local_addr,
        relay_addr,
        inner_conn,
        relay_conn,
        stream,
    }
}

#[cfg(feature = "relay-server")]
/// Drives until the client holds a reservation; returns the NAT events
/// the client's Endpoint event stream delivered meanwhile.
fn drive_until_reserved(
    client: &mut Endpoint,
    relay: &mut Endpoint,
    transport: &str,
) -> Vec<NatEvent> {
    let deadline = Instant::now() + std::time::Duration::from_secs(5);
    let mut nat_events = Vec::new();
    while client.active_reservation().is_none() {
        assert!(
            Instant::now() < deadline,
            "client did not acquire {transport} relay reservation"
        );
        if let Some(Event::Nat(event)) = client
            .next_event(std::time::Duration::from_millis(10))
            .expect("drive reservation client")
        {
            nat_events.push(event);
        }
        match relay
            .next_event(std::time::Duration::from_millis(10))
            .expect("drive reservation relay")
        {
            Some(_) | None => {}
        }
    }
    nat_events
}

#[cfg(all(feature = "quic", feature = "relay-server"))]
#[test]
fn idle_quic_relay_reservation_stays_live_past_transport_timeout() {
    let limits = QuicLimits {
        idle_timeout_ms: 300,
        ..QuicLimits::default()
    };
    let mut relay = Endpoint::builder()
        .identity(Ed25519Keypair::from_secret_key_bytes([82; 32]))
        .quic_limits(limits.clone())
        .relay_server()
        .bind_quic("127.0.0.1:0")
        .expect("bind relay");
    let relay_addr = relay.listen().expect("relay listens");
    let mut client = Endpoint::builder()
        .identity(Ed25519Keypair::from_secret_key_bytes([81; 32]))
        .quic_limits(limits)
        .nat_config(NatConfig {
            relays: vec![relay_addr.clone()],
            reservation_policy: ReservationPolicy::Always,
            reservation_keep_alive_interval_ms: 100,
            ..NatConfig::default()
        })
        .bind_quic("127.0.0.1:0")
        .expect("bind client");

    let mut reservation_events = drive_until_reserved(&mut client, &mut relay, "QUIC");

    let observe_until = Instant::now() + std::time::Duration::from_millis(1_200);
    let mut ping_rtts = 0;
    while Instant::now() < observe_until {
        match client
            .next_event(std::time::Duration::from_millis(10))
            .expect("drive client")
        {
            Some(Event::PingRttMeasured { .. }) => ping_rtts += 1,
            Some(Event::Nat(event)) => reservation_events.push(event),
            _ => {}
        }
        match relay
            .next_event(std::time::Duration::from_millis(10))
            .expect("drive relay")
        {
            Some(_) | None => {}
        }
    }

    reservation_events.extend(client.take_nat_events());
    assert!(ping_rtts > 0, "reservation liveness should send QUIC pings");
    assert!(client.active_reservation().is_some());
    assert_eq!(
        reservation_events
            .iter()
            .filter(|event| matches!(event, NatEvent::RelayReserved { .. }))
            .count(),
        1,
        "an idle reservation must not be reacquired"
    );
    assert!(
        !reservation_events
            .iter()
            .any(|event| matches!(event, NatEvent::RelayReservationLost { .. })),
        "an idle reservation must not be reported lost"
    );

    relay
        .disconnect(&client.peer_id().clone())
        .expect("disconnect reservation owner");
    let reconnect_deadline = Instant::now() + std::time::Duration::from_secs(5);
    let mut lost = false;
    let mut reacquired = false;
    while !reacquired {
        assert!(
            Instant::now() < reconnect_deadline,
            "genuine relay loss did not trigger reacquisition"
        );
        match client
            .next_event(std::time::Duration::from_millis(10))
            .expect("drive reconnecting client")
        {
            Some(Event::Nat(NatEvent::RelayReservationLost { .. })) => lost = true,
            Some(Event::Nat(NatEvent::RelayReserved { .. })) if lost => reacquired = true,
            _ => {}
        }
        match relay
            .next_event(std::time::Duration::from_millis(10))
            .expect("drive relay after disconnect")
        {
            Some(_) | None => {}
        }
    }
    assert!(lost, "genuine relay loss must remain observable");
}

#[cfg(all(feature = "relay-server", feature = "tcp"))]
#[test]
fn tcp_relay_reservation_does_not_schedule_liveness_pings() {
    let mut relay = Endpoint::builder()
        .identity(Ed25519Keypair::from_secret_key_bytes([84; 32]))
        .relay_server()
        .bind_tcp("127.0.0.1:0")
        .expect("bind TCP relay");
    let relay_addr = relay.listen().expect("TCP relay listens");
    let mut client = Endpoint::builder()
        .identity(Ed25519Keypair::from_secret_key_bytes([83; 32]))
        .nat_config(NatConfig {
            relays: vec![relay_addr],
            reservation_policy: ReservationPolicy::Always,
            reservation_keep_alive_interval_ms: 25,
            ..NatConfig::default()
        })
        .bind_tcp("127.0.0.1:0")
        .expect("bind TCP client");

    drive_until_reserved(&mut client, &mut relay, "TCP");

    let observe_until = Instant::now() + std::time::Duration::from_millis(250);
    while Instant::now() < observe_until {
        assert!(
            !matches!(
                client
                    .next_event(std::time::Duration::from_millis(10))
                    .expect("drive TCP client"),
                Some(Event::PingRttMeasured { .. })
            ),
            "TCP reservation behavior must not gain automatic pings"
        );
        match relay
            .next_event(std::time::Duration::from_millis(10))
            .expect("drive TCP relay")
        {
            Some(_) | None => {}
        }
    }
    assert!(client.active_reservation().is_some());
}

fn drain_actions(agent: &mut NatAgent) -> Vec<NatAction> {
    core::iter::from_fn(|| agent.poll_action()).collect()
}

fn only_dial_token(actions: &[NatAction]) -> NatToken {
    actions
        .iter()
        .find_map(|action| match action {
            NatAction::Dial { token, .. } => Some(*token),
            _ => None,
        })
        .expect("dial token")
}

fn only_open_token(actions: &[NatAction]) -> NatToken {
    actions
        .iter()
        .find_map(|action| match action {
            NatAction::OpenStream { token, .. } => Some(*token),
            _ => None,
        })
        .expect("open token")
}

fn promotion_driver(pair: &BridgePair, remote_write_closed: bool) -> (NatDriver, NatAction) {
    let target = Ed25519Keypair::from_secret_key_bytes([73; 32]).peer_id();
    let relay_peer = pair.relay_addr.peer_id().clone();
    let config = NatConfig {
        relays: vec![pair.relay_addr.clone()],
        force_relay: true,
        reservation_policy: ReservationPolicy::Never,
        ..NatConfig::default()
    };
    let mut agent = NatAgent::new(pair.local.peer_id().clone(), config);
    agent.connect(
        minip2p_core::ConnectId::from_u64(1),
        target,
        minip2p_nat::ConnectLegs {
            direct_racing: false,
            allow_relay: true,
        },
        Now::from_mono(0),
    );
    let dial = drain_actions(&mut agent);
    agent.dial_result(
        only_dial_token(&dial),
        Ok(pair.inner_conn),
        Now::from_mono(1),
    );
    agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            peer_id: relay_peer.clone(),
            conn_id: pair.inner_conn,
        },
        Now::from_mono(2),
    );
    agent.handle_event(
        &SwarmEvent::PeerReady {
            peer_id: relay_peer.clone(),
            protocols: vec![HOP_PROTOCOL_ID.to_string()],
        },
        Now::from_mono(3),
    );
    let open = drain_actions(&mut agent);
    agent.stream_open_result(only_open_token(&open), Ok(pair.stream), Now::from_mono(4));
    agent.handle_event(
        &SwarmEvent::StreamReady {
            peer_id: relay_peer.clone(),
            conn_id: pair.inner_conn,
            stream_id: pair.stream,
            protocol_id: HOP_PROTOCOL_ID.to_string(),
            initiated_locally: true,
        },
        Now::from_mono(5),
    );
    drain_actions(&mut agent); // HOP CONNECT
    let status = HopMessage {
        kind: HopMessageType::Status,
        peer: None,
        reservation: None,
        limit: None,
        status: Some(Status::Ok),
    };
    agent.handle_event(
        &SwarmEvent::StreamData {
            peer_id: relay_peer.clone(),
            conn_id: pair.inner_conn,
            stream_id: pair.stream,
            data: encode_frame(&status.encode()),
        },
        Now::from_mono(6),
    );
    let mut promotion = drain_actions(&mut agent)
        .into_iter()
        .find(|action| matches!(action, NatAction::PromoteBridge { .. }))
        .expect("promotion action");
    if let NatAction::PromoteBridge {
        remote_write_closed: closed,
        ..
    } = &mut promotion
    {
        *closed = remote_write_closed;
    }
    let driver = NatDriver::new(
        agent,
        vec![(relay_peer, pair.relay_addr.transport().clone())],
        StdEntropy,
    );
    (driver, promotion)
}

fn execute(driver: &mut NatDriver, action: NatAction, endpoint: &mut Endpoint) {
    let now = endpoint.swarm.now();
    driver.execute(action, endpoint.swarm.runtime_mut(), now);
}

fn circuit_id(driver: &NatDriver, key: (ConnectionId, StreamId)) -> ConnectionId {
    *driver.promoted.get(&key).expect("promoted bridge entry")
}

#[test]
fn autonat_listen_addrs_stay_empty_until_a_listener_is_bound() {
    let mut endpoint = Endpoint::builder()
        .nat_config(NatConfig::default())
        .bind_quic("127.0.0.1:0")
        .expect("bind endpoint");
    // QUIC reports its bound socket from `local_addresses` even before
    // `listen` runs, and the socket drops Initials until then — AutoNAT
    // must not offer it for dial-back or it would be judged Private.
    endpoint
        .next_event(std::time::Duration::from_millis(10))
        .expect("drive endpoint");
    assert!(
        endpoint.nat.as_ref().unwrap().listen_addrs().is_empty(),
        "bound-but-not-listening socket must not seed AutoNAT"
    );

    endpoint.listen().expect("listen");
    endpoint
        .next_event(std::time::Duration::from_millis(10))
        .expect("drive endpoint");
    assert_eq!(endpoint.nat.as_ref().unwrap().listen_addrs().len(), 1);
}

#[test]
fn confirmed_public_addresses_are_advertised_and_cleared() {
    let mut endpoint = Endpoint::builder()
        .nat_config(NatConfig::default())
        .bind_quic("127.0.0.1:0")
        .expect("bind endpoint");
    let public: Multiaddr = "/ip4/203.0.113.9/udp/4001/quic-v1"
        .parse()
        .expect("public addr");
    endpoint
        .nat
        .as_mut()
        .expect("NAT configured")
        .observe(&NatEvent::ReachabilityChanged {
            old: ReachabilityState::Unknown,
            new: ReachabilityState::Public,
            confirmed_addrs: vec![public.clone()],
        });
    endpoint.refresh_external_address_contributions();
    endpoint.swarm.poll().expect("refresh identify addresses");
    assert!(endpoint.swarm.core().local_addresses().contains(&public));

    endpoint
        .nat
        .as_mut()
        .expect("NAT configured")
        .observe(&NatEvent::ReachabilityChanged {
            old: ReachabilityState::Public,
            new: ReachabilityState::Private,
            confirmed_addrs: Vec::new(),
        });
    endpoint.refresh_external_address_contributions();
    endpoint.swarm.poll().expect("refresh identify addresses");
    assert!(!endpoint.swarm.core().local_addresses().contains(&public));
}

#[test]
fn endpoint_path_tracks_outbound_and_inbound_establishment_and_upgrade() {
    let mut endpoint = Endpoint::builder()
        .nat_config(NatConfig::default())
        .bind_quic("127.0.0.1:0")
        .expect("bind endpoint");
    let peer = Ed25519Keypair::from_secret_key_bytes([74; 32]).peer_id();
    let inbound = Ed25519Keypair::from_secret_key_bytes([75; 32]).peer_id();
    let relay = Ed25519Keypair::from_secret_key_bytes([76; 32]).peer_id();

    {
        let driver = endpoint.nat.as_mut().expect("NAT configured");
        let connect_id = minip2p_core::ConnectId::from_u64(1);
        driver.observe(&NatEvent::PathEstablished {
            connect_id,
            peer: peer.clone(),
            path: Path::Relayed {
                relay: relay.clone(),
            },
        });
    }
    assert_eq!(
        endpoint.path(&peer),
        Some(Path::Relayed {
            relay: relay.clone()
        })
    );

    {
        let driver = endpoint.nat.as_mut().expect("NAT configured");
        let connect_id = minip2p_core::ConnectId::from_u64(1);
        driver.observe(&NatEvent::PathUpgraded {
            connect_id,
            peer: peer.clone(),
            from: Path::Relayed {
                relay: relay.clone(),
            },
            to: Path::DirectPunched,
        });
        driver.observe(&NatEvent::InboundPathEstablished {
            peer: inbound.clone(),
            path: Path::Relayed {
                relay: relay.clone(),
            },
        });
    }
    assert_eq!(
        endpoint.path(&inbound),
        Some(Path::Relayed {
            relay: relay.clone()
        })
    );

    {
        let driver = endpoint.nat.as_mut().expect("NAT configured");
        driver.observe(&NatEvent::InboundDirectUpgrade {
            peer: inbound.clone(),
        });
    }
    assert_eq!(endpoint.path(&peer), Some(Path::DirectPunched));
    assert_eq!(endpoint.path(&inbound), Some(Path::DirectPunched));
}

#[test]
fn driver_promotes_idempotently_routes_exact_stragglers_and_closes_idempotently() {
    let mut pair = negotiated_bridge();
    let key = (pair.inner_conn, pair.stream);
    let (mut driver, promotion) = promotion_driver(&pair, false);
    let duplicate = promotion.clone();

    execute(&mut driver, promotion, &mut pair.local);
    let promoted = circuit_id(&driver, key);
    assert_eq!(pair.local.swarm.transport().circuit_ids(), vec![promoted]);

    execute(&mut driver, duplicate, &mut pair.local);
    assert_eq!(driver.promoted.len(), 1);
    assert_eq!(pair.local.swarm.transport().circuit_ids(), vec![promoted]);
    assert!(driver.bridge_reset_attempts.is_empty());

    let mut header = vec![19];
    header.extend_from_slice(b"/multistream/1.0.0\n");
    assert!(driver.ingest(
        &SwarmEvent::StreamData {
            peer_id: pair.relay_addr.peer_id().clone(),
            conn_id: pair.inner_conn,
            stream_id: pair.stream,
            data: header,
        },
        pair.local.swarm.runtime_mut(),
        minip2p_platform::Now::from_millis(10),
    ));
    assert!(driver.promoted.contains_key(&key));
    assert!(!driver.ingest(
        &SwarmEvent::StreamData {
            peer_id: pair.relay_addr.peer_id().clone(),
            conn_id: ConnectionId::new(pair.inner_conn.as_u64() + 100),
            stream_id: pair.stream,
            data: vec![1],
        },
        pair.local.swarm.runtime_mut(),
        minip2p_platform::Now::from_millis(10),
    ));

    execute(
        &mut driver,
        NatAction::CloseCircuit { conn_id: promoted },
        &mut pair.local,
    );
    execute(
        &mut driver,
        NatAction::CloseCircuit { conn_id: promoted },
        &mut pair.local,
    );
    assert!(driver.promoted.is_empty());
    assert!(pair.local.swarm.transport().circuit_ids().is_empty());
    match pair.relay.next_event(std::time::Duration::from_millis(10)) {
        Ok(_) | Err(_) => {}
    }
}

#[test]
fn promotion_uses_action_connection_after_same_batch_relay_supersede() {
    let mut pair = negotiated_bridge();
    let old_conn = pair.inner_conn;
    let stream = pair.stream;
    let relay_peer = pair.relay_addr.peer_id().clone();
    let (mut driver, promotion) = promotion_driver(&pair, false);

    // Establish a replacement relay connection, but stop as soon as both
    // public Established events have been delivered. At this seam the
    // core points at B while its eager close of A is still deferred.
    pair.relay
        .dial(&pair.local_addr)
        .expect("relay dials replacement");
    let deadline = Instant::now() + std::time::Duration::from_secs(5);
    let mut replacement = None;
    let mut relay_established = false;
    while replacement.is_none() || !relay_established {
        assert!(Instant::now() < deadline, "replacement did not establish");
        if replacement.is_none()
            && let Some(Event::ConnectionEstablished { peer_id, conn_id }) = pair
                .local
                .next_event(std::time::Duration::from_millis(10))
                .expect("drive local replacement")
            && peer_id == relay_peer
            && conn_id != old_conn
        {
            replacement = Some(conn_id);
        }
        if !relay_established
            && let Some(Event::ConnectionEstablished { peer_id, .. }) = pair
                .relay
                .next_event(std::time::Duration::from_millis(10))
                .expect("drive relay replacement")
            && peer_id == *pair.local.peer_id()
        {
            relay_established = true;
        }
    }
    let replacement = replacement.expect("replacement connection id");
    assert_eq!(
        pair.local.swarm.core().conn_for(&relay_peer),
        Some(replacement)
    );

    execute(&mut driver, promotion, &mut pair.local);
    assert!(driver.promoted.contains_key(&(old_conn, stream)));
    assert!(!driver.promoted.contains_key(&(replacement, stream)));
    assert!(!driver.ingest(
        &SwarmEvent::StreamData {
            peer_id: relay_peer,
            conn_id: replacement,
            stream_id: stream,
            data: vec![1],
        },
        pair.local.swarm.runtime_mut(),
        minip2p_platform::Now::from_millis(10),
    ));
}

#[test]
fn driver_resets_failed_adoptions_but_not_unknown_connections() {
    let mut failed_pair = negotiated_bridge();
    let failed_key = (failed_pair.inner_conn, failed_pair.stream);
    let (mut failed, action) = promotion_driver(&failed_pair, true);
    execute(&mut failed, action, &mut failed_pair.local);
    assert!(failed.promoted.is_empty());
    assert_eq!(failed.bridge_reset_attempts, vec![failed_key]);

    let mut unknown_pair = negotiated_bridge();
    let (mut unknown, mut action) = promotion_driver(&unknown_pair, false);
    let missing = ConnectionId::new(9_999);
    if let NatAction::PromoteBridge { inner_conn, .. } = &mut action {
        *inner_conn = missing;
    }
    execute(&mut unknown, action, &mut unknown_pair.local);
    assert!(unknown.promoted.is_empty());
    assert!(unknown.bridge_reset_attempts.is_empty());
    assert!(
        unknown_pair
            .local
            .swarm
            .transport()
            .circuit_ids()
            .is_empty()
    );
}

#[test]
fn driver_prunes_promotions_on_every_external_cleanup_path() {
    // A remote bridge FIN is routed through the promoted transport even
    // though the raw stream was forgotten by the swarm at adoption.
    let mut fin_pair = negotiated_bridge();
    let (mut fin, action) = promotion_driver(&fin_pair, false);
    execute(&mut fin, action, &mut fin_pair.local);
    assert!(fin.ingest(
        &SwarmEvent::StreamRemoteWriteClosed {
            peer_id: fin_pair.relay_addr.peer_id().clone(),
            conn_id: fin_pair.inner_conn,
            stream_id: fin_pair.stream,
        },
        fin_pair.local.swarm.runtime_mut(),
        minip2p_platform::Now::from_millis(10),
    ));

    // Exact bridge closure is terminal and removes the keyed adoption.
    let mut closed_pair = negotiated_bridge();
    let closed_key = (closed_pair.inner_conn, closed_pair.stream);
    let (mut closed, action) = promotion_driver(&closed_pair, false);
    execute(&mut closed, action, &mut closed_pair.local);
    assert!(closed.ingest(
        &SwarmEvent::StreamClosed {
            peer_id: closed_pair.relay_addr.peer_id().clone(),
            conn_id: closed_pair.inner_conn,
            stream_id: closed_pair.stream,
        },
        closed_pair.local.swarm.runtime_mut(),
        minip2p_platform::Now::from_millis(10),
    ));
    assert!(!closed.promoted.contains_key(&closed_key));

    // An inner relay connection close drops every circuit riding it.
    let mut inner_pair = negotiated_bridge();
    let inner_key = (inner_pair.inner_conn, inner_pair.stream);
    let (mut inner, action) = promotion_driver(&inner_pair, false);
    execute(&mut inner, action, &mut inner_pair.local);
    let promoted = circuit_id(&inner, inner_key);
    inner.ingest(
        &SwarmEvent::ConnectionClosed {
            peer_id: inner_pair.relay_addr.peer_id().clone(),
            conn_id: inner_pair.inner_conn,
            cause: minip2p_swarm::ConnectionCloseCause::Transport,
        },
        inner_pair.local.swarm.runtime_mut(),
        minip2p_platform::Now::from_millis(10),
    );
    assert!(!inner.promoted.contains_key(&inner_key));
    let events = inner_pair
        .local
        .swarm
        .transport_mut()
        .poll(minip2p_platform::Now::from_millis(0))
        .expect("promoted circuit closure");
    assert!(events.iter().any(
        |event| matches!(event, minip2p_transport::TransportEvent::Closed { id } if *id == promoted)
    ));

    // A circuit lifecycle close also removes its reverse map entry.
    let mut circuit_pair = negotiated_bridge();
    let circuit_key = (circuit_pair.inner_conn, circuit_pair.stream);
    let (mut circuit, action) = promotion_driver(&circuit_pair, false);
    execute(&mut circuit, action, &mut circuit_pair.local);
    let promoted = circuit_id(&circuit, circuit_key);
    circuit.ingest(
        &SwarmEvent::ConnectionClosed {
            peer_id: Ed25519Keypair::from_secret_key_bytes([73; 32]).peer_id(),
            conn_id: promoted,
            cause: minip2p_swarm::ConnectionCloseCause::Transport,
        },
        circuit_pair.local.swarm.runtime_mut(),
        minip2p_platform::Now::from_millis(10),
    );
    assert!(!circuit.promoted.contains_key(&circuit_key));

    // Reconciliation catches transport-side removal even if no lifecycle
    // event passed through the driver.
    let mut swept_pair = negotiated_bridge();
    let swept_key = (swept_pair.inner_conn, swept_pair.stream);
    let (mut swept, action) = promotion_driver(&swept_pair, false);
    execute(&mut swept, action, &mut swept_pair.local);
    let promoted = circuit_id(&swept, swept_key);
    swept_pair
        .local
        .swarm
        .transport_mut()
        .close(promoted)
        .expect("transport-side close");
    swept.pump(
        swept_pair.local.swarm.runtime_mut(),
        minip2p_platform::Now::from_millis(10),
    );
    assert!(swept.promoted.is_empty());
}

#[test]
fn remote_bridge_reset_closes_promoted_circuit() {
    let mut pair = negotiated_bridge();
    let key = (pair.inner_conn, pair.stream);
    let (mut driver, action) = promotion_driver(&pair, false);
    execute(&mut driver, action, &mut pair.local);
    let promoted = circuit_id(&driver, key);

    pair.relay
        .swarm
        .transport_mut()
        .reset_stream(pair.relay_conn, pair.stream)
        .expect("reset bridge at relay");

    let deadline = Instant::now() + std::time::Duration::from_secs(2);
    let mut circuit_failed = false;
    while Instant::now() < deadline && !circuit_failed {
        match pair
            .relay
            .swarm
            .poll_next(std::time::Duration::from_millis(10))
            .expect("drive reset sender")
        {
            Some(_) | None => {}
        }
        if let Some(event) = pair
            .local
            .swarm
            .poll_next(std::time::Duration::from_millis(10))
            .expect("drive reset receiver")
        {
            circuit_failed = matches!(
                &event,
                SwarmEvent::Error(error) if error.conn_id == Some(promoted)
            );
            let now = pair.local.swarm.now();
            driver.ingest(&event, pair.local.swarm.runtime_mut(), now);
        }
    }

    assert!(
        circuit_failed,
        "remote RESET_STREAM did not fail the promoted circuit"
    );
    assert!(!driver.promoted.contains_key(&key));
    assert!(pair.local.swarm.transport().circuit_ids().is_empty());
}
