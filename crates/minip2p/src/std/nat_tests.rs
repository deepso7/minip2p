//! Standard Endpoint NAT regression tests.
use minip2p_core::Multiaddr;
use minip2p_nat::{NatAction, NatAgent, NatEvent, Now};
use minip2p_platform::StdEntropy;
use minip2p_swarm::SwarmEvent;
use minip2p_transport::Transport;
use minip2p_transport::{Bytes, ConnectionId, StreamId};
use std::time::Instant;
type NatDriver = crate::nat::NatDriver<StdEntropy>;
use super::NextEvent;
#[cfg(all(feature = "quic", feature = "relay-server"))]
use crate::QuicLimits;
use crate::{Ed25519Keypair, Endpoint, EndpointEvent, NatConfig, ReachabilityState};
use minip2p_nat::{DialStart, NatSwarm, NatSwarmError, NatToken, ReservationPolicy};
use minip2p_relay::{HOP_PROTOCOL_ID, HopMessage, HopMessageType, Status, encode_frame};

/// Shares the loopback relay application with the integration tests; it is
/// written against the public `minip2p` API (see `extern crate self` in
/// `lib.rs`).
#[path = "../../../../tests/support/relay.rs"]
mod relay_support;

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
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind relay");
    let relay_addr = relay.listen().expect("relay listens");
    let mut local = Endpoint::builder()
        .identity(Ed25519Keypair::from_secret_key_bytes([71; 32]))
        .protocol(HOP_PROTOCOL_ID)
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind local");
    let local_addr = local.listen().expect("local listens");
    local
        .swarm
        .core_mut()
        .dial(&relay_addr)
        .expect("dial relay");

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
                EndpointEvent::ConnectionEstablished { peer_id, conn_id }
                    if peer_id == *relay_addr.peer_id() =>
                {
                    inner_conn = Some(conn_id);
                }
                EndpointEvent::PeerReady { peer_id, .. } if peer_id == *relay_addr.peer_id() => {
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
                EndpointEvent::ConnectionEstablished { peer_id, conn_id }
                    if peer_id == *local.peer_id() =>
                {
                    relay_conn = Some(conn_id);
                }
                EndpointEvent::PeerReady { peer_id, .. } if peer_id == *local.peer_id() => {
                    relay_ready = true;
                }
                _ => {}
            }
        }
    }
    let inner_conn = inner_conn.expect("local connection id");
    let relay_conn = relay_conn.expect("relay connection id");
    let (_, stream) = local
        .open_stream(relay_addr.peer_id(), HOP_PROTOCOL_ID)
        .expect("open bridge stream");
    let mut local_stream_ready = false;
    let mut relay_stream_ready = false;
    while !local_stream_ready || !relay_stream_ready {
        assert!(Instant::now() < deadline, "bridge stream did not negotiate");
        if let Some(EndpointEvent::StreamReady { stream_id, .. }) = local
            .next_event(std::time::Duration::from_millis(10))
            .expect("drive local stream")
            && stream_id == stream
        {
            local_stream_ready = true;
        }
        if let Some(EndpointEvent::StreamReady { stream_id, .. }) = relay
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
        if let Some(EndpointEvent::Nat(event)) = client
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

/// Reads every event `client` already has, keeping the NAT ones.
#[cfg(all(feature = "quic", feature = "relay-server"))]
fn drain_nat_events(client: &mut Endpoint, nat_events: &mut Vec<NatEvent>) {
    while let Some(event) = client
        .next_event(std::time::Duration::ZERO)
        .expect("drain client")
    {
        if let EndpointEvent::Nat(event) = event {
            nat_events.push(event);
        }
    }
}

#[cfg(all(feature = "quic", feature = "relay-server"))]
#[test]
fn idle_quic_relay_reservation_stays_live_past_transport_timeout() {
    // The timeout has to be long enough that a stall cannot expire the relay
    // connection: the transport keeps a quiet connection alive at half of it,
    // so one would have to exceed half of `IDLE_MS`. This test also runs alone
    // (see `.config/nextest.toml`), since it drives both endpoints from one
    // thread.
    const IDLE_MS: u64 = 1_500;
    const KEEPALIVE_MS: u64 = 300;
    /// Failure backstop for a keepalive that never lands, not a window.
    const BACKSTOP: std::time::Duration = std::time::Duration::from_secs(10);

    let limits = QuicLimits {
        idle_timeout_ms: IDLE_MS,
        ..QuicLimits::default()
    };
    let mut relay = Endpoint::builder()
        .identity(Ed25519Keypair::from_secret_key_bytes([82; 32]))
        .quic_limits(limits.clone())
        .relay_server()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind relay");
    let relay_addr = relay.listen().expect("relay listens");
    let mut client = Endpoint::builder()
        .identity(Ed25519Keypair::from_secret_key_bytes([81; 32]))
        .quic_limits(limits)
        .nat_config(NatConfig {
            relays: vec![relay_addr.clone()],
            reservation_policy: ReservationPolicy::Always,
            reservation_keep_alive_interval_ms: KEEPALIVE_MS,
            ..NatConfig::default()
        })
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind client");

    let mut reservation_events = drive_until_reserved(&mut client, &mut relay, "QUIC");

    // Drive until a ping round trip completes after the transport timeout
    // would have expired an untouched connection. That ping proves the relay
    // connection outlived the timeout, so the loop ends on it rather than on a
    // fixed window.
    //
    // A ping is counted when it is read, not when it completed, so a stall
    // across the mark could hand over one that finished before it. Crossing
    // the mark therefore drains everything already queued first; only a round
    // trip read after that can end the loop.
    let past_idle = Instant::now() + std::time::Duration::from_millis(IDLE_MS);
    let backstop = Instant::now() + BACKSTOP;
    let mut drained_at_mark = false;
    let mut pinged_past_idle = false;
    while !pinged_past_idle {
        assert!(
            Instant::now() < backstop,
            "no ping completed past the {IDLE_MS}ms transport timeout"
        );
        if !drained_at_mark && Instant::now() >= past_idle {
            drain_nat_events(&mut client, &mut reservation_events);
            drained_at_mark = true;
        }
        match client
            .next_event(std::time::Duration::from_millis(10))
            .expect("drive client")
        {
            Some(EndpointEvent::PingRttMeasured { .. }) => pinged_past_idle = drained_at_mark,
            Some(EndpointEvent::Nat(event)) => reservation_events.push(event),
            _ => {}
        }
        match relay
            .next_event(std::time::Duration::from_millis(10))
            .expect("drive relay")
        {
            Some(_) | None => {}
        }
    }

    // A loss can be queued behind the ping that ended the loop. Drain the
    // client before judging rather than reading state the last poll never
    // caught up with.
    drain_nat_events(&mut client, &mut reservation_events);

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
            Some(EndpointEvent::Nat(NatEvent::RelayReservationLost { .. })) => lost = true,
            Some(EndpointEvent::Nat(NatEvent::RelayReserved { .. })) if lost => reacquired = true,
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

#[cfg(feature = "relay-server")]
#[test]
fn a_relay_configured_by_name_is_resolved_off_the_driver_and_reserved() {
    // The transports refuse `/dns*`, so a relay dial reaches one only
    // because the endpoint resolved the name first.
    let mut relay = Endpoint::builder()
        .identity(Ed25519Keypair::from_secret_key_bytes([86; 32]))
        .relay_server()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind relay");
    let relay_addr = relay.listen().expect("relay listens");
    let mut protocols = relay_addr.transport().protocols().to_vec();
    *protocols.first_mut().expect("a host") = minip2p_core::Protocol::Dns4("localhost".to_string());
    let named = minip2p_core::PeerAddr::new(
        Multiaddr::from_protocols(protocols),
        relay_addr.peer_id().clone(),
    )
    .expect("named relay addr");
    let mut client = Endpoint::builder()
        .identity(Ed25519Keypair::from_secret_key_bytes([85; 32]))
        .nat_config(NatConfig {
            relays: vec![named],
            reservation_policy: ReservationPolicy::Always,
            ..NatConfig::default()
        })
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind client");

    drive_until_reserved(&mut client, &mut relay, "QUIC");
}

#[cfg(all(feature = "relay-server", feature = "tcp"))]
#[test]
fn tcp_relay_reservation_does_not_schedule_liveness_pings() {
    let mut relay = Endpoint::builder()
        .identity(Ed25519Keypair::from_secret_key_bytes([84; 32]))
        .relay_server()
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
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
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
        .expect("bind TCP client");

    drive_until_reserved(&mut client, &mut relay, "TCP");

    let observe_until = Instant::now() + std::time::Duration::from_millis(250);
    while Instant::now() < observe_until {
        assert!(
            !matches!(
                client
                    .next_event(std::time::Duration::from_millis(10))
                    .expect("drive TCP client"),
                Some(EndpointEvent::PingRttMeasured { .. })
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

/// A swarm already holding the negotiated bridge: the relay is ready on
/// the pair's inner connection, and the one stream it opens is the pair's.
struct BridgeSwarm {
    relay: minip2p_core::PeerId,
    conn: ConnectionId,
    stream: StreamId,
    protocols: Vec<String>,
}

impl NatSwarm for BridgeSwarm {
    fn connection(&self, peer: &minip2p_core::PeerId) -> Option<ConnectionId> {
        (*peer == self.relay).then_some(self.conn)
    }

    fn readiness(&self, peer: &minip2p_core::PeerId) -> Option<(ConnectionId, &[String])> {
        (*peer == self.relay).then_some((self.conn, self.protocols.as_slice()))
    }

    fn dial(
        &mut self,
        addr: &minip2p_core::PeerAddr,
        _token: NatToken,
    ) -> Result<DialStart, NatSwarmError> {
        Err(NatSwarmError::NamedAddress(addr.clone()))
    }

    fn open_stream(
        &mut self,
        _peer: &minip2p_core::PeerId,
        _protocol_id: &str,
        _now_ms: u64,
    ) -> Result<(ConnectionId, StreamId), NatSwarmError> {
        Ok((self.conn, self.stream))
    }

    fn send_stream(
        &mut self,
        _peer: &minip2p_core::PeerId,
        _conn_id: ConnectionId,
        _stream_id: StreamId,
        _data: Bytes,
        _now_ms: u64,
    ) -> Result<(), NatSwarmError> {
        Ok(())
    }

    fn close_stream_write(
        &mut self,
        _peer: &minip2p_core::PeerId,
        _conn_id: ConnectionId,
        _stream_id: StreamId,
        _now_ms: u64,
    ) -> Result<(), NatSwarmError> {
        Ok(())
    }

    fn reset_stream(
        &mut self,
        _peer: &minip2p_core::PeerId,
        _conn_id: ConnectionId,
        _stream_id: StreamId,
        _now_ms: u64,
    ) -> Result<(), NatSwarmError> {
        Ok(())
    }

    fn ping(&mut self, _peer: &minip2p_core::PeerId, _now_ms: u64) -> Result<(), NatSwarmError> {
        Ok(())
    }
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
    let mut swarm = BridgeSwarm {
        relay: relay_peer.clone(),
        conn: pair.inner_conn,
        stream: pair.stream,
        protocols: vec![HOP_PROTOCOL_ID.to_string()],
    };
    let mut agent = NatAgent::new(pair.local.peer_id().clone(), config);
    agent.connect(
        &mut swarm,
        minip2p_core::ConnectId::from_u64(1),
        target,
        minip2p_nat::ConnectLegs {
            direct_racing: false,
            allow_relay: true,
            target_addrs: Vec::new(),
            deadline_ms: None,
        },
        Now::from_mono(0),
    );
    assert!(agent.owns_stream(&relay_peer, pair.stream));
    agent.handle_event(
        &mut swarm,
        &SwarmEvent::StreamReady {
            peer_id: relay_peer.clone(),
            conn_id: pair.inner_conn,
            stream_id: pair.stream,
            protocol_id: HOP_PROTOCOL_ID.to_string(),
            initiated_locally: true,
        },
        false,
        Now::from_mono(5),
    );
    let status = HopMessage {
        kind: HopMessageType::Status,
        peer: None,
        reservation: None,
        limit: None,
        status: Some(Status::Ok),
    };
    agent.handle_event(
        &mut swarm,
        &SwarmEvent::StreamData {
            peer_id: relay_peer.clone(),
            conn_id: pair.inner_conn,
            stream_id: pair.stream,
            data: Bytes::from(encode_frame(&status.encode())),
        },
        false,
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
    driver.execute(action, endpoint.swarm.core_mut(), now);
}

fn circuit_id(driver: &NatDriver, key: (ConnectionId, StreamId)) -> ConnectionId {
    *driver.promoted().get(&key).expect("promoted bridge entry")
}

#[test]
fn autonat_listen_addrs_stay_empty_until_a_listener_is_bound() {
    let mut endpoint = Endpoint::builder()
        .nat_config(NatConfig::default())
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
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
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
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
fn driver_promotes_idempotently_routes_exact_stragglers_and_closes_idempotently() {
    let mut pair = negotiated_bridge();
    let key = (pair.inner_conn, pair.stream);
    let (mut driver, promotion) = promotion_driver(&pair, false);
    let duplicate = promotion.clone();

    execute(&mut driver, promotion, &mut pair.local);
    let promoted = circuit_id(&driver, key);
    assert_eq!(
        pair.local.swarm.core().transport().circuit_ids(),
        vec![promoted]
    );

    execute(&mut driver, duplicate, &mut pair.local);
    assert_eq!(driver.promoted().len(), 1);
    assert_eq!(
        pair.local.swarm.core().transport().circuit_ids(),
        vec![promoted]
    );
    assert!(driver.bridge_reset_attempts.is_empty());

    let mut header = vec![19];
    header.extend_from_slice(b"/multistream/1.0.0\n");
    assert!(driver.ingest(
        &SwarmEvent::StreamData {
            peer_id: pair.relay_addr.peer_id().clone(),
            conn_id: pair.inner_conn,
            stream_id: pair.stream,
            data: Bytes::from(header),
        },
        pair.local.swarm.core_mut(),
        minip2p_platform::Now::from_millis(10),
    ));
    assert!(driver.promoted().contains_key(&key));
    assert!(!driver.ingest(
        &SwarmEvent::StreamData {
            peer_id: pair.relay_addr.peer_id().clone(),
            conn_id: ConnectionId::new(pair.inner_conn.as_u64() + 100),
            stream_id: pair.stream,
            data: Bytes::from(vec![1]),
        },
        pair.local.swarm.core_mut(),
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
    assert!(driver.promoted().is_empty());
    assert!(pair.local.swarm.core().transport().circuit_ids().is_empty());
    match pair.relay.next_event(std::time::Duration::from_millis(10)) {
        Ok(_) | Err(_) => {}
    }
}

#[test]
fn promotion_uses_action_connection_after_same_batch_relay_replacement() {
    let mut pair = negotiated_bridge();
    let old_conn = pair.inner_conn;
    let stream = pair.stream;
    let relay_peer = pair.relay_addr.peer_id().clone();
    let (mut driver, promotion) = promotion_driver(&pair, false);

    // Replace the relay connection, but stop as soon as both public
    // ConnectionReplaced events have been delivered. At this seam the core
    // points at B while the transport close of A is still deferred.
    pair.relay
        .swarm
        .core_mut()
        .dial(&pair.local_addr)
        .expect("relay dials replacement");
    let deadline = Instant::now() + std::time::Duration::from_secs(5);
    let mut replacement = None;
    let mut relay_established = false;
    while replacement.is_none() || !relay_established {
        assert!(Instant::now() < deadline, "replacement did not establish");
        if replacement.is_none()
            && let Some(EndpointEvent::ConnectionReplaced { peer_id, old, new }) = pair
                .local
                .next_event(std::time::Duration::from_millis(10))
                .expect("drive local replacement")
            && peer_id == relay_peer
        {
            assert_eq!(old, old_conn);
            replacement = Some(new);
        }
        if !relay_established
            && let Some(EndpointEvent::ConnectionReplaced { peer_id, .. }) = pair
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
        pair.local.swarm.core().connection_id(&relay_peer),
        Some(replacement)
    );

    execute(&mut driver, promotion, &mut pair.local);
    assert!(driver.promoted().contains_key(&(old_conn, stream)));
    assert!(!driver.promoted().contains_key(&(replacement, stream)));
    assert!(!driver.ingest(
        &SwarmEvent::StreamData {
            peer_id: relay_peer,
            conn_id: replacement,
            stream_id: stream,
            data: Bytes::from(vec![1]),
        },
        pair.local.swarm.core_mut(),
        minip2p_platform::Now::from_millis(10),
    ));
}

#[test]
fn driver_resets_failed_adoptions_but_not_unknown_connections() {
    let mut failed_pair = negotiated_bridge();
    let failed_key = (failed_pair.inner_conn, failed_pair.stream);
    let (mut failed, action) = promotion_driver(&failed_pair, true);
    execute(&mut failed, action, &mut failed_pair.local);
    assert!(failed.promoted().is_empty());
    assert_eq!(failed.bridge_reset_attempts, vec![failed_key]);

    let mut unknown_pair = negotiated_bridge();
    let (mut unknown, mut action) = promotion_driver(&unknown_pair, false);
    let missing = ConnectionId::new(9_999);
    if let NatAction::PromoteBridge { inner_conn, .. } = &mut action {
        *inner_conn = missing;
    }
    execute(&mut unknown, action, &mut unknown_pair.local);
    assert!(unknown.promoted().is_empty());
    assert!(unknown.bridge_reset_attempts.is_empty());
    assert!(
        unknown_pair
            .local
            .swarm
            .core()
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
        fin_pair.local.swarm.core_mut(),
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
        closed_pair.local.swarm.core_mut(),
        minip2p_platform::Now::from_millis(10),
    ));
    assert!(!closed.promoted().contains_key(&closed_key));

    // An inner relay connection that closes, or is replaced (its streams end
    // with it), drops every circuit riding it.
    for replaced in [false, true] {
        let mut inner_pair = negotiated_bridge();
        let inner_key = (inner_pair.inner_conn, inner_pair.stream);
        let (mut inner, action) = promotion_driver(&inner_pair, false);
        execute(&mut inner, action, &mut inner_pair.local);
        let promoted = circuit_id(&inner, inner_key);
        let peer_id = inner_pair.relay_addr.peer_id().clone();
        let carrier_gone = if replaced {
            SwarmEvent::ConnectionReplaced {
                peer_id,
                old: inner_pair.inner_conn,
                new: ConnectionId::new(9_998),
            }
        } else {
            SwarmEvent::ConnectionClosed {
                peer_id,
                conn_id: inner_pair.inner_conn,
            }
        };
        inner.ingest(
            &carrier_gone,
            inner_pair.local.swarm.core_mut(),
            minip2p_platform::Now::from_millis(10),
        );
        assert!(!inner.promoted().contains_key(&inner_key));
        let events = inner_pair
            .local
            .swarm
            .core_mut()
            .transport_mut()
            .poll(minip2p_platform::Now::from_millis(0))
            .expect("promoted circuit closure");
        assert!(
            events.iter().any(|event| matches!(
                event,
                minip2p_transport::TransportEvent::Closed { id } if *id == promoted
            )),
            "replaced={replaced}"
        );
    }

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
        },
        circuit_pair.local.swarm.core_mut(),
        minip2p_platform::Now::from_millis(10),
    );
    assert!(!circuit.promoted().contains_key(&circuit_key));

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
        .core_mut()
        .transport_mut()
        .close(promoted)
        .expect("transport-side close");
    swept.pump(
        swept_pair.local.swarm.core_mut(),
        minip2p_platform::Now::from_millis(10),
    );
    assert!(swept.promoted().is_empty());
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
        .core_mut()
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
            driver.ingest(&event, pair.local.swarm.core_mut(), now);
        }
    }

    assert!(
        circuit_failed,
        "remote RESET_STREAM did not fail the promoted circuit"
    );
    assert!(!driver.promoted().contains_key(&key));
    assert!(pair.local.swarm.core().transport().circuit_ids().is_empty());
}

#[test]
fn cancel_mid_relay_leg_emits_cancelled_and_closes_circuits() {
    let relay = relay_support::RelayServer::spawn();
    let relay_addr = relay.addr().clone();

    let mut responder = Endpoint::builder()
        .relay(relay_addr.clone())
        .nat_config(NatConfig {
            force_relay: true,
            reservation_policy: ReservationPolicy::Always,
            ..NatConfig::default()
        })
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind responder");
    responder.listen().expect("responder listens");
    let responder_peer = responder.peer_id().clone();

    let reservation_deadline = Instant::now() + std::time::Duration::from_secs(10);
    loop {
        assert!(
            Instant::now() < reservation_deadline,
            "responder did not reserve on relay"
        );
        if let Some(EndpointEvent::Nat(NatEvent::RelayReserved { relay, .. })) = responder
            .next_event(std::time::Duration::from_millis(20))
            .expect("drive responder reservation")
            && &relay == relay_addr.peer_id()
        {
            break;
        }
        relay.assert_healthy();
    }

    let mut initiator = Endpoint::builder()
        .relay(relay_addr)
        .nat_config(NatConfig {
            force_relay: true,
            reservation_policy: ReservationPolicy::Never,
            ..NatConfig::default()
        })
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind initiator");
    initiator.listen().expect("initiator listens");
    let id = initiator
        .connect(&responder_peer)
        .expect("start relay-only connect");
    initiator.cancel_connect(id);

    let deadline = Instant::now() + std::time::Duration::from_secs(5);
    let mut cancelled = false;
    while !cancelled {
        assert!(Instant::now() < deadline, "cancel did not settle");
        if let Some(EndpointEvent::ConnectSettled {
            connect_id,
            outcome: crate::ConnectOutcome::Cancelled,
            ..
        }) = initiator
            .next_event(std::time::Duration::from_millis(20))
            .expect("drive initiator cancel")
            && connect_id == id
        {
            cancelled = true;
        }
        let _ = responder
            .next_event(std::time::Duration::from_millis(20))
            .expect("drive responder");
        relay.assert_healthy();
    }

    assert!(initiator.swarm.core().transport().circuit_ids().is_empty());
    assert!(!initiator.connected_peers().contains(&responder_peer));
}

/// Drives `endpoints` until `condition` holds over the Gossipsub events each
/// one has delivered so far.
#[cfg(feature = "pubsub")]
fn drive_gossipsub_until(
    endpoints: &mut [&mut Endpoint],
    deadline: std::time::Duration,
    mut condition: impl FnMut(&[Vec<crate::GossipsubEvent>]) -> bool,
) {
    let mut all = vec![Vec::new(); endpoints.len()];
    let until = Instant::now() + deadline;
    while !condition(&all) {
        assert!(Instant::now() < until, "condition not met in time: {all:?}");
        for (endpoint, events) in endpoints.iter_mut().zip(&mut all) {
            if let Some(EndpointEvent::Gossipsub(event)) = endpoint
                .next_event(std::time::Duration::from_millis(20))
                .expect("endpoint drives")
            {
                events.push(event);
            }
        }
    }
}

#[cfg(feature = "pubsub")]
fn saw_message(events: &[crate::GossipsubEvent], data: &[u8]) -> bool {
    events.iter().any(
        |e| matches!(e, crate::GossipsubEvent::Message { data: got, .. } if got.as_slice() == data),
    )
}

#[cfg(feature = "pubsub")]
fn saw_subscription(events: &[crate::GossipsubEvent], topic: &str) -> bool {
    events.iter().any(
        |e| matches!(e, crate::GossipsubEvent::PeerSubscribed { topic: got, .. } if got == topic),
    )
}

#[cfg(feature = "pubsub")]
#[test]
fn pubsub_flows_over_relay_and_reannounces_after_direct_replacement() {
    use crate::{GossipsubEvent, Path};
    use std::time::Duration;
    const TOPIC: &str = "loopback-chat";

    let relay = relay_support::RelayServer::spawn();
    let relay_addr = relay.addr().clone();
    let mut b = Endpoint::builder()
        .gossipsub()
        .relay(relay_addr.clone())
        .nat_config(NatConfig {
            force_relay: true,
            reservation_policy: ReservationPolicy::Always,
            ..NatConfig::default()
        })
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind responder");
    let b_addr = b.listen().expect("responder listens");
    let b_peer = b.peer_id().clone();
    b.subscribe(TOPIC).expect("responder subscribes");

    let reserve_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(Instant::now() < reserve_deadline, "reservation timed out");
        if let Some(EndpointEvent::Nat(NatEvent::RelayReserved { relay, .. })) = b
            .next_event(Duration::from_millis(20))
            .expect("drive reservation")
            && &relay == relay_addr.peer_id()
        {
            break;
        }
        relay.assert_healthy();
    }

    let mut a = Endpoint::builder()
        .gossipsub()
        .relay(relay_addr)
        .nat_config(NatConfig {
            force_relay: true,
            reservation_policy: ReservationPolicy::Never,
            ..NatConfig::default()
        })
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind initiator");
    a.listen().expect("initiator listens");
    a.subscribe(TOPIC).expect("initiator subscribes");
    a.connect(&b_peer).expect("relay-only connect");

    drive_gossipsub_until(&mut [&mut a, &mut b], Duration::from_secs(15), |all| {
        saw_subscription(&all[0], TOPIC) && saw_subscription(&all[1], TOPIC)
    });
    // `drive` consumed the NAT path event; the State snapshot keeps the truth.
    assert!(matches!(
        a.path(&b_peer),
        Some(Path::Relayed { relay: found_relay }) if &found_relay == relay.addr().peer_id()
    ));
    let circuit_id = *a
        .swarm
        .core()
        .transport()
        .circuit_ids()
        .first()
        .expect("active circuit");

    a.publish(TOPIC, b"over relay").expect("publish over relay");
    drive_gossipsub_until(&mut [&mut a, &mut b], Duration::from_secs(10), |all| {
        saw_message(&all[1], b"over relay")
    });

    // A direct connection replaces the ready circuit. The public sequence is
    // one ConnectionReplaced (never a close or a second establishment), and
    // the pubsub driver must re-open and re-announce subscriptions.
    // A raw swarm dial forces the direct replacement; `connect` would
    // settle against the existing relayed connection.
    a.swarm
        .core_mut()
        .dial(&b_addr)
        .expect("manual direct upgrade");
    let upgrade_deadline = Instant::now() + Duration::from_secs(15);
    let mut a_sequence = Vec::new();
    let mut a_resubscribed = false;
    let mut b_resubscribed = false;
    while !a_resubscribed || !b_resubscribed {
        assert!(
            Instant::now() < upgrade_deadline,
            "pubsub did not recover after replacement: {a_sequence:?}"
        );
        if let Some(event) = a
            .next_event(Duration::from_millis(20))
            .expect("drive initiator upgrade")
        {
            match event {
                EndpointEvent::ConnectionClosed {
                    peer_id, conn_id, ..
                } if peer_id == b_peer => {
                    a_sequence.push(("closed", conn_id, conn_id));
                }
                EndpointEvent::ConnectionEstablished { peer_id, conn_id } if peer_id == b_peer => {
                    a_sequence.push(("established", conn_id, conn_id));
                }
                EndpointEvent::ConnectionReplaced { peer_id, old, new } if peer_id == b_peer => {
                    a_sequence.push(("replaced", old, new));
                }
                EndpointEvent::Gossipsub(GossipsubEvent::PeerSubscribed { topic, .. })
                    if topic == TOPIC =>
                {
                    a_resubscribed = true;
                }
                _ => {}
            }
        }
        if let Some(EndpointEvent::Gossipsub(GossipsubEvent::PeerSubscribed { topic, .. })) = b
            .next_event(Duration::from_millis(20))
            .expect("drive responder upgrade")
            && topic == TOPIC
        {
            b_resubscribed = true;
        }
        relay.assert_healthy();
    }
    assert!(
        matches!(
            a_sequence.as_slice(),
            [("replaced", old, direct)]
                if *old == circuit_id && !direct.is_circuit()
        ),
        "replacement sequence: {a_sequence:?}"
    );
    assert!(a.swarm.core().transport().circuit_ids().is_empty());
    assert_eq!(a.path(&b_peer), Some(Path::DirectDialed));

    a.publish(TOPIC, b"after upgrade")
        .expect("publish after upgrade");
    drive_gossipsub_until(&mut [&mut a, &mut b], Duration::from_secs(10), |all| {
        saw_message(&all[1], b"after upgrade")
    });
}
