//! WebTransport on an Endpoint: one socket serves `quic-v1` and WebTransport,
//! WebTransport connections never feed hole punching, and WebTransport
//! addresses are not natively dialable (a connect that mixes them with
//! `/quic-v1` candidates connects over QUIC).

#![cfg(feature = "quic")]

use std::time::{Duration, Instant};

use minip2p::{ConnectOutcome, Endpoint, EndpointEvent, Multiaddr, PeerAddr};
use minip2p_core::platform::{Now, StdEntropy};
use minip2p_identity::Ed25519Keypair;
use minip2p_swarm::{SwarmBuilder, SwarmCore, SwarmEvent};
use minip2p_webtransport::WebTransportClient;

#[path = "../../../tests/support/endpoint.rs"]
mod endpoint_support;
use endpoint_support::NextEvent;

#[expect(dead_code, reason = "shared with the QUIC tests, which use more of it")]
#[path = "../../../transports/quic/tests/common/wt_client.rs"]
mod wt_client;

/// Failure backstop, not a budget the test has to fit in.
const BACKSTOP: Duration = Duration::from_secs(10);

fn bind() -> Endpoint {
    Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("listen address")
        .bind()
        .expect("bind loopback")
}

#[test]
fn connect_skips_webtransport_candidates_and_connects_over_quic_v1() {
    let mut a = bind();
    let mut b = bind();
    let b_quic = b.listen().expect("b listens");
    let b_webtransport = PeerAddr::new(
        format!(
            "{}/webtransport/certhash/uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g",
            b_quic.transport()
        )
        .parse::<Multiaddr>()
        .expect("webtransport multiaddr"),
        b_quic.peer_id().clone(),
    )
    .expect("peer addr");

    // The WebTransport candidate comes first, so its refusal must not end
    // the attempt.
    let id = a
        .connect(vec![b_webtransport, b_quic.clone()])
        .expect("connect starts");

    let deadline = Instant::now() + BACKSTOP;
    let outcome = loop {
        assert!(Instant::now() < deadline, "connect never settled");
        if let Some(EndpointEvent::ConnectSettled {
            connect_id,
            outcome,
            ..
        }) = a.next_event(Duration::from_millis(5)).expect("a drives")
            && connect_id == id
        {
            break outcome;
        }
        let _ = b.next_event(Duration::from_millis(5)).expect("b drives");
    };

    let ConnectOutcome::Connected { conn_id, .. } = outcome else {
        panic!("expected Connected, got {outcome:?}");
    };
    let info = a.connection_info(conn_id).expect("connection info");
    assert_eq!(&info.remote_addr, b_quic.transport());
}

#[test]
fn one_socket_serves_both_shapes_and_webtransport_never_feeds_hole_punching() {
    let mut server = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic-v1")
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1/webtransport")
        .expect("webtransport")
        .bind()
        .expect("bind");
    let listen = server.listen_all().expect("listen addrs");
    let quic = listen
        .iter()
        .find(|addr| addr.transport().is_quic_transport())
        .expect("a quic-v1 address")
        .clone();
    let webtransport = listen
        .iter()
        .find(|addr| addr.transport().is_webtransport())
        .expect("a WebTransport address")
        .clone();
    assert_eq!(webtransport.transport().certhashes().count(), 2);
    assert_eq!(
        webtransport.transport().protocols().get(..3),
        quic.transport().protocols().get(..3),
        "one socket: {listen:?}"
    );

    // A libp2p peer connects over quic-v1 ...
    let mut native = bind();
    let id = native.connect(vec![quic.clone()]).expect("connect");
    let deadline = Instant::now() + BACKSTOP;
    loop {
        assert!(
            Instant::now() < deadline,
            "the quic-v1 connect never settled"
        );
        if let Some(EndpointEvent::ConnectSettled {
            connect_id,
            outcome,
            ..
        }) = native.next_event(Duration::from_millis(5)).expect("native")
            && connect_id == id
        {
            assert!(
                matches!(outcome, ConnectOutcome::Connected { .. }),
                "{outcome:?}"
            );
            break;
        }
        let _ = server.next_event(Duration::from_millis(5)).expect("server");
    }

    // ... and a WebTransport client over the same port.
    let key = Ed25519Keypair::generate();
    let mut client: SwarmCore<_, StdEntropy> = SwarmBuilder::new(&key)
        .build_core(
            WebTransportClient::new(
                wt_client::QuinnIo::new(wt_client::Options::default()),
                key.clone(),
                StdEntropy::new(),
            ),
            StdEntropy::new(),
        )
        .expect("client swarm");
    client.dial(&webtransport).expect("dial");
    let epoch = Instant::now();
    let mut observed = None;
    let mut server_conn = None;
    while observed.is_none() || server_conn.is_none() {
        assert!(
            Instant::now() < deadline,
            "the WebTransport client never identified"
        );
        let now = Now::from_millis(epoch.elapsed().as_millis() as u64);
        for event in client.poll(now).expect("client poll") {
            if let SwarmEvent::IdentifyReceived { info, .. } = event {
                observed = info.observed_addr.clone();
            }
        }
        if let Some(EndpointEvent::PeerReady {
            peer_id, conn_id, ..
        }) = server.next_event(Duration::from_millis(5)).expect("server")
            && peer_id == key.peer_id()
        {
            server_conn = Some(conn_id);
        }
    }

    // What the server sees and reports of the browser is a WebTransport
    // address, which hole punching and NAT candidates never take.
    let info = server
        .connection_info(server_conn.expect("server connection"))
        .expect("connection info");
    assert!(info.remote_addr.is_webtransport(), "{}", info.remote_addr);
    assert!(!info.remote_addr.is_quic_transport());
    let observed = Multiaddr::from_bytes(&observed.expect("observed")).expect("observed addr");
    assert_eq!(observed, info.remote_addr);
    assert!(!observed.is_quic_transport());
}

type PortableServer = minip2p::PortableEndpoint<minip2p_quic::QuicTransport, StdEntropy>;

/// A portable server over `quic-v1` + WebTransport on one loopback socket,
/// so the test sets its wall clock.
fn portable_server(key: &Ed25519Keypair) -> PortableServer {
    let addrs: Vec<Multiaddr> = [
        "/ip4/127.0.0.1/udp/0/quic-v1",
        "/ip4/127.0.0.1/udp/0/quic-v1/webtransport",
    ]
    .iter()
    .map(|addr| addr.parse().expect("multiaddr"))
    .collect();
    let transport =
        minip2p_quic::QuicTransport::bind(minip2p_quic::QuicNodeConfig::new(key.clone()), &addrs)
            .expect("bind");
    let mut server = Endpoint::portable(key, StdEntropy::new())
        .build(transport)
        .expect("portable server");
    server.listen_all().expect("listen");
    server
}

/// Polls `server` with its wall clock at `unix`.
fn poll_at(server: &mut PortableServer, epoch: Instant, unix: u64) -> Vec<EndpointEvent> {
    let now = Now::new(epoch.elapsed().as_millis() as u64, unix);
    server.poll(now).expect("server poll")
}

fn webtransport_of(addrs: &[PeerAddr]) -> PeerAddr {
    addrs
        .iter()
        .find(|addr| addr.transport().is_webtransport())
        .expect("a WebTransport address")
        .clone()
}

fn listen_changes(events: &[EndpointEvent]) -> Vec<Vec<PeerAddr>> {
    events
        .iter()
        .filter_map(|event| match event {
            EndpointEvent::ListenAddressesChanged { addrs } => Some(addrs.clone()),
            _ => None,
        })
        .collect()
}

/// Connects `native` to `server` and returns the listen addresses the
/// server's Identify carried; the server's events go to `seen`.
fn identify_listen_addrs(
    native: &mut Endpoint,
    server: &mut PortableServer,
    target: &PeerAddr,
    (epoch, unix): (Instant, u64),
    seen: &mut Vec<EndpointEvent>,
) -> Vec<Multiaddr> {
    native.connect(vec![target.clone()]).expect("connect");
    let deadline = Instant::now() + BACKSTOP;
    loop {
        assert!(Instant::now() < deadline, "never identified the server");
        seen.extend(poll_at(server, epoch, unix));
        if let Some(EndpointEvent::IdentifyReceived { peer_id, info, .. }) =
            native.next_event(Duration::from_millis(5)).expect("native")
            && &peer_id == target.peer_id()
        {
            return info
                .listen_addrs
                .iter()
                .map(|bytes| Multiaddr::from_bytes(bytes).expect("listen addr"))
                .collect();
        }
    }
}

#[test]
fn rotation_reports_the_new_listen_set_once_and_identify_carries_it() {
    let key = Ed25519Keypair::generate();
    let mut server = portable_server(&key);
    let epoch = Instant::now();
    let unix_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs();
    // The next real boundary, so libp2p certificates stay valid.
    let boundary = minip2p_tls::webtransport::next_boundary(unix_now);
    let mut seen = poll_at(&mut server, epoch, boundary - 5);
    let before = server.listen_all().expect("listen addrs");
    let quic = before
        .iter()
        .find(|addr| addr.transport().is_quic_transport())
        .expect("quic-v1")
        .clone();

    // A native peer connected before the boundary.
    let mut native = bind();
    let advertised = identify_listen_addrs(
        &mut native,
        &mut server,
        &quic,
        (epoch, boundary - 5),
        &mut seen,
    );
    assert!(advertised.contains(webtransport_of(&before).transport()));
    assert!(listen_changes(&seen).is_empty(), "{seen:?}");

    // One poll at the boundary reports the change, with `/p2p` kept.
    let events = poll_at(&mut server, epoch, boundary);
    let after = server.listen_all().expect("listen addrs");
    assert_eq!(listen_changes(&events), std::slice::from_ref(&after));
    assert_eq!(after.len(), before.len());
    assert_ne!(webtransport_of(&after), webtransport_of(&before));
    assert_eq!(webtransport_of(&after).peer_id(), &key.peer_id());
    assert!(after.contains(&quic));

    // After reconnecting, Identify carries the new set.
    native.disconnect(&key.peer_id()).expect("disconnect");
    let deadline = Instant::now() + BACKSTOP;
    while native.is_peer_ready(&key.peer_id()) || server.is_peer_ready(native.peer_id()) {
        assert!(Instant::now() < deadline, "never disconnected");
        let _ = poll_at(&mut server, epoch, boundary);
        let _ = native.next_event(Duration::from_millis(5)).expect("native");
    }
    let mut seen = Vec::new();
    let advertised = identify_listen_addrs(
        &mut native,
        &mut server,
        &quic,
        (epoch, boundary),
        &mut seen,
    );
    assert!(advertised.contains(webtransport_of(&after).transport()));
    assert!(!advertised.contains(webtransport_of(&before).transport()));
    assert!(listen_changes(&seen).is_empty(), "{seen:?}");
}
