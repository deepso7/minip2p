//! libp2p WebTransport end to end: `WebTransportClient` over the test-only
//! quinn client, against a real `QuicTransport` listener.

use std::sync::LazyLock;
use std::time::{Duration, Instant};

use minip2p_core::platform::{Clock, Now, StdClock, StdEntropy};
use minip2p_core::{Multiaddr, PeerAddr, Protocol};
use minip2p_identity::Ed25519Keypair;
use minip2p_quic::{QuicNodeConfig, QuicTransport};
use minip2p_swarm::{SwarmBuilder, SwarmCore, SwarmEvent};
use minip2p_transport::ConnectionCloseReason;
use minip2p_transport::{
    Bytes, ConnectionEndpoint, ConnectionId, StreamId, Transport, TransportEvent,
};
use minip2p_webtransport::WebTransportClient;

#[path = "common/wt_client.rs"]
mod wt_client;
use wt_client::{Options, QuinnIo};

type Client = WebTransportClient<QuinnIo, StdEntropy>;

static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Samples one clock for every transport in the binary.
fn now() -> Now {
    StdClock::with_epoch(*EPOCH).now()
}

/// A listener serving `quic-v1` and WebTransport on one loopback socket.
fn server() -> QuicTransport {
    let mut server = server_with(QuicNodeConfig::generate());
    server.listen_on_bound_addrs().expect("listen");
    server
}

/// `quic-v1` and WebTransport bound on one loopback socket, not listening.
fn server_with(config: QuicNodeConfig) -> QuicTransport {
    let addrs: Vec<Multiaddr> = [
        "/ip4/127.0.0.1/udp/0/quic-v1",
        "/ip4/127.0.0.1/udp/0/quic-v1/webtransport",
    ]
    .iter()
    .map(|addr| addr.parse().expect("multiaddr"))
    .collect();
    QuicTransport::bind(config, &addrs).expect("bind")
}

/// The server's WebTransport address, with its certhash and `/p2p`.
fn webtransport_addr(server: &QuicTransport) -> PeerAddr {
    server
        .local_peer_addrs()
        .expect("peer addrs")
        .into_iter()
        .find(|addr| addr.transport().is_webtransport())
        .expect("a WebTransport address")
}

fn client(options: Options) -> Client {
    WebTransportClient::new(
        QuinnIo::new(options),
        Ed25519Keypair::generate(),
        StdEntropy::new(),
    )
}

/// Both ends' events so far.
#[derive(Default)]
struct Seen {
    server: Vec<TransportEvent>,
    client: Vec<TransportEvent>,
}

/// Polls both until `done` accepts what they reported.
fn drive(
    server: &mut QuicTransport,
    client: &mut Client,
    seen: &mut Seen,
    what: &str,
    mut done: impl FnMut(&Seen) -> bool,
) {
    let start = Instant::now();
    while !done(seen) {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed out waiting for {what}; server: {:?}; client: {:?}",
            seen.server,
            seen.client
        );
        std::thread::sleep(Duration::from_millis(1));
        seen.server.extend(server.poll(now()).expect("server poll"));
        seen.client.extend(client.poll(now()).expect("client poll"));
    }
}

fn connected(events: &[TransportEvent]) -> Option<(ConnectionId, ConnectionEndpoint)> {
    events.iter().find_map(|event| match event {
        TransportEvent::Connected { id, endpoint } => Some((*id, endpoint.clone())),
        _ => None,
    })
}

fn incoming_stream(events: &[TransportEvent]) -> Option<StreamId> {
    events.iter().find_map(|event| match event {
        TransportEvent::IncomingStream { stream_id, .. } => Some(*stream_id),
        _ => None,
    })
}

/// Every byte `events` delivered on `stream`, in order.
fn stream_bytes(events: &[TransportEvent], stream: StreamId) -> Vec<u8> {
    events
        .iter()
        .filter_map(|event| match event {
            TransportEvent::StreamData {
                stream_id, data, ..
            } if *stream_id == stream => Some(data.to_vec()),
            _ => None,
        })
        .flatten()
        .collect()
}

fn remote_closed(events: &[TransportEvent], stream: StreamId) -> bool {
    events.iter().any(|event| {
        matches!(event, TransportEvent::StreamRemoteWriteClosed { stream_id, .. } if *stream_id == stream)
    })
}

/// Dials the server and drives both ends to `Connected`.
fn connect(
    server: &mut QuicTransport,
    client: &mut Client,
    seen: &mut Seen,
) -> (ConnectionEndpoint, ConnectionEndpoint) {
    client.dial(&webtransport_addr(server)).expect("dial");
    drive(server, client, seen, "both ends connected", |seen| {
        connected(&seen.server).is_some() && connected(&seen.client).is_some()
    });
    let (_, server_end) = connected(&seen.server).expect("server connected");
    let (_, client_end) = connected(&seen.client).expect("client connected");
    (server_end, client_end)
}

#[test]
fn a_client_connects_and_both_ends_agree_who_and_which_connection() {
    let mut server = server();
    let mut client = client(Options::default());
    let mut seen = Seen::default();

    let (server_end, client_end) = connect(&mut server, &mut client, &mut seen);

    assert_eq!(client_end.peer_id(), Some(&server.local_peer_id()));
    assert!(server_end.peer_id().is_some());
    assert!(server_end.token().is_some());
    assert_eq!(server_end.token(), client_end.token());
    // The client's address is a WebTransport one, without a certhash.
    let port = client_end
        .transport()
        .protocols()
        .get(1)
        .cloned()
        .expect("a udp port");
    assert!(server_end.transport().is_webtransport());
    assert_eq!(server_end.transport().certhashes().count(), 0);
    assert!(!server_end.transport().is_quic_transport());
    assert_ne!(server_end.transport().protocols().get(1), Some(&port));
}

#[test]
fn a_client_stream_echoes_with_fin() {
    echo_with(Options::default());
}

#[test]
fn a_prefix_split_across_packets_still_opens_the_stream() {
    echo_with(Options {
        split_prefix: true,
        ..Options::default()
    });
}

#[test]
fn a_noise_stream_racing_the_200_is_held_until_the_session_is_accepted() {
    echo_with(Options {
        race_noise: true,
        ..Options::default()
    });
}

/// Connects with `options`, then echoes one stream with FIN.
fn echo_with(options: Options) {
    let mut server = server();
    let mut client = client(options);
    let mut seen = Seen::default();
    connect(&mut server, &mut client, &mut seen);
    let (client_conn, _) = connected(&seen.client).expect("client connected");
    let (server_conn, _) = connected(&seen.server).expect("server connected");

    let stream = client.open_stream(client_conn).expect("open");
    client
        .send_stream(client_conn, stream, Bytes::from_static(b"hello"))
        .expect("send");
    client.close_stream_write(client_conn, stream).expect("fin");
    drive(&mut server, &mut client, &mut seen, "the request", |seen| {
        incoming_stream(&seen.server).is_some_and(|s| remote_closed(&seen.server, s))
    });
    let inbound = incoming_stream(&seen.server).expect("incoming");
    // The prefix is the server's own: only the caller's bytes arrive.
    assert_eq!(stream_bytes(&seen.server, inbound), b"hello");
    server.ack_stream(server_conn, inbound, 5).expect("ack");

    server
        .send_stream(server_conn, inbound, Bytes::from_static(b"hello"))
        .expect("echo");
    server
        .close_stream_write(server_conn, inbound)
        .expect("fin");
    drive(&mut server, &mut client, &mut seen, "the echo", |seen| {
        seen.client.iter().any(|event| {
            matches!(event, TransportEvent::StreamClosed { stream_id, .. } if *stream_id == stream)
        })
    });
    assert_eq!(stream_bytes(&seen.client, stream), b"hello");
    assert!(remote_closed(&seen.client, stream));
}

#[test]
fn a_server_stream_reaches_the_client_without_its_prefix() {
    let mut server = server();
    let mut client = client(Options::default());
    let mut seen = Seen::default();
    connect(&mut server, &mut client, &mut seen);
    let (server_conn, _) = connected(&seen.server).expect("server connected");

    let stream = server.open_stream(server_conn).expect("open");
    server
        .send_stream(server_conn, stream, Bytes::from_static(b"from the server"))
        .expect("send");
    server.close_stream_write(server_conn, stream).expect("fin");
    drive(
        &mut server,
        &mut client,
        &mut seen,
        "the server stream",
        |seen| incoming_stream(&seen.client).is_some_and(|s| remote_closed(&seen.client, s)),
    );
    let inbound = incoming_stream(&seen.client).expect("incoming");
    assert_eq!(stream_bytes(&seen.client, inbound), b"from the server");
}

/// Dials the address `target` makes of the server's WebTransport address,
/// and drives until the client's connection closes. Returns why, after
/// checking neither end reported it connected.
fn failed_dial(target: impl FnOnce(PeerAddr) -> PeerAddr) -> String {
    let mut server = server();
    let mut client = client(Options::default());
    let mut seen = Seen::default();
    client
        .dial(&target(webtransport_addr(&server)))
        .expect("dial");
    drive(
        &mut server,
        &mut client,
        &mut seen,
        "the client to fail",
        |seen| {
            seen.client
                .iter()
                .any(|event| matches!(event, TransportEvent::Closed { .. }))
        },
    );
    for _ in 0..20 {
        std::thread::sleep(Duration::from_millis(2));
        seen.server.extend(server.poll(now()).expect("server poll"));
    }
    assert_eq!(connected(&seen.client), None);
    assert_eq!(connected(&seen.server), None, "{:?}", seen.server);
    seen.client
        .iter()
        .find_map(|event| match event {
            TransportEvent::Closed {
                reason: ConnectionCloseReason::Error(reason),
                ..
            } => Some(reason.clone()),
            _ => None,
        })
        .expect("closed with an error")
}

#[test]
fn a_dialed_certhash_the_server_does_not_list_fails_the_client() {
    // The certificate verifies against the real hash; Noise then lacks the
    // second one.
    let reason = failed_dial(|addr| {
        let (mut transport, peer) = addr.into_parts();
        transport.push(Protocol::Certhash(minip2p_tls::webtransport::certhash(
            b"some other certificate",
        )));
        PeerAddr::new(transport, peer).expect("peer addr")
    });
    assert!(reason.contains("certhash"), "{reason}");
}

#[test]
fn a_wrong_peer_id_fails_the_client() {
    let reason = failed_dial(|addr| {
        PeerAddr::new(
            addr.transport().clone(),
            Ed25519Keypair::generate().peer_id(),
        )
        .expect("peer addr")
    });
    assert!(reason.contains("Noise"), "{reason}");
}

#[test]
fn identify_and_ping_run_over_webtransport() {
    let server_key = Ed25519Keypair::generate();
    let client_key = Ed25519Keypair::generate();
    let mut transport = server_with(QuicNodeConfig::new(server_key.clone()));
    let addr = webtransport_addr(&transport);
    transport.listen_on_bound_addrs().expect("listen");
    let mut server: SwarmCore<QuicTransport, StdEntropy> = SwarmBuilder::new(&server_key)
        .build_core(transport, StdEntropy::new())
        .expect("server swarm");
    let mut client: SwarmCore<Client, StdEntropy> = SwarmBuilder::new(&client_key)
        .build_core(
            WebTransportClient::new(
                QuinnIo::new(Options::default()),
                client_key.clone(),
                StdEntropy::new(),
            ),
            StdEntropy::new(),
        )
        .expect("client swarm");

    client.dial(&addr).expect("dial");
    let mut server_events = Vec::new();
    let mut client_events = Vec::new();
    let mut pinged = false;
    let start = Instant::now();
    loop {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "server: {server_events:?}; client: {client_events:?}"
        );
        std::thread::sleep(Duration::from_millis(1));
        let now = now();
        server_events.extend(server.poll(now).expect("server poll"));
        client_events.extend(client.poll(now).expect("client poll"));
        let identified = |events: &[SwarmEvent], peer: &minip2p_core::PeerId| {
            events.iter().any(|event| {
                matches!(event, SwarmEvent::IdentifyReceived { peer_id, .. } if peer_id == peer)
            })
        };
        if !pinged
            && identified(&client_events, &server_key.peer_id())
            && identified(&server_events, &client_key.peer_id())
        {
            client
                .ping(&server_key.peer_id(), now.monotonic_ms)
                .expect("client ping");
            server
                .ping(&client_key.peer_id(), now.monotonic_ms)
                .expect("server ping");
            pinged = true;
        }
        let measured = |events: &[SwarmEvent]| {
            events
                .iter()
                .any(|event| matches!(event, SwarmEvent::PingRttMeasured { .. }))
        };
        if measured(&client_events) && measured(&server_events) {
            break;
        }
    }
}

#[test]
fn local_addresses_report_the_bound_shapes_and_relisten_ignores_certhashes() {
    let mut transport = server_with(QuicNodeConfig::generate());
    let addrs = transport.local_addresses();
    assert_eq!(addrs.len(), 2, "{addrs:?}");
    assert!(addrs[0].is_quic_transport());
    assert!(addrs[1].is_webtransport());
    assert_eq!(addrs[1].certhashes().count(), 1);
    assert_eq!(
        addrs[1].without_certhashes().protocols()[..3],
        addrs[0].protocols()[..]
    );

    // Re-listening matches the socket whatever certhashes the address has.
    assert_eq!(transport.listen(&addrs[1]), Ok(addrs[1].clone()));
    let mut stale = addrs[1].without_certhashes();
    stale.push(Protocol::Certhash(minip2p_tls::webtransport::certhash(
        b"an older certificate",
    )));
    assert_eq!(transport.listen(&stale), Ok(addrs[1].clone()));

    let only: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1/webtransport"
        .parse()
        .expect("multiaddr");
    let webtransport_only = QuicTransport::bind(QuicNodeConfig::generate(), &[only]).expect("bind");
    let addrs = webtransport_only.local_addresses();
    assert_eq!(addrs.len(), 1, "{addrs:?}");
    assert!(addrs[0].is_webtransport());
}
