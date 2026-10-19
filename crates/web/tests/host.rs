//! The browser host over an in-memory transport: config limits, the pump,
//! commands and close, without wasm or a browser.

use minip2p::{Ed25519Keypair, Now, PeerId};
use minip2p_ffi_core::{CloseOutcome, ConfigCapability, EndpointConfig, FfiError, P2pEvent};
use minip2p_test_support::InMemoryTransport;
use minip2p_web::Host;

const LIMIT: usize = 256;

fn config() -> EndpointConfig {
    EndpointConfig {
        agent_version: None,
        relays: Vec::new(),
        autonat_servers: Vec::new(),
        listen: None,
        force_relay: false,
        allow_unsigned: false,
        protocols: vec!["/echo/1".into()],
        discovery: None,
        mdns: None,
    }
}

fn peer(secret: u8) -> PeerId {
    Ed25519Keypair::from_secret_key_bytes([secret; 32]).peer_id()
}

/// Two started hosts joined by an in-memory link.
fn pair() -> (Host<InMemoryTransport>, Host<InMemoryTransport>) {
    let (a, b) = InMemoryTransport::pair(peer(1), peer(2));
    let mut a = Host::new(vec![1; 32], config(), |_| a).expect("host a");
    let mut b = Host::new(vec![2; 32], config(), |_| b).expect("host b");
    a.start().expect("start a");
    b.start().expect("start b");
    (a, b)
}

/// Pumps both hosts for `rounds` milliseconds and returns what each carried.
fn run(
    a: &mut Host<InMemoryTransport>,
    b: &mut Host<InMemoryTransport>,
    from_ms: u64,
    rounds: u64,
) -> (Vec<P2pEvent>, Vec<P2pEvent>) {
    let (mut a_events, mut b_events) = (Vec::new(), Vec::new());
    for ms in from_ms..from_ms + rounds {
        a.pump(Now::from_millis(ms));
        b.pump(Now::from_millis(ms));
        a_events.extend(a.drain_events(LIMIT));
        b_events.extend(b.drain_events(LIMIT));
    }
    (a_events, b_events)
}

#[test]
fn browser_config_rejects_what_a_browser_cannot_do() {
    type Edit = fn(&mut EndpointConfig);
    let cases: [(Edit, ConfigCapability, &str); 6] = [
        (
            |c| c.listen = Some(vec!["/ip4/0.0.0.0/udp/0/quic-v1".into()]),
            ConfigCapability::Options,
            "cannot listen",
        ),
        (
            |c| {
                c.mdns = Some(minip2p_ffi_core::MdnsOptions {
                    enable_ipv6: false,
                    ttl_ms: 1,
                    query_interval_ms: 1,
                    max_packet_bytes: 1400,
                    max_announced_addrs: 1,
                    interface_refresh_ms: 1,
                    auto_dial: true,
                })
            },
            ConfigCapability::Mdns,
            "multicast",
        ),
        (
            |c| {
                c.discovery = Some(minip2p_ffi_core::DiscoveryOptions {
                    topic: "t".into(),
                    beacon_interval_ms: 1,
                    peer_ttl_ms: 1,
                    auto_dial: true,
                })
            },
            ConfigCapability::Discovery,
            "browser",
        ),
        (
            |c| c.autonat_servers = vec!["/ip4/192.0.2.1/udp/1/quic-v1".into()],
            ConfigCapability::Options,
            "AutoNAT",
        ),
        (
            |c| c.relays = vec!["/ip4/192.0.2.1/udp/1/quic-v1".into()],
            ConfigCapability::Options,
            "later release",
        ),
        (
            |c| c.force_relay = true,
            ConfigCapability::Options,
            "later release",
        ),
    ];
    for (edit, expected, words) in cases {
        let mut config = config();
        edit(&mut config);
        let error = Host::new(vec![1; 32], config, |_| {
            InMemoryTransport::pair(peer(1), peer(2)).0
        })
        .err()
        .expect("rejected");
        match error {
            FfiError::InvalidConfig { capability, detail } => {
                assert_eq!(capability, expected, "{detail}");
                assert!(detail.contains(words), "{detail}");
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }
}

#[test]
fn a_pumped_host_connects_rings_once_and_reports_its_deadline() {
    let (mut a, mut b) = pair();

    let first = a.pump(Now::from_millis(0));
    assert!(first.ring, "the first events ring the doorbell");
    assert!(
        !a.pump(Now::from_millis(0)).ring,
        "a non-empty carry does not ring again"
    );
    let (a_events, _) = run(&mut a, &mut b, 1, 32);

    assert!(
        a_events
            .iter()
            .any(|event| matches!(event, P2pEvent::PeerReady { peer_id, .. } if *peer_id == peer(2).to_base58())),
        "{a_events:?}"
    );
    assert_eq!(
        a.connected_peers().expect("peers"),
        vec![peer(2).to_base58()]
    );
    assert!(a.is_peer_ready(peer(2).to_base58()).expect("ready"));
    // Ping and Identify keep timers, so an idle host still has a deadline.
    assert!(a.pump(Now::from_millis(40)).next_deadline.is_some());
}

#[test]
fn a_ping_and_a_stream_echo_cross_the_hosts() {
    let (mut a, mut b) = pair();
    run(&mut a, &mut b, 0, 32);

    a.ping(peer(2).to_base58(), Now::from_millis(32))
        .expect("ping");
    let opened = a
        .open_stream(peer(2).to_base58(), "/echo/1".into(), Now::from_millis(32))
        .expect("open");
    let (a_events, b_events) = run(&mut a, &mut b, 32, 32);
    assert!(
        a_events
            .iter()
            .any(|event| matches!(event, P2pEvent::PingRttMeasured { .. })),
        "{a_events:?}"
    );
    assert!(
        a_events
            .iter()
            .any(|event| matches!(event, P2pEvent::StreamReady { stream_id, .. } if *stream_id == opened.stream_id)),
        "{a_events:?}"
    );
    let remote = b_events
        .iter()
        .find_map(|event| match event {
            P2pEvent::StreamReady {
                conn_id, stream_id, ..
            } => Some((*conn_id, *stream_id)),
            _ => None,
        })
        .expect("b accepted the stream");

    assert!(
        a.send_stream(
            opened.conn_id,
            opened.stream_id,
            b"hi".to_vec(),
            Now::from_millis(64)
        )
        .expect("send")
    );
    a.close_stream_write(opened.conn_id, opened.stream_id, Now::from_millis(64))
        .expect("fin");
    let (_, b_events) = run(&mut a, &mut b, 64, 16);
    let data: Vec<u8> = b_events
        .iter()
        .filter_map(|event| match event {
            P2pEvent::StreamData { data, .. } => Some(data.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(data, b"hi");
    assert!(
        b_events
            .iter()
            .any(|event| matches!(event, P2pEvent::StreamRemoteWriteClosed { .. })),
        "{b_events:?}"
    );
    // The binding acknowledges what its reader consumed: the bytes stay
    // unacknowledged until then, so acknowledging more fails.
    assert!(matches!(
        b.stream_consumed(remote.0, remote.1, 3, Now::from_millis(80)),
        Err(FfiError::Transport { .. })
    ));
    b.stream_consumed(remote.0, remote.1, 2, Now::from_millis(80))
        .expect("ack");
}

#[test]
fn close_carries_endpoint_closed_last_and_stops_commands() {
    let (mut a, mut b) = pair();
    run(&mut a, &mut b, 0, 32);

    a.close(Now::from_millis(32));
    let events = a.drain_events(LIMIT);
    assert!(
        matches!(
            events.last(),
            Some(P2pEvent::EndpointClosed {
                outcome: CloseOutcome::Drained,
                ..
            })
        ),
        "{events:?}"
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, P2pEvent::ConnectionClosed { .. })),
        "the drain's connection end comes first: {events:?}"
    );
    assert!(!a.is_running());
    assert!(matches!(
        a.ping(peer(2).to_base58(), Now::from_millis(33)),
        Err(FfiError::Stopped)
    ));
    assert!(a.pump(Now::from_millis(33)).next_deadline.is_none());
    // A second close is a no-op.
    a.close(Now::from_millis(34));
    assert!(a.drain_events(LIMIT).is_empty());
}

#[test]
fn a_never_started_host_closes_without_an_event() {
    let (a, _b) = InMemoryTransport::pair(peer(1), peer(2));
    let mut a = Host::new(vec![1; 32], config(), |_| a).expect("host");
    a.close(Now::from_millis(0));
    assert!(a.drain_events(LIMIT).is_empty());
    assert!(matches!(a.start(), Err(FfiError::Stopped)));
}
