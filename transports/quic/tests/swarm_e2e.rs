//! End-to-end tests proving the Swarm eliminates all manual wiring.
//!
//! Contrast with `ping_e2e.rs` which requires ~200 lines of manual negotiation
//! and dispatch code. Here, the Swarm handles everything.

use minip2p_core::{Multiaddr, Protocol};
use minip2p_identity::Ed25519Keypair;
use minip2p_ping::PING_PROTOCOL_ID;
use minip2p_quic::{QuicEndpoint, QuicNodeConfig, QuicTransport};
use minip2p_swarm::{DriverError, Swarm, SwarmBuilder, SwarmError, SwarmErrorKind, SwarmEvent};
use minip2p_transport::{StreamId, Transport};

fn make_swarm(keypair: Ed25519Keypair) -> Swarm<QuicTransport> {
    let transport =
        QuicTransport::new(QuicNodeConfig::new(keypair.clone()), "127.0.0.1:0").expect("bind");
    SwarmBuilder::new(&keypair)
        .agent_version("minip2p-test/0.1.0")
        .build(transport)
}

fn make_dual_stack_swarm(keypair: Ed25519Keypair) -> Swarm<QuicEndpoint> {
    let transport = QuicEndpoint::dual_stack(QuicNodeConfig::new(keypair.clone())).expect("bind");
    SwarmBuilder::new(&keypair)
        .agent_version("minip2p-test/0.1.0")
        .build(transport)
}

fn drive_pair(
    server: &mut Swarm<QuicTransport>,
    client: &mut Swarm<QuicTransport>,
) -> (Vec<SwarmEvent>, Vec<SwarmEvent>) {
    std::thread::sleep(std::time::Duration::from_millis(5));
    let server_events = server.poll().expect("server poll");
    let client_events = client.poll().expect("client poll");
    (server_events, client_events)
}

fn drive_three(
    a: &mut Swarm<QuicTransport>,
    b: &mut Swarm<QuicTransport>,
    c: &mut Swarm<QuicTransport>,
) -> (Vec<SwarmEvent>, Vec<SwarmEvent>, Vec<SwarmEvent>) {
    std::thread::sleep(std::time::Duration::from_millis(5));
    let a_events = a.poll().expect("a poll");
    let b_events = b.poll().expect("b poll");
    let c_events = c.poll().expect("c poll");
    (a_events, b_events, c_events)
}

#[test]
fn listen_on_bound_addrs_returns_ipv4_and_ipv6_peer_addrs() {
    let mut swarm = make_dual_stack_swarm(Ed25519Keypair::generate());
    let addrs = swarm
        .listen_on_bound_addrs()
        .expect("listen on bound addrs");

    assert!(
        addrs
            .iter()
            .any(|addr| matches!(addr.transport().protocols().first(), Some(Protocol::Ip4(_)))),
        "expected an IPv4 peer addr: {addrs:?}"
    );
    assert!(
        addrs
            .iter()
            .any(|addr| matches!(addr.transport().protocols().first(), Some(Protocol::Ip6(_)))),
        "expected an IPv6 peer addr: {addrs:?}"
    );
}

#[test]
fn listen_on_bound_addr_keeps_first_address_contract() {
    let keypair = Ed25519Keypair::generate();
    let transport = QuicEndpoint::dual_stack(QuicNodeConfig::new(keypair.clone())).expect("bind");
    let first_addr = transport
        .local_addresses()
        .into_iter()
        .next()
        .expect("dual stack exposes a first address");
    let mut swarm = SwarmBuilder::new(&keypair)
        .agent_version("minip2p-test/0.1.0")
        .build(transport);

    let addr = swarm.listen_on_bound_addr().expect("listen");

    assert_eq!(addr.transport(), &first_addr);
}

#[test]
fn swarm_ping_roundtrip_with_auto_identify() {
    // Set up server.
    let mut server = make_swarm(Ed25519Keypair::generate());
    let peer_addr = server.listen_on_bound_addr().expect("server listen");
    let server_peer_id = peer_addr.peer_id().clone();

    // Set up client and dial -- no ConnectionId ceremony, no `now_ms` plumbing.
    let mut client = make_swarm(Ed25519Keypair::generate());
    let _conn = client.dial(&peer_addr).expect("dial");

    let mut client_connected = false;
    let mut client_identified = false;
    let mut client_ready = false;
    let mut ping_issued = false;
    let mut rtt_measured = false;

    for _ in 0..500 {
        let (_server_events, client_events) = drive_pair(&mut server, &mut client);

        for event in client_events {
            match event {
                SwarmEvent::ConnectionEstablished { ref peer_id } => {
                    assert_eq!(peer_id, &server_peer_id);
                    client_connected = true;
                }
                SwarmEvent::IdentifyReceived {
                    ref peer_id,
                    ref info,
                } => {
                    if *peer_id == server_peer_id {
                        assert_eq!(info.agent_version.as_deref(), Some("minip2p-test/0.1.0"));
                        assert!(info.protocols.contains(&PING_PROTOCOL_ID.to_string()));
                        client_identified = true;
                    }
                }
                SwarmEvent::PeerReady {
                    ref peer_id,
                    ref protocols,
                } => {
                    assert_eq!(peer_id, &server_peer_id);
                    assert!(protocols.contains(&PING_PROTOCOL_ID.to_string()));
                    assert!(client.is_peer_ready(&server_peer_id));
                    assert!(client.connected_peers().contains(&server_peer_id));
                    assert!(
                        client
                            .peer_info(&server_peer_id)
                            .expect("peer info should exist")
                            .protocols
                            .contains(&PING_PROTOCOL_ID.to_string())
                    );
                    client_ready = true;
                }
                SwarmEvent::PingRttMeasured {
                    ref peer_id,
                    rtt_ms,
                } => {
                    assert_eq!(peer_id, &server_peer_id);
                    assert!(rtt_ms < 5_000, "rtt should be bounded: {rtt_ms}ms");
                    rtt_measured = true;
                }
                SwarmEvent::Error(ref error) => {
                    eprintln!("[client] {:?}: {}", error.kind, error.detail);
                }
                _ => {}
            }
        }

        // One-call ping: opens a stream if needed, sends the payload as soon
        // as it's negotiated. No `open_ping` + `send_ping` two-step required.
        if client_ready && !ping_issued {
            client.ping(&server_peer_id).expect("ping");
            ping_issued = true;
        }

        if rtt_measured {
            break;
        }
    }

    assert!(client_connected, "client should connect");
    assert!(client_identified, "client should receive identify");
    assert!(client_ready, "client should become ready");
    assert!(rtt_measured, "ping RTT should be measured");
}

#[test]
fn inbound_connection_does_not_collide_with_later_outbound_dial() {
    let mut inbound_peer = make_swarm(Ed25519Keypair::generate());
    let mut middle = make_swarm(Ed25519Keypair::generate());
    let mut outbound_peer = make_swarm(Ed25519Keypair::generate());

    let middle_addr = middle.listen_on_bound_addr().expect("middle listen");
    let middle_peer_id = middle_addr.peer_id().clone();
    let outbound_addr = outbound_peer
        .listen_on_bound_addr()
        .expect("outbound listen");
    let outbound_peer_id = outbound_addr.peer_id().clone();

    inbound_peer.dial(&middle_addr).expect("inbound dial");

    let mut middle_saw_inbound = false;
    for _ in 0..500 {
        let (inbound_events, middle_events, _outbound_events) =
            drive_three(&mut inbound_peer, &mut middle, &mut outbound_peer);

        let inbound_connected = inbound_events.iter().any(
            |event| matches!(event, SwarmEvent::ConnectionEstablished { peer_id } if peer_id == &middle_peer_id),
        );
        middle_saw_inbound |= middle_events
            .iter()
            .any(|event| matches!(event, SwarmEvent::ConnectionEstablished { .. }));

        if inbound_connected && middle_saw_inbound {
            break;
        }
    }

    assert!(
        middle_saw_inbound,
        "middle should accept inbound connection"
    );

    middle
        .dial(&outbound_addr)
        .expect("later outbound dial must not collide with inbound connection id");

    for _ in 0..500 {
        let (_inbound_events, middle_events, _outbound_events) =
            drive_three(&mut inbound_peer, &mut middle, &mut outbound_peer);

        if middle_events.iter().any(
            |event| matches!(event, SwarmEvent::ConnectionEstablished { peer_id } if peer_id == &outbound_peer_id),
        ) {
            return;
        }
    }

    panic!("middle should connect to outbound peer after accepting inbound connection");
}

const USER_PROTOCOL_ID: &str = "/minip2p/test/echo/1.0.0";

#[test]
fn swarm_user_protocol_round_trip() {
    let mut server = make_swarm(Ed25519Keypair::generate());
    server.add_user_protocol(USER_PROTOCOL_ID);
    let peer_addr = server.listen_on_bound_addr().expect("server listen");
    let server_peer_id = peer_addr.peer_id().clone();

    let mut client = make_swarm(Ed25519Keypair::generate());
    client.add_user_protocol(USER_PROTOCOL_ID);
    client.dial(&peer_addr).expect("dial");

    let mut user_stream: Option<StreamId> = None;
    let mut server_echo_sent = false;
    let mut echo_received: Option<Vec<u8>> = None;
    let payload = b"hello-user-protocol".to_vec();

    for _ in 0..400 {
        let (server_events, client_events) = drive_pair(&mut server, &mut client);

        for event in server_events {
            match event {
                SwarmEvent::UserStreamData {
                    ref peer_id,
                    stream_id,
                    ref data,
                } if !server_echo_sent => {
                    // Echo the data back on the same stream.
                    server
                        .send_user_stream(peer_id, stream_id, data.clone())
                        .expect("server echo");
                    server_echo_sent = true;
                }
                SwarmEvent::Error(ref error) => {
                    eprintln!("[server] {:?}: {}", error.kind, error.detail)
                }
                _ => {}
            }
        }

        for event in client_events {
            match event {
                SwarmEvent::PeerReady { ref peer_id, .. }
                    if *peer_id == server_peer_id && user_stream.is_none() =>
                {
                    let sid = client
                        .open_user_stream(&server_peer_id, USER_PROTOCOL_ID)
                        .expect("open user stream");
                    user_stream = Some(sid);
                }
                SwarmEvent::UserStreamReady {
                    ref peer_id,
                    stream_id,
                    ref protocol_id,
                    initiated_locally,
                } => {
                    assert_eq!(peer_id, &server_peer_id);
                    assert_eq!(protocol_id, USER_PROTOCOL_ID);
                    assert!(initiated_locally);
                    client
                        .send_user_stream(&server_peer_id, stream_id, payload.clone())
                        .expect("client send");
                }
                SwarmEvent::UserStreamData {
                    ref peer_id,
                    ref data,
                    ..
                } => {
                    assert_eq!(peer_id, &server_peer_id);
                    echo_received = Some(data.clone());
                }
                SwarmEvent::Error(ref error) => {
                    eprintln!("[client] {:?}: {}", error.kind, error.detail)
                }
                _ => {}
            }
        }

        if echo_received.is_some() {
            break;
        }
    }

    assert_eq!(echo_received.as_deref(), Some(payload.as_slice()));
}

#[test]
fn open_user_stream_fails_fast_when_peer_did_not_advertise_protocol() {
    let mut server = make_swarm(Ed25519Keypair::generate());
    let peer_addr = server.listen_on_bound_addr().expect("server listen");
    let server_peer_id = peer_addr.peer_id().clone();

    let mut client = make_swarm(Ed25519Keypair::generate());
    client.add_user_protocol(USER_PROTOCOL_ID);
    client.dial(&peer_addr).expect("dial");

    for _ in 0..500 {
        let (_server_events, client_events) = drive_pair(&mut server, &mut client);

        if client_events.iter().any(
            |ev| matches!(ev, SwarmEvent::PeerReady { peer_id, .. } if peer_id == &server_peer_id),
        ) {
            break;
        }
    }

    assert!(client.is_peer_ready(&server_peer_id));
    let err = client
        .open_user_stream(&server_peer_id, USER_PROTOCOL_ID)
        .expect_err("unsupported user protocol should fail synchronously");
    assert!(
        matches!(
            err,
            DriverError::Swarm(SwarmError::RemoteDoesNotSupport {
                ref peer_id,
                ref protocol_id,
            }) if peer_id == &server_peer_id && protocol_id == USER_PROTOCOL_ID
        ),
        "expected fail-fast unsupported protocol error, got {err:?}"
    );
}

/// Regression test: after the client dials and Identify completes, the
/// client's `IdentifyReceived` event must carry a non-empty `observed_addr`
/// that parses back into a valid QUIC transport multiaddr.
///
/// This covers the prior behavior where `SwarmCore` passed an empty
/// `observed_addr` byte vector into the Identify responder (the TODO at
/// the former `crates/swarm/src/core.rs:982`). The fix plumbs the
/// transport endpoint cached on `TransportEvent::Connected` /
/// `IncomingConnection` into `IdentifyInput::RegisterOutboundStream`.
///
/// Note: we intentionally only assert the client-observed direction.
/// The symmetric server-observed case requires the server to learn the
/// client's real PeerId at handshake time so it can open its own Identify
/// initiator stream -- that is the Milestone 6 mutual-TLS work and is not
/// what this test covers.
#[test]
fn identify_exchange_carries_observed_addr() {
    let mut server = make_swarm(Ed25519Keypair::generate());
    let peer_addr = server.listen_on_bound_addr().expect("server listen");
    let server_peer_id = peer_addr.peer_id().clone();

    let mut client = make_swarm(Ed25519Keypair::generate());
    client.dial(&peer_addr).expect("dial");

    let mut client_observed: Option<Vec<u8>> = None;

    for _ in 0..500 {
        let (_server_events, client_events) = drive_pair(&mut server, &mut client);

        for event in client_events {
            if let SwarmEvent::IdentifyReceived { peer_id, info } = event
                && peer_id == server_peer_id
            {
                client_observed = info.observed_addr;
            }
        }

        if client_observed.is_some() {
            break;
        }
    }

    let client_bytes = client_observed.expect("client should see observed_addr");
    assert!(
        !client_bytes.is_empty(),
        "client-side observed_addr must not be empty"
    );

    // Identify now encodes observed_addr per the libp2p spec -- varint
    // multicodec + value -- so decode with Multiaddr::from_bytes.
    let addr = Multiaddr::from_bytes(&client_bytes)
        .expect("observed_addr should decode as binary multiaddr");
    assert!(
        addr.is_quic_transport(),
        "observed_addr should be a QUIC transport multiaddr, got {addr}"
    );
}

/// Regression test: calling `ping()` repeatedly before the ping stream has
/// finished multistream-select must not open duplicate streams or surface
/// "outbound ping stream already exists" errors.
#[test]
fn rapid_ping_calls_do_not_open_duplicate_streams() {
    let mut server = make_swarm(Ed25519Keypair::generate());
    let peer_addr = server.listen_on_bound_addr().expect("server listen");
    let server_peer_id = peer_addr.peer_id().clone();

    let mut client = make_swarm(Ed25519Keypair::generate());
    client.dial(&peer_addr).expect("dial");

    let mut client_identified = false;
    let mut ping_bursts_fired = false;
    let mut rtt_measured = false;
    let mut saw_register_error = false;

    for _ in 0..500 {
        let (_server_events, client_events) = drive_pair(&mut server, &mut client);

        for event in client_events {
            match event {
                SwarmEvent::PeerReady { ref peer_id, .. } if *peer_id == server_peer_id => {
                    client_identified = true;
                }
                SwarmEvent::PingRttMeasured { ref peer_id, .. } => {
                    assert_eq!(peer_id, &server_peer_id);
                    rtt_measured = true;
                }
                SwarmEvent::Error(ref error)
                    if error.kind == SwarmErrorKind::Ping
                        && error.detail.contains("ping register error") =>
                {
                    saw_register_error = true;
                }
                _ => {}
            }
        }

        // Once identified, fire three ping() calls back-to-back before the
        // stream has a chance to negotiate. With the bug, this would open
        // three outbound streams and trigger "OutboundStreamExists" errors
        // on the second and third.
        if client_identified && !ping_bursts_fired {
            client.ping(&server_peer_id).expect("first ping");
            client.ping(&server_peer_id).expect("second ping");
            client.ping(&server_peer_id).expect("third ping");
            ping_bursts_fired = true;
        }

        if rtt_measured {
            break;
        }
    }

    assert!(rtt_measured, "at least one ping RTT should be measured");
    assert!(
        !saw_register_error,
        "rapid ping() calls must not emit ping-register errors"
    );
}
