//! End-to-end tests proving the Swarm eliminates all manual wiring.
//!
//! Contrast with `ping_e2e.rs` which requires ~200 lines of manual negotiation
//! and dispatch code. Here, the Swarm handles everything.

use minip2p_identity::Ed25519Keypair;
use minip2p_ping::PING_PROTOCOL_ID;
use minip2p_quic::{QuicNodeConfig, QuicTransport};
use minip2p_swarm::{Swarm, SwarmBuilder, SwarmEvent};
use minip2p_transport::StreamId;

fn make_swarm(keypair: Ed25519Keypair) -> Swarm<QuicTransport> {
    let transport = QuicTransport::new(QuicNodeConfig::with_keypair(keypair.clone()), "127.0.0.1:0")
        .expect("bind");
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

#[test]
fn swarm_ping_roundtrip_with_auto_identify() {
    // Set up server.
    let mut server = make_swarm(Ed25519Keypair::generate());
    server
        .transport_mut()
        .listen_on_bound_addr()
        .expect("server listen");
    let peer_addr = server.transport().local_peer_addr().expect("peer addr");
    let server_peer_id = peer_addr.peer_id().clone();

    // Set up client and dial -- no ConnectionId ceremony, no `now_ms` plumbing.
    let mut client = make_swarm(Ed25519Keypair::generate());
    let _conn = client.dial(&peer_addr).expect("dial");

    let mut client_connected = false;
    let mut client_identified = false;
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
                SwarmEvent::IdentifyReceived { ref peer_id, ref info } => {
                    if *peer_id == server_peer_id {
                        assert_eq!(info.agent_version.as_deref(), Some("minip2p-test/0.1.0"));
                        assert!(info.protocols.contains(&PING_PROTOCOL_ID.to_string()));
                        client_identified = true;
                    }
                }
                SwarmEvent::PingRttMeasured { ref peer_id, rtt_ms } => {
                    assert_eq!(peer_id, &server_peer_id);
                    assert!(rtt_ms < 5_000, "rtt should be bounded: {rtt_ms}ms");
                    rtt_measured = true;
                }
                SwarmEvent::Error { ref message } => {
                    eprintln!("[client] {message}");
                }
                _ => {}
            }
        }

        // One-call ping: opens a stream if needed, sends the payload as soon
        // as it's negotiated. No `open_ping` + `send_ping` two-step required.
        if client_identified && !ping_issued {
            client.ping(&server_peer_id).expect("ping");
            ping_issued = true;
        }

        if rtt_measured {
            break;
        }
    }

    assert!(client_connected, "client should connect");
    assert!(client_identified, "client should receive identify");
    assert!(rtt_measured, "ping RTT should be measured");
}

const USER_PROTOCOL_ID: &str = "/minip2p/test/echo/1.0.0";

#[test]
fn swarm_user_protocol_round_trip() {
    let mut server = make_swarm(Ed25519Keypair::generate());
    server.add_user_protocol(USER_PROTOCOL_ID);
    server
        .transport_mut()
        .listen_on_bound_addr()
        .expect("server listen");
    let peer_addr = server.transport().local_peer_addr().expect("peer addr");
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
                SwarmEvent::Error { ref message } => eprintln!("[server] {message}"),
                _ => {}
            }
        }

        for event in client_events {
            match event {
                SwarmEvent::IdentifyReceived { ref peer_id, .. }
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
                SwarmEvent::UserStreamData { ref peer_id, ref data, .. } => {
                    assert_eq!(peer_id, &server_peer_id);
                    echo_received = Some(data.clone());
                }
                SwarmEvent::Error { ref message } => eprintln!("[client] {message}"),
                _ => {}
            }
        }

        if echo_received.is_some() {
            break;
        }
    }

    assert_eq!(echo_received.as_deref(), Some(payload.as_slice()));
}
