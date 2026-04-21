//! End-to-end tests proving the Swarm eliminates all manual wiring.
//!
//! Contrast with `ping_e2e.rs` which requires ~200 lines of manual negotiation
//! and dispatch code. Here, the Swarm handles everything.

use std::time::Instant;

use minip2p_identify::{IdentifyConfig, IDENTIFY_PROTOCOL_ID};
use minip2p_ping::{PING_PAYLOAD_LEN, PING_PROTOCOL_ID, PingConfig};
use minip2p_quic::{QuicNodeConfig, QuicTransport};
use minip2p_swarm::{Swarm, SwarmEvent};
use minip2p_transport::ConnectionId;

fn make_identify_config(transport: &QuicTransport) -> IdentifyConfig {
    let public_key = transport
        .local_peer_id()
        .map(|pid| pid.to_bytes())
        .unwrap_or_default();

    IdentifyConfig {
        protocol_version: "minip2p/0.1.0".to_string(),
        agent_version: "minip2p-test/0.1.0".to_string(),
        protocols: vec![
            IDENTIFY_PROTOCOL_ID.to_string(),
            PING_PROTOCOL_ID.to_string(),
        ],
        listen_addrs: vec![],
        public_key,
    }
}

fn drive_pair(
    server: &mut Swarm<QuicTransport>,
    client: &mut Swarm<QuicTransport>,
    start: &Instant,
) -> (Vec<SwarmEvent>, Vec<SwarmEvent>) {
    std::thread::sleep(std::time::Duration::from_millis(5));
    let now_ms = start.elapsed().as_millis() as u64;
    let server_events = server.poll(now_ms).expect("server poll");
    let client_events = client.poll(now_ms).expect("client poll");
    (server_events, client_events)
}

#[test]
fn swarm_ping_roundtrip_with_auto_identify() {
    // Set up server.
    let server_transport =
        QuicTransport::new(QuicNodeConfig::dev_listener(), "127.0.0.1:0").expect("server bind");
    let server_config = make_identify_config(&server_transport);
    let mut server = Swarm::new(server_transport, server_config, PingConfig::default());
    server
        .transport_mut()
        .listen_on_bound_addr()
        .expect("server listen");

    let peer_addr = server
        .transport()
        .local_peer_addr()
        .expect("server peer addr");
    let server_peer_id = peer_addr.peer_id().clone();

    // Set up client.
    let client_transport =
        QuicTransport::new(QuicNodeConfig::dev_dialer(), "127.0.0.1:0").expect("client bind");
    let client_config = make_identify_config(&client_transport);
    let mut client = Swarm::new(client_transport, client_config, PingConfig::default());

    // Dial.
    let client_conn_id = ConnectionId::new(1);
    client.dial(client_conn_id, &peer_addr).expect("dial");

    let start = Instant::now();
    let mut client_connected = false;
    let mut client_identified = false;
    let mut ping_stream_opened = false;
    let mut ping_sent = false;
    let mut rtt_measured = false;

    for _ in 0..500 {
        let (server_events, client_events) = drive_pair(&mut server, &mut client, &start);

        for event in server_events {
            if let SwarmEvent::Error { message } = &event {
                eprintln!("[server] {message}");
            }
        }

        for event in client_events {
            match event {
                SwarmEvent::ConnectionEstablished { ref peer_id } => {
                    assert_eq!(peer_id, &server_peer_id);
                    client_connected = true;
                }
                SwarmEvent::IdentifyReceived { ref peer_id, ref info } => {
                    if *peer_id == server_peer_id {
                        assert_eq!(
                            info.agent_version.as_deref(),
                            Some("minip2p-test/0.1.0")
                        );
                        assert!(info
                            .protocols
                            .contains(&PING_PROTOCOL_ID.to_string()));
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

        // Once identified, open a ping stream.
        if client_identified && !ping_stream_opened {
            client
                .open_ping(&server_peer_id)
                .expect("open ping stream");
            ping_stream_opened = true;
        }

        // Once we have a ping stream, send a ping. We need a few poll
        // iterations for the outbound stream to be negotiated.
        if ping_stream_opened && !ping_sent {
            let now_ms = start.elapsed().as_millis() as u64;
            let payload: [u8; PING_PAYLOAD_LEN] = core::array::from_fn(|i| i as u8);
            // send_ping may fail if the stream is still negotiating — retry.
            if client.send_ping(&server_peer_id, &payload, now_ms).is_ok() {
                ping_sent = true;
            }
        }

        if rtt_measured {
            break;
        }
    }

    assert!(client_connected, "client should connect");
    assert!(client_identified, "client should receive identify");
    assert!(rtt_measured, "ping RTT should be measured");
}
