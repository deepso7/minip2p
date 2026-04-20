use std::io::Write;

use minip2p_core::{Multiaddr, PeerAddr, Protocol};
use minip2p_quic::{QuicConfig, QuicTransport};
use minip2p_transport::{ConnectionId, Transport, TransportEvent};
use tempfile::TempDir;

fn generate_cert_pair() -> (TempDir, String, String) {
    let dir = tempfile::tempdir().expect("tempdir");

    let mut params = rcgen::CertificateParams::new(Vec::new()).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "minip2p-test");

    let key_pair = rcgen::KeyPair::generate().expect("keypair");
    let cert = params.self_signed(&key_pair).expect("cert");

    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");

    std::fs::File::create(&cert_path)
        .expect("create cert file")
        .write_all(cert.pem().as_bytes())
        .expect("write cert");

    std::fs::File::create(&key_path)
        .expect("create key file")
        .write_all(key_pair.serialize_pem().as_bytes())
        .expect("write key");

    let cert_str = cert_path.to_str().expect("cert path").to_string();
    let key_str = key_path.to_str().expect("key path").to_string();

    (dir, cert_str, key_str)
}

fn make_listen_multiaddr(port: u16) -> Multiaddr {
    Multiaddr::from_protocols(vec![
        Protocol::Ip4([127, 0, 0, 1]),
        Protocol::Udp(port),
        Protocol::QuicV1,
    ])
}

#[test]
fn two_peers_connect_and_exchange_data() {
    let (_cert_dir, cert_path, key_path) = generate_cert_pair();

    let server_config = QuicConfig::new()
        .with_cert_paths(&cert_path, &key_path)
        .verify_peer(false);

    let client_config = QuicConfig::new().verify_peer(false);

    let mut server =
        QuicTransport::new(server_config, "127.0.0.1:0").expect("server bind");
    let mut client =
        QuicTransport::new(client_config, "127.0.0.1:0").expect("client bind");

    let server_addr = server.local_addr().expect("server local addr");
    let listen_ma = make_listen_multiaddr(server_addr.port());

    server.listen(&listen_ma).expect("server listen");

    let dummy_peer_id =
        minip2p_identity::PeerId::from_bytes(&[0x00, 0x04, 0x01, 0x02, 0x03, 0x04])
            .expect("peer id");

    let peer_addr = PeerAddr::new(listen_ma, dummy_peer_id).expect("peer addr");

    let client_conn_id = ConnectionId::new(1);
    client
        .dial(client_conn_id, &peer_addr)
        .expect("client dial");

    let mut server_got_connection = false;
    let mut client_got_connected = false;
    let mut server_received = false;
    let mut client_received = false;

    let mut server_conn_id = ConnectionId::new(0);

    for _ in 0..200 {
        std::thread::sleep(std::time::Duration::from_millis(5));

        let server_events = server.poll().expect("server poll");
        for event in &server_events {
            match event {
                TransportEvent::IncomingConnection { id, .. } => {
                    server_got_connection = true;
                    server_conn_id = *id;
                }
                TransportEvent::Connected { id, .. } => {
                    if !server_got_connection {
                        server_got_connection = true;
                        server_conn_id = *id;
                    }
                }
                TransportEvent::Received { data, .. } => {
                    assert_eq!(data, b"hello from client");
                    server_received = true;
                }
                _ => {}
            }
        }

        let client_events = client.poll().expect("client poll");
        for event in &client_events {
            match event {
                TransportEvent::Connected { .. } => {
                    client_got_connected = true;
                }
                TransportEvent::Received { data, .. } => {
                    assert_eq!(data, b"hello from server");
                    client_received = true;
                }
                _ => {}
            }
        }

        if client_got_connected && server_got_connection {
            break;
        }
    }

    assert!(server_got_connection, "server should see incoming connection");
    assert!(client_got_connected, "client should be connected");

    client
        .send(client_conn_id, b"hello from client".to_vec())
        .expect("client send");

    for _ in 0..200 {
        std::thread::sleep(std::time::Duration::from_millis(5));

        let server_events = server.poll().expect("server poll");
        for event in &server_events {
            if let TransportEvent::Received { data, .. } = event {
                assert_eq!(data, b"hello from client");
                server_received = true;
            }
        }

        if server_received {
            break;
        }
    }

    assert!(server_received, "server should receive client data");

    server
        .send(server_conn_id, b"hello from server".to_vec())
        .expect("server send");

    for _ in 0..200 {
        std::thread::sleep(std::time::Duration::from_millis(5));

        let client_events = client.poll().expect("client poll");
        for event in &client_events {
            if let TransportEvent::Received { data, .. } = event {
                assert_eq!(data, b"hello from server");
                client_received = true;
            }
        }

        if client_received {
            break;
        }
    }

    assert!(client_received, "client should receive server data");
}
