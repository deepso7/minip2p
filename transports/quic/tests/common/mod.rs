//! Helpers shared by the QUIC integration tests via `mod common;`.

use minip2p_core::PeerAddr;
use minip2p_quic::{QuicNodeConfig, QuicTransport};
use minip2p_transport::{Transport, TransportEvent};

/// Binds a listening server and an unconnected client on loopback and
/// returns them together with the server's peer-addr.
pub fn setup_pair() -> (QuicTransport, QuicTransport, PeerAddr) {
    let mut server =
        QuicTransport::new(QuicNodeConfig::generate(), "127.0.0.1:0").expect("server bind");
    let client =
        QuicTransport::new(QuicNodeConfig::generate(), "127.0.0.1:0").expect("client bind");

    server.listen_on_bound_addr().expect("server listen");
    let peer_addr = server.local_peer_addr().expect("peer addr");

    (server, client, peer_addr)
}

/// Sleeps briefly to let packets flow, then polls both transports once.
pub fn drive_pair_once(
    server: &mut QuicTransport,
    client: &mut QuicTransport,
) -> (Vec<TransportEvent>, Vec<TransportEvent>) {
    std::thread::sleep(std::time::Duration::from_millis(5));
    let server_events = server.poll().expect("server poll");
    let client_events = client.poll().expect("client poll");
    (server_events, client_events)
}
