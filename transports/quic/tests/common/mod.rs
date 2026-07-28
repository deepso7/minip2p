//! Helpers shared by the QUIC integration tests via `mod common;`.

use std::sync::LazyLock;
use std::time::Instant;

use minip2p_core::PeerAddr;
use minip2p_platform::{Clock, Now, StdClock};
use minip2p_quic::{QuicNodeConfig, QuicTransport};
use minip2p_transport::{Transport, TransportEvent};

/// One epoch for the whole test binary, so every sample handed to a transport
/// sits on the same timeline and QUIC's deadlines stay comparable across them.
static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Samples the shared test clock.
///
/// These tests drive real sockets and sleep for real time, so they need a real
/// clock rather than a frozen sample.
pub fn now() -> Now {
    StdClock::with_epoch(*EPOCH).now()
}

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
    let server_events = server.poll(now()).expect("server poll");
    let client_events = client.poll(now()).expect("client poll");
    (server_events, client_events)
}
