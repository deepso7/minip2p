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

/// A transport bound to one IPv4 loopback socket.
pub fn loopback(config: QuicNodeConfig) -> QuicTransport {
    let addr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().expect("multiaddr");
    QuicTransport::bind(config, &[addr]).expect("bind loopback")
}

/// The first address other nodes can dial `transport` at.
pub fn peer_addr(transport: &QuicTransport) -> PeerAddr {
    transport
        .local_peer_addrs()
        .expect("peer addrs")
        .into_iter()
        .next()
        .expect("a bound socket")
}

/// Binds a listening server and an unconnected client on loopback and
/// returns them together with the server's peer-addr.
pub fn setup_pair() -> (QuicTransport, QuicTransport, PeerAddr) {
    let mut server = loopback(QuicNodeConfig::generate());
    let client = loopback(QuicNodeConfig::generate());
    server.listen_on_bound_addrs().expect("server listen");
    let peer_addr = peer_addr(&server);
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
