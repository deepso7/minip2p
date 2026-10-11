//! rust-libp2p QUIC peer for interop checks (test tooling only).
//! `interop-rl listen` prints `LISTEN <multiaddr>/p2p/<peer>`;
//! `interop-rl dial <multiaddr>` dials. Prints `ESTABLISHED <peer>` per connection.
use std::time::Duration;

use futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, ping};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_quic()
        .with_behaviour(|_| ping::Behaviour::default())
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
        .build();
    let me = *swarm.local_peer_id();
    match args.get(1).map(String::as_str) {
        Some("listen") => {
            swarm.listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()).unwrap();
        }
        Some("dial") => {
            let addr: Multiaddr = args[2].parse().unwrap();
            swarm.dial(addr).unwrap();
        }
        _ => panic!("usage"),
    }
    let deadline = tokio::time::sleep(Duration::from_secs(10));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => break,
            ev = swarm.select_next_some() => match ev {
                SwarmEvent::NewListenAddr { address, .. } => println!("LISTEN {address}/p2p/{me}"),
                SwarmEvent::ConnectionEstablished { peer_id, .. } => println!("ESTABLISHED {peer_id}"),
                SwarmEvent::OutgoingConnectionError { error, .. } => println!("DIAL_ERROR {error}"),
                SwarmEvent::IncomingConnectionError { error, .. } => println!("INCOMING_ERROR {error}"),
                SwarmEvent::ConnectionClosed { peer_id, cause, .. } => println!("CLOSED {peer_id} {cause:?}"),
                _ => {}
            },
        }
    }
}
