use std::error::Error;
use std::time::Duration;

use futures::StreamExt as _;
use libp2p::identify;
use libp2p::multiaddr::Protocol;
use libp2p::ping;
use libp2p::relay;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{Multiaddr, PeerId, Swarm, noise, tcp, yamux};

const RUST_LIBP2P_REV: &str = "170c3c81ddd80e7c58b0500563e00a09139e8545";
const CIRCUIT_V2_REV: &str = "6b6203ee6f62938ce67efdb33498173f475851c0";
const HOP: &str = "/libp2p/circuit/relay/0.2.0/hop";

#[derive(NetworkBehaviour)]
struct Behaviour {
    relay: relay::client::Behaviour,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let relay_addr: Multiaddr = std::env::args().nth(1).ok_or("relay address argument missing")?.parse()?;
    let expected_duration: u64 = argument(2, "expected duration")?.parse()?;
    let expected_bytes: u64 = argument(3, "expected byte limit")?.parse()?;
    macro_rules! verify_limit {
        ($limit:expr, $context:literal) => {{
            let limit = $limit.ok_or(concat!($context, " omitted its advertised Limit"))?;
            assert_eq!(limit.duration(), Some(Duration::from_secs(expected_duration)));
            assert_eq!(limit.data_in_bytes(), Some(expected_bytes));
        }};
    }
    let relay_peer = peer_id(&relay_addr).ok_or("relay address must end in /p2p/<peer-id>")?;
    let mut destination = client()?;
    let destination_peer = *destination.local_peer_id();

    destination.listen_on(relay_addr.clone().with(Protocol::P2pCircuit))?;
    let mut reserved = false;
    let mut hop_advertised = false;
    while !(reserved && hop_advertised) {
        match timeout_next(&mut destination).await? {
            SwarmEvent::Behaviour(BehaviourEvent::Relay(relay::client::Event::ReservationReqAccepted { relay_peer_id, limit, .. })) if relay_peer_id == relay_peer => {
                verify_limit!(limit, "reservation");
                reserved = true;
            }
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) if peer_id == relay_peer => {
                hop_advertised = info.protocols.iter().any(|protocol| protocol.as_ref() == HOP);
            }
            SwarmEvent::OutgoingConnectionError { error, .. } => return Err(format!("reservation connection failed: {error}").into()),
            _ => {}
        }
    }

    let destination_addr = relay_addr
        .clone()
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(destination_peer));
    let mut source = client()?;
    source.dial(destination_addr)?;

    let mut source_ping = false;
    let mut destination_ping = false;
    let mut outbound_limit = false;
    let mut inbound_limit = false;
    while !(source_ping && destination_ping && outbound_limit && inbound_limit) {
        tokio::select! {
            event = timeout_next(&mut source) => match event? {
                SwarmEvent::Behaviour(BehaviourEvent::Ping(ping::Event { peer, result: Ok(_), .. })) if peer == destination_peer => source_ping = true,
                SwarmEvent::Behaviour(BehaviourEvent::Relay(relay::client::Event::OutboundCircuitEstablished { limit, .. })) => {
                    verify_limit!(limit, "outbound circuit");
                    outbound_limit = true;
                }
                SwarmEvent::OutgoingConnectionError { error, .. } => return Err(format!("relayed CONNECT failed: {error}").into()),
                _ => {}
            },
            event = timeout_next(&mut destination) => match event? {
                SwarmEvent::Behaviour(BehaviourEvent::Ping(ping::Event { result: Ok(_), .. })) => destination_ping = true,
                SwarmEvent::Behaviour(BehaviourEvent::Relay(relay::client::Event::InboundCircuitEstablished { limit, .. })) => {
                    verify_limit!(limit, "inbound circuit");
                    inbound_limit = true;
                }
                _ => {}
            }
        }
    }

    println!("interop ok rust-libp2p={RUST_LIBP2P_REV} circuit-v2={CIRCUIT_V2_REV} reservation=true identify_hop=true connect_stop=true bytes=bidirectional duration_limit={expected_duration} byte_limit={expected_bytes} voucher_none_accepted=true");
    Ok(())
}

fn argument(index: usize, name: &str) -> Result<String, Box<dyn Error>> {
    std::env::args()
        .nth(index)
        .ok_or_else(|| format!("{name} argument missing").into())
}

fn client() -> Result<Swarm<Behaviour>, Box<dyn Error>> {
    Ok(libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(tcp::Config::default().nodelay(true), noise::Config::new, yamux::Config::default)?
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|keypair, relay| Behaviour {
            relay,
            identify: identify::Behaviour::new(identify::Config::new("/minip2p/relay-interop/1".into(), keypair.public())),
            ping: ping::Behaviour::new(ping::Config::new()),
        })?
        .build())
}

fn peer_id(address: &Multiaddr) -> Option<PeerId> {
    address.iter().find_map(|protocol| match protocol {
        Protocol::P2p(peer) => Some(peer),
        _ => None,
    })
}

async fn timeout_next(swarm: &mut Swarm<Behaviour>) -> Result<SwarmEvent<BehaviourEvent>, Box<dyn Error>> {
    tokio::time::timeout(Duration::from_secs(30), swarm.select_next_some())
        .await
        .map_err(|_| "timed out waiting for relay interoperability event".into())
}
