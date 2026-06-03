//! Direct QUIC peer-to-peer mode (no relay).
//!
//! Serves as the baseline smoke test for the stack and as the target of
//! the CI E2E test at `tests/direct.rs`. The logic is intentionally
//! linear: bring up the swarm, do the one interesting thing, exit.

use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use minip2p_core::{Multiaddr, PeerAddr, Protocol};
use minip2p_quic::QuicEndpoint;
use minip2p_swarm::{Swarm, SwarmBuilder, SwarmEvent};

use crate::cli::{RunOptions, print_event};
use crate::runtime::{build_peer_transport, load_keypair};

const AGENT: &str = "minip2p-peer/0.1.0";
/// Far-future deadline for the listener; practically "run forever".
const LISTEN_FOREVER: Duration = Duration::from_secs(60 * 60 * 24 * 365);
/// Dialer's hard ceiling: connect, identify, ping -- comfortably fast.
const DIAL_DEADLINE: Duration = Duration::from_secs(10);

/// Runs the listener until interrupted (SIGINT).
pub fn run_listen(options: RunOptions) -> Result<(), Box<dyn Error>> {
    let mut swarm = build_swarm(&options, "listen")?;
    let peer_addrs = swarm
        .listen_on_bound_addrs()
        .map_err(|e| format!("listen failed: {e}"))?;
    let peer_addr = peer_addrs
        .first()
        .ok_or("listen completed without any bound peer addresses")?;
    // Stdout: the machine-readable event stream the E2E test scans.
    println!("[listen] bound={}", local_dialable_peer_addr(peer_addr));
    for addr in peer_addrs {
        println!("[listen] listen-addr={addr}");
    }
    eprintln!("[listen] waiting for dialers (Ctrl-C to stop)");

    // Loop until a long deadline; SIGINT tears the process down.
    let deadline = Instant::now() + LISTEN_FOREVER;
    while swarm
        .run_until(deadline, |ev| {
            print_event("listen", ev);
            false // never stop on our own -- caller-driven shutdown
        })
        .map_err(|e| format!("swarm run_until: {e}"))?
        .is_some()
    {}
    Ok(())
}

/// Dials `target`, waits for Identify, pings, prints RTT, exits.
pub fn run_dial(target: PeerAddr, options: RunOptions) -> Result<(), Box<dyn Error>> {
    let mut swarm = build_swarm(&options, "dial")?;
    let target_peer_id = target.peer_id().clone();
    swarm
        .dial(&target)
        .map_err(|e| format!("dial failed: {e}"))?;
    println!("[dial] dialing {target}");

    let deadline = Instant::now() + DIAL_DEADLINE;

    // Wait until the peer id is stable and Identify has populated protocol support.
    swarm
        .run_until(deadline, |ev| {
            print_event("dial", ev);
            matches!(ev, SwarmEvent::PeerReady { peer_id, .. } if peer_id == &target_peer_id)
        })
        .map_err(|e| format!("waiting for peer ready: {e}"))?
        .ok_or("deadline exceeded before peer became ready")?;

    swarm
        .ping(&target_peer_id)
        .map_err(|e| format!("ping failed: {e}"))?;

    // Wait for the first RTT measurement, print it via print_event, exit.
    swarm
        .run_until(deadline, |ev| {
            print_event("dial", ev);
            matches!(ev, SwarmEvent::PingRttMeasured { peer_id, .. } if peer_id == &target_peer_id)
        })
        .map_err(|e| format!("waiting for ping rtt: {e}"))?
        .ok_or("deadline exceeded before ping rtt arrived")?;

    Ok(())
}

/// Builds a swarm with a fresh Ed25519 identity and the default
/// Identify/Ping stack.
fn build_swarm(options: &RunOptions, role: &str) -> Result<Swarm<QuicEndpoint>, Box<dyn Error>> {
    let keypair = load_keypair(options, role)?;
    let transport = build_peer_transport(options, &keypair)?;
    Ok(SwarmBuilder::new(&keypair)
        .agent_version(AGENT)
        .build(transport))
}

fn local_dialable_peer_addr(peer_addr: &PeerAddr) -> PeerAddr {
    let protocols = peer_addr.transport().protocols();
    let Some(first) = protocols.first() else {
        return peer_addr.clone();
    };

    let replacement = match first {
        Protocol::Ip4(bytes) if *bytes == [0, 0, 0, 0] => {
            Some(Protocol::Ip4(Ipv4Addr::LOCALHOST.octets()))
        }
        Protocol::Ip6(bytes) if *bytes == [0; 16] => {
            Some(Protocol::Ip6(Ipv6Addr::LOCALHOST.octets()))
        }
        _ => None,
    };

    let Some(replacement) = replacement else {
        return peer_addr.clone();
    };

    let mut rewritten = protocols.to_vec();
    rewritten[0] = replacement;
    PeerAddr::new(
        Multiaddr::from_protocols(rewritten),
        peer_addr.peer_id().clone(),
    )
    .unwrap_or_else(|_| peer_addr.clone())
}
