//! Direct QUIC peer-to-peer mode (no relay).
//!
//! Serves as the baseline smoke test for the stack and as the target of
//! the CI E2E test at `tests/direct.rs`. The logic is intentionally
//! linear: bring up the swarm, do the one interesting thing, exit.

use std::error::Error;
use std::time::{Duration, Instant};

use minip2p_core::PeerAddr;
use minip2p_identity::Ed25519Keypair;
use minip2p_quic::{QuicNodeConfig, QuicTransport};
use minip2p_swarm::{Swarm, SwarmBuilder, SwarmEvent};

use crate::cli::print_event;

const LOCAL_BIND: &str = "127.0.0.1:0";
const AGENT: &str = "minip2p-peer/0.1.0";
/// Far-future deadline for the listener; practically "run forever".
const LISTEN_FOREVER: Duration = Duration::from_secs(60 * 60 * 24 * 365);
/// Dialer's hard ceiling: connect, identify, ping -- comfortably fast.
const DIAL_DEADLINE: Duration = Duration::from_secs(10);

/// Runs the listener until interrupted (SIGINT).
pub fn run_listen() -> Result<(), Box<dyn Error>> {
    let mut swarm = build_swarm()?;
    let peer_addr = swarm
        .listen_on_bound_addr()
        .map_err(|e| format!("listen failed: {e}"))?;
    // Stdout: the machine-readable event stream the E2E test scans.
    println!("[listen] bound={peer_addr}");
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
pub fn run_dial(target: PeerAddr) -> Result<(), Box<dyn Error>> {
    let mut swarm = build_swarm()?;
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

/// Builds a `Swarm<QuicTransport>` bound to an ephemeral loopback UDP
/// port with a fresh Ed25519 identity and the default Identify/Ping
/// stack.
fn build_swarm() -> Result<Swarm<QuicTransport>, Box<dyn Error>> {
    let keypair = Ed25519Keypair::generate();
    let transport = QuicTransport::new(QuicNodeConfig::with_keypair(keypair.clone()), LOCAL_BIND)
        .map_err(|e| format!("quic bind failed: {e}"))?;
    Ok(SwarmBuilder::new(&keypair)
        .agent_version(AGENT)
        .build(transport))
}
