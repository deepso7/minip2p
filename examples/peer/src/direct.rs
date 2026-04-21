//! Direct QUIC peer-to-peer mode (no relay).
//!
//! This module proves the basic stack works end-to-end before the relay +
//! DCUtR flow lands. It's also the target of the automated E2E test --
//! a CI-safe regression net that spawns two `minip2p-peer` subprocesses
//! and asserts the ping round-trip completes.

use std::error::Error;
use std::thread;
use std::time::{Duration, Instant};

use minip2p_core::PeerAddr;
use minip2p_identity::Ed25519Keypair;
use minip2p_quic::{QuicNodeConfig, QuicTransport};
use minip2p_swarm::{Swarm, SwarmBuilder, SwarmEvent};

use crate::cli::print_event;

/// Poll cadence for the event loop. Matches the existing swarm tests.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Local bind address used by both listener and dialer. `127.0.0.1:0`
/// lets the kernel pick an ephemeral port; the listener reports the
/// chosen address via `local_peer_addr()`.
const LOCAL_BIND: &str = "127.0.0.1:0";

/// User-agent advertised on Identify so ad-hoc packet captures can tell
/// minip2p-peer-originated traffic from other libp2p implementations.
const AGENT: &str = "minip2p-peer/0.1.0";

/// Hard deadline for the dialer. If we can't connect + identify + ping
/// in this window, something is wrong and the binary exits non-zero.
const DIAL_DEADLINE: Duration = Duration::from_secs(10);

/// Runs the direct-mode listener until interrupted (SIGINT / SIGTERM).
///
/// Binds a fresh ephemeral QUIC socket, prints the resulting peer-addr
/// on stdout (so the E2E test can parse it), and loops forever pumping
/// the swarm. Inbound pings are echoed automatically by the swarm's
/// built-in ping responder -- this function only prints lifecycle
/// events.
pub fn run_listen() -> Result<(), Box<dyn Error>> {
    let mut swarm = build_swarm()?;
    swarm
        .transport_mut()
        .listen_on_bound_addr()
        .map_err(|e| format!("listen failed: {e}"))?;

    let peer_addr = swarm
        .transport()
        .local_peer_addr()
        .map_err(|e| format!("local_peer_addr failed: {e}"))?;
    // Stdout is the structured-events channel; stderr is for diagnostics.
    println!("[listen] bound={peer_addr}");
    eprintln!("[listen] waiting for dialers (Ctrl-C to stop)");

    loop {
        thread::sleep(POLL_INTERVAL);
        let events = swarm
            .poll()
            .map_err(|e| format!("swarm poll failed: {e}"))?;
        for event in events {
            print_event("listen", &event);
        }
    }
}

/// Runs the direct-mode dialer against `target`, returning `Ok(())` once
/// a ping RTT has been measured and printed.
pub fn run_dial(target: PeerAddr) -> Result<(), Box<dyn Error>> {
    let mut swarm = build_swarm()?;
    let target_peer_id = target.peer_id().clone();

    swarm
        .dial(&target)
        .map_err(|e| format!("dial failed: {e}"))?;
    println!("[dial] dialing {target}");

    let deadline = Instant::now() + DIAL_DEADLINE;
    let mut identified = false;
    let mut ping_issued = false;

    loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "deadline exceeded ({}s) before ping RTT was measured",
                DIAL_DEADLINE.as_secs()
            )
            .into());
        }

        thread::sleep(POLL_INTERVAL);
        let events = swarm
            .poll()
            .map_err(|e| format!("swarm poll failed: {e}"))?;

        for event in events {
            print_event("dial", &event);
            match event {
                SwarmEvent::IdentifyReceived { peer_id, .. }
                    if peer_id == target_peer_id =>
                {
                    // Gate the ping on Identify so we know the real peer-id
                    // mapping is in place; firing ping() too early races
                    // with the synthetic-to-verified peer-id migration.
                    identified = true;
                }
                SwarmEvent::PingRttMeasured { peer_id, .. }
                    if peer_id == target_peer_id =>
                {
                    // Exactly what we came here to do.
                    return Ok(());
                }
                _ => {}
            }
        }

        if identified && !ping_issued {
            swarm
                .ping(&target_peer_id)
                .map_err(|e| format!("ping failed: {e}"))?;
            ping_issued = true;
        }
    }
}

/// Constructs a `Swarm<QuicTransport>` bound to an ephemeral loopback UDP
/// port with a fresh Ed25519 identity and the default Identify/Ping stack.
fn build_swarm() -> Result<Swarm<QuicTransport>, Box<dyn Error>> {
    let keypair = Ed25519Keypair::generate();
    let transport = QuicTransport::new(QuicNodeConfig::with_keypair(keypair.clone()), LOCAL_BIND)
        .map_err(|e| format!("quic bind failed: {e}"))?;
    Ok(SwarmBuilder::new(&keypair).agent_version(AGENT).build(transport))
}
