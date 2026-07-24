use std::{str::FromStr, time::Duration};

use minip2p::{Endpoint, PeerAddr};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = std::env::args()
        .nth(1)
        .ok_or("usage: dialer <peer-address>")?;
    let target = PeerAddr::from_str(&target)?;

    let mut node = Endpoint::builder()
        .agent_version("minip2p-hello/dialer")
        .bind_quic_dual_stack()?;

    node.dial(&target)?;
    let ready = node.wait_peer_ready(target.peer_id(), Duration::from_secs(10))?;
    if ready.is_none() {
        return Err("peer did not become ready within 10 seconds".into());
    }

    node.ping(target.peer_id())?;
    let rtt = node
        .wait_ping_rtt(target.peer_id(), Duration::from_secs(5))?
        .ok_or("ping timed out")?;

    println!("peer={} rtt={}ms", target.peer_id(), rtt);
    Ok(())
}
