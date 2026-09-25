use std::time::{Duration, Instant};

use minip2p::{ConnectOutcome, Endpoint, EndpointEvent, EndpointWaitOutcome, PeerAddr};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A complete peer address, e.g. /ip4/127.0.0.1/udp/4001/quic-v1/p2p/12D3KooW...
    let target: PeerAddr = std::env::args()
        .nth(1)
        .ok_or("usage: dialer <peer-address>")?
        .parse()?;
    let peer = target.peer_id().clone();

    let mut node = Endpoint::builder()
        .agent_version("minip2p-hello/dialer")
        .listen_default()?
        .bind()?;

    // One Connection attempt, one Connect ID, one terminal event.
    let connect_id = node.connect(target)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let EndpointWaitOutcome::Event(event) = node.wait(deadline)? else {
            // Deadline (or an interruption we have no use for): give up.
            return Err("peer did not answer within 10 seconds".into());
        };
        match event {
            EndpointEvent::ConnectSettled {
                connect_id: id,
                outcome,
                ..
            } if id == connect_id => {
                if !matches!(outcome, ConnectOutcome::Connected { .. }) {
                    return Err(format!("connect failed: {outcome:?}").into());
                }
            }
            EndpointEvent::PeerReady { peer_id, .. } if peer_id == peer => node.ping(&peer)?,
            EndpointEvent::PingRttMeasured { peer_id, rtt_ms } if peer_id == peer => {
                println!("peer={peer} rtt={rtt_ms}ms");
                return Ok(());
            }
            // Everything else is unrelated to this exchange.
            _ => {}
        }
    }
}
