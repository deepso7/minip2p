use std::time::{Duration, Instant};

use minip2p::{ConnectOutcome, Endpoint, EndpointEvent, EndpointWaitOutcome, PeerAddr};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target: PeerAddr = std::env::args()
        .nth(1)
        .ok_or("usage: dialer <peer-address>")?
        .parse()?;
    let peer = target.peer_id().clone();

    let mut node = Endpoint::builder()
        .agent_version("minip2p-hello/dialer")
        .listen_default()?
        .bind()?;

    let connect_id = node.connect(target)?;
    let mut deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let event = match node.wait(deadline)? {
            EndpointWaitOutcome::Event(event) => event,
            EndpointWaitOutcome::Deadline => {
                return Err("peer did not answer in time".into());
            }
            _ => continue,
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
            EndpointEvent::PeerReady { peer_id, .. } if peer_id == peer => {
                node.ping(&peer)?;
                deadline = Instant::now() + Duration::from_secs(5);
            }
            EndpointEvent::PingRttMeasured { peer_id, rtt_ms, .. } if peer_id == peer => {
                println!("peer={peer} rtt={rtt_ms}ms");
                return Ok(());
            }
            _ => {}
        }
    }
}
