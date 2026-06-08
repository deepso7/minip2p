use std::error::Error;
use std::time::{Duration, Instant};

use minip2p::{Endpoint, Event};

const AGENT: &str = "minip2p-ping-app/0.1.0";
const DEADLINE: Duration = Duration::from_secs(5);

fn main() -> Result<(), Box<dyn Error>> {
    let mut receiver = Endpoint::builder()
        .agent_version(AGENT)
        .bind_quic("127.0.0.1:0")?;
    let recv_addr = receiver.listen()?;

    let mut sender = Endpoint::builder()
        .agent_version(AGENT)
        .bind_quic("127.0.0.1:0")?;
    let recv_peer = recv_addr.peer_id().clone();
    sender.dial(&recv_addr)?;

    drive_two(
        &mut sender,
        &mut receiver,
        DEADLINE,
        |event| matches!(event, Event::PeerReady { peer_id, .. } if peer_id == &recv_peer),
    )?;

    sender.ping(&recv_peer)?;

    let event = drive_two(
        &mut sender,
        &mut receiver,
        DEADLINE,
        |event| matches!(event, Event::PingRttMeasured { peer_id, .. } if peer_id == &recv_peer),
    )?;

    if let Event::PingRttMeasured { rtt_ms, .. } = event {
        println!("ping took {rtt_ms}ms");
    }

    Ok(())
}

fn drive_two<F>(
    a: &mut Endpoint,
    b: &mut Endpoint,
    timeout: Duration,
    mut done: F,
) -> Result<Event, Box<dyn Error>>
where
    F: FnMut(&Event) -> bool,
{
    let deadline = Instant::now() + timeout;
    loop {
        for event in a.poll()? {
            if done(&event) {
                return Ok(event);
            }
        }
        for event in b.poll()? {
            if done(&event) {
                return Ok(event);
            }
        }
        if Instant::now() >= deadline {
            return Err("deadline exceeded while driving swarms".into());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
