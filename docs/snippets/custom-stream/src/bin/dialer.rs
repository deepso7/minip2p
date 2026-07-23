use std::{str::FromStr, time::Duration};

use minip2p::{Endpoint, Event, PeerAddr};

const ECHO_PROTOCOL: &str = "/my-app/echo/1.0.0";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = std::env::args()
        .nth(1)
        .ok_or("usage: dialer <peer-address>")?;
    let target = PeerAddr::from_str(&target)?;
    let peer_id = target.peer_id().clone();

    let mut node = Endpoint::builder()
        .agent_version("minip2p-stream/dialer")
        .protocol(ECHO_PROTOCOL)
        .bind_quic_dual_stack()?;

    node.dial(&target)?;
    node.wait_peer_ready(&peer_id, Duration::from_secs(10))?
        .ok_or("peer did not become ready")?;

    let stream_id = node.open_stream(&peer_id, ECHO_PROTOCOL)?;
    let mut response = Vec::new();

    loop {
        let event = node
            .next_event(Duration::from_secs(10))?
            .ok_or("stream exchange timed out")?;

        match event {
            Event::StreamReady {
                peer_id: peer,
                stream_id: ready,
                protocol_id,
                ..
            } if peer == peer_id && ready == stream_id && protocol_id == ECHO_PROTOCOL => {
                node.send_stream(&peer_id, stream_id, b"hello".to_vec())?;
                node.close_stream_write(&peer_id, stream_id)?;
            }
            Event::StreamData {
                peer_id: peer,
                stream_id: ready,
                data,
                ..
            } if peer == peer_id && ready == stream_id => {
                response.extend_from_slice(&data);
            }
            Event::StreamRemoteWriteClosed {
                peer_id: peer,
                stream_id: ready,
                ..
            } if peer == peer_id && ready == stream_id => {
                println!("{}", String::from_utf8_lossy(&response));
                return Ok(());
            }
            Event::StreamClosed {
                peer_id: peer,
                stream_id: ready,
                ..
            } if peer == peer_id && ready == stream_id => {
                return Err("stream closed before the echo completed".into());
            }
            Event::Error(error) => eprintln!("runtime error: {error:?}"),
            _ => {}
        }
    }
}
