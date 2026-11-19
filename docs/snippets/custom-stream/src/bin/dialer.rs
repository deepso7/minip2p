use std::{
    str::FromStr,
    time::{Duration, Instant},
};

use minip2p::{ConnectOutcome, Endpoint, EndpointEvent, EndpointWaitOutcome, PeerAddr};

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
        .listen_default()?
        .bind()?;

    let connect_id = node.connect(target)?;
    // A `StreamKey`: stream ids are per connection, so it names both.
    let mut stream = None;
    let mut response = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);

    loop {
        let event = match node.wait(deadline)? {
            EndpointWaitOutcome::Event(event) => event,
            // Another thread woke the wait; nothing to service here.
            EndpointWaitOutcome::Deadline => return Err("stream exchange timed out".into()),
            _ => continue, // interrupted by a WaitHandle
        };

        match event {
            EndpointEvent::ConnectSettled {
                connect_id: id,
                outcome,
                ..
            } if id == connect_id => {
                match outcome {
                    // A known protocol does not need to wait for Identify.
                    ConnectOutcome::Connected { .. } => {
                        stream = Some(node.open_stream(&peer_id, ECHO_PROTOCOL)?);
                    }
                    other => return Err(format!("connect failed: {other:?}").into()),
                }
            }
            EndpointEvent::StreamReady {
                peer_id: peer,
                stream: ready,
                protocol_id,
                ..
            } if peer == peer_id && Some(ready) == stream && protocol_id == ECHO_PROTOCOL => {
                // The endpoint queues what the stream cannot take at once,
                // and the FIN waits behind it.
                node.send_stream(ready, b"hello".to_vec())?;
                node.close_stream_write(ready)?;
            }
            EndpointEvent::StreamData {
                peer_id: peer,
                stream: from,
                data,
            } if peer == peer_id && Some(from) == stream => {
                response.extend_from_slice(&data);
            }
            EndpointEvent::StreamRemoteWriteClosed {
                peer_id: peer,
                stream: from,
            } if peer == peer_id && Some(from) == stream => {
                println!("{}", String::from_utf8_lossy(&response));
                return Ok(());
            }
            EndpointEvent::StreamClosed {
                peer_id: peer,
                stream: from,
            } if peer == peer_id && Some(from) == stream => {
                return Err("stream closed before the echo completed".into());
            }
            EndpointEvent::Error(error) => eprintln!("runtime error: {error:?}"),
            _ => {}
        }
    }
}
