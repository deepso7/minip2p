use std::collections::HashSet;

use minip2p::{Deadline, Endpoint, EndpointEvent, EndpointWaitOutcome, PeerAddr, PeerId, StreamId};

const ECHO_PROTOCOL: &str = "/my-app/echo/1.0.0";

fn main() -> Result<(), minip2p::Error> {
    let mut node = Endpoint::builder()
        .agent_version("minip2p-stream/listener")
        .protocol(ECHO_PROTOCOL)
        .listen_default()?
        .bind()?;

    for address in node.listen_all()? {
        println!("listen={}", local_dialable(&address));
    }

    let mut echo_streams: HashSet<(PeerId, StreamId)> = HashSet::new();

    loop {
        let EndpointWaitOutcome::Event(event) = node.wait(Deadline::NEVER)? else {
            continue;
        };
        match event {
            EndpointEvent::StreamReady {
                peer_id,
                stream_id,
                protocol_id,
                initiated_locally: false,
                ..
            } if protocol_id == ECHO_PROTOCOL => {
                echo_streams.insert((peer_id, stream_id));
            }
            EndpointEvent::StreamData {
                peer_id,
                stream_id,
                data,
                ..
            } if echo_streams.contains(&(peer_id.clone(), stream_id)) => {
                node.send_stream(&peer_id, stream_id, data)?;
                node.close_stream_write(&peer_id, stream_id)?;
                echo_streams.remove(&(peer_id, stream_id));
            }
            EndpointEvent::StreamRemoteWriteClosed {
                peer_id, stream_id, ..
            } if echo_streams.remove(&(peer_id.clone(), stream_id)) => {
                node.close_stream_write(&peer_id, stream_id)?;
            }
            EndpointEvent::StreamClosed {
                peer_id, stream_id, ..
            } => {
                echo_streams.remove(&(peer_id, stream_id));
            }
            EndpointEvent::Error(error) => eprintln!("runtime error: {error:?}"),
            _ => {}
        }
    }
}

fn local_dialable(address: &PeerAddr) -> String {
    address
        .to_string()
        .replace("/ip4/0.0.0.0/", "/ip4/127.0.0.1/")
        .replace("/ip6/::/", "/ip6/::1/")
}
