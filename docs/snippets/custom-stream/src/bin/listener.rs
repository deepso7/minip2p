use std::collections::HashSet;

use minip2p::{Deadline, Endpoint, Event, PeerAddr, PeerId, StreamId};

const ECHO_PROTOCOL: &str = "/my-app/echo/1.0.0";

fn main() -> Result<(), minip2p::Error> {
    let mut node = Endpoint::builder()
        .agent_version("minip2p-stream/listener")
        .protocol(ECHO_PROTOCOL)
        .bind_quic_dual_stack()?;

    for address in node.listen_all()? {
        println!("listen={}", local_dialable(&address));
    }

    let mut echo_streams: HashSet<(PeerId, StreamId)> = HashSet::new();

    while let Some(event) = node.next_event(Deadline::NEVER)? {
        match event {
            Event::StreamReady {
                peer_id,
                stream_id,
                protocol_id,
                initiated_locally: false,
                ..
            } if protocol_id == ECHO_PROTOCOL => {
                echo_streams.insert((peer_id, stream_id));
            }
            Event::StreamData {
                peer_id,
                stream_id,
                data,
                ..
            } if echo_streams.contains(&(peer_id.clone(), stream_id)) => {
                node.send_stream(&peer_id, stream_id, data)?;
                node.close_stream_write(&peer_id, stream_id)?;
                echo_streams.remove(&(peer_id, stream_id));
            }
            Event::StreamRemoteWriteClosed {
                peer_id, stream_id, ..
            } if echo_streams.remove(&(peer_id.clone(), stream_id)) => {
                node.close_stream_write(&peer_id, stream_id)?;
            }
            Event::StreamClosed {
                peer_id, stream_id, ..
            } => {
                echo_streams.remove(&(peer_id, stream_id));
            }
            Event::Error(error) => eprintln!("runtime error: {error:?}"),
            _ => {}
        }
    }

    Ok(())
}

fn local_dialable(address: &PeerAddr) -> String {
    address
        .to_string()
        .replace("/ip4/0.0.0.0/", "/ip4/127.0.0.1/")
        .replace("/ip6/::/", "/ip6/::1/")
}
