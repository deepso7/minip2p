use std::collections::HashSet;

use minip2p::{Endpoint, EndpointEvent, EndpointWaitOutcome, PeerAddr, StreamKey, WaitDeadline};

const ECHO_PROTOCOL: &str = "/my-app/echo/1.0.0";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut node = Endpoint::builder()
        .agent_version("minip2p-stream/listener")
        .protocol(ECHO_PROTOCOL)
        .listen_default()?
        .bind()?;

    for address in node.listen_all()? {
        println!("listen={}", local_dialable(&address));
    }

    // A `StreamKey` names a stream by its connection and its id.
    let mut echo_streams: HashSet<StreamKey> = HashSet::new();

    loop {
        let EndpointWaitOutcome::Event(event) = node.wait(WaitDeadline::NEVER)? else {
            continue;
        };
        match event {
            EndpointEvent::StreamReady {
                stream,
                protocol_id,
                initiated_locally: false,
                ..
            } if protocol_id == ECHO_PROTOCOL => {
                echo_streams.insert(stream);
            }
            EndpointEvent::StreamData { stream, data, .. } if echo_streams.contains(&stream) => {
                // `send_stream` queues what a full stream cannot take yet and
                // resends it on its own, so every chunk is echoed in order.
                // A failure ends this stream, not the listener.
                if let Err(error) = node.send_stream(stream, data) {
                    eprintln!("echo on stream {stream} failed: {error}");
                    echo_streams.remove(&stream);
                    let _ = node.reset_stream(stream);
                }
            }
            EndpointEvent::StreamRemoteWriteClosed { stream, .. }
                if echo_streams.remove(&stream) =>
            {
                // The FIN waits behind every echoed byte still queued.
                if let Err(error) = node.close_stream_write(stream) {
                    eprintln!("closing stream {stream} failed: {error}");
                }
            }
            EndpointEvent::StreamClosed { stream, .. } => {
                echo_streams.remove(&stream);
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
