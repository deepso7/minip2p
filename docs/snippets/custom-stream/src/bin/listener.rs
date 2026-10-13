use std::collections::HashSet;

use minip2p::{
    ConnectionId, Endpoint, EndpointEvent, EndpointWaitOutcome, PeerAddr, StreamId,
    StreamWriter, WaitDeadline,
};

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

    // Stream ids are per connection, so a stream is named by both.
    let mut echo_streams: HashSet<(ConnectionId, StreamId)> = HashSet::new();
    // Holds what a full stream could not take yet and finishes it on
    // `StreamWritable`; `?` on a bare `send_stream` would drop that tail.
    let mut writer = StreamWriter::new(1024 * 1024);

    loop {
        let EndpointWaitOutcome::Event(event) = node.wait(WaitDeadline::NEVER)? else {
            continue;
        };
        writer.observe(&mut node, &event);
        match event {
            EndpointEvent::StreamReady {
                conn_id,
                stream_id,
                protocol_id,
                initiated_locally: false,
                ..
            } if protocol_id == ECHO_PROTOCOL => {
                echo_streams.insert((conn_id, stream_id));
            }
            EndpointEvent::StreamData {
                conn_id,
                stream_id,
                data,
                ..
            } if echo_streams.remove(&(conn_id, stream_id)) => {
                // A single-chunk echo: it answers the first `StreamData`
                // and half-closes, so a message split across chunks loses
                // the rest. Echoing every chunk needs a backlog behind the
                // one pending write (see `examples/peer`). The FIN waits for
                // every byte of the echo, and a failure ends this stream,
                // not the listener.
                let echoed = writer
                    .write(&mut node, conn_id, stream_id, data)
                    .and_then(|_| writer.close_write(&mut node, conn_id, stream_id));
                if let Err(error) = echoed {
                    eprintln!("echo on stream {stream_id} failed: {error}");
                    writer.forget(conn_id, stream_id);
                    let _ = node.reset_stream(conn_id, stream_id);
                }
            }
            EndpointEvent::StreamRemoteWriteClosed {
                conn_id, stream_id, ..
            } if echo_streams.remove(&(conn_id, stream_id)) => {
                if let Err(error) = writer.close_write(&mut node, conn_id, stream_id) {
                    eprintln!("closing stream {stream_id} failed: {error}");
                }
            }
            EndpointEvent::StreamClosed {
                conn_id, stream_id, ..
            } => {
                echo_streams.remove(&(conn_id, stream_id));
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
