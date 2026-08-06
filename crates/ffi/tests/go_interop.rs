//! Live TCP/Noise/Yamux interoperability with an independent go-libp2p peer.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex, PoisonError, mpsc};
use std::time::{Duration, Instant};

use minip2p_ffi::{
    EndpointConfig, FfiError, P2pEndpoint, P2pEvent, P2pEventListener, PubsubRouter,
    TransportOptions,
};
use serde_json::{Value, json};

const ECHO_PROTOCOL: &str = "/minip2p/interop/echo/1.0.0";
const PAYLOAD_FROM_MINIP2P: &[u8] = b"hello from minip2p";
const PAYLOAD_FROM_GO_BYTES: usize = 128 * 1024;
const TIMEOUT: Duration = Duration::from_secs(20);

struct GoPeer {
    child: Child,
    stdin: ChildStdin,
    events: mpsc::Receiver<Value>,
}

impl GoPeer {
    fn spawn() -> Self {
        let project = format!(
            "{}/../../tests/interop/go-libp2p",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut child = Command::new("go")
            .args(["run", "."])
            .current_dir(project)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn go-libp2p peer; install Go to run this ignored test");
        let stdin = child.stdin.take().expect("go peer stdin");
        let stdout = child.stdout.take().expect("go peer stdout");
        let (sender, events) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let line = line.expect("read go peer event");
                let value = serde_json::from_str(&line)
                    .unwrap_or_else(|error| panic!("invalid go peer event `{line}`: {error}"));
                if sender.send(value).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            events,
        }
    }

    fn command(&mut self, command: Value) {
        serde_json::to_writer(&mut self.stdin, &command).expect("write go peer command");
        self.stdin.write_all(b"\n").expect("terminate go command");
        self.stdin.flush().expect("flush go peer command");
    }

    fn event(&self, expected: &str) -> Value {
        let event = self
            .events
            .recv_timeout(TIMEOUT)
            .unwrap_or_else(|error| panic!("waiting for go `{expected}` event: {error}"));
        assert_ne!(event["event"], "error", "go peer failed: {event}");
        assert_eq!(event["event"], expected, "unexpected go peer event");
        event
    }
}

impl Drop for GoPeer {
    fn drop(&mut self) {
        let _ = serde_json::to_writer(&mut self.stdin, &json!({ "op": "stop" }));
        let _ = self.stdin.write_all(b"\n");
        let _ = self.stdin.flush();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(None) | Err(_) => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    return;
                }
            }
        }
    }
}

#[derive(Default)]
struct EventLog {
    events: Mutex<Vec<P2pEvent>>,
    changed: Condvar,
}

impl EventLog {
    fn wait_for(&self, predicate: impl Fn(&P2pEvent) -> bool) -> P2pEvent {
        let events = self.events.lock().unwrap_or_else(PoisonError::into_inner);
        let (events, _) = self
            .changed
            .wait_timeout_while(events, TIMEOUT, |events| !events.iter().any(&predicate))
            .unwrap_or_else(PoisonError::into_inner);
        events
            .iter()
            .find(|event| predicate(event))
            .cloned()
            .expect("expected minip2p event")
    }

    fn take_for(&self, predicate: impl Fn(&P2pEvent) -> bool) -> P2pEvent {
        let events = self.events.lock().unwrap_or_else(PoisonError::into_inner);
        let (mut events, _) = self
            .changed
            .wait_timeout_while(events, TIMEOUT, |events| !events.iter().any(&predicate))
            .unwrap_or_else(PoisonError::into_inner);
        let index = events
            .iter()
            .position(predicate)
            .expect("expected minip2p event");
        events.remove(index)
    }
}

impl P2pEventListener for EventLog {
    fn on_event(&self, event: P2pEvent) {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(event);
        self.changed.notify_all();
    }
}

fn config() -> EndpointConfig {
    EndpointConfig {
        agent_version: Some("minip2p-go-interop".into()),
        relays: Vec::new(),
        autonat_servers: Vec::new(),
        quic: None,
        tcp: Some(TransportOptions {
            listen_addrs: Some(vec!["/ip4/127.0.0.1/tcp/0".into()]),
        }),
        force_relay: false,
        allow_unsigned: false,
        pubsub_router: PubsubRouter::Gossipsub,
        protocols: vec![ECHO_PROTOCOL.into()],
        discovery: None,
        mdns: None,
    }
}

/// Run with `just interop-go`; ignored in ordinary CI because it requires Go
/// and downloads the independently versioned go-libp2p module.
#[test]
#[ignore = "requires Go and the go-libp2p module"]
fn tcp_noise_yamux_identify_ping_and_streams_interoperate_with_go() -> Result<(), FfiError> {
    let payload_from_go = "g".repeat(PAYLOAD_FROM_GO_BYTES);
    let mut go = GoPeer::spawn();
    let ready = go.event("ready");
    let go_peer = ready["peer_id"].as_str().expect("go peer id").to_owned();
    let go_addr = ready["addr"].as_str().expect("go peer address").to_owned();

    let endpoint = P2pEndpoint::new(vec![77; 32], config())?;
    let log = Arc::new(EventLog::default());
    endpoint.start(Arc::clone(&log) as Arc<dyn P2pEventListener>)?;

    endpoint.connect_addr(go_addr)?;
    let initial_conn = match log.wait_for(|event| {
        matches!(event, P2pEvent::ConnectionEstablished { peer_id, .. } if peer_id == &go_peer)
    }) {
        P2pEvent::ConnectionEstablished { conn_id, .. } => conn_id,
        _ => unreachable!("predicate pins the event variant"),
    };
    log.wait_for(|event| {
        matches!(event, P2pEvent::PeerReady { peer_id, protocols }
            if peer_id == &go_peer && protocols.iter().any(|id| id == ECHO_PROTOCOL))
    });
    let identify = log.wait_for(|event| {
        matches!(event, P2pEvent::IdentifyReceived { peer_id, info }
            if peer_id == &go_peer && info.protocols.iter().any(|id| id == ECHO_PROTOCOL))
    });
    let P2pEvent::IdentifyReceived { info, .. } = identify else {
        unreachable!("predicate pins the event variant")
    };
    assert!(
        info.agent_version
            .as_deref()
            .is_some_and(|agent| agent.contains("go-libp2p")),
        "Identify names the foreign implementation: {:?}",
        info.agent_version
    );
    let queried = endpoint
        .peer_info(go_peer.clone())?
        .expect("Identify snapshot is queryable");
    assert!(queried.protocols.iter().any(|id| id == ECHO_PROTOCOL));
    endpoint.ping(go_peer.clone())?;
    log.wait_for(
        |event| matches!(event, P2pEvent::PingRttMeasured { peer_id, .. } if peer_id == &go_peer),
    );

    let opened = endpoint.open_stream(go_peer.clone(), ECHO_PROTOCOL.into())?;
    log.wait_for(|event| {
        matches!(event, P2pEvent::StreamReady { stream_id, initiated_locally: true, .. }
            if *stream_id == opened.stream_id)
    });
    endpoint.send_stream(
        go_peer.clone(),
        opened.stream_id,
        PAYLOAD_FROM_MINIP2P.to_vec(),
    )?;
    endpoint.close_stream_write(go_peer.clone(), opened.stream_id)?;
    log.wait_for(|event| {
        matches!(event, P2pEvent::StreamData { stream_id, data, .. }
            if *stream_id == opened.stream_id && data == PAYLOAD_FROM_MINIP2P)
    });

    let endpoint_addr = endpoint.listen_addrs()[0].clone();
    go.command(json!({
        "op": "echo",
        "addr": endpoint_addr,
        "payload": &payload_from_go,
    }));
    let reverse_conn = match log.wait_for(|event| {
        matches!(event, P2pEvent::ConnectionEstablished { peer_id, conn_id }
            if peer_id == &go_peer && *conn_id != initial_conn)
    }) {
        P2pEvent::ConnectionEstablished { conn_id, .. } => conn_id,
        _ => unreachable!("predicate pins the event variant"),
    };
    let reverse_stream = match log.wait_for(|event| {
        matches!(event, P2pEvent::StreamReady {
            conn_id,
            protocol_id,
            initiated_locally: false,
            ..
        } if *conn_id == reverse_conn && protocol_id == ECHO_PROTOCOL)
    }) {
        P2pEvent::StreamReady { stream_id, .. } => stream_id,
        _ => unreachable!("predicate pins the event variant"),
    };
    let mut received = Vec::with_capacity(payload_from_go.len());
    loop {
        let event = log.take_for(|event| {
            matches!(event,
                P2pEvent::StreamData { conn_id, stream_id, .. }
                    | P2pEvent::StreamRemoteWriteClosed { conn_id, stream_id, .. }
                    if *conn_id == reverse_conn && *stream_id == reverse_stream)
        });
        match event {
            P2pEvent::StreamData {
                peer_id,
                stream_id,
                data,
                ..
            } => {
                received.extend_from_slice(&data);
                endpoint.send_stream(peer_id, stream_id, data)?;
            }
            P2pEvent::StreamRemoteWriteClosed {
                peer_id, stream_id, ..
            } => {
                endpoint.close_stream_write(peer_id, stream_id)?;
                break;
            }
            _ => unreachable!("predicate pins the event variants"),
        }
    }
    assert_eq!(received, payload_from_go.as_bytes());
    let echoed = go.event("echo");
    assert_eq!(echoed["payload"], payload_from_go);

    endpoint.stop();
    assert!(endpoint.wait_stopped(5_000), "minip2p driver stopped");
    Ok(())
}
