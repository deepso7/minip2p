//! Live TCP/Noise/Yamux interoperability with an independent go-libp2p peer.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex, PoisonError, mpsc};
use std::time::{Duration, Instant};

use minip2p_ffi::{
    EndpointConfig, FfiError, P2pEndpoint, P2pEvent, P2pEventDoorbell, PubsubRouter,
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
    #[expect(
        clippy::panic,
        reason = "Malformed output from the independent Go fixture is a test-harness failure."
    )]
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

    #[expect(
        clippy::panic,
        reason = "A missing response from the independent Go fixture must fail the ignored test clearly."
    )]
    fn event(&self, expected: &str) -> Value {
        let event = self
            .events
            .recv_timeout(TIMEOUT)
            .unwrap_or_else(|error| panic!("waiting for go `{expected}` event: {error}"));
        let event_name = required_string(&event, "event");
        assert_ne!(event_name, "error", "go peer failed: {event}");
        assert_eq!(event_name, expected, "unexpected go peer event");
        event
    }
}

impl Drop for GoPeer {
    fn drop(&mut self) {
        // The child may have already exited; shutdown is best-effort in Drop.
        drop(serde_json::to_writer(
            &mut self.stdin,
            &json!({ "op": "stop" }),
        ));
        drop(self.stdin.write_all(b"\n"));
        drop(self.stdin.flush());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(None) | Err(_) => {
                    drop(self.child.kill());
                    drop(self.child.wait());
                    return;
                }
            }
        }
    }
}

#[expect(
    clippy::panic,
    reason = "A malformed event from the independent Go fixture must fail the ignored test clearly."
)]
fn required_string<'a>(event: &'a Value, field: &str) -> &'a str {
    event
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("go event has no string `{field}` field: {event}"))
}

struct EventLog {
    endpoint: Arc<P2pEndpoint>,
    events: Mutex<Vec<P2pEvent>>,
    changed: Condvar,
}

impl EventLog {
    fn new(endpoint: Arc<P2pEndpoint>) -> Self {
        Self {
            endpoint,
            events: Mutex::new(Vec::new()),
            changed: Condvar::new(),
        }
    }
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

impl P2pEventDoorbell for EventLog {
    fn on_events_ready(&self) {
        loop {
            let batch = self.endpoint.drain_events(512);
            if batch.is_empty() {
                break;
            }
            self.events
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend(batch);
        }
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
#[expect(
    clippy::panic_in_result_fn,
    reason = "The ignored interoperability test uses assertions to preserve the foreign peer trace."
)]
fn tcp_noise_yamux_identify_ping_and_streams_interoperate_with_go() -> Result<(), FfiError> {
    let payload_from_go = "g".repeat(PAYLOAD_FROM_GO_BYTES);
    let mut go = GoPeer::spawn();
    let ready = go.event("ready");
    let go_peer = required_string(&ready, "peer_id").to_owned();
    let go_addr = required_string(&ready, "addr").to_owned();

    let endpoint = P2pEndpoint::new(vec![77; 32], config())?;
    let log = Arc::new(EventLog::new(Arc::clone(&endpoint)));
    endpoint.start(Arc::clone(&log) as Arc<dyn P2pEventDoorbell>)?;

    endpoint.connect_addr(go_addr)?;
    let initial_conn = match log.wait_for(|event| {
        matches!(event, P2pEvent::ConnectionEstablished { peer_id, .. } if peer_id == &go_peer)
    }) {
        P2pEvent::ConnectionEstablished { conn_id, .. } => conn_id,
        _ => panic!("connection predicate returned a different event"),
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
        panic!("identify predicate returned a different event")
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
    let mut echoed_to_minip2p = Vec::with_capacity(PAYLOAD_FROM_MINIP2P.len());
    loop {
        let event = log.take_for(|event| {
            matches!(event,
                P2pEvent::StreamData { stream_id, .. }
                    | P2pEvent::StreamRemoteWriteClosed { stream_id, .. }
                    if *stream_id == opened.stream_id)
        });
        match event {
            P2pEvent::StreamData { data, .. } => echoed_to_minip2p.extend_from_slice(&data),
            P2pEvent::StreamRemoteWriteClosed { .. } => break,
            _ => panic!("echo predicate returned a different event"),
        }
    }
    assert_eq!(echoed_to_minip2p, PAYLOAD_FROM_MINIP2P);

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
        _ => panic!("reverse-connection predicate returned a different event"),
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
        _ => panic!("reverse-stream predicate returned a different event"),
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
            _ => panic!("reverse-echo predicate returned a different event"),
        }
    }
    assert_eq!(received, payload_from_go.as_bytes());
    let echoed = go.event("echo");
    assert_eq!(required_string(&echoed, "payload"), payload_from_go);

    endpoint.stop();
    assert!(endpoint.wait_stopped(5_000), "minip2p driver stopped");
    Ok(())
}
