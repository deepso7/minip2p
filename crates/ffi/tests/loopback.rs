//! End-to-end FFI tests over real loopback QUIC sockets.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use minip2p_ffi::{EndpointConfig, FfiError, P2pEndpoint, P2pEvent, P2pEventListener, PathKind};

static LOOPBACK_TEST_LOCK: Mutex<()> = Mutex::new(());

#[derive(Default)]
struct EventLog {
    events: Mutex<Vec<P2pEvent>>,
    changed: Condvar,
}

impl EventLog {
    fn wait_for(
        &self,
        timeout: Duration,
        predicate: impl Fn(&P2pEvent) -> bool,
    ) -> Option<P2pEvent> {
        let started = Instant::now();
        let mut events = self.events.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if let Some(event) = events.iter().find(|event| predicate(event)) {
                return Some(event.clone());
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return None;
            }
            let (next, result) = self
                .changed
                .wait_timeout(events, remaining)
                .unwrap_or_else(PoisonError::into_inner);
            events = next;
            if result.timed_out() {
                return events.iter().find(|event| predicate(event)).cloned();
            }
        }
    }

    fn wait_for_message_count(&self, timeout: Duration, count: usize) -> Vec<Vec<u8>> {
        let started = Instant::now();
        let mut events = self.events.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            let messages: Vec<_> = events
                .iter()
                .filter_map(|event| match event {
                    P2pEvent::Message { data, .. } => Some(data.clone()),
                    _ => None,
                })
                .collect();
            if messages.len() >= count {
                return messages;
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            assert!(!remaining.is_zero(), "message delivery timed out");
            let (next, result) = self
                .changed
                .wait_timeout(events, remaining)
                .unwrap_or_else(PoisonError::into_inner);
            events = next;
            if result.timed_out() {
                let delivered = events
                    .iter()
                    .filter(|event| matches!(event, P2pEvent::Message { .. }))
                    .count();
                assert!(
                    delivered >= count,
                    "message delivery timed out: delivered {delivered} of {count}"
                );
            }
        }
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

struct PanicOnceListener {
    log: Arc<EventLog>,
    panicked: AtomicBool,
}

struct SlowListener {
    log: Arc<EventLog>,
}

#[derive(Default)]
struct CallbackGate {
    state: Mutex<(bool, bool)>,
    changed: Condvar,
}

impl CallbackGate {
    fn wait_until_entered(&self, timeout: Duration) -> bool {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let (state, _) = self
            .changed
            .wait_timeout_while(state, timeout, |(entered, _)| !*entered)
            .unwrap_or_else(PoisonError::into_inner);
        state.0
    }

    fn release(&self) {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).1 = true;
        self.changed.notify_all();
    }
}

struct BlockingListener {
    log: Arc<EventLog>,
    gate: Arc<CallbackGate>,
}

impl P2pEventListener for BlockingListener {
    fn on_event(&self, event: P2pEvent) {
        if matches!(event, P2pEvent::Message { .. }) {
            let mut state = self
                .gate
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            state.0 = true;
            self.gate.changed.notify_all();
            while !state.1 {
                state = self
                    .gate
                    .changed
                    .wait(state)
                    .unwrap_or_else(PoisonError::into_inner);
            }
        }
        self.log.on_event(event);
    }
}

impl P2pEventListener for SlowListener {
    fn on_event(&self, event: P2pEvent) {
        if matches!(event, P2pEvent::Message { .. }) {
            std::thread::sleep(Duration::from_millis(1));
        }
        self.log.on_event(event);
    }
}

impl P2pEventListener for PanicOnceListener {
    fn on_event(&self, event: P2pEvent) {
        if matches!(event, P2pEvent::Message { .. }) && !self.panicked.swap(true, Ordering::AcqRel)
        {
            panic!("injected listener panic");
        }
        self.log.on_event(event);
    }
}

fn config() -> EndpointConfig {
    config_on("/ip4/127.0.0.1/udp/0/quic-v1")
}

fn config_on(listen_addr: &str) -> EndpointConfig {
    EndpointConfig {
        agent_version: Some("minip2p-ffi-loopback-test".into()),
        relays: Vec::new(),
        autonat_servers: Vec::new(),
        listen_addr: Some(listen_addr.into()),
        force_relay: false,
        allow_unsigned: false,
        pubsub_router: minip2p_ffi::PubsubRouter::Gossipsub,
        protocols: Vec::new(),
        discovery: None,
        mdns: None,
    }
}

fn endpoint(seed: u8) -> Arc<P2pEndpoint> {
    P2pEndpoint::new(vec![seed; 32], config()).expect("construct endpoint")
}

fn stop(endpoint: &P2pEndpoint) {
    endpoint.stop();
    assert!(endpoint.wait_stopped(5_000), "driver did not stop");
}

#[test]
fn a_tcp_listen_address_binds_tcp_and_is_dialed_over_it() -> Result<(), FfiError> {
    let _serial = LOOPBACK_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    // A foreign runtime that hands over a `/tcp` listener gets TCP. Parsing
    // `/tcp` peers to dial while binding only QUIC would leave a device that
    // has only TCP able to call out and never be called -- and the address it
    // reported would name a socket it does not have.
    let a = P2pEndpoint::new(vec![31; 32], config_on("/ip4/127.0.0.1/tcp/0"))
        .expect("construct a TCP endpoint");
    let b = P2pEndpoint::new(vec![32; 32], config_on("/ip4/127.0.0.1/tcp/0"))
        .expect("construct a TCP endpoint");
    for endpoint in [&a, &b] {
        let addrs = endpoint.listen_addrs();
        assert!(
            addrs.iter().all(|addr| addr.contains("/tcp/")),
            "a TCP endpoint reports TCP addresses, got {addrs:?}"
        );
    }

    let a_log = Arc::new(EventLog::default());
    let b_log = Arc::new(EventLog::default());
    let b_peer = b.peer_id();
    a.start(Arc::clone(&a_log) as Arc<dyn P2pEventListener>)?;
    b.start(Arc::clone(&b_log) as Arc<dyn P2pEventListener>)?;

    let connect_id = a.connect_addr(b.listen_addrs()[0].clone())?;
    assert!(
        a_log
            .wait_for(Duration::from_secs(5), |event| matches!(
                event,
                P2pEvent::PathEstablished {
                    connect_id: observed,
                    peer_id,
                    path: PathKind::DirectDialed,
                } if *observed == connect_id && peer_id == &b_peer
            ))
            .is_some(),
        "the TCP address was dialed and the path came up"
    );
    assert!(
        a_log
            .wait_for(Duration::from_secs(5), |event| matches!(
                event,
                P2pEvent::PeerReady { peer_id, .. } if peer_id == &b_peer
            ))
            .is_some(),
        "and identify and ping ran over it like any other connection"
    );

    stop(&a);
    stop(&b);
    Ok(())
}

#[test]
fn two_endpoints_chat_over_loopback() -> Result<(), FfiError> {
    let _serial = LOOPBACK_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let a = endpoint(21);
    let b = endpoint(22);
    let a_log = Arc::new(EventLog::default());
    let b_log = Arc::new(EventLog::default());
    let a_peer = a.peer_id();
    let b_peer = b.peer_id();

    a.start(Arc::clone(&a_log) as Arc<dyn P2pEventListener>)?;
    b.start(Arc::clone(&b_log) as Arc<dyn P2pEventListener>)?;
    a.subscribe("room".into())?;
    b.subscribe("room".into())?;

    let connect_id = a.connect_addr(b.listen_addrs()[0].clone())?;
    assert!(matches!(
        a_log.wait_for(Duration::from_secs(5), |event| matches!(
            event,
            P2pEvent::PathEstablished {
                connect_id: observed,
                peer_id,
                path: PathKind::DirectDialed,
            } if *observed == connect_id && peer_id == &b_peer
        )),
        Some(P2pEvent::PathEstablished { .. })
    ));
    assert!(
        a_log
            .wait_for(Duration::from_secs(5), |event| matches!(
                event,
            P2pEvent::PeerReady { peer_id, protocols }
                if peer_id == &b_peer
                    && protocols.iter().any(|protocol| protocol.contains("meshsub"))
            ))
            .is_some()
    );
    assert!(
        b_log
            .wait_for(Duration::from_secs(5), |event| matches!(
                event,
                P2pEvent::PeerReady { peer_id, .. } if peer_id == &a_peer
            ))
            .is_some()
    );
    assert!(
        a_log
            .wait_for(Duration::from_secs(5), |event| matches!(
                event,
                P2pEvent::PeerSubscribed { peer_id, topic }
                    if peer_id == &b_peer && topic == "room"
            ))
            .is_some()
    );

    b.publish("room".into(), b"hello from b".to_vec())?;
    assert!(
        a_log
            .wait_for(Duration::from_secs(5), |event| matches!(
                event,
                P2pEvent::Message {
                    from_peer_id,
                    topics,
                    data,
                    seqno,
                    signed: true,
                } if from_peer_id == &b_peer
                    && topics == &["room".to_string()]
                    && data == b"hello from b"
                    && !seqno.is_empty()
            ))
            .is_some()
    );

    for index in 0_u8..10 {
        b.publish("room".into(), vec![index])?;
    }
    let messages = a_log.wait_for_message_count(Duration::from_secs(5), 11);
    assert_eq!(
        &messages[1..],
        &(0_u8..10).map(|index| vec![index]).collect::<Vec<_>>()
    );

    stop(&a);
    stop(&b);
    assert!(!a.is_running());
    assert!(!b.is_running());
    Ok(())
}

#[test]
fn identify_ping_and_custom_streams_cross_the_ffi_boundary() -> Result<(), FfiError> {
    let _serial = LOOPBACK_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let a = endpoint(23);
    let b = endpoint(24);
    let a_log = Arc::new(EventLog::default());
    let b_log = Arc::new(EventLog::default());
    let protocol = "/minip2p/ffi-test/1";
    let b_peer = b.peer_id();

    a.add_protocol(protocol.into())?;
    b.add_protocol(protocol.into())?;
    a.start(Arc::clone(&a_log) as Arc<dyn P2pEventListener>)?;
    b.start(Arc::clone(&b_log) as Arc<dyn P2pEventListener>)?;
    a.connect_with_addrs(b_peer.clone(), vec![b.listen_addrs()[0].clone()])?;

    assert!(
        a_log
            .wait_for(Duration::from_secs(5), |event| matches!(
                event,
                P2pEvent::PeerReady { peer_id, protocols }
                    if peer_id == &b_peer && protocols.iter().any(|id| id == protocol)
            ))
            .is_some()
    );
    assert!(a.is_peer_ready(b_peer.clone())?);
    let info = a
        .peer_info(b_peer.clone())?
        .expect("ready peer has Identify info");
    assert!(info.protocols.iter().any(|id| id == protocol));
    assert!(!info.listen_addrs.is_empty());
    assert!(
        a_log
            .wait_for(Duration::from_secs(5), |event| matches!(
                event,
                P2pEvent::IdentifyReceived { peer_id, info }
                    if peer_id == &b_peer && info.protocols.iter().any(|id| id == protocol)
            ))
            .is_some()
    );

    a.ping(b_peer.clone())?;
    assert!(
        a_log
            .wait_for(Duration::from_secs(5), |event| matches!(
                event,
                P2pEvent::PingRttMeasured { peer_id, .. } if peer_id == &b_peer
            ))
            .is_some()
    );

    let opened = a.open_stream(b_peer.clone(), protocol.into())?;
    let stream_id = opened.stream_id;
    let ready = a_log
        .wait_for(Duration::from_secs(5), |event| {
            matches!(
                event,
                P2pEvent::StreamReady {
                    peer_id,
                    stream_id: observed,
                    protocol_id,
                    initiated_locally: true,
                    ..
                } if peer_id == &b_peer && *observed == stream_id && protocol_id == protocol
            )
        })
        .expect("outbound stream becomes ready");
    assert!(matches!(
        ready,
        P2pEvent::StreamReady { conn_id, .. } if conn_id == opened.conn_id
    ));
    a.send_stream(b_peer.clone(), stream_id, b"stream payload".to_vec())?;
    a.close_stream_write(b_peer, stream_id)?;
    assert!(
        b_log
            .wait_for(Duration::from_secs(5), |event| matches!(
                event,
                P2pEvent::StreamData { data, .. } if data == b"stream payload"
            ))
            .is_some()
    );

    stop(&a);
    stop(&b);
    Ok(())
}

#[test]
fn panicking_listener_does_not_kill_driver() -> Result<(), FfiError> {
    let _serial = LOOPBACK_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let a = endpoint(23);
    let b = endpoint(24);
    let a_log = Arc::new(EventLog::default());
    let b_log = Arc::new(EventLog::default());
    let listener = Arc::new(PanicOnceListener {
        log: Arc::clone(&a_log),
        panicked: AtomicBool::new(false),
    });
    let a_peer = a.peer_id();

    a.start(Arc::clone(&listener) as Arc<dyn P2pEventListener>)?;
    b.start(Arc::clone(&b_log) as Arc<dyn P2pEventListener>)?;
    a.subscribe("panic-room".into())?;
    b.subscribe("panic-room".into())?;
    a.connect_addr(b.listen_addrs()[0].clone())?;
    assert!(
        b_log
            .wait_for(Duration::from_secs(5), |event| matches!(
                event,
                P2pEvent::PeerSubscribed { peer_id, topic }
                    if peer_id == &a_peer && topic == "panic-room"
            ))
            .is_some()
    );

    b.publish("panic-room".into(), b"panic".to_vec())?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while !listener.panicked.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert!(listener.panicked.load(Ordering::Acquire));

    b.publish("panic-room".into(), b"survived".to_vec())?;
    assert!(
        a_log
            .wait_for(Duration::from_secs(5), |event| matches!(
                event,
                P2pEvent::Message { data, .. } if data == b"survived"
            ))
            .is_some()
    );
    assert!(a.is_running());

    stop(&a);
    stop(&b);
    Ok(())
}

#[test]
fn query_completes_while_listener_callback_is_in_flight() -> Result<(), FfiError> {
    let _serial = LOOPBACK_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let a = endpoint(27);
    let b = endpoint(28);
    let a_log = Arc::new(EventLog::default());
    let b_log = Arc::new(EventLog::default());
    let gate = Arc::new(CallbackGate::default());
    let a_peer = a.peer_id();

    a.start(Arc::new(BlockingListener {
        log: a_log,
        gate: Arc::clone(&gate),
    }))?;
    b.start(Arc::clone(&b_log) as Arc<dyn P2pEventListener>)?;
    a.subscribe("handoff-room".into())?;
    b.subscribe("handoff-room".into())?;
    a.connect_addr(b.listen_addrs()[0].clone())?;
    assert!(
        b_log
            .wait_for(Duration::from_secs(5), |event| matches!(
                event,
                P2pEvent::PeerSubscribed { peer_id, topic }
                    if peer_id == &a_peer && topic == "handoff-room"
            ))
            .is_some()
    );

    b.publish("handoff-room".into(), b"block callback".to_vec())?;
    assert!(
        gate.wait_until_entered(Duration::from_secs(5)),
        "listener callback did not start"
    );

    let query_endpoint = Arc::clone(&a);
    let (sent, received) = std::sync::mpsc::sync_channel(1);
    let query = std::thread::spawn(move || {
        sent.send(query_endpoint.connected_peers().is_ok())
            .expect("query result receiver");
    });
    let query_completed = received.recv_timeout(Duration::from_secs(1));
    gate.release();
    query.join().expect("query worker");
    assert!(query_completed.expect("query blocked behind listener callback"));

    stop(&a);
    stop(&b);
    Ok(())
}

#[test]
fn bounded_load_preserves_order_and_accounting() -> Result<(), FfiError> {
    const MESSAGE_COUNT: usize = 600;

    let _serial = LOOPBACK_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let a = endpoint(25);
    let b = endpoint(26);
    let a_log = Arc::new(EventLog::default());
    let b_log = Arc::new(EventLog::default());
    let a_peer = a.peer_id();
    a.start(Arc::new(SlowListener {
        log: Arc::clone(&a_log),
    }))?;
    b.start(Arc::clone(&b_log) as Arc<dyn P2pEventListener>)?;
    a.set_active(true);
    a.subscribe("load-room".into())?;
    b.subscribe("load-room".into())?;
    a.connect_addr(b.listen_addrs()[0].clone())?;
    assert!(
        b_log
            .wait_for(Duration::from_secs(5), |event| matches!(
                event,
                P2pEvent::PeerSubscribed { peer_id, topic }
                    if peer_id == &a_peer && topic == "load-room"
            ))
            .is_some()
    );

    for index in 0..MESSAGE_COUNT {
        let payload = (index as u32).to_be_bytes().to_vec();
        loop {
            match b.publish("load-room".into(), payload.clone()) {
                Ok(()) => break,
                Err(FfiError::Backpressure) => std::thread::yield_now(),
                Err(error) => return Err(error),
            }
        }
    }
    let messages = a_log.wait_for_message_count(Duration::from_secs(15), MESSAGE_COUNT);
    let expected: Vec<_> = (0..MESSAGE_COUNT)
        .map(|index| (index as u32).to_be_bytes().to_vec())
        .collect();
    assert_eq!(messages, expected);

    stop(&a);
    stop(&b);
    let stats = a.driver_stats();
    assert!(stats.converted > 0);
    assert!(stats.dispatch_attempted > 0);
    assert_eq!(stats.converted, stats.dispatch_attempted + stats.dropped);
    Ok(())
}
