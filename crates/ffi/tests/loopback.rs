//! End-to-end FFI tests over real loopback QUIC sockets.

use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use minip2p_ffi::{EndpointConfig, FfiError, P2pEndpoint, P2pEvent, P2pEventListener, PathKind};

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
        agent_version: Some("minip2p-ffi-loopback-test".into()),
        relays: Vec::new(),
        listen_addr: Some("/ip4/127.0.0.1/udp/0/quic-v1".into()),
        force_relay: false,
        allow_unsigned: false,
        discovery: None,
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
fn two_endpoints_chat_over_loopback() -> Result<(), FfiError> {
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

    stop(&a);
    stop(&b);
    assert!(!a.is_running());
    assert!(!b.is_running());
    Ok(())
}
