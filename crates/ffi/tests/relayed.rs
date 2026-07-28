//! End-to-end FFI coverage over a real loopback Circuit Relay v2 service.

use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use minip2p_ffi::{
    EndpointConfig, P2pEndpoint, P2pEvent, P2pEventListener, PathKind, circuit_address,
};

#[path = "../../../tests/support/relay.rs"]
mod relay_support;

const TOPIC: &str = "ffi-relayed-room";
const TIMEOUT: Duration = Duration::from_secs(15);
const RELAY_LOSS_TIMEOUT: Duration = Duration::from_secs(75);

#[derive(Default)]
struct EventLog {
    events: Mutex<Vec<P2pEvent>>,
    changed: Condvar,
}

impl EventLog {
    fn wait_for(&self, predicate: impl Fn(&P2pEvent) -> bool) -> P2pEvent {
        self.wait_for_with_timeout(TIMEOUT, predicate)
    }

    fn wait_for_with_timeout(
        &self,
        timeout: Duration,
        predicate: impl Fn(&P2pEvent) -> bool,
    ) -> P2pEvent {
        let deadline = Instant::now() + timeout;
        let mut events = self.events.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if let Some(event) = events.iter().find(|event| predicate(event)) {
                return event.clone();
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "timed out waiting for event; observed {events:#?}"
            );
            let (next, result) = self
                .changed
                .wait_timeout(events, remaining)
                .unwrap_or_else(PoisonError::into_inner);
            events = next;
            assert!(
                !result.timed_out() || events.iter().any(&predicate),
                "timed out waiting for event; observed {events:#?}"
            );
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

fn endpoint(seed: u8, relay: String) -> Arc<P2pEndpoint> {
    P2pEndpoint::new(
        vec![seed; 32],
        EndpointConfig {
            agent_version: Some("minip2p-ffi-relay-test".into()),
            relays: vec![relay],
            listen_addr: Some("/ip4/127.0.0.1/udp/0/quic-v1".into()),
            force_relay: true,
            allow_unsigned: false,
            discovery: None,
        },
    )
    .expect("construct relay endpoint")
}

fn stop(endpoint: &P2pEndpoint) {
    endpoint.stop();
    assert!(endpoint.wait_stopped(5_000), "driver did not stop");
}

#[test]
fn relayed_chat_and_reservation_loss() {
    let relay = relay_support::RelayServer::spawn();
    let relay_addr = relay.addr().to_string();
    let relay_peer = relay.addr().peer_id().to_base58();
    let a = endpoint(31, relay_addr.clone());
    let b = endpoint(32, relay_addr.clone());
    let a_log = Arc::new(EventLog::default());
    let b_log = Arc::new(EventLog::default());
    let b_peer = b.peer_id();

    a.start(Arc::clone(&a_log) as Arc<dyn P2pEventListener>)
        .expect("start initiator");
    b.start(Arc::clone(&b_log) as Arc<dyn P2pEventListener>)
        .expect("start responder");

    let reserved = b_log.wait_for(|event| {
        matches!(
            event,
            P2pEvent::RelayReserved { relay_peer_id, .. } if relay_peer_id == &relay_peer
        )
    });
    let reservation = b
        .active_reservation()
        .expect("reservation query")
        .expect("active reservation");
    assert_eq!(reservation.relay_peer_id, relay_peer);
    assert_eq!(reservation.expires_unix_secs, Some(9_999_999_999));
    assert!(matches!(
        reserved,
        P2pEvent::RelayReserved {
            expires_unix_secs: Some(9_999_999_999),
            ..
        }
    ));
    let expected_circuit =
        circuit_address(relay_addr, b_peer.clone()).expect("compose circuit address");
    assert!(expected_circuit.ends_with(&format!("/p2p-circuit/p2p/{b_peer}")));

    a.subscribe(TOPIC.into()).expect("subscribe initiator");
    b.subscribe(TOPIC.into()).expect("subscribe responder");
    let connect_id = a.connect(b_peer.clone()).expect("start relay connect");
    a_log.wait_for(|event| {
        matches!(
            event,
            P2pEvent::PathEstablished {
                connect_id: found,
                peer_id,
                path: PathKind::Relayed { relay_peer_id },
            } if *found == connect_id && peer_id == &b_peer && relay_peer_id == &relay_peer
        )
    });
    b_log.wait_for(|event| {
        matches!(
            event,
            P2pEvent::PeerSubscribed { peer_id, topic }
                if peer_id == &a.peer_id() && topic == TOPIC
        )
    });

    a.publish(TOPIC.into(), b"through relay".to_vec())
        .expect("publish over relay");
    b_log.wait_for(|event| {
        matches!(
            event,
            P2pEvent::Message {
                from_peer_id,
                data,
                signed: true,
                ..
            } if from_peer_id == &a.peer_id() && data == b"through relay"
        )
    });

    drop(relay);
    // Stopping the relay cannot signal an immediate close over UDP. The
    // endpoint detects the dead relay through QUIC's 30-second idle timeout.
    // The wider bound covers the keepalive/idle phase and slower CI scheduling.
    b_log.wait_for_with_timeout(RELAY_LOSS_TIMEOUT, |event| {
        matches!(
            event,
            P2pEvent::RelayReservationLost { relay_peer_id } if relay_peer_id == &relay_peer
        )
    });
    assert!(
        b.active_reservation()
            .expect("reservation query after loss")
            .is_none()
    );

    stop(&a);
    stop(&b);
}
