//! The std endpoint's unit tests: binding, routing, the blocking wait,
//! and close.

use super::builder::*;
use super::*;
#[cfg(feature = "discovery")]
use crate::BeaconConfig;
#[cfg(feature = "relay")]
use crate::CircuitLimits;
use crate::ConnectionCloseReason;
#[cfg(feature = "discovery")]
use crate::GossipsubError;
#[cfg(feature = "pubsub")]
use crate::GossipsubEvent;
#[cfg(feature = "mdns")]
use crate::MdnsConfig;
#[cfg(feature = "relay")]
use crate::NatEvent;
#[cfg(feature = "mdns")]
use crate::PeerDiscoveryConfig;
#[cfg(feature = "relay")]
use crate::ReachabilityState;
#[cfg(all(feature = "relay-server", feature = "quic"))]
use crate::RelayMeshConfig;
use crate::SwarmEvent;
#[cfg(feature = "tcp")]
use crate::TcpConfig;
use crate::{Bytes, ConnectId, Multiaddr, PeerId, Protocol, SwarmTimeouts, TransportKind};
use crate::{ConnectFailure, ConnectOutcome};
use crate::{ConnectionId, StreamId, Transport};
#[cfg(feature = "relay-server")]
use crate::{RelayServerAddressError, RelayServerAddressErrorKind};
#[cfg(feature = "relay-server")]
use crate::{RelayServerEvent, RelayServerRuntimeError, RelayServerRuntimeErrorKind};
#[cfg(any(feature = "quic", feature = "tcp"))]
use minip2p_transport::ConnectionNamespace;
#[cfg(any(feature = "tcp", feature = "relay"))]
use minip2p_transport::InvalidLimit;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Drives `endpoint` on a thread until the returned guard is dropped.
///
/// A peer that is not being driven answers nothing, so anything asserting
/// on a connection needs the other end alive for as long as the assertion
/// takes.
struct Driven {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Driven {
    fn new(mut endpoint: Endpoint) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                endpoint
                    .next_event(Duration::from_millis(20))
                    .expect("drive peer");
            }
        });
        Self {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Driven {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            // A test panic in the driver must not panic again while unwinding.
            drop(thread.join());
        }
    }
}

/// Drives `endpoint` until an event `wanted` accepts, or gives up.
///
/// A connection produces more than the event a test is waiting for --
/// identify, ping, readiness -- and an earlier connection keeps producing
/// them, so taking whatever arrives next is a race rather than an
/// assertion.
#[expect(
    clippy::panic,
    reason = "A timed-out test must include the unexpected event trace."
)]
fn wait_for(
    endpoint: &mut Endpoint,
    what: &str,
    mut wanted: impl FnMut(&EndpointEvent) -> bool,
) -> EndpointEvent {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut seen = Vec::new();
    while std::time::Instant::now() < deadline {
        let Some(event) = endpoint
            .next_event(Duration::from_millis(50))
            .expect("drive endpoint")
        else {
            continue;
        };
        if wanted(&event) {
            return event;
        }
        seen.push(event);
    }
    panic!("no {what} arrived; saw {seen:?}");
}

#[expect(
    clippy::panic,
    reason = "A timed-out test must include the unexpected event."
)]
fn connect_outcome(endpoint: &mut Endpoint, id: ConnectId) -> ConnectOutcome {
    match wait_for(
        endpoint,
        "connect settled",
        |event| matches!(event, EndpointEvent::ConnectSettled { connect_id, .. } if *connect_id == id),
    ) {
        EndpointEvent::ConnectSettled { outcome, .. } => outcome,
        other => panic!("expected ConnectSettled, got {other:?}"),
    }
}

fn tcp_peer_addr(peer: PeerId, port: u16) -> PeerAddr {
    PeerAddr::new(
        Multiaddr::from_protocols(vec![Protocol::Ip4([127, 0, 0, 1]), Protocol::Tcp(port)]),
        peer,
    )
    .expect("peer addr")
}

#[test]
fn connect_races_quic_and_tcp_candidates_on_a_quic_only_endpoint() {
    let mut listener = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind listener");
    let quic_addr = listener.listen().expect("listen");
    let tcp_addr = tcp_peer_addr(*quic_addr.peer_id(), 9);
    let _driver = Driven::new(listener);
    let mut dialer = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind dialer");
    let id = dialer
        .connect(vec![quic_addr.clone(), tcp_addr.clone()])
        .expect("connect");
    let ConnectOutcome::Connected { conn_id, .. } = connect_outcome(&mut dialer, id) else {
        panic!("expected connected");
    };
    let remote = dialer
        .connection_remote_addr(conn_id)
        .expect("remote addr")
        .clone();
    assert!(
        remote == *quic_addr.transport() || remote == *tcp_addr.transport(),
        "remote {remote} must be one of the candidates"
    );
}

#[test]
fn connect_without_a_transport_for_the_address_is_no_usable_route() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind");
    let target = tcp_peer_addr(Ed25519Keypair::generate().peer_id(), 9);
    let id = endpoint.connect(target.clone()).expect("admitted");
    match connect_outcome(&mut endpoint, id) {
        ConnectOutcome::Failed(ConnectFailure::NoUsableRoute { candidates, .. }) => {
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].addr, target);
            assert!(
                candidates[0].reason.contains("Tcp transport"),
                "{}",
                candidates[0].reason
            );
        }
        other => panic!("expected NoUsableRoute, got {other:?}"),
    }
}

#[test]
fn cancel_connect_before_handshake_settles_cancelled() {
    let mut listener = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind listener");
    let addr = listener.listen().expect("listen");
    let _driver = Driven::new(listener);
    let mut dialer = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind dialer");
    let id = dialer.connect(addr).expect("connect");
    dialer.cancel_connect(id);
    assert!(matches!(
        connect_outcome(&mut dialer, id),
        ConnectOutcome::Cancelled
    ));
    assert!(dialer.connected_peers().is_empty());
}

/// A lookup that reports each name it is asked for on `started` and
/// then blocks until the test sends it an answer (or drops the sender).
fn stalling_lookup() -> (
    dial::Lookup,
    std::sync::mpsc::Receiver<String>,
    std::sync::mpsc::Sender<crate::names::Answer>,
) {
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (answer_tx, answer_rx) = std::sync::mpsc::channel::<crate::names::Answer>();
    let answer_rx = std::sync::Mutex::new(answer_rx);
    let lookup: dial::Lookup = Arc::new(move |host: &str| {
        drop(started_tx.send(host.to_string()));
        let answer = answer_rx.lock().expect("lookup lock").recv();
        answer.unwrap_or_else(|_| Err("test ended".to_string()))
    });
    (lookup, started_rx, answer_tx)
}

fn quic_endpoint() -> Endpoint {
    Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind")
}

fn with_lookup(endpoint: &mut Endpoint, lookup: dial::Lookup) {
    let wake = endpoint.platform.poll.wake_handle();
    endpoint.platform.resolver = dial::Resolver::with_lookup(move || wake.wake(), lookup);
}

/// `addr` with its host swapped for the name `host`.
fn named(addr: &PeerAddr, host: &str) -> PeerAddr {
    let mut protocols = addr.transport().protocols().to_vec();
    *protocols.first_mut().expect("a host") = Protocol::Dns(host.to_string());
    PeerAddr::new(Multiaddr::from_protocols(protocols), *addr.peer_id()).expect("named peer addr")
}

#[test]
fn a_stalled_lookup_does_not_hold_up_other_attempts() {
    let mut listener = quic_endpoint();
    let addr = listener.listen().expect("listen");
    let _driver = Driven::new(listener);
    let mut dialer = quic_endpoint();
    let (lookup, started, _answer) = stalling_lookup();
    with_lookup(&mut dialer, lookup);

    let stalled_peer = Ed25519Keypair::generate().peer_id();
    let stalled = dialer
        .connect(named(
            &PeerAddr::new(addr.transport().clone(), stalled_peer).expect("addr"),
            "stalled.invalid",
        ))
        .expect("connect returns without waiting for the lookup");
    assert_eq!(started.recv().expect("lookup started"), "stalled.invalid");

    let id = dialer.connect(addr).expect("connect");
    assert!(matches!(
        connect_outcome(&mut dialer, id),
        ConnectOutcome::Connected { .. }
    ));
    assert!(
        dialer.engine.connect.is_pending(stalled),
        "the stalled attempt is still waiting on its lookup"
    );
}

#[test]
fn an_ip_candidate_dials_while_a_name_in_the_same_attempt_resolves() {
    let mut listener = quic_endpoint();
    let addr = listener.listen().expect("listen");
    let _driver = Driven::new(listener);
    let mut dialer = quic_endpoint();
    let (lookup, _started, _answer) = stalling_lookup();
    with_lookup(&mut dialer, lookup);

    let id = dialer
        .connect(vec![named(&addr, "stalled.invalid"), addr.clone()])
        .expect("connect");
    let ConnectOutcome::Connected { conn_id, .. } = connect_outcome(&mut dialer, id) else {
        panic!("the /ip4 candidate must not wait for the name");
    };
    assert_eq!(
        dialer.connection_remote_addr(conn_id),
        Some(addr.transport())
    );
}

#[test]
fn attempts_naming_one_host_share_a_lookup_and_its_failure() {
    let mut dialer = quic_endpoint();
    let (lookup, started, answer) = stalling_lookup();
    with_lookup(&mut dialer, lookup);
    let peer = Ed25519Keypair::generate().peer_id();
    let target = |text: &str| PeerAddr::new(text.parse().expect("addr"), peer).expect("peer addr");

    let first = dialer
        .connect(target("/dns/gone.invalid/udp/4001/quic-v1"))
        .expect("connect");
    let second = dialer
        .connect(target("/dns4/gone.invalid/udp/4002/quic-v1"))
        .expect("connect");
    assert_eq!(started.recv().expect("lookup started"), "gone.invalid");
    assert!(
        started.recv_timeout(Duration::from_millis(200)).is_err(),
        "the second attempt joined the first lookup"
    );
    answer
        .send(Err("NXDOMAIN".to_string()))
        .expect("lookup waiting");

    // The lookup thread wakes the driver; that is not the caller's
    // interrupt, so `wait` keeps going instead of surfacing it.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut unsettled = vec![first, second];
    while !unsettled.is_empty() {
        match dialer.wait(deadline).expect("wait") {
            EndpointWaitOutcome::Event(EndpointEvent::ConnectSettled {
                connect_id,
                outcome,
                ..
            }) => {
                let ConnectOutcome::Failed(ConnectFailure::NoUsableRoute { candidates, .. }) =
                    outcome
                else {
                    panic!("expected NoUsableRoute, got {outcome:?}");
                };
                assert!(
                    candidates[0].reason.contains("gone.invalid")
                        && candidates[0].reason.contains("NXDOMAIN"),
                    "the reason names the host: {}",
                    candidates[0].reason
                );
                unsettled.retain(|id| *id != connect_id);
            }
            EndpointWaitOutcome::Event(_) => {}
            other => panic!("expected both attempts to settle, got {other:?}"),
        }
    }
}

/// A lookup's wake and an event queued in the same batch both arrive:
/// the event is returned first, the wake stays pending behind it, and
/// neither is lost or reported as the caller's interrupt.
#[test]
fn a_resolver_wake_and_a_queued_event_in_one_batch_both_arrive() {
    let mut dialer = quic_endpoint();
    let (lookup, started, answer) = stalling_lookup();
    with_lookup(&mut dialer, lookup);
    let peer = Ed25519Keypair::generate().peer_id();
    let named_target = PeerAddr::new(
        "/dns/gone.invalid/udp/4001/quic-v1".parse().expect("addr"),
        peer,
    )
    .expect("peer addr");
    let connect_id = dialer.connect(named_target).expect("connect");
    assert_eq!(started.recv().expect("lookup started"), "gone.invalid");

    answer
        .send(Err("NXDOMAIN".to_string()))
        .expect("lookup waiting");
    // Let the lookup thread queue its answer and wake the poll.
    std::thread::sleep(Duration::from_millis(100));
    let other = Ed25519Keypair::generate().peer_id();
    dialer.engine.events.push_back(EndpointEvent::PingFailed {
        peer_id: other,
        conn_id: ConnectionId::new(1),
        cause: minip2p_swarm::PingFailure::TimedOut,
    });

    let (mut settled, mut queued) = (false, false);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !(settled && queued) {
        match dialer.wait(deadline).expect("wait") {
            EndpointWaitOutcome::Event(EndpointEvent::ConnectSettled {
                connect_id: id, ..
            }) if id == connect_id => settled = true,
            EndpointWaitOutcome::Event(EndpointEvent::PingFailed { peer_id, .. })
                if peer_id == other =>
            {
                queued = true;
            }
            EndpointWaitOutcome::Event(_) => {}
            other => panic!("lost something: settled {settled}, queued {queued}: {other:?}"),
        }
    }
}

#[test]
fn cancelling_a_resolving_attempt_is_immediate_and_the_late_answer_is_dropped() {
    let mut listener = quic_endpoint();
    let addr = listener.listen().expect("listen");
    let _driver = Driven::new(listener);
    let mut dialer = quic_endpoint();
    let (lookup, started, answer) = stalling_lookup();
    with_lookup(&mut dialer, lookup);

    let id = dialer
        .connect(named(&addr, "late.invalid"))
        .expect("connect");
    started.recv().expect("lookup started");
    dialer.cancel_connect(id);
    assert!(matches!(
        dialer.poll().expect("poll").as_slice(),
        [EndpointEvent::ConnectSettled {
            connect_id,
            outcome: ConnectOutcome::Cancelled,
            ..
        }] if *connect_id == id
    ));

    // An answer that would reach the live listener, had anything kept it.
    answer
        .send(Ok(vec![std::net::Ipv4Addr::LOCALHOST.into()]))
        .expect("lookup waiting");
    let until = std::time::Instant::now() + Duration::from_millis(500);
    while let Some(event) = dialer.next_event(until).expect("drive") {
        assert!(
            !matches!(
                event,
                EndpointEvent::ConnectSettled { .. } | EndpointEvent::ConnectionEstablished { .. }
            ),
            "the late answer must have no effect, got {event:?}"
        );
    }
    assert!(dialer.connected_peers().is_empty());
}

#[test]
fn an_answer_after_the_deadline_leaves_the_attempt_timed_out() {
    let mut dialer = Endpoint::builder()
        .connect_deadline(Duration::from_millis(50))
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind");
    let (lookup, started, answer) = stalling_lookup();
    with_lookup(&mut dialer, lookup);
    let target = PeerAddr::new(
        "/dns/slow.invalid/udp/4001/quic-v1".parse().expect("addr"),
        Ed25519Keypair::generate().peer_id(),
    )
    .expect("peer addr");

    let id = dialer.connect(target).expect("connect");
    started.recv().expect("lookup started");
    // The answer lands past the deadline but before the next poll: the
    // attempt already ran out of time, so the answer must not decide it.
    std::thread::sleep(Duration::from_millis(100));
    answer
        .send(Err("NXDOMAIN".to_string()))
        .expect("lookup waiting");
    // Give the lookup thread time to queue its answer.
    std::thread::sleep(Duration::from_millis(50));
    match connect_outcome(&mut dialer, id) {
        ConnectOutcome::Failed(ConnectFailure::Timeout { candidates, .. }) => {
            assert!(candidates[0].reason.contains("resolving"), "{candidates:?}");
        }
        other => panic!("expected Timeout, got {other:?}"),
    }
}

#[test]
fn a_dns_candidate_connects_through_the_system_resolver() {
    let mut listener = quic_endpoint();
    let addr = listener.listen().expect("listen");
    let _driver = Driven::new(listener);
    let mut dialer = quic_endpoint();

    let mut protocols = addr.transport().protocols().to_vec();
    *protocols.first_mut().expect("a host") = Protocol::Dns4("localhost".to_string());
    let target = PeerAddr::new(Multiaddr::from_protocols(protocols), *addr.peer_id())
        .expect("named peer addr");
    let id = dialer.connect(target).expect("connect");
    let ConnectOutcome::Connected { conn_id, .. } = connect_outcome(&mut dialer, id) else {
        panic!("localhost must resolve and connect");
    };
    assert_eq!(
        dialer.connection_remote_addr(conn_id),
        Some(addr.transport())
    );
}

#[cfg(feature = "tcp")]
#[test]
fn connect_reaches_quic_when_the_tcp_candidate_is_closed() {
    let mut listener = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind listener");
    let quic_addr = listener.listen().expect("listen");
    let tcp_addr = tcp_peer_addr(*quic_addr.peer_id(), 9);
    let _driver = Driven::new(listener);
    let mut dialer = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic")
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp")
        .bind()
        .expect("bind both");
    let id = dialer
        .connect(vec![quic_addr.clone(), tcp_addr])
        .expect("connect");
    let ConnectOutcome::Connected { conn_id, .. } = connect_outcome(&mut dialer, id) else {
        panic!("expected connected");
    };
    let remote = dialer.connection_remote_addr(conn_id).expect("remote");
    assert_eq!(remote, quic_addr.transport());
}

#[test]
fn wait_delivers_connect_timeout_before_the_caller_deadline() {
    let mut listener = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind listener");
    let addr = listener.listen().expect("listen");
    // Leave the listener undriven so the handshake hangs past the
    // attempt deadline instead of failing immediately.
    let mut dialer = Endpoint::builder()
        .connect_deadline(Duration::from_millis(80))
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind dialer");
    let id = dialer.connect(addr).expect("connect");
    let caller = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match dialer.wait(caller).expect("wait") {
            EndpointWaitOutcome::Event(EndpointEvent::ConnectSettled {
                connect_id,
                outcome: ConnectOutcome::Failed(ConnectFailure::Timeout { .. }),
                ..
            }) if connect_id == id => return,
            EndpointWaitOutcome::Event(_) => {}
            EndpointWaitOutcome::Deadline => {
                panic!("caller deadline beat the connect timeout")
            }
            EndpointWaitOutcome::Interrupted => {}
        }
    }
}

#[cfg(feature = "tcp")]
#[expect(
    clippy::panic,
    reason = "A malformed fixture address is a test setup failure."
)]
fn tcp_port(addr: &PeerAddr) -> u16 {
    match addr.transport().protocols() {
        [_, Protocol::Tcp(port)] => *port,
        other => panic!("not a /tcp address: {other:?}"),
    }
}

#[cfg(feature = "discovery")]
#[test]
fn discovery_config_is_rejected_before_binding() {
    let config = BeaconConfig {
        beacon_interval_ms: 0,
        ..BeaconConfig::default()
    };
    // TEST-NET-1 is never a local address: a socket bind would fail.
    assert!(matches!(
        Endpoint::builder()
            .discovery_config(config)
            .listen_on("/ip4/192.0.2.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .err(),
        Some(BindError::Discovery(
            crate::DiscoveryConfigError::ZeroBeaconInterval
        ))
    ));
}

#[test]
fn an_endpoint_with_nothing_to_bind_is_refused() {
    // It could neither dial nor be reached; failing here says that once,
    // where the mistake is, instead of at every later call.
    let Err(error) = Endpoint::builder().bind() else {
        panic!("an endpoint with no transport must not build");
    };
    assert!(
        format!("{error}").contains("at least one transport"),
        "got {error}"
    );
}

#[test]
fn listen_configures_a_quic_multiaddr() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("listen accepts QUIC")
        .bind()
        .expect("bind");
    let addrs = endpoint.listen_all().expect("listen_all");
    assert_eq!(addrs.len(), 1);
    assert!(
        addrs[0]
            .transport()
            .to_string()
            .starts_with("/ip4/127.0.0.1/udp/"),
        "{addrs:?}"
    );
    assert!(
        addrs[0].transport().to_string().ends_with("/quic-v1"),
        "{addrs:?}"
    );
}

#[cfg(feature = "tcp")]
#[test]
fn listen_configures_a_tcp_multiaddr() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("listen accepts TCP")
        .bind()
        .expect("bind");
    let addrs = endpoint.listen_all().expect("listen_all");
    assert_eq!(addrs.len(), 1);
    assert!(
        addrs[0]
            .transport()
            .to_string()
            .starts_with("/ip4/127.0.0.1/tcp/"),
        "{addrs:?}"
    );
}

#[test]
fn listen_groups_ipv4_and_ipv6_quic_without_duplicating_transports() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("ipv4")
        .listen_on("/ip6/::1/udp/0/quic-v1")
        .expect("ipv6")
        .bind()
        .expect("bind dual");
    let addrs = endpoint.listen_all().expect("listen_all");
    assert_eq!(addrs.len(), 2, "{addrs:?}");
    assert!(
        addrs
            .iter()
            .any(|a| a.transport().to_string().contains("/ip4/"))
    );
    assert!(
        addrs
            .iter()
            .any(|a| a.transport().to_string().contains("/ip6/"))
    );
}

#[cfg(feature = "tcp")]
#[test]
fn listen_composes_quic_and_tcp() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic")
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp")
        .bind()
        .expect("bind both");
    let reported: Vec<String> = endpoint
        .listen_all()
        .expect("listen_all")
        .iter()
        .map(|addr| addr.transport().to_string())
        .collect();
    assert_eq!(reported.len(), 2, "{reported:?}");
    assert!(reported.iter().any(|addr| addr.contains("/quic-v1")));
    assert!(reported.iter().any(|addr| addr.contains("/tcp/")));
}

#[test]
fn listen_rejects_unsupported_and_contradictory_shapes() {
    let Err(dns) = Endpoint::builder().listen_on("/dns/example.com/udp/0/quic-v1") else {
        panic!("DNS listen must fail");
    };
    assert!(
        matches!(
            &dns,
            EndpointOptionsError::UnsupportedListenShape { expected, .. }
                if expected.contains("DNS")
        ),
        "{dns}"
    );

    let Err(circuit) = Endpoint::builder().listen_on("/ip4/127.0.0.1/udp/0/quic-v1/p2p-circuit")
    else {
        panic!("circuit listen must fail");
    };
    assert!(
        matches!(
            &circuit,
            EndpointOptionsError::UnsupportedListenShape { expected, .. }
                if expected.contains("p2p-circuit")
        ),
        "{circuit}"
    );

    let Err(duplicate) = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("first")
        .listen_on("/ip4/0.0.0.0/udp/0/quic-v1")
    else {
        panic!("duplicate IPv4 QUIC must fail");
    };
    assert!(
        matches!(
            &duplicate,
            EndpointOptionsError::DuplicateQuicFamily {
                family: IpFamily::Ipv4,
                ..
            }
        ),
        "{duplicate}"
    );
}

#[test]
fn webtransport_listens_share_the_quic_socket_of_their_family() {
    let builder = || {
        Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic-v1")
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1/webtransport")
            .expect("WebTransport on the same socket")
    };
    for rejected in [
        // Another port: QUIC has one socket per family.
        "/ip4/127.0.0.1/udp/4001/quic-v1/webtransport",
        // The same shape twice.
        "/ip4/127.0.0.1/udp/0/quic-v1/webtransport",
    ] {
        let Err(error) = builder().listen_on(rejected) else {
            panic!("{rejected} must be refused");
        };
        assert!(
            matches!(error, EndpointOptionsError::DuplicateQuicFamily { .. }),
            "{rejected}: {error}"
        );
    }
    let Err(certhash) = Endpoint::builder().listen_on(
        "/ip4/127.0.0.1/udp/0/quic-v1/webtransport/certhash/uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g",
    ) else {
        panic!("a listen certhash must be refused");
    };
    assert!(
        matches!(
            &certhash,
            EndpointOptionsError::UnsupportedListenShape { expected, .. }
                if expected.contains("without /certhash")
        ),
        "{certhash}"
    );
}

/// The `localhost` leaf and key from the QUIC transport's CA fixtures.
#[cfg(feature = "quic")]
const CA_LEAF: &[u8] =
    include_bytes!("../../../../transports/quic/tests/fixtures/ca/localhost.pem");
#[cfg(feature = "quic")]
const CA_KEY: &[u8] = include_bytes!("../../../../transports/quic/tests/fixtures/ca/localhost.key");

#[cfg(feature = "quic")]
#[test]
fn webtransport_certificate_pem_names_what_is_missing() {
    let two_keys = [CA_KEY, CA_KEY].concat();
    for (chain, key, expected) in [
        (CA_KEY, CA_KEY, "no `BEGIN CERTIFICATE`"),
        (CA_LEAF, CA_LEAF, "no `BEGIN PRIVATE KEY`"),
        (CA_LEAF, two_keys.as_slice(), "2 private keys"),
    ] {
        let Err(error) = Endpoint::builder().webtransport_certificate_pem(chain, key) else {
            panic!("{expected}: the PEM must be refused");
        };
        assert!(
            matches!(
                &error,
                EndpointOptionsError::WebTransportCertificatePem { problem }
                    if problem.contains(expected)
            ),
            "{expected}: {error}"
        );
    }
}

#[cfg(feature = "quic")]
#[test]
fn webtransport_certificate_without_a_webtransport_listener_fails_bind() {
    let result = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic-v1")
        .webtransport_certificate_pem(CA_LEAF, CA_KEY)
        .expect("fixture PEM")
        .bind();
    assert!(matches!(
        result,
        Err(BindError::Options(
            EndpointOptionsError::WebTransportCertificateWithoutListener
        ))
    ));
}

#[cfg(feature = "quic")]
#[test]
fn ca_webtransport_listener_reports_a_hash_free_address() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1/webtransport")
        .expect("WebTransport")
        .webtransport_certificate_pem(CA_LEAF, CA_KEY)
        .expect("fixture PEM")
        .bind()
        .expect("bind with the fixture certificate");
    let addrs = endpoint.listen_all().expect("listen_all");
    assert!(
        matches!(
            addrs.as_slice(),
            [addr] if addr.transport().is_webtransport()
                && addr.transport().certhashes().next().is_none()
        ),
        "{addrs:?}"
    );
}

#[cfg(feature = "quic")]
#[test]
fn set_webtransport_certificate_pem_needs_ca_mode_and_a_matching_key() {
    const CHAIN: &[u8] = include_bytes!("../../../../transports/quic/tests/fixtures/ca/chain.pem");
    const CHAIN_KEY: &[u8] =
        include_bytes!("../../../../transports/quic/tests/fixtures/ca/chain.key");
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1/webtransport")
        .expect("WebTransport")
        .webtransport_certificate_pem(CA_LEAF, CA_KEY)
        .expect("fixture PEM")
        .bind()
        .expect("bind with the fixture certificate");
    endpoint
        .set_webtransport_certificate_pem(CHAIN, CHAIN_KEY)
        .expect("replace");
    assert!(matches!(
        endpoint.set_webtransport_certificate_pem(CA_LEAF, CHAIN_KEY),
        Err(SetWebTransportCertificateError::Invalid { reason })
            if reason.contains("does not match")
    ));

    let mut derived = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1/webtransport")
        .expect("WebTransport")
        .bind()
        .expect("bind");
    assert_eq!(
        derived.set_webtransport_certificate_pem(CHAIN, CHAIN_KEY),
        Err(SetWebTransportCertificateError::NotConfigured)
    );
}

#[test]
fn listen_default_binds_dual_stack_quic() {
    let mut endpoint = Endpoint::builder()
        .listen_default()
        .expect("default listen")
        .bind()
        .expect("default dual-stack");
    let addrs = endpoint.listen_all().expect("listen_all");
    assert_eq!(
        addrs.len(),
        2,
        "dual-stack default binds both families: {addrs:?}"
    );
    assert!(
        addrs
            .iter()
            .all(|addr| addr.transport().to_string().contains("/quic-v1")),
        "{addrs:?}"
    );
    let has_v4 = addrs
        .iter()
        .any(|addr| addr.transport().to_string().contains("/ip4/"));
    let has_v6 = addrs
        .iter()
        .any(|addr| addr.transport().to_string().contains("/ip6/"));
    assert!(
        has_v4 && has_v6,
        "default listen binds IPv4 and IPv6: {addrs:?}"
    );
}

#[test]
fn listen_default_rejects_duplicate_quic_family() {
    let ipv4 = "/ip4/127.0.0.1/udp/0/quic-v1".parse().expect("ipv4");
    let Err(error) = Endpoint::builder()
        .listen_on_multiaddr(&ipv4)
        .expect("listen ipv4")
        .listen_default()
    else {
        panic!("listen_default after IPv4 QUIC must fail");
    };
    assert!(
        matches!(
            &error,
            EndpointOptionsError::DuplicateQuicFamily {
                family: IpFamily::Ipv4,
                ..
            }
        ),
        "{error}"
    );
}

#[cfg(feature = "tcp")]
#[test]
fn a_tcp_endpoint_reports_the_port_it_was_given() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
        .expect("bind tcp endpoint");

    // Bound at build time like a QUIC socket, so a caller that asked for
    // port 0 can learn which port it got without driving anything first.
    let addrs = endpoint.listen_all().expect("listen");
    assert_eq!(addrs.len(), 1, "one transport, one address: {addrs:?}");
    let port = tcp_port(&addrs[0]);
    assert_ne!(
        port, 0,
        "an ephemeral bind reports the port it actually got"
    );
    assert_eq!(
        addrs[0].transport().to_string(),
        format!("/ip4/127.0.0.1/tcp/{port}"),
        "the host asked for is the host reported, and nothing is added to it"
    );
    assert_eq!(addrs[0].peer_id(), endpoint.peer_id());
}

#[cfg(feature = "tcp")]
#[test]
fn every_bound_transport_reports_where_it_listens() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
        .expect("bind both");

    // A host announces where it can be reached. Leaving a transport out
    // would make half of those ways invisible to peers, and the host would
    // have no way to tell.
    let reported: Vec<String> = endpoint
        .listen_all()
        .expect("listen")
        .iter()
        .map(|addr| addr.transport().to_string())
        .collect();
    assert_eq!(reported.len(), 2, "one per transport: {reported:?}");
    assert!(
        reported.iter().any(|addr| addr.contains("/quic-v1")),
        "{reported:?}"
    );
    assert!(
        reported.iter().any(|addr| addr.contains("/tcp/")),
        "{reported:?}"
    );
}

#[cfg(feature = "tcp")]
#[test]
fn a_second_tcp_address_joins_the_transport_that_already_serves_tcp() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
        .expect("both tcp addresses bind");
    let addrs = endpoint.listen_all().expect("listen");
    assert_eq!(addrs.len(), 2, "both addresses are listening: {addrs:?}");
    assert_ne!(
        tcp_port(&addrs[0]),
        tcp_port(&addrs[1]),
        "two binds, two sockets"
    );

    // A transport claims an address shape, not an address family, so
    // asking for two /tcp addresses asks for two sockets on one transport
    // -- not a second one, which the set would refuse.
    let second = addrs[1].clone();
    let _driver = Driven::new(endpoint);
    let mut dialer = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
        .expect("bind dialer");
    dialer
        .connect(second.clone())
        .expect("connect to the second address");
    wait_for(
        &mut dialer,
        "connection",
        |event| matches!(event, EndpointEvent::ConnectionEstablished { peer_id, .. } if peer_id == second.peer_id()),
    );
}

#[cfg(feature = "tcp")]
#[test]
fn listening_arms_every_bound_transport_not_just_the_first() {
    // TCP first, so the transport that still needs arming is the one
    // `listen` does not return. An endpoint that reported success while
    // QUIC accepted nothing would look bound and be unreachable.
    let mut listener = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind both");
    // Read straight off the bound sockets, so nothing here arms anything:
    // `listen` below is the only call that does.
    let bound = listener
        .core()
        .transport()
        .local_addresses()
        .into_iter()
        .find(|addr| addr.to_string().contains("quic"))
        .expect("a bound quic socket");
    let quic_addr = PeerAddr::new(bound, *listener.peer_id()).expect("target");
    let first = listener.listen().expect("listen returns the first address");
    assert!(
        first.transport().to_string().contains("/tcp/"),
        "the returned address is the first bound one: {first:?}"
    );
    let _driver = Driven::new(listener);

    let mut dialer = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind dialer");
    dialer.connect(&quic_addr).expect("connect");
    wait_for(
        &mut dialer,
        "connection",
        |event| matches!(event, EndpointEvent::ConnectionEstablished { peer_id, .. } if peer_id == quic_addr.peer_id()),
    );
}

#[cfg(feature = "tcp")]
#[test]
fn a_peer_is_reached_over_the_transport_its_address_names() {
    // One peer per transport: the swarm keeps a single connection per
    // peer, so two paths to one host would be the second replacing the
    // first rather than a test of which path each address took.
    let mut over_tcp = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
        .expect("bind tcp peer");
    let mut over_quic = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind quic peer");
    let tcp_addr = over_tcp.listen().expect("tcp peer listens");
    let quic_addr = over_quic.listen().expect("quic peer listens");

    let mut dialer = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
        .expect("bind dialer");
    let _drivers = (Driven::new(over_tcp), Driven::new(over_quic));

    // The address decides the transport, and nothing above the endpoint
    // had to choose: the namespace on the connection id says which one
    // actually carried it. Each connection is waited for by name, since
    // the one before it keeps producing events of its own.
    for (addr, expected) in [
        (&tcp_addr, ConnectionNamespace::TCP_IPV4),
        (&quic_addr, ConnectionNamespace::QUIC_IPV4),
    ] {
        dialer.connect(addr).expect("connect");
        let event = wait_for(
            &mut dialer,
            "connection",
            |event| matches!(event, EndpointEvent::ConnectionEstablished { peer_id, .. } if peer_id == addr.peer_id()),
        );
        let EndpointEvent::ConnectionEstablished { conn_id, .. } = event else {
            panic!("the connection predicate returned an unrelated event")
        };
        assert_eq!(
            conn_id.namespace(),
            expected,
            "{} should have been carried by {expected}",
            addr.transport()
        );
    }
}

#[cfg(feature = "tcp")]
#[test]
fn tcp_limits_and_namespace_reach_the_transport() {
    let mut endpoint = Endpoint::builder()
        .tcp_config(TcpConfig {
            namespace: ConnectionNamespace::TCP_IPV6,
            ..TcpConfig::default()
        })
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
        .expect("bind tcp endpoint");
    let target = PeerAddr::new(
        "/ip4/127.0.0.1/tcp/1".parse().expect("address"),
        Ed25519Keypair::generate().peer_id(),
    )
    .expect("target");

    // The id a raw swarm dial hands back is minted by the transport, so
    // its namespace is what the configuration actually reached -- whether
    // anything answers is beside the point.
    let id = endpoint.core_mut().dial(&target).expect("the dial starts");
    assert_eq!(id.namespace(), ConnectionNamespace::TCP_IPV6);
}

#[cfg(feature = "tcp")]
#[test]
fn a_tcp_config_that_breaks_the_yamux_invariants_is_refused_at_bind() {
    let mut config = TcpConfig::default();
    config.yamux.max_frame_len = 0;
    let Err(error) = Endpoint::builder()
        .tcp_config(config)
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
    else {
        panic!("a zero frame length cannot work");
    };
    assert!(
        matches!(
            error,
            BindError::Options(EndpointOptionsError::InvalidLimit(InvalidLimit {
                field: "TcpConfig::yamux",
                ..
            }))
        ),
        "got {error}"
    );
}

#[cfg(all(feature = "relay", feature = "quic"))]
#[test]
fn circuit_limits_that_break_the_yamux_invariants_are_refused_at_bind() {
    let mut limits = CircuitLimits::default();
    limits.yamux.max_frame_len = 0;
    let Err(error) = Endpoint::builder()
        .circuit_limits(limits)
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
    else {
        panic!("a zero frame length cannot work");
    };
    assert!(
        matches!(
            error,
            BindError::Options(EndpointOptionsError::InvalidLimit(InvalidLimit {
                field: "CircuitLimits::yamux",
                ..
            }))
        ),
        "got {error}"
    );
}

#[cfg(feature = "tcp")]
#[test]
fn a_tcp_transport_tagged_for_another_carrier_is_refused() {
    // The namespace routes a connection id back to the transport that
    // minted it. Tagged as QUIC's, TCP's ids would name the wrong carrier
    // and take a claim the QUIC member needs.
    let Err(error) = Endpoint::builder()
        .tcp_config(TcpConfig {
            namespace: ConnectionNamespace::QUIC_IPV4,
            ..TcpConfig::default()
        })
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
    else {
        panic!("a tcp transport must not claim another transport's ids");
    };
    assert!(
        matches!(
            error,
            BindError::Options(EndpointOptionsError::TcpNamespace {
                namespace: ConnectionNamespace::QUIC_IPV4
            })
        ),
        "got {error}"
    );
}

#[test]
fn wait_reports_deadline_without_swallowing_control_outcomes() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind loopback endpoint");

    assert!(matches!(
        endpoint.wait(Duration::ZERO).expect("wait endpoint"),
        EndpointWaitOutcome::Deadline
    ));
}

/// An `Instant` that has already passed.
fn past_instant() -> std::time::Instant {
    let now = std::time::Instant::now();
    now.checked_sub(Duration::from_secs(1)).unwrap_or(now)
}

#[test]
fn wait_with_a_passed_instant_delivers_a_queued_event() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind loopback endpoint");
    let peer = Ed25519Keypair::generate().peer_id();
    endpoint
        .engine
        .events
        .push_back(EndpointEvent::ConnectionClosed {
            peer_id: peer,
            conn_id: ConnectionId::new(1),
            reason: ConnectionCloseReason::Local,
        });
    assert!(matches!(
        endpoint.wait(past_instant()).expect("wait past deadline"),
        EndpointWaitOutcome::Event(EndpointEvent::ConnectionClosed { peer_id, .. })
            if peer_id == peer
    ));
}

#[test]
fn wait_with_a_passed_instant_drives_a_connect_to_settlement() {
    let mut listener = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind listener");
    let listen_addr = listener.listen().expect("listen");
    let mut dialer = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind dialer");
    let _listener = Driven::new(listener);

    // A loop whose own timer has gone stale: every call gets a past
    // deadline, yet each call must still drive the endpoint.
    let connect_id = dialer.connect(&listen_addr).expect("connect");
    let stale = past_instant();
    let give_up = std::time::Instant::now() + Duration::from_secs(10);
    let outcome = loop {
        assert!(
            std::time::Instant::now() < give_up,
            "a stale deadline must not stop the connect from settling"
        );
        if let EndpointWaitOutcome::Event(EndpointEvent::ConnectSettled {
            connect_id: settled,
            outcome,
            ..
        }) = dialer.wait(stale).expect("wait past deadline")
            && settled == connect_id
        {
            break outcome;
        }
    };
    assert!(
        matches!(outcome, ConnectOutcome::Connected { .. }),
        "got {outcome:?}"
    );
}

#[test]
fn a_caller_clock_check_ends_a_fixed_deadline_loop_while_events_keep_arriving() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind loopback endpoint");
    let peer = Ed25519Keypair::generate().peer_id();
    let arrive = |endpoint: &mut Endpoint| {
        endpoint
            .engine
            .events
            .push_back(EndpointEvent::ConnectionClosed {
                peer_id: peer,
                conn_id: ConnectionId::new(1),
                reason: ConnectionCloseReason::Local,
            });
    };
    let deadline = std::time::Instant::now() + Duration::from_millis(50);
    loop {
        // The documented guard: `wait` serves events past the deadline.
        if std::time::Instant::now() >= deadline {
            break;
        }
        arrive(&mut endpoint);
        assert!(matches!(
            endpoint.wait(deadline).expect("wait"),
            EndpointWaitOutcome::Event(_)
        ));
    }
    assert!(std::time::Instant::now() < deadline + Duration::from_secs(1));
    // Without the guard, a steady stream keeps the loop going.
    arrive(&mut endpoint);
    assert!(matches!(
        endpoint.wait(deadline).expect("wait past deadline"),
        EndpointWaitOutcome::Event(_)
    ));
}

#[test]
fn a_pending_interrupt_is_reported_once_even_past_the_deadline() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind loopback endpoint");
    endpoint.wait_handle().interrupt();
    endpoint.wait_handle().interrupt();

    // A pending interrupt outranks an expired deadline, so a host's
    // non-blocking pump still notices it; the two calls are one.
    assert!(matches!(
        endpoint.wait(past_instant()).expect("wait past deadline"),
        EndpointWaitOutcome::Interrupted
    ));
    assert!(matches!(
        endpoint.wait(past_instant()).expect("wait past deadline"),
        EndpointWaitOutcome::Deadline
    ));
}

/// A steady stream of host wakes cannot hold a wait past its deadline:
/// it runs at most one batch for them, and newer wakes stay pending.
#[test]
fn a_stream_of_wakes_does_not_hold_a_wait_past_its_deadline() {
    let mut endpoint = quic_endpoint();
    let wake = endpoint.platform.poll.wake_handle();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sent = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let waker = {
        let (stop, sent) = (std::sync::Arc::clone(&stop), std::sync::Arc::clone(&sent));
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                wake.wake();
                sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                std::thread::yield_now();
            }
        })
    };
    // The stream is flowing before the wait starts.
    while sent.load(std::sync::atomic::Ordering::Relaxed) < 100 {
        std::thread::yield_now();
    }
    let passes = endpoint.engine.stats.capability_passes;
    let outcome = endpoint.wait(past_instant()).expect("wait past deadline");
    let batches = endpoint.engine.stats.capability_passes - passes;
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    waker.join().expect("waker thread");
    assert!(
        matches!(outcome, EndpointWaitOutcome::Deadline),
        "{outcome:?}"
    );
    // The one drive every wait makes, plus at most one for a wake.
    assert!(batches <= 2, "ran {batches} batches past the deadline");
}

#[cfg(feature = "relay")]
#[test]
fn wait_with_duration_zero_still_drains_queued_events() {
    let mut endpoint = Endpoint::builder()
        .nat_config(super::nat_tests::idle_nat_config())
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind loopback endpoint");
    let peer = Ed25519Keypair::generate().peer_id();
    endpoint
        .engine
        .events
        .push_back(EndpointEvent::ConnectionClosed {
            peer_id: peer,
            conn_id: ConnectionId::new(1),
            reason: ConnectionCloseReason::Local,
        });
    assert!(matches!(
        endpoint.wait(Duration::ZERO).expect("zero-duration drain"),
        EndpointWaitOutcome::Event(EndpointEvent::ConnectionClosed { peer_id, .. })
            if peer_id == peer
    ));
    assert!(
        endpoint.engine.events.is_empty(),
        "Duration::ZERO must drain queued events"
    );
}

#[test]
fn wait_reports_interrupt_without_swallowing_it() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind loopback endpoint");
    endpoint.wait_handle().interrupt();

    assert!(matches!(
        endpoint.wait(WaitDeadline::NEVER).expect("wait endpoint"),
        EndpointWaitOutcome::Interrupted
    ));
}

#[test]
fn wait_delivers_connection_events_once_through_the_endpoint_stream() {
    let mut listener = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind listener");
    let listen_addr = listener.listen().expect("listen");
    let mut dialer = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind dialer");
    let _listener = Driven::new(listener);

    dialer.connect(&listen_addr).expect("connect");
    let peer = *listen_addr.peer_id();

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut established_count = 0u32;
    let mut conn_id = None;
    let mut saw_peer_ready = false;
    while std::time::Instant::now() < deadline {
        match dialer.wait(deadline).expect("wait") {
            EndpointWaitOutcome::Event(EndpointEvent::ConnectionEstablished {
                peer_id,
                conn_id: id,
            }) if peer_id == peer => {
                established_count += 1;
                conn_id = Some(id);
            }
            EndpointWaitOutcome::Event(EndpointEvent::PeerReady { peer_id, .. })
                if peer_id == peer =>
            {
                saw_peer_ready = true;
                break;
            }
            EndpointWaitOutcome::Event(_) | EndpointWaitOutcome::Interrupted => {}
            EndpointWaitOutcome::Deadline => break,
        }
    }
    assert_eq!(
        established_count, 1,
        "ConnectionEstablished must appear exactly once before PeerReady"
    );
    let conn_id = conn_id.expect("dialer saw ConnectionEstablished");
    assert!(saw_peer_ready, "PeerReady follows the single establishment");
    assert_eq!(dialer.connection_id(&peer), Some(conn_id));
    assert!(dialer.connected_peers().contains(&peer));
}

#[test]
fn wait_delivers_peer_ready_through_the_endpoint_stream() {
    let mut listener = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind listener");
    let listen_addr = listener.listen().expect("listen");
    let mut dialer = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind dialer");
    let _listener = Driven::new(listener);

    dialer.connect(&listen_addr).expect("connect");
    let peer = *listen_addr.peer_id();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut ready = false;
    while std::time::Instant::now() < deadline {
        match dialer.wait(deadline).expect("wait") {
            EndpointWaitOutcome::Event(EndpointEvent::PeerReady { peer_id, .. })
                if peer_id == peer =>
            {
                ready = true;
                break;
            }
            EndpointWaitOutcome::Event(_) | EndpointWaitOutcome::Interrupted => {}
            EndpointWaitOutcome::Deadline => break,
        }
    }
    assert!(ready, "PeerReady arrives once through Endpoint::wait");
    assert!(dialer.is_peer_ready(&peer));
    assert!(dialer.peer_info(&peer).is_some());
}

#[test]
fn state_getters_expose_bound_addresses_and_connection_without_driving() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind loopback endpoint");
    let before = endpoint.bound_addresses();
    assert!(
        !before.is_empty(),
        "bound transport addresses are visible before listen/drive"
    );
    let listened = endpoint.listen_all().expect("listen");
    assert_eq!(endpoint.bound_addresses(), before);
    assert_eq!(endpoint.connected_peers(), Vec::<PeerId>::new());
    assert!(endpoint.connection_id(listened[0].peer_id()).is_none());
    assert!(endpoint.peer_info(listened[0].peer_id()).is_none());
    assert!(!endpoint.is_peer_ready(listened[0].peer_id()));
}

#[cfg(feature = "relay")]
#[test]
fn wait_delivers_queued_nat_events_once() {
    let mut endpoint = Endpoint::builder()
        .nat_config(super::nat_tests::idle_nat_config())
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind NAT endpoint");
    endpoint
        .engine
        .nat
        .as_mut()
        .expect("NAT configured")
        .push_event(NatEvent::ReachabilityChanged {
            old: ReachabilityState::Unknown,
            new: ReachabilityState::Private,
            confirmed_addrs: Vec::new(),
        });

    assert!(matches!(
        endpoint.wait(Duration::ZERO).expect("wait"),
        EndpointWaitOutcome::Event(EndpointEvent::Nat(NatEvent::ReachabilityChanged { .. }))
    ));
    assert!(matches!(
        endpoint.wait(Duration::ZERO).expect("wait"),
        EndpointWaitOutcome::Deadline
    ));
}

#[cfg(feature = "pubsub")]
#[test]
fn wait_delivers_queued_gossipsub_events_as_endpoint_events() {
    let mut endpoint = Endpoint::builder()
        .gossipsub()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind pubsub endpoint");
    let peer = Ed25519Keypair::generate().peer_id();
    endpoint
        .engine
        .gossipsub
        .as_mut()
        .expect("pubsub configured")
        .events
        .push_back(GossipsubEvent::PeerSubscribed {
            peer,
            topic: "test".into(),
        });

    assert!(matches!(
        endpoint.wait(Duration::ZERO).expect("wait"),
        EndpointWaitOutcome::Event(EndpointEvent::Gossipsub(GossipsubEvent::PeerSubscribed {
            peer: returned,
            topic,
        })) if returned == peer && topic == "test"
    ));
}

#[cfg(all(feature = "relay", feature = "pubsub", feature = "relay-server"))]
#[test]
fn capability_events_leave_once_in_endpoint_order() {
    let mut endpoint = Endpoint::builder()
        .nat_config(super::nat_tests::idle_nat_config())
        .gossipsub()
        .relay_server()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind capability endpoint");
    let peer = Ed25519Keypair::generate().peer_id();
    endpoint
        .engine
        .gossipsub
        .as_mut()
        .unwrap()
        .events
        .push_back(GossipsubEvent::PeerSubscribed {
            peer,
            topic: "test".into(),
        });
    let nat = endpoint.engine.nat.as_mut().unwrap();
    nat.push_event(NatEvent::FellBackToRelay {
        connect_id: ConnectId::from_u64(99),
        peer,
        reason: minip2p_nat::UpgradeStop::PunchFailed { rounds: 3 },
    });
    nat.push_event(NatEvent::ReachabilityChanged {
        old: ReachabilityState::Unknown,
        new: ReachabilityState::Private,
        confirmed_addrs: Vec::new(),
    });
    endpoint
        .engine
        .relay_server
        .as_mut()
        .unwrap()
        .events
        .push_back(RelayServerEvent::Error(RelayServerRuntimeError {
            kind: RelayServerRuntimeErrorKind::InternalInvariant,
            peer_id: None,
            detail: "test diagnostic".into(),
        }));

    // A Peer-ID target with no route settles inside `connect`; its
    // terminal must still follow the capability events already queued.
    let settled_id = endpoint
        .connect(Ed25519Keypair::generate().peer_id())
        .expect("admit route-less connect");

    let events = endpoint.poll().expect("poll");
    let order: Vec<&str> = events
        .iter()
        .filter_map(|event| match event {
            EndpointEvent::RelayServer(_) => Some("relay-server"),
            EndpointEvent::Nat(_) => Some("nat"),
            EndpointEvent::Gossipsub(_) => Some("gossipsub"),
            EndpointEvent::ConnectSettled { connect_id, .. } if *connect_id == settled_id => {
                Some("settled")
            }
            _ => None,
        })
        .collect();
    // FellBackToRelay is an attempt terminal the engine reports as
    // ConnectSettled; it is not repeated as a NAT event.
    assert_eq!(order, ["relay-server", "nat", "gossipsub", "settled"]);
}

/// A transport with nothing to do whose `poll` fails while `fail` is set.
struct FlakyPollTransport {
    fail: Arc<AtomicBool>,
}

impl Transport for FlakyPollTransport {
    fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
        Err(TransportError::Unsupported { operation: "dial" })
    }
    fn listen(&mut self, _: &Multiaddr) -> Result<Multiaddr, TransportError> {
        Err(TransportError::Unsupported {
            operation: "listen",
        })
    }
    fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
        Err(TransportError::Unsupported {
            operation: "open stream",
        })
    }
    fn send_stream(
        &mut self,
        _: ConnectionId,
        _: StreamId,
        _: Bytes,
    ) -> Result<(), TransportError> {
        Err(TransportError::Unsupported {
            operation: "send stream",
        })
    }
    fn close_stream_write(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Err(TransportError::Unsupported {
            operation: "close stream write",
        })
    }
    fn reset_stream(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Err(TransportError::Unsupported {
            operation: "reset stream",
        })
    }
    fn ack_stream(&mut self, _: ConnectionId, _: StreamId, _: usize) -> Result<(), TransportError> {
        Ok(())
    }
    fn close(&mut self, _: ConnectionId) -> Result<(), TransportError> {
        Err(TransportError::Unsupported {
            operation: "close connection",
        })
    }
    fn poll(
        &mut self,
        _: minip2p_core::platform::Now,
    ) -> Result<Vec<minip2p_transport::TransportEvent>, TransportError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(TransportError::PollError {
                reason: "injected".into(),
            });
        }
        Ok(Vec::new())
    }
}

impl minip2p_transport::PollSource for FlakyPollTransport {
    fn attach(
        &mut self,
        _: minip2p_transport::mio::Registry,
        _: minip2p_transport::TokenSpace,
        _: std::sync::Arc<minip2p_transport::mio::Waker>,
    ) -> std::io::Result<()> {
        Ok(())
    }

    fn dispatch(&mut self, _: &minip2p_transport::mio::event::Event) {}
}

/// Events already queued survive a `poll` that fails, and come out of the
/// next one.
#[test]
fn a_failed_poll_keeps_queued_events_for_the_next() {
    let fail = Arc::new(AtomicBool::new(false));
    let mut set = TransportSet::new();
    insert_member(
        &mut set,
        TransportKind::Tcp,
        [ConnectionNamespace::TCP_IPV4],
        FlakyPollTransport {
            fail: Arc::clone(&fail),
        },
    )
    .expect("insert transport");
    let mut endpoint = Endpoint::builder().bind_over(set).expect("build");
    let peer = Ed25519Keypair::generate().peer_id();
    endpoint
        .engine
        .events
        .push_back(EndpointEvent::ConnectionClosed {
            peer_id: peer,
            conn_id: ConnectionId::new(1),
            reason: ConnectionCloseReason::Local,
        });

    fail.store(true, Ordering::SeqCst);
    endpoint.poll().expect_err("injected poll failure");
    fail.store(false, Ordering::SeqCst);

    let events = endpoint.poll().expect("poll");
    assert!(
        events.iter().any(|event| matches!(
            event,
            EndpointEvent::ConnectionClosed { peer_id, .. } if peer_id == &peer
        )),
        "the queued event must survive the failed poll: {events:?}"
    );
}

/// A close whose drain fails still returns the events queued before it,
/// alongside the error.
#[test]
fn close_reports_queued_events_with_a_drain_failure() {
    let fail = Arc::new(AtomicBool::new(true));
    let mut set = TransportSet::new();
    insert_member(
        &mut set,
        TransportKind::Tcp,
        [ConnectionNamespace::TCP_IPV4],
        FlakyPollTransport { fail },
    )
    .expect("insert transport");
    let mut endpoint = Endpoint::builder().bind_over(set).expect("build");
    let peer = Ed25519Keypair::generate().peer_id();
    endpoint
        .engine
        .events
        .push_back(EndpointEvent::ConnectionClosed {
            peer_id: peer,
            conn_id: ConnectionId::new(1),
            reason: ConnectionCloseReason::Local,
        });

    let report = endpoint.close();
    assert!(
        matches!(
            report.events.as_slice(),
            [EndpointEvent::ConnectionClosed { peer_id, .. }] if peer_id == &peer
        ),
        "{:?}",
        report.events
    );
    assert_eq!(report.errors.len(), 1, "{:?}", report.errors);
    assert_eq!(report.outcome, CloseOutcome::Failed);
}

#[test]
fn closing_an_idle_endpoint_drains_with_nothing_unfinished() {
    let endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind");

    let report = endpoint.close();
    assert_eq!(report.outcome, CloseOutcome::Drained);
    assert!(report.unfinished.is_empty(), "{:?}", report.unfinished);
    assert!(report.errors.is_empty(), "{:?}", report.errors);
}

/// A zero deadline tears down at once and names the live connection it
/// did not wait for.
#[test]
fn closing_within_zero_reports_the_live_connection_unfinished() {
    let mut listener = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind listener");
    let addr = listener.listen().expect("listen");
    let _listener = Driven::new(listener);
    let mut dialer = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind dialer");
    dialer.connect(addr.clone()).expect("connect");
    let EndpointEvent::ConnectionEstablished { conn_id, .. } =
        wait_for(&mut dialer, "connection", |event| {
            matches!(event, EndpointEvent::ConnectionEstablished { .. })
        })
    else {
        panic!("the connection predicate returned an unrelated event")
    };

    let report = dialer.close_within(Duration::ZERO);
    assert_eq!(report.outcome, CloseOutcome::DeadlineExpired);
    assert_eq!(report.unfinished, [(conn_id, Some(*addr.peer_id()))]);
}

/// A dial the transport still holds is unfinished teardown, not a drain.
#[test]
fn closing_within_zero_reports_a_pending_dial_unfinished() {
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind silent socket");
    let port = silent.local_addr().expect("silent addr").port();
    let peer = Ed25519Keypair::generate().peer_id();
    let target = PeerAddr::new(
        format!("/ip4/127.0.0.1/udp/{port}/quic-v1")
            .parse()
            .expect("addr"),
        peer,
    )
    .expect("peer addr");
    let mut dialer = quic_endpoint();
    dialer.connect(target).expect("connect");

    let report = dialer.close_within(Duration::ZERO);
    assert_eq!(report.outcome, CloseOutcome::DeadlineExpired);
    assert!(
        matches!(report.unfinished.as_slice(), [(_, Some(unfinished))] if *unfinished == peer),
        "{:?}",
        report.unfinished
    );
}

#[cfg(feature = "relay")]
#[test]
fn wait_honors_expired_deadline_with_active_driver() {
    let mut endpoint = Endpoint::builder()
        .nat_config(super::nat_tests::idle_nat_config())
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind NAT endpoint");

    assert!(matches!(
        endpoint.wait(Duration::ZERO).expect("expired wait"),
        EndpointWaitOutcome::Deadline
    ));
}

#[cfg(feature = "relay")]
#[test]
fn wait_returns_application_event_produced_during_driver_poll() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let mut endpoint = Endpoint::builder()
        .nat_config(super::nat_tests::idle_nat_config())
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind driven endpoint");
    let mut remote = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind remote endpoint");
    endpoint.listen().expect("driven endpoint listens");
    let remote_addr = remote.listen().expect("remote listens");

    let stop = Arc::new(AtomicBool::new(false));
    let remote_stop = Arc::clone(&stop);
    let remote_thread = std::thread::spawn(move || {
        while !remote_stop.load(Ordering::Relaxed) {
            remote
                .next_event(Duration::from_millis(20))
                .expect("drive remote");
        }
    });

    endpoint.connect(&remote_addr).expect("connect to remote");
    let wake = endpoint
        .wait(Duration::from_secs(5))
        .expect("wait for application event");
    stop.store(true, Ordering::Relaxed);
    remote_thread.join().expect("remote driver exits");

    assert!(matches!(
        wake,
        EndpointWaitOutcome::Event(EndpointEvent::ConnectionEstablished { peer_id, .. })
            if peer_id == *remote_addr.peer_id()
    ));
}

/// A step's first event is often `ConnectionEstablished`, with the NAT
/// path and `ConnectSettled` behind it. `wait` must hand them out in that
/// order: the terminal never overtakes the connection it reports.
#[cfg(feature = "relay")]
#[test]
fn nat_path_and_connect_settled_follow_connection_established() {
    let mut endpoint = Endpoint::builder()
        .nat_config(super::nat_tests::idle_nat_config())
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind NAT endpoint");
    let mut remote = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind remote endpoint");
    endpoint.listen().expect("NAT endpoint listens");
    let remote_addr = remote.listen().expect("remote listens");
    let _remote = Driven::new(remote);

    let connect_id = endpoint.connect(&remote_addr).expect("connect");
    let mut events = Vec::new();
    wait_for(&mut endpoint, "connect settled", |event| {
        events.push(format!("{event:?}"));
        matches!(event, EndpointEvent::ConnectSettled { connect_id: id, .. } if *id == connect_id)
    });
    let position = |needle: &str| events.iter().position(|event| event.contains(needle));
    match (
        position("ConnectionEstablished"),
        position("PathEstablished"),
        position("ConnectSettled"),
    ) {
        (Some(established), Some(path), Some(settled)) => assert!(
            established < path && path < settled,
            "expected ConnectionEstablished, PathEstablished, ConnectSettled: {events:?}"
        ),
        _ => panic!("missing connection, path, or terminal event: {events:?}"),
    }
}

#[cfg(feature = "relay")]
#[test]
fn wait_delivers_connect_timeout_with_an_active_driver() {
    use std::net::{IpAddr, Ipv4Addr};

    let mut endpoint = Endpoint::builder()
        .connect_deadline(Duration::from_millis(20))
        .nat_config(super::nat_tests::idle_nat_config())
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind NAT endpoint");
    let unreachable = PeerAddr::quic_v1(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        9,
        Ed25519Keypair::generate().peer_id(),
    );
    let id = endpoint.connect(&unreachable).expect("start timed connect");

    let wake = endpoint
        .wait(Duration::from_secs(1))
        .expect("wait for connect deadline");
    match wake {
        EndpointWaitOutcome::Event(EndpointEvent::ConnectSettled {
            connect_id,
            outcome: ConnectOutcome::Failed(ConnectFailure::Timeout { .. }),
            ..
        }) => assert_eq!(connect_id, id),
        other => panic!("expected ConnectSettled Timeout, got {other:?}"),
    }
}

#[cfg(any(feature = "discovery", feature = "mdns"))]
#[test]
fn discovery_clock_is_present_only_for_an_active_source() {
    let mut inactive = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind plain endpoint");
    assert_eq!(inactive.discovery_now_ms(), None);

    let builder = Endpoint::builder();
    #[cfg(feature = "discovery")]
    let builder = builder.discovery();
    #[cfg(all(feature = "mdns", not(feature = "discovery")))]
    let builder = builder.mdns();
    let mut active = builder
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind discovery endpoint");
    let first = active.discovery_now_ms().expect("discovery clock");
    let second = active.discovery_now_ms().expect("discovery clock");
    assert!(second >= first);
}

#[cfg(feature = "mdns")]
#[test]
fn mdns_config_is_rejected_before_binding() {
    let config = MdnsConfig {
        max_packet_bytes: 4_097,
        ..MdnsConfig::default()
    };
    // TEST-NET-1 is never a local address: a socket bind would fail.
    assert!(matches!(
        Endpoint::builder()
            .mdns_config(config)
            .listen_on("/ip4/192.0.2.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .err(),
        Some(BindError::Mdns(
            crate::MdnsConfigError::InvalidMaxPacketBytes
        ))
    ));
}

#[cfg(feature = "mdns")]
#[test]
fn mdns_shutdown_is_idempotent_and_leaves_quic_usable() {
    let mut endpoint = Endpoint::builder()
        .mdns()
        .peer_discovery_config(PeerDiscoveryConfig {
            auto_dial: false,
            ..PeerDiscoveryConfig::default()
        })
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind mDNS endpoint");
    endpoint.listen().expect("QUIC listens");
    endpoint.shutdown_mdns().expect("first mDNS shutdown");
    endpoint.shutdown_mdns().expect("second mDNS shutdown");
    assert!(
        endpoint.poll().is_ok(),
        "QUIC remains usable after shutdown"
    );
}

#[cfg(feature = "discovery")]
#[test]
fn discovery_topic_cannot_be_unsubscribed_independently() {
    let topic = "/minip2p/test/discovery";
    let config = BeaconConfig {
        topic: topic.into(),
        ..BeaconConfig::default()
    };
    let mut endpoint = Endpoint::builder()
        .discovery_config(config)
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind discovery endpoint");

    assert!(matches!(
        endpoint.unsubscribe(topic),
        Err(GossipsubError::DiscoveryTopicReserved)
    ));
    assert!(matches!(
        endpoint.publish(topic, b"not a beacon".to_vec()),
        Err(GossipsubError::DiscoveryTopicReserved)
    ));
}

const PROTOCOL: &str = "/myapp/1.0.0";

#[test]
fn builder_protocol_registers_for_stream_routing() {
    let mut endpoint = Endpoint::builder()
        .protocol(PROTOCOL)
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind loopback endpoint");

    // A registered protocol fails with NotConnected for an unknown
    // peer, not ProtocolNotRegistered -- proving the builder wired the
    // protocol into user-stream routing.
    let peer_id = Ed25519Keypair::generate().peer_id();
    assert!(matches!(
        endpoint.open_stream(&peer_id, PROTOCOL),
        Err(Error::Swarm(SwarmError::NotConnected { .. }))
    ));
    assert!(matches!(
        endpoint.open_stream(&peer_id, "/other/1.0.0"),
        Err(Error::Swarm(SwarmError::ProtocolNotRegistered { .. }))
    ));
}

/// Every bind failure names what failed and carries its typed cause.
#[test]
fn bind_errors_name_what_failed() {
    let quic = || {
        Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
    };
    let limits = QuicLimits {
        idle_timeout_ms: 0,
        ..QuicLimits::default()
    };
    assert!(matches!(
        quic().quic_limits(limits).bind().err(),
        Some(BindError::Quic(minip2p_quic::QuicBindError::InvalidLimit {
            field: "idle_timeout_ms",
            ..
        }))
    ));
    assert!(matches!(
        Endpoint::builder().bind().err(),
        Some(BindError::Options(EndpointOptionsError::NoTransport))
    ));
    #[cfg(feature = "pubsub")]
    assert!(matches!(
        quic()
            .gossipsub_config(crate::GossipsubConfig {
                heartbeat_interval_ms: 0,
                ..crate::GossipsubConfig::default()
            })
            .bind()
            .err(),
        Some(BindError::Gossipsub(crate::GossipsubConfigError {
            field: "heartbeat_interval_ms",
            ..
        }))
    ));
    #[cfg(feature = "relay-server")]
    {
        let announce: Multiaddr = format!(
            "/ip4/198.51.100.7/udp/4001/quic-v1/p2p/{}",
            Ed25519Keypair::generate().peer_id()
        )
        .parse()
        .expect("announce address");
        assert!(matches!(
            quic()
                .relay_server_announce_addrs(vec![announce.clone()])
                .expect("valid for the peer it names")
                .bind()
                .err(),
            Some(BindError::Options(
                EndpointOptionsError::RelayAnnounceWithoutServer
            ))
        ));
        // Valid for the peer it names, but this endpoint is another one.
        let Some(BindError::RelayServerAnnounce(error)) = quic()
            .relay_server()
            .relay_server_announce_addrs(vec![announce])
            .expect("valid for the peer it names")
            .bind()
            .err()
        else {
            panic!("a foreign announce address must fail the bind");
        };
        assert!(matches!(
            error.reason,
            minip2p_relay_server::RelayServerAddressErrorKind::ConflictingPeerId { .. }
        ));
    }
}

#[test]
fn builder_rejects_reserved_protocol_ids() {
    for reserved in RESERVED_PROTOCOL_IDS {
        let error = Endpoint::builder()
            .protocol(reserved)
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .err()
            .expect("reserved ids must fail the build");
        assert!(matches!(
            error,
            BindError::Swarm(SwarmError::ReservedProtocol { .. })
        ));
    }
}

#[test]
fn builder_rejects_reserved_protocol_ids_before_binding() {
    // An unbindable address must not mask the configuration error:
    // validation happens before any socket is allocated.
    let error = Endpoint::builder()
        .protocol(RESERVED_PROTOCOL_IDS[0])
        // TEST-NET-1 is never a local address, so this bind would fail.
        .listen_on("/ip4/192.0.2.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .err()
        .expect("reserved ids must fail the build");
    assert!(matches!(
        error,
        BindError::Swarm(SwarmError::ReservedProtocol { .. })
    ));
}

#[test]
fn builder_rejects_a_zero_timeout_before_binding() {
    let error = Endpoint::builder()
        .timeouts(SwarmTimeouts {
            identify_ms: 0,
            ..SwarmTimeouts::default()
        })
        // TEST-NET-1 is never a local address, so this bind would fail.
        .listen_on("/ip4/192.0.2.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .err()
        .expect("a zero deadline must fail the build");
    assert!(matches!(
        error,
        BindError::Swarm(SwarmError::ZeroTimeout {
            field: "identify_ms"
        })
    ));
}

#[test]
fn add_protocol_rejects_reserved_protocol_ids() {
    let mut endpoint = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind loopback endpoint");
    let error = endpoint
        .add_protocol(RESERVED_PROTOCOL_IDS[0])
        .expect_err("reserved ids must be rejected");
    assert!(matches!(
        error,
        Error::Swarm(SwarmError::ReservedProtocol { .. })
    ));
    endpoint
        .add_protocol(PROTOCOL)
        .expect("application ids must be accepted");
}

#[cfg(feature = "relay-server")]
#[test]
fn relay_mesh_is_checked_before_any_socket_opens() {
    let public = Ed25519Keypair::generate();
    let quic: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();
    let member = |transport: &str| {
        PeerAddr::new(
            transport.parse().unwrap(),
            Ed25519Keypair::generate().peer_id(),
        )
        .unwrap()
    };
    let mesh = |identity: &Ed25519Keypair, members| RelayMeshConfig {
        identity: identity.clone(),
        listen: vec![quic.clone()],
        members,
    };
    let bind = |builder: EndpointBuilder| match builder
        .identity(public.clone())
        .listen_on_multiaddr(&quic)
        .unwrap()
        .bind()
    {
        Err(BindError::Options(error)) => error,
        Err(other) => panic!("expected an options error, got {other:?}"),
        Ok(_) => panic!("bound despite an invalid relay mesh"),
    };
    let backbone = Ed25519Keypair::generate();

    let error = bind(Endpoint::builder().relay_mesh(mesh(&backbone, Vec::new())));
    assert_eq!(error, EndpointOptionsError::RelayMeshWithoutServer);
    let error = bind(
        Endpoint::builder()
            .relay_server()
            .relay_mesh(mesh(&public, Vec::new())),
    );
    assert_eq!(error, EndpointOptionsError::RelayMeshPublicIdentity);
    // Backbone transports take `/ip4|ip6` QUIC only: no names, no TCP.
    for transport in [
        "/dns4/relay.example/udp/19877/quic-v1",
        "/ip4/127.0.0.1/tcp/19877",
    ] {
        let bad = member(transport);
        let error = bind(
            Endpoint::builder()
                .relay_server()
                .relay_mesh(mesh(&backbone, vec![bad.clone()])),
        );
        assert_eq!(error, EndpointOptionsError::RelayMeshMember { addr: bad });
    }
    let error = bind(
        Endpoint::builder()
            .relay_server()
            .relay_mesh(RelayMeshConfig {
                listen: vec!["/ip4/127.0.0.1/udp/0/quic-v1/webtransport".parse().unwrap()],
                ..mesh(&backbone, Vec::new())
            }),
    );
    assert!(matches!(
        error,
        EndpointOptionsError::UnsupportedListenShape { .. }
    ));
}

#[cfg(all(feature = "relay-server", feature = "tcp"))]
#[test]
fn relay_server_builder_is_order_independent_and_announce_does_not_enable() {
    let announce = vec!["/ip4/127.0.0.1/tcp/4001".parse().unwrap()];
    let endpoint = Endpoint::builder()
        .relay_server_announce_addrs(announce.clone())
        .expect("valid announce address")
        .relay_server()
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
        .expect("enabled relay server binds");
    assert!(endpoint.engine.relay_server.is_some());

    let result = Endpoint::builder()
        .relay_server_announce_addrs(announce)
        .expect("valid announce address")
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind();
    let error = match result {
        Ok(_) => panic!("announce addresses alone must not enable the service"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("relay server is not enabled"));
}

#[cfg(feature = "relay-server")]
#[test]
fn relay_server_builder_rejects_structurally_invalid_addresses_immediately() {
    let wildcard = "/ip4/0.0.0.0/tcp/4001".parse().unwrap();
    let error = match Endpoint::builder().relay_server_announce_addrs(vec![wildcard]) {
        Ok(_) => panic!("wildcards are not announceable"),
        Err(RelayServerAnnounceError::Address(error)) => error,
        Err(RelayServerAnnounceError::Config(error)) => {
            panic!("default validator configuration is valid: {error}")
        }
    };
    assert_eq!(error.index, 0);
    assert_eq!(error.reason, RelayServerAddressErrorKind::Wildcard);
}

#[cfg(feature = "relay-server")]
#[test]
fn relay_server_builder_checks_announce_peer_against_fixed_identity_immediately() {
    let identity = Ed25519Keypair::from_secret_key_bytes([91; 32]);
    let other = Ed25519Keypair::from_secret_key_bytes([92; 32]).peer_id();
    let address = format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{other}")
        .parse()
        .unwrap();
    let error = match Endpoint::builder()
        .identity(identity.clone())
        .relay_server_announce_addrs(vec![address])
    {
        Ok(_) => panic!("conflicting peer id must fail immediately"),
        Err(RelayServerAnnounceError::Address(error)) => error,
        Err(RelayServerAnnounceError::Config(error)) => {
            panic!("default validator configuration is valid: {error}")
        }
    };
    assert!(matches!(
        error.reason,
        RelayServerAddressErrorKind::ConflictingPeerId { expected, found }
            if expected == identity.peer_id() && found == other
    ));
}

#[cfg(feature = "relay-server")]
#[test]
fn relay_server_runtime_controls_are_typed_and_address_replacement_is_atomic() {
    let mut absent = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind endpoint");
    assert!(matches!(
        absent.set_relay_server_accepting(false),
        Err(RelayServerControlError::NotConfigured)
    ));

    let original: Multiaddr = "/ip4/127.0.0.1/udp/4001/quic-v1".parse().unwrap();
    let mut endpoint = Endpoint::builder()
        .relay_server()
        .relay_server_announce_addrs(vec![original.clone()])
        .expect("valid initial address")
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind relay server");
    let invalid = "/ip4/0.0.0.0/udp/4002/quic-v1".parse().unwrap();
    let error = endpoint
        .set_relay_server_announce_addrs(vec![invalid])
        .expect_err("invalid replacement");
    assert!(matches!(
        error,
        RelayServerControlError::InvalidAddress(RelayServerAddressError {
            index: 0,
            reason: RelayServerAddressErrorKind::Wildcard,
            ..
        })
    ));
    assert_eq!(
        endpoint
            .engine
            .relay_server
            .as_ref()
            .unwrap()
            .agent
            .selected_addrs(),
        core::slice::from_ref(&original)
    );
    endpoint
        .set_relay_server_announce_addrs(Vec::new())
        .expect("empty replacement clears override");
    let selected = endpoint
        .engine
        .relay_server
        .as_ref()
        .unwrap()
        .agent
        .selected_addrs();
    assert!(!selected.is_empty());
    assert_ne!(selected, [original]);
}

#[cfg(feature = "relay-server")]
#[test]
fn wildcard_listener_binds_without_becoming_a_relay_announce_address() {
    let endpoint = Endpoint::builder()
        .relay_server()
        .listen_on("/ip4/0.0.0.0/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("wildcard listener may host once a usable address source appears");
    assert!(
        endpoint
            .engine
            .relay_server
            .as_ref()
            .unwrap()
            .agent
            .selected_addrs()
            .is_empty()
    );
}

#[cfg(all(feature = "relay-server", feature = "quic"))]
#[test]
fn relay_server_webtransport_announces_follow_the_certificate_mode() {
    let hash_free: Multiaddr = "/dns/relay.example/udp/4001/quic-v1/webtransport"
        .parse()
        .unwrap();
    let hashed: Multiaddr =
        format!("{hash_free}/certhash/uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g")
            .parse()
            .unwrap();
    // Announce addresses are set before the certificate: the mode is
    // checked at bind, once every option is in.
    let relay = |announce: &Multiaddr, ca: bool| {
        let builder = Endpoint::builder()
            .relay_server()
            .relay_server_announce_addrs(vec![announce.clone()])
            .expect("well-shaped announce address")
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1/webtransport")
            .expect("WebTransport");
        if ca {
            builder
                .webtransport_certificate_pem(CA_LEAF, CA_KEY)
                .expect("fixture PEM")
        } else {
            builder
        }
        .bind()
    };
    let reason = |result: Result<Endpoint, BindError>| match result {
        Err(BindError::RelayServerAnnounce(error)) => error.reason,
        Err(error) => panic!("unexpected bind error: {error}"),
        Ok(_) => panic!("the announce address must be refused"),
    };
    assert_eq!(
        reason(relay(&hash_free, false)),
        RelayServerAddressErrorKind::MissingCerthash
    );
    assert_eq!(
        reason(relay(&hashed, true)),
        RelayServerAddressErrorKind::UnexpectedCerthash
    );

    // At runtime too, and a refused replacement keeps the override.
    let mut ca = relay(&hash_free, true).expect("CA mode announces hash-free");
    let error = ca
        .set_relay_server_announce_addrs(vec![hashed.clone()])
        .expect_err("CA mode refuses a certhash");
    assert!(matches!(
        error,
        RelayServerControlError::InvalidAddress(RelayServerAddressError {
            index: 0,
            reason: RelayServerAddressErrorKind::UnexpectedCerthash,
            ..
        })
    ));
    let selected = ca
        .engine
        .relay_server
        .as_ref()
        .unwrap()
        .agent
        .selected_addrs();
    assert_eq!(selected, core::slice::from_ref(&hash_free));

    let mut derived = relay(&hashed, false).expect("derived mode announces a certhash");
    let error = derived
        .set_relay_server_announce_addrs(vec![hash_free])
        .expect_err("derived mode needs a certhash");
    assert!(matches!(
        error,
        RelayServerControlError::InvalidAddress(RelayServerAddressError {
            reason: RelayServerAddressErrorKind::MissingCerthash,
            ..
        })
    ));
}

#[cfg(feature = "relay-server")]
#[test]
fn wait_delivers_relay_server_events() {
    let mut endpoint = Endpoint::builder()
        .relay_server()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind relay server");
    endpoint
        .engine
        .relay_server
        .as_mut()
        .unwrap()
        .events
        .push_back(RelayServerEvent::Error(RelayServerRuntimeError {
            kind: RelayServerRuntimeErrorKind::InternalInvariant,
            peer_id: None,
            detail: "test diagnostic".into(),
        }));
    assert!(matches!(
        endpoint.wait(Duration::ZERO).expect("queue wait"),
        EndpointWaitOutcome::Event(EndpointEvent::RelayServer(RelayServerEvent::Error(_)))
    ));
    assert!(matches!(
        endpoint.wait(Duration::ZERO).expect("drained wait"),
        EndpointWaitOutcome::Deadline
    ));
}

#[cfg(all(feature = "relay", feature = "relay-server"))]
#[test]
fn nat_and_relay_address_contributions_form_a_stable_first_wins_union() {
    let mut endpoint = Endpoint::builder()
        .nat_config(super::nat_tests::idle_nat_config())
        .relay_server()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind combined endpoint");
    let nat_only: Multiaddr = "/ip4/203.0.113.1/udp/4001/quic-v1".parse().unwrap();
    let duplicate: Multiaddr = "/ip4/203.0.113.2/udp/4002/quic-v1".parse().unwrap();
    let relay_only: Multiaddr = "/ip4/203.0.113.3/udp/4003/quic-v1".parse().unwrap();
    endpoint
        .engine
        .nat
        .as_mut()
        .unwrap()
        .set_test_public_addrs(vec![nat_only.clone(), duplicate.clone()]);
    endpoint
        .engine
        .relay_server
        .as_mut()
        .unwrap()
        .agent
        .replace_announce_addrs(vec![duplicate.clone(), relay_only.clone()])
        .unwrap();
    // One batch merges the contributions; the next advertises them.
    endpoint.poll().expect("merge address contributions");
    endpoint.poll().expect("refresh identify snapshot");
    let advertised = endpoint.core().local_addresses();
    let nat_index = advertised
        .iter()
        .position(|addr| addr == &nat_only)
        .unwrap();
    let duplicate_indices: Vec<_> = advertised
        .iter()
        .enumerate()
        .filter_map(|(index, addr)| (addr == &duplicate).then_some(index))
        .collect();
    let relay_index = advertised
        .iter()
        .position(|addr| addr == &relay_only)
        .unwrap();
    assert_eq!(duplicate_indices.len(), 1);
    assert!(nat_index < duplicate_indices[0] && duplicate_indices[0] < relay_index);
}

#[cfg(feature = "relay-server")]
#[test]
fn relay_refresh_preserves_caller_owned_swarm_external_addresses() {
    let mut endpoint = Endpoint::builder()
        .relay_server()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind relay endpoint");
    let caller_owned: Multiaddr = "/ip4/203.0.113.8/udp/4008/quic-v1".parse().unwrap();
    let relay_owned: Multiaddr = "/ip4/203.0.113.9/udp/4009/quic-v1".parse().unwrap();
    endpoint.set_external_addresses(vec![caller_owned.clone()]);
    endpoint
        .set_relay_server_announce_addrs(vec![relay_owned.clone()])
        .expect("replace relay addresses");
    endpoint.raw_poll().expect("refresh identify snapshot");

    let advertised = endpoint.core().local_addresses();
    assert!(advertised.contains(&caller_owned));
    assert!(advertised.contains(&relay_owned));
}

#[cfg(feature = "relay-server")]
#[test]
fn caller_keeps_an_address_after_the_matching_driver_contribution_clears() {
    let mut endpoint = Endpoint::builder()
        .relay_server()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind relay endpoint");
    let shared: Multiaddr = "/ip4/203.0.113.10/udp/4010/quic-v1".parse().unwrap();
    endpoint
        .set_relay_server_announce_addrs(vec![shared.clone()])
        .expect("set relay contribution");
    endpoint.set_external_addresses(vec![shared.clone()]);

    endpoint
        .set_relay_server_announce_addrs(Vec::new())
        .expect("clear relay contribution");
    endpoint.raw_poll().expect("refresh identify snapshot");

    assert!(endpoint.core().local_addresses().contains(&shared));
}

#[test]
fn abandoning_a_closed_stream_acks_data_left_in_the_endpoint_queue() {
    const PROTOCOL: &str = "/test/abandon-split/1";
    let bind = || {
        Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .protocol(PROTOCOL)
            .bind()
            .expect("bind endpoint")
    };
    let (mut writer, mut reader) = (bind(), bind());
    let (writer_peer, reader_peer) = (*writer.peer_id(), *reader.peer_id());
    let give_up = std::time::Instant::now() + Duration::from_secs(10);
    let tick = Duration::from_millis(5);
    writer
        .connect(reader.listen().expect("listen"))
        .expect("connect");
    while !writer.is_peer_ready(&reader_peer) || !reader.is_peer_ready(&writer_peer) {
        assert!(std::time::Instant::now() < give_up, "never ready");
        writer.next_event(tick).expect("drive writer");
        reader.next_event(tick).expect("drive reader");
    }
    let (_, out_stream) = writer.open_stream(&reader_peer, PROTOCOL).expect("open");
    let (conn, stream) = loop {
        assert!(std::time::Instant::now() < give_up, "never negotiated");
        writer.next_event(tick).expect("drive writer");
        if let Some(EndpointEvent::StreamReady {
            conn_id, stream_id, ..
        }) = reader.next_event(tick).expect("drive reader")
        {
            break (conn_id, stream_id);
        }
    };
    // The reader closes first, so the writer's FIN closes the stream.
    reader
        .close_stream_write(conn, stream)
        .expect("reader close");
    loop {
        assert!(std::time::Instant::now() < give_up, "reader FIN lost");
        reader.next_event(tick).expect("drive reader");
        if let Some(EndpointEvent::StreamRemoteWriteClosed { stream_id, .. }) =
            writer.next_event(tick).expect("drive writer")
            && stream_id == out_stream
        {
            break;
        }
    }
    let conn_out = writer.core().connection_id(&reader_peer).expect("conn");
    writer
        .send_stream(conn_out, out_stream, vec![1, 2, 3])
        .expect("send");
    writer
        .close_stream_write(conn_out, out_stream)
        .expect("writer close");
    writer.next_event(tick).expect("flush writer");

    // Stage what a `wait` cut short leaves behind: the batch's data and
    // its close still in the Endpoint queue, the close already gone from
    // the swarm. Data and FIN may arrive separately, so pull until the
    // close.
    loop {
        assert!(std::time::Instant::now() < give_up, "stream never closed");
        writer.next_event(tick).expect("drive writer");
        match reader.raw_poll_next(tick).expect("poll reader") {
            Some(event @ SwarmEvent::StreamData { stream_id, .. }) if stream_id == stream => {
                reader.engine.events.push_back(event.into());
            }
            Some(event @ SwarmEvent::StreamClosed { stream_id, .. }) if stream_id == stream => {
                reader.engine.events.push_back(event.into());
                break;
            }
            _ => {}
        }
    }

    reader.abandon_stream(conn, stream).expect("abandon");
    // Its three bytes were acknowledged, so the stream settled and an
    // over-acknowledgement is a no-op rather than `AckExceedsDelivered`.
    reader
        .stream_consumed(conn, stream, 4)
        .expect("stream settled");
}

#[test]
fn default_agent_version_matches_package_version() {
    assert_eq!(
        DEFAULT_AGENT_VERSION,
        format!("minip2p/{}", env!("CARGO_PKG_VERSION"))
    );
}
