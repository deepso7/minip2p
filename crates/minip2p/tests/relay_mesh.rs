//! Relay-mesh Endpoints over real loopback transports: relay nodes that
//! share one public identity, linked over their backbone by signed
//! membership (ADR 0028), with clients reserved on them and circuits
//! forwarded between them.
//!
//! Relays are driven on their own threads with long waits, woken only by
//! readiness and the timers the Endpoint schedules, so a backbone timer
//! left out of the wait budget stalls these tests rather than passing them.

#![cfg(all(feature = "relay-server", feature = "relay", feature = "quic"))]
#![expect(
    clippy::unwrap_used,
    reason = "the mesh harness uses fixed local operations that must succeed"
)]

use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use minip2p::{
    CloseOutcome, ConnectId, ConnectOutcome, Ed25519Keypair, Endpoint, EndpointEvent,
    EndpointWaitOutcome, MeshRejectionReason, NatConfig, NatEvent, Path, PeerAddr, PeerId,
    RelayMeshConfig, RelayServerEvent, ReservationPolicy, WaitHandle,
};

#[path = "../../../tests/support/endpoint.rs"]
mod endpoint_support;
use endpoint_support::NextEvent;

const ECHO_PROTOCOL: &str = "/minip2p/tests/relay-mesh-echo/1.0.0";

/// A relay Endpoint driven on its own thread until dropped, handing its
/// events to the test.
struct Relay {
    public: PeerAddr,
    backbone: PeerAddr,
    events: mpsc::Receiver<EndpointEvent>,
    stop: Arc<AtomicBool>,
    interrupt: WaitHandle,
    thread: Option<thread::JoinHandle<()>>,
}

impl Relay {
    fn spawn(mut endpoint: Endpoint) -> Self {
        let public = PeerAddr::new(
            endpoint.bound_addresses().pop().unwrap(),
            *endpoint.peer_id(),
        )
        .unwrap();
        let backbone = endpoint.relay_mesh_addresses().pop().unwrap();
        let (events_tx, events) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let interrupt = endpoint.wait_handle();
        let flag = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                if let EndpointWaitOutcome::Event(event) =
                    endpoint.wait(Duration::from_secs(60)).unwrap()
                {
                    drop(events_tx.send(event));
                }
            }
        });
        Self {
            public,
            backbone,
            events,
            stop,
            interrupt,
            thread: Some(thread),
        }
    }

    /// Waits up to `within` for an event `wanted` accepts.
    #[expect(
        clippy::panic,
        reason = "A timed-out test must include the relay's event trace."
    )]
    fn expect(
        &self,
        what: &str,
        within: Duration,
        mut wanted: impl FnMut(&EndpointEvent) -> bool,
    ) -> EndpointEvent {
        let deadline = Instant::now() + within;
        let mut seen = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.events.recv_timeout(left) {
                Ok(event) if wanted(&event) => return event,
                Ok(event) => seen.push(event),
                Err(_) => panic!("{what} did not arrive; saw {seen:#?}"),
            }
        }
    }

    fn expect_member_up(&self, member: &PeerId) {
        self.expect("member up", Duration::from_secs(20), |event| {
            matches!(event, EndpointEvent::RelayServer(RelayServerEvent::MeshMemberUp { member: up }) if up == member)
        });
    }

    fn expect_member_down(&self, member: &PeerId) {
        self.expect("member down", Duration::from_secs(20), |event| {
            matches!(event, EndpointEvent::RelayServer(RelayServerEvent::MeshMemberDown { member: down }) if down == member)
        });
    }

    /// Stops the driver and drops the relay, closing its backbone.
    fn stop(mut self) {
        self.halt();
    }

    fn halt(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.interrupt.interrupt();
        if let Some(thread) = self.thread.take() {
            drop(thread.join());
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.halt();
    }
}

/// A port no socket holds right now, for a node whose backbone address
/// another node must know before it binds.
fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn backbone_addr(port: u16, identity: &Ed25519Keypair) -> PeerAddr {
    PeerAddr::new(
        format!("/ip4/127.0.0.1/udp/{port}/quic-v1")
            .parse()
            .unwrap(),
        identity.peer_id(),
    )
    .unwrap()
}

/// Binds a relay under the mesh's shared `public` identity, with its
/// backbone on `port` (0 for any).
fn bind_relay(
    public: &Ed25519Keypair,
    backbone: &Ed25519Keypair,
    port: u16,
    members: Vec<PeerAddr>,
) -> Endpoint {
    Endpoint::builder()
        .identity(public.clone())
        .relay_server()
        .relay_mesh(RelayMeshConfig {
            identity: backbone.clone(),
            listen: vec![
                format!("/ip4/127.0.0.1/udp/{port}/quic-v1")
                    .parse()
                    .unwrap(),
            ],
            members,
        })
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .unwrap()
        .bind()
        .unwrap()
}

/// Two meshed relays, their backbone link up on both ends. A lists
/// nobody; B, added later, lists A.
fn meshed_pair() -> (Relay, Relay) {
    let public = Ed25519Keypair::generate();
    let (key_a, key_b) = (Ed25519Keypair::generate(), Ed25519Keypair::generate());
    let a = Relay::spawn(bind_relay(&public, &key_a, 0, Vec::new()));
    let b = Relay::spawn(bind_relay(&public, &key_b, 0, vec![a.backbone.clone()]));
    a.expect_member_up(b.backbone.peer_id());
    b.expect_member_up(a.backbone.peer_id());
    (a, b)
}

/// A client using `relay`, listening on loopback.
fn client(relay: &PeerAddr, config: NatConfig) -> Endpoint {
    let mut endpoint = Endpoint::builder()
        .protocol(ECHO_PROTOCOL)
        .relay(relay.clone())
        .nat_config(config)
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .unwrap()
        .bind()
        .unwrap();
    endpoint.listen().unwrap();
    endpoint
}

/// Connects `dialer` to `target` and drives both until the connect
/// settles, which must be over a relayed path; returns the connection.
#[expect(
    clippy::panic,
    reason = "A failed connect must include the relays' event traces."
)]
fn relayed(
    dialer: &mut Endpoint,
    target: &mut Endpoint,
    relays: &[&Relay],
) -> minip2p::ConnectionId {
    let target_peer = *target.peer_id();
    let connect_id: ConnectId = dialer.connect(target_peer).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut trace = Vec::new();
    loop {
        assert!(Instant::now() < deadline, "no relayed path: {trace:#?}");
        if let Some(event) = dialer.next_event(Duration::from_millis(20)).unwrap() {
            trace.push(format!("dialer: {event:?}"));
            if let EndpointEvent::ConnectSettled {
                connect_id: id,
                outcome,
                ..
            } = event
                && id == connect_id
            {
                match outcome {
                    ConnectOutcome::Connected {
                        conn_id,
                        path: Path::Relayed { .. },
                    } => return conn_id,
                    other => panic!(
                        "expected a relayed connection, got {other:?}\nrelays: {:#?}",
                        relays
                            .iter()
                            .map(|relay| relay.events.try_iter().collect::<Vec<_>>())
                            .collect::<Vec<_>>()
                    ),
                }
            }
        }
        if let Some(event) = target.next_event(Duration::from_millis(20)).unwrap() {
            trace.push(format!("target: {event:?}"));
        }
    }
}

/// Drives `client` until it holds a reservation on the mesh.
fn await_reservation(client: &mut Endpoint, relay: &PeerAddr) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        assert!(Instant::now() < deadline, "no reservation on {relay}");
        if let Some(EndpointEvent::Nat(NatEvent::RelayReserved {
            relay: reserved, ..
        })) = client.next_event(Duration::from_millis(20)).unwrap()
            && &reserved == relay.peer_id()
        {
            return;
        }
    }
}

#[test]
fn a_circuit_forwarded_across_the_mesh_carries_data_both_ways() {
    let (a, b) = meshed_pair();
    let no_punch = |reservation_policy| NatConfig {
        force_relay: true,
        dcutr: false,
        reservation_policy,
        ..NatConfig::default()
    };
    let mut alice = client(&a.public, no_punch(ReservationPolicy::Always));
    await_reservation(&mut alice, &a.public);
    let mut bob = client(&b.public, no_punch(ReservationPolicy::Never));
    let alice_peer = *alice.peer_id();
    let bob_peer = *bob.peer_id();
    let conn = relayed(&mut bob, &mut alice, &[&a, &b]);

    let stream = bob.open_stream(&alice_peer, ECHO_PROTOCOL).unwrap();
    assert_eq!(stream.conn_id(), conn);
    let (hello, reply) = (
        b"hello from bob".to_vec(),
        b"hello back from alice".to_vec(),
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    let (mut at_alice, mut received) = (Vec::new(), Vec::new());
    while received.len() < reply.len() {
        assert!(Instant::now() < deadline, "payload did not cross the mesh");
        if let Some(event) = bob.next_event(Duration::from_millis(20)).unwrap() {
            match event {
                EndpointEvent::StreamReady {
                    stream: ready,
                    initiated_locally: true,
                    ..
                } if ready == stream => bob.send_stream(stream, hello.clone()).unwrap(),
                EndpointEvent::StreamData {
                    stream: from, data, ..
                } if from == stream => received.extend_from_slice(&data),
                _ => {}
            }
        }
        if let Some(EndpointEvent::StreamData {
            peer_id,
            stream,
            data,
        }) = alice.next_event(Duration::from_millis(20)).unwrap()
            && peer_id == bob_peer
        {
            at_alice.extend_from_slice(&data);
            assert!(at_alice.len() <= hello.len(), "Bob sent only hello");
            if at_alice.len() == hello.len() {
                assert_eq!(at_alice, hello);
                alice.send_stream(stream, reply.clone()).unwrap();
            }
        }
    }
    assert_eq!(received, reply);

    for (node, other) in [(&b, &a), (&a, &b)] {
        node.expect("forwarded circuit", Duration::from_secs(5), |event| {
            matches!(
                event,
                EndpointEvent::RelayServer(RelayServerEvent::CircuitOpened {
                    source_peer_id,
                    destination_peer_id,
                    via: Some(via),
                }) if source_peer_id == &bob_peer
                    && destination_peer_id == &alice_peer
                    && **via == *other.backbone.peer_id()
            )
        });
    }
}

#[test]
fn each_node_reports_the_others_directory_size_once_synced() {
    let (a, b) = meshed_pair();
    for (node, other) in [(&a, &b), (&b, &a)] {
        node.expect("member synced", Duration::from_secs(10), |event| {
            matches!(
                event,
                EndpointEvent::RelayServer(RelayServerEvent::MeshMemberSynced { member, entries: 0 })
                    if member == other.backbone.peer_id()
            )
        });
    }
}

#[test]
fn dcutr_punches_a_direct_path_over_a_forwarded_circuit() {
    let (a, b) = meshed_pair();
    let punch = |reservation_policy| NatConfig {
        reservation_policy,
        allow_private_punch_targets: true,
        ..NatConfig::default()
    };
    let mut alice = client(&a.public, punch(ReservationPolicy::Always));
    await_reservation(&mut alice, &a.public);
    let mut bob = client(&b.public, punch(ReservationPolicy::Never));
    let alice_peer = *alice.peer_id();
    let connect_id = bob.connect(alice_peer).unwrap();

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut trace = Vec::new();
    let outcome = loop {
        assert!(Instant::now() < deadline, "no settle: {trace:#?}");
        if let Some(event) = bob.next_event(Duration::from_millis(20)).unwrap() {
            trace.push(format!("bob: {event:?}"));
            if let EndpointEvent::ConnectSettled {
                connect_id: id,
                outcome,
                ..
            } = event
                && id == connect_id
            {
                break outcome;
            }
        }
        if let Some(event) = alice.next_event(Duration::from_millis(20)).unwrap() {
            trace.push(format!("alice: {event:?}"));
        }
    };
    assert!(
        matches!(
            outcome,
            ConnectOutcome::Connected {
                path: Path::Punched,
                ..
            }
        ),
        "expected a punched connection, got {outcome:?}: {trace:#?}"
    );
    assert_eq!(bob.path(&alice_peer), Some(Path::Punched));
    b.expect("forwarded circuit", Duration::from_secs(5), |event| {
        matches!(
            event,
            EndpointEvent::RelayServer(RelayServerEvent::CircuitOpened { via: Some(via), .. })
                if **via == *a.backbone.peer_id()
        )
    });
}

/// Node A dials B before B is up, so only A's own retransmissions and
/// redials can bring the link up: B lists nobody, so it never dials A, and
/// leaves the redial to A when the link drops. No client traffic runs, and
/// both relays sleep on long waits, so the link comes up only if A
/// schedules its backbone timers.
#[test]
fn an_idle_backbone_retransmits_and_redials_on_its_own_timers() {
    let public = Ed25519Keypair::generate();
    let (key_a, key_b) = (Ed25519Keypair::generate(), Ed25519Keypair::generate());
    let port_b = free_udp_port();
    let a = Relay::spawn(bind_relay(
        &public,
        &key_a,
        0,
        vec![backbone_addr(port_b, &key_b)],
    ));
    thread::sleep(Duration::from_millis(300));
    let bind_b = || Relay::spawn(bind_relay(&public, &key_b, port_b, Vec::new()));
    let b = bind_b();
    a.expect_member_up(&key_b.peer_id());

    b.stop();
    a.expect_member_down(&key_b.peer_id());
    let _b = bind_b();
    a.expect_member_up(&key_b.peer_id());
}

#[test]
fn a_node_under_another_public_identity_is_rejected() {
    let key_a = Ed25519Keypair::generate();
    let a = Relay::spawn(bind_relay(
        &Ed25519Keypair::generate(),
        &key_a,
        0,
        Vec::new(),
    ));
    let stranger = Ed25519Keypair::generate();
    let c = Relay::spawn(bind_relay(
        &Ed25519Keypair::generate(),
        &stranger,
        0,
        vec![a.backbone.clone()],
    ));

    let deadline = Instant::now() + Duration::from_secs(20);
    let rejected = |event: &EndpointEvent, other: &PeerId| {
        assert!(
            !matches!(
                event,
                EndpointEvent::RelayServer(RelayServerEvent::MeshMemberUp { .. })
            ),
            "a node under another identity came up as a member"
        );
        matches!(
            event,
            EndpointEvent::RelayServer(RelayServerEvent::MeshPeerRejected {
                peer_id,
                reason: MeshRejectionReason::InvalidProof,
            }) if peer_id == other
        )
    };
    loop {
        assert!(Instant::now() < deadline, "neither node rejected the other");
        let by_a = a
            .events
            .recv_timeout(Duration::from_millis(20))
            .is_ok_and(|event| rejected(&event, &stranger.peer_id()));
        let by_c = c
            .events
            .recv_timeout(Duration::from_millis(20))
            .is_ok_and(|event| rejected(&event, &key_a.peer_id()));
        if by_a || by_c {
            return;
        }
    }
}

/// A lists nobody, B lists A, C lists A and B: every pair links, syncs, and
/// forwards circuits, with no node listing every other.
#[test]
fn a_node_that_lists_the_existing_ones_joins_a_full_mesh() {
    let public = Ed25519Keypair::generate();
    let [key_a, key_b, key_c]: [Ed25519Keypair; 3] =
        std::array::from_fn(|_| Ed25519Keypair::generate());
    let a = Relay::spawn(bind_relay(&public, &key_a, 0, Vec::new()));
    let b = Relay::spawn(bind_relay(&public, &key_b, 0, vec![a.backbone.clone()]));
    let c = Relay::spawn(bind_relay(
        &public,
        &key_c,
        0,
        vec![a.backbone.clone(), b.backbone.clone()],
    ));
    let relays = [&a, &b, &c];
    for (i, relay) in relays.iter().enumerate() {
        let mut unsynced: Vec<&PeerId> = relays
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, other)| other.backbone.peer_id())
            .collect();
        relay.expect(
            &format!("node {i} synced with both others"),
            Duration::from_secs(20),
            |event| {
                if let EndpointEvent::RelayServer(RelayServerEvent::MeshMemberSynced {
                    member,
                    ..
                }) = event
                {
                    unsynced.retain(|peer| *peer != member);
                }
                unsynced.is_empty()
            },
        );
    }

    let nat = NatConfig {
        force_relay: true,
        dcutr: false,
        reservation_policy: ReservationPolicy::Always,
        ..NatConfig::default()
    };
    let mut clients = relays.map(|relay| {
        let mut client = client(&relay.public, nat.clone());
        await_reservation(&mut client, &relay.public);
        client
    });
    for (entry, holding) in [(1, 0), (2, 0), (2, 1)] {
        let [first, second, third] = &mut clients;
        let (dialer, target) = match (entry, holding) {
            (1, 0) => (second, first),
            (2, 0) => (third, first),
            _ => (third, second),
        };
        relayed(dialer, target, &relays);
        relays[entry].expect("forwarded circuit", Duration::from_secs(5), |event| {
            matches!(
                event,
                EndpointEvent::RelayServer(RelayServerEvent::CircuitOpened { via: Some(via), .. })
                    if **via == *relays[holding].backbone.peer_id()
            )
        });
    }
}

#[test]
fn close_waits_for_a_pending_member_dial() {
    let member = backbone_addr(free_udp_port(), &Ed25519Keypair::generate());
    let mut relay = bind_relay(
        &Ed25519Keypair::generate(),
        &Ed25519Keypair::generate(),
        0,
        vec![member],
    );
    drop(relay.poll());

    let report = relay.close_within(Duration::from_millis(200));
    assert_eq!(report.outcome, CloseOutcome::DeadlineExpired, "{report:?}");
    assert_eq!(report.unfinished.len(), 1, "{report:?}");
}
