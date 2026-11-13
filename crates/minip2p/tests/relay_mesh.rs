//! Relay-mesh Endpoints over real loopback transports: two relay nodes that
//! share one public identity, a client reserved on each, and circuits
//! forwarded across their backbone.
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
    ConnectOutcome, Ed25519Keypair, Endpoint, EndpointEvent, EndpointWaitOutcome, NatConfig,
    NatEvent, Path, PeerAddr, PeerId, RelayMeshConfig, RelayServerEvent,
    RelayServerRuntimeErrorKind, ReservationPolicy, WaitHandle,
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
            endpoint.peer_id().clone(),
        )
        .unwrap();
        let backbone = endpoint.relay_mesh_addresses().pop().unwrap();
        let (events_tx, events) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let interrupt = endpoint.wait_handle();
        let flag = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                // Long waits: only readiness, a scheduled timer or the
                // stop interrupt end them.
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
            matches!(event, EndpointEvent::RelayMeshMemberUp { peer_id } if peer_id == member)
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

/// Two meshed relays, their backbone link up on both ends. Both take the
/// same member list, each skipping its own entry.
fn meshed_pair() -> (Relay, Relay) {
    let public = Ed25519Keypair::generate();
    let (key_a, key_b) = (Ed25519Keypair::generate(), Ed25519Keypair::generate());
    let port_b = free_udp_port();
    let b_addr = backbone_addr(port_b, &key_b);
    let a = Relay::spawn(bind_relay(&public, &key_a, 0, vec![b_addr.clone()]));
    let members = vec![a.backbone.clone(), b_addr];
    let b = Relay::spawn(bind_relay(&public, &key_b, port_b, members));
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
    // Alice reserves on node A; Bob reaches the mesh through node B.
    let mut alice = client(&a.public, no_punch(ReservationPolicy::Always));
    await_reservation(&mut alice, &a.public);
    let mut bob = client(&b.public, no_punch(ReservationPolicy::Never));
    let alice_peer = alice.peer_id().clone();
    let bob_peer = bob.peer_id().clone();
    let connect_id = bob.connect(&alice_peer).unwrap();

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut trace = Vec::new();
    let conn = loop {
        assert!(Instant::now() < deadline, "no relayed path: {trace:#?}");
        if let Some(event) = bob.next_event(Duration::from_millis(20)).unwrap() {
            trace.push(format!("bob: {event:?}"));
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
                    } => break conn_id,
                    other => panic!(
                        "expected a relayed connection, got {other:?}\nA: {:#?}\nB: {:#?}",
                        a.events.try_iter().collect::<Vec<_>>(),
                        b.events.try_iter().collect::<Vec<_>>()
                    ),
                }
            }
        }
        if let Some(event) = alice.next_event(Duration::from_millis(20)).unwrap() {
            trace.push(format!("alice: {event:?}"));
        }
    };

    // Bob speaks first; Alice answers with bytes of her own on the stream.
    let (bob_conn, stream) = bob.open_stream(&alice_peer, ECHO_PROTOCOL).unwrap();
    assert_eq!(bob_conn, conn);
    let (hello, reply) = (
        b"hello from bob".to_vec(),
        b"hello back from alice".to_vec(),
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut answered = false;
    let mut received = None;
    while received.is_none() {
        assert!(Instant::now() < deadline, "payload did not cross the mesh");
        if let Some(event) = bob.next_event(Duration::from_millis(20)).unwrap() {
            match event {
                EndpointEvent::StreamReady {
                    stream_id,
                    initiated_locally: true,
                    ..
                } if stream_id == stream => bob.send_stream(conn, stream, hello.clone()).unwrap(),
                EndpointEvent::StreamData {
                    stream_id, data, ..
                } if stream_id == stream => received = Some(data),
                _ => {}
            }
        }
        if let Some(EndpointEvent::StreamData {
            peer_id,
            conn_id,
            stream_id,
            data,
        }) = alice.next_event(Duration::from_millis(20)).unwrap()
            && peer_id == bob_peer
        {
            assert_eq!(&data[..], &hello[..]);
            assert!(!answered);
            alice
                .send_stream(conn_id, stream_id, reply.clone())
                .unwrap();
            answered = true;
        }
    }
    assert_eq!(received.as_deref(), Some(reply.as_slice()));

    // Both nodes report the circuit as crossing the backbone.
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
                    && via == other.backbone.peer_id()
            )
        });
    }
}

#[test]
fn dcutr_punches_a_direct_path_over_a_forwarded_circuit() {
    let (a, b) = meshed_pair();
    // Loopback is not global unicast: both sides must opt in to punch it.
    let punch = |reservation_policy| NatConfig {
        reservation_policy,
        allow_private_punch_targets: true,
        ..NatConfig::default()
    };
    let mut alice = client(&a.public, punch(ReservationPolicy::Always));
    await_reservation(&mut alice, &a.public);
    let mut bob = client(&b.public, punch(ReservationPolicy::Never));
    let alice_peer = alice.peer_id().clone();
    // No candidates: the forwarded circuit is the only way in, so a direct
    // connection can only come from the punch.
    let connect_id = bob.connect(&alice_peer).unwrap();

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
                if via == a.backbone.peer_id()
        )
    });
}

/// Node A dials B before B is up, so only A's own retransmissions and
/// redials can bring the link up: B never dials A (its entry for A names a
/// closed port). No client traffic runs, and both relays sleep on long
/// waits, so the link comes up only if A schedules its backbone timers.
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
    // A's first dial is already out when B binds: its handshake reaches B
    // on a retransmission.
    thread::sleep(Duration::from_millis(300));
    let unreachable_a = backbone_addr(free_udp_port(), &key_a);
    let bind_b = || {
        Relay::spawn(bind_relay(
            &public,
            &key_b,
            port_b,
            vec![unreachable_a.clone()],
        ))
    };
    let b = bind_b();
    a.expect_member_up(&key_b.peer_id());

    // B goes away and comes back on the same address: A sees the link
    // drop and redials it after its backoff.
    b.stop();
    a.expect("member down", Duration::from_secs(20), |event| {
        matches!(event, EndpointEvent::RelayMeshMemberDown { peer_id } if *peer_id == key_b.peer_id())
    });
    let _b = bind_b();
    a.expect_member_up(&key_b.peer_id());
}

#[test]
fn a_backbone_connection_from_a_non_member_is_closed() {
    let public = Ed25519Keypair::generate();
    let (key_a, stranger) = (Ed25519Keypair::generate(), Ed25519Keypair::generate());
    // A's only member is a node that never runs.
    let absent = backbone_addr(free_udp_port(), &Ed25519Keypair::generate());
    let a = Relay::spawn(bind_relay(&public, &key_a, 0, vec![absent]));
    // The stranger lists A, but A does not list it.
    let c = Relay::spawn(bind_relay(&public, &stranger, 0, vec![a.backbone.clone()]));

    a.expect("non-member refused", Duration::from_secs(20), |event| {
        matches!(
            event,
            EndpointEvent::RelayServer(RelayServerEvent::Error(error))
                if error.kind == RelayServerRuntimeErrorKind::Mesh
                    && error.peer_id == Some(stranger.peer_id())
        )
    });
    c.expect("closed by A", Duration::from_secs(20), |event| {
        matches!(event, EndpointEvent::RelayMeshMemberDown { peer_id } if peer_id == a.backbone.peer_id())
    });
    // A never counted the stranger as a member.
    assert!(
        !a.events
            .try_iter()
            .any(|event| matches!(event, EndpointEvent::RelayMeshMemberUp { .. })),
        "a non-member came up as a member"
    );
}
