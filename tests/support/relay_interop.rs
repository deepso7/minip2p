#![allow(
    dead_code,
    reason = "the shared relay interop harness exposes helpers selected by different test binaries"
)]

//! Minip2p relays driven against a foreign relay client process, shared by
//! the rust-libp2p and go-libp2p relay interop gates.
//!
//! The foreign client takes `<relay-addr> <duration-secs> <byte-limit>
//! [source-relay-addr]`: its destination reserves on the first address, its
//! source dials through the second, and both ping across the circuit. It
//! checks the relay's [`Limits`] on every leg and exits non-zero on failure.

use std::process::{Child, Command};
use std::time::{Duration, Instant};

use minip2p::{Endpoint, EndpointEvent, PeerId, RelayServerConfig, RelayServerEvent};

use super::endpoint_support::NextEvent;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        match self.0.kill() {
            Ok(()) | Err(_) => {}
        }
        match self.0.wait() {
            Ok(_) | Err(_) => {}
        }
    }
}

/// Non-default circuit limits the client checks it decodes on every leg.
#[derive(Clone, Copy)]
pub struct Limits {
    pub duration_secs: u64,
    pub bytes: u64,
}

impl Limits {
    pub fn config(self) -> RelayServerConfig {
        RelayServerConfig {
            max_circuit_duration_secs: self.duration_secs,
            max_circuit_bytes: self.bytes,
            ..RelayServerConfig::default()
        }
    }

    /// The client's `<duration-secs> <byte-limit>` arguments.
    pub fn args(self) -> [String; 2] {
        [self.duration_secs.to_string(), self.bytes.to_string()]
    }
}

/// What the relays saw while the client ran.
#[derive(Default)]
pub struct Observed {
    pub reserved: bool,
    /// `via` of every `CircuitOpened`, across all relays.
    pub opened: Vec<Option<PeerId>>,
    pub bidirectional: bool,
}

/// Runs the foreign client, driving every relay until it exits, then a
/// little longer for circuit closure and accounting.
#[expect(
    clippy::panic,
    reason = "a relay error fails the gate with the error itself"
)]
pub fn run_client(relays: &mut [Endpoint], mut client: Command) -> Observed {
    let mut child = ChildGuard(client.spawn().expect("spawn the foreign relay client"));
    let mut observed = Observed::default();
    let mut observe = |event| match event {
        RelayServerEvent::ReservationAccepted { .. } => observed.reserved = true,
        RelayServerEvent::CircuitOpened { via, .. } => observed.opened.push(via.map(|via| *via)),
        RelayServerEvent::CircuitClosed { bytes, .. } => {
            observed.bidirectional |=
                bytes.source_to_destination > 0 && bytes.destination_to_source > 0;
        }
        RelayServerEvent::Error(error)
            if matches!(
                error.kind,
                minip2p::RelayServerRuntimeErrorKind::ResetStream
            ) =>
        {
            eprintln!("expected foreign-exit reset race: {error:?}");
        }
        RelayServerEvent::Error(error) => panic!("relay server error: {error:?}"),
        _ => {}
    };
    let mut drive = |relays: &mut [Endpoint]| {
        for relay in relays.iter_mut() {
            if let Some(EndpointEvent::RelayServer(event)) = relay
                .next_event(Duration::from_millis(20))
                .expect("drive the relay")
            {
                observe(event);
            }
        }
    };

    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        drive(relays);
        if let Some(status) = child.0.try_wait().expect("poll the client") {
            assert!(status.success(), "foreign relay client failed: {status}");
            break;
        }
        assert!(Instant::now() < deadline, "foreign relay client timed out");
    }
    // Drive closure/accounting after the foreign process exits.
    for _ in 0..50 {
        drive(relays);
    }
    observed
}

/// Two relay Endpoints meshed over a loopback QUIC backbone, sharing one
/// public identity and applying `limits`, with both links up, as in
/// production, where DNS only points at nodes whose members are up.
/// Returns the relays, their TCP listen addresses, and their backbone peer
/// ids.
#[cfg(feature = "quic")]
pub fn mesh(limits: Limits) -> ([Endpoint; 2], [String; 2], [PeerId; 2]) {
    use minip2p::{Ed25519Keypair, PeerAddr, RelayMeshConfig};

    let public = Ed25519Keypair::generate();
    // Each node's backbone key and a port no socket holds now, so each node
    // can list the other before either binds.
    let nodes = [(), ()].map(|()| {
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .and_then(|socket| socket.local_addr())
            .expect("pick a free loopback UDP port")
            .port();
        let listen: minip2p::Multiaddr = format!("/ip4/127.0.0.1/udp/{port}/quic-v1")
            .parse()
            .expect("backbone listen address");
        (Ed25519Keypair::generate(), listen)
    });
    let members: Vec<PeerAddr> = nodes
        .iter()
        .map(|(key, listen)| PeerAddr::new(listen.clone(), key.peer_id()).expect("member address"))
        .collect();
    let mut relays = nodes.each_ref().map(|(key, listen)| {
        Endpoint::builder()
            .identity(public.clone())
            .relay_server_config(limits.config())
            .relay_mesh(RelayMeshConfig {
                identity: key.clone(),
                listen: vec![listen.clone()],
                members: members.clone(),
            })
            .listen_on("/ip4/127.0.0.1/tcp/0")
            .expect("tcp listen address")
            .bind()
            .expect("bind a mesh relay")
    });

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut up = [false; 2];
    while up != [true; 2] {
        assert!(Instant::now() < deadline, "backbone links never came up");
        for (relay, up) in relays.iter_mut().zip(&mut up) {
            if let Some(EndpointEvent::RelayMeshMemberUp { .. }) = relay
                .next_event(Duration::from_millis(20))
                .expect("drive the relay")
            {
                *up = true;
            }
        }
    }
    let addrs = relays
        .each_mut()
        .map(|relay| relay.listen().expect("relay listen address").to_string());
    (relays, addrs, nodes.map(|(key, _)| key.peer_id()))
}

/// Asserts a mesh run reserved, crossed the backbone exactly once (the entry
/// node reports the holding node's backbone peer id in `via`, and the
/// holding node the entry node's), and carried bytes both ways.
pub fn assert_crossed_mesh(observed: Observed, backbones: &[PeerId]) {
    assert!(observed.reserved, "foreign reservation was not observed");
    let mut opened = observed.opened;
    opened.sort();
    let mut expected: Vec<_> = backbones.iter().cloned().map(Some).collect();
    expected.sort();
    assert_eq!(
        opened, expected,
        "the circuit did not cross the backbone once"
    );
    assert!(
        observed.bidirectional,
        "foreign ping did not produce bytes in both directions"
    );
}
