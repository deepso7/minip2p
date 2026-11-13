//! Opt-in live gate against the pinned rust-libp2p relay client: one relay,
//! and a two-node relay mesh with the foreign peers on different nodes.

#![cfg(all(feature = "relay-server", feature = "tcp", feature = "std"))]

use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use minip2p::{Endpoint, EndpointEvent, PeerId, RelayServerConfig, RelayServerEvent};

#[path = "../../../tests/support/endpoint.rs"]
mod endpoint_support;
use endpoint_support::NextEvent;

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

/// Non-default limits the client checks it decodes on every leg.
fn config() -> RelayServerConfig {
    RelayServerConfig {
        max_circuit_duration_secs: 7,
        max_circuit_bytes: 2_048,
        ..RelayServerConfig::default()
    }
}

/// Builds the pinned client and returns its binary.
fn build_client() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/interop/rust-relay-client/Cargo.toml");
    let target_dir = manifest
        .parent()
        .expect("interop manifest has a parent")
        .join("target");
    let rustc_version = Command::new("rustc")
        .arg("-vV")
        .output()
        .expect("query rustc host target");
    assert!(rustc_version.status.success(), "rustc -vV failed");
    let rustc_version = String::from_utf8(rustc_version.stdout).expect("rustc -vV is UTF-8");
    let host_target = rustc_version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .expect("rustc -vV reports a host target");
    let build_status = Command::new("cargo")
        .args(["build", "--quiet", "--locked", "--manifest-path"])
        .arg(&manifest)
        .arg("--target-dir")
        .arg(&target_dir)
        .arg("--target")
        .arg(host_target)
        .status()
        .expect("build pinned rust-libp2p client");
    assert!(
        build_status.success(),
        "pinned client build failed: {build_status}"
    );
    target_dir.join(host_target).join("debug").join(format!(
        "minip2p-rust-relay-interop{}",
        std::env::consts::EXE_SUFFIX
    ))
}

/// What the relays saw while the client ran.
#[derive(Default)]
struct Observed {
    reserved: bool,
    /// `via` of every `CircuitOpened`, across all relays.
    opened: Vec<Option<PeerId>>,
    bidirectional: bool,
}

/// Runs the pinned client with `args`, driving every relay until it exits,
/// then a little longer for circuit closure and accounting.
#[expect(
    clippy::panic,
    reason = "a relay error fails the gate with the error itself"
)]
fn run_client(relays: &mut [Endpoint], args: &[&str]) -> Observed {
    let mut child = ChildGuard(
        Command::new(build_client())
            .args(args)
            .spawn()
            .expect("spawn pinned rust-libp2p client"),
    );
    let mut observed = Observed::default();
    let mut observe = |event| match event {
        RelayServerEvent::ReservationAccepted { .. } => observed.reserved = true,
        RelayServerEvent::CircuitOpened { via, .. } => observed.opened.push(via),
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
            assert!(
                status.success(),
                "pinned rust-libp2p client failed: {status}"
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "pinned rust-libp2p client timed out"
        );
    }
    // Drive closure/accounting after the foreign process exits.
    for _ in 0..50 {
        drive(relays);
    }
    observed
}

#[test]
#[ignore = "downloads/builds pinned rust-libp2p and opens loopback sockets"]
fn pinned_rust_libp2p_reserves_connects_and_exchanges_bytes() {
    let mut relay = Endpoint::builder()
        .relay_server_config(config())
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
        .unwrap();
    let relay_addr = relay.listen().unwrap().to_string();

    let observed = run_client(
        std::slice::from_mut(&mut relay),
        &[&relay_addr, "7", "2048"],
    );

    assert!(observed.reserved, "foreign reservation was not observed");
    assert_eq!(
        observed.opened,
        [None],
        "foreign CONNECT/STOP circuit was not observed"
    );
    assert!(
        observed.bidirectional,
        "foreign ping did not produce bytes in both directions"
    );
}

/// Two relay Endpoints meshed over a loopback backbone, sharing one public
/// identity: the destination reserves on the first, the source dials
/// through the second, so the circuit crosses the backbone.
#[cfg(feature = "quic")]
#[test]
#[ignore = "downloads/builds pinned rust-libp2p and opens loopback sockets"]
fn pinned_rust_libp2p_connects_across_a_relay_mesh() {
    use minip2p::{Ed25519Keypair, PeerAddr, RelayMeshConfig};

    let public = Ed25519Keypair::generate();
    let backbones = [Ed25519Keypair::generate(), Ed25519Keypair::generate()];
    // Ports no socket holds now, so each node can list the other before
    // either binds.
    let listen = backbones.each_ref().map(|_| {
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        format!("/ip4/127.0.0.1/udp/{port}/quic-v1")
    });
    let members: Vec<PeerAddr> = backbones
        .iter()
        .zip(&listen)
        .map(|(key, addr)| PeerAddr::new(addr.parse().unwrap(), key.peer_id()).unwrap())
        .collect();
    let mut relays: Vec<Endpoint> = backbones
        .iter()
        .zip(&listen)
        .map(|(key, addr)| {
            Endpoint::builder()
                .identity(public.clone())
                .relay_server_config(config())
                .relay_mesh(RelayMeshConfig {
                    identity: key.clone(),
                    listen: vec![addr.parse().unwrap()],
                    members: members.clone(),
                })
                .listen_on("/ip4/127.0.0.1/tcp/0")
                .expect("tcp listen address")
                .bind()
                .unwrap()
        })
        .collect();

    // Both links up before the clients start, as in production, where DNS
    // only points at nodes whose members are up.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut up = [false; 2];
    while up != [true; 2] {
        assert!(Instant::now() < deadline, "backbone links never came up");
        for (index, relay) in relays.iter_mut().enumerate() {
            if let Some(EndpointEvent::RelayMeshMemberUp { .. }) =
                relay.next_event(Duration::from_millis(20)).unwrap()
            {
                up[index] = true;
            }
        }
    }
    let addrs: Vec<String> = relays
        .iter_mut()
        .map(|relay| relay.listen().unwrap().to_string())
        .collect();

    let observed = run_client(&mut relays, &[&addrs[0], "7", "2048", &addrs[1]]);

    assert!(observed.reserved, "foreign reservation was not observed");
    // The entry node reports the holding node's backbone peer id, and the
    // holding node the entry node's.
    let mut opened = observed.opened;
    opened.sort();
    let mut expected: Vec<_> = backbones.iter().map(|key| Some(key.peer_id())).collect();
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
