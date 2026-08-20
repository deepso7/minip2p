//! Opt-in live gate against the pinned rust-libp2p relay client.

#![cfg(all(feature = "relay-server", feature = "tcp"))]

use std::process::{Child, Command};
use std::time::{Duration, Instant};

use minip2p::{Endpoint, RelayServerConfig, RelayServerEvent};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "downloads/builds pinned rust-libp2p and opens loopback sockets"]
fn pinned_rust_libp2p_reserves_connects_and_exchanges_bytes() {
    let config = RelayServerConfig {
        max_circuit_duration_secs: 7,
        max_circuit_bytes: 2_048,
        ..RelayServerConfig::default()
    };
    let mut relay = Endpoint::builder()
        .relay_server_config(config)
        .unwrap()
        .bind_tcp("127.0.0.1:0")
        .unwrap();
    let relay_addr = relay.listen().unwrap().to_string();
    let manifest = format!(
        "{}/../../tests/interop/rust-relay-client/Cargo.toml",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut child = ChildGuard(
        Command::new("cargo")
            .args([
                "run",
                "--quiet",
                "--manifest-path",
                &manifest,
                "--",
                &relay_addr,
                "7",
                "2048",
            ])
            .spawn()
            .expect("spawn pinned rust-libp2p client"),
    );

    let deadline = Instant::now() + Duration::from_secs(180);
    let mut reserved = false;
    let mut opened = false;
    let mut bidirectional = false;
    loop {
        if let Some(event) = relay
            .next_relay_server_event(Duration::from_millis(100))
            .unwrap()
        {
            match event {
                RelayServerEvent::ReservationAccepted { .. } => reserved = true,
                RelayServerEvent::CircuitOpened { .. } => opened = true,
                RelayServerEvent::CircuitClosed { bytes, .. } => {
                    bidirectional =
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
            }
        }
        if let Some(status) = child.0.try_wait().unwrap() {
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
    for _ in 0..20 {
        if let Some(RelayServerEvent::CircuitClosed { bytes, .. }) = relay
            .next_relay_server_event(Duration::from_millis(100))
            .unwrap()
        {
            bidirectional = bytes.source_to_destination > 0 && bytes.destination_to_source > 0;
            break;
        }
    }
    assert!(reserved, "foreign reservation was not observed");
    assert!(opened, "foreign CONNECT/STOP circuit was not observed");
    assert!(
        bidirectional,
        "foreign ping did not produce bytes in both directions"
    );
}
