//! Opt-in live gate against the pinned rust-libp2p relay client: one relay,
//! and a two-node relay mesh with the foreign peers on different nodes.

#![cfg(all(feature = "relay-server", feature = "tcp", feature = "std"))]

use std::path::PathBuf;
use std::process::Command;

use minip2p::Endpoint;

#[path = "../../../tests/support/endpoint.rs"]
mod endpoint_support;
#[path = "../../../tests/support/relay_interop.rs"]
mod relay_interop;
use relay_interop::{Limits, run_client};

/// rust-libp2p's handshake and Identify fit well inside 2 KiB per direction.
const LIMITS: Limits = Limits {
    duration_secs: 7,
    bytes: 2_048,
};

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

#[test]
#[ignore = "downloads/builds pinned rust-libp2p and opens loopback sockets"]
fn pinned_rust_libp2p_reserves_connects_and_exchanges_bytes() {
    let client = build_client();
    let mut relay = Endpoint::builder()
        .relay_server_config(LIMITS.config())
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
        .unwrap();
    let relay_addr = relay.listen().unwrap().to_string();

    let mut command = Command::new(client);
    command.arg(&relay_addr).args(LIMITS.args());
    let observed = run_client(std::slice::from_mut(&mut relay), command);

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

/// The destination reserves on the first mesh node and the source dials
/// through the second, so the circuit crosses the backbone.
#[cfg(feature = "quic")]
#[test]
#[ignore = "downloads/builds pinned rust-libp2p and opens loopback sockets"]
fn pinned_rust_libp2p_connects_across_a_relay_mesh() {
    let client = build_client();
    let (mut relays, [first, second], backbones) = relay_interop::mesh(LIMITS);

    let mut command = Command::new(client);
    command.arg(first).args(LIMITS.args()).arg(second);
    let observed = run_client(&mut relays, command);

    relay_interop::assert_crossed_mesh(observed, &backbones);
}
