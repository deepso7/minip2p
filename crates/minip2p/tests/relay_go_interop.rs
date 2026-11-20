//! Opt-in live gate against go-libp2p's circuit relay v2 client
//! (`tests/interop/go-libp2p`, `relay` mode): a two-node relay mesh with the
//! foreign peers on different nodes.

#![cfg(all(
    feature = "relay-server",
    feature = "tcp",
    feature = "std",
    feature = "quic"
))]

use std::path::PathBuf;
use std::process::Command;

#[path = "../../../tests/support/endpoint.rs"]
mod endpoint_support;
#[path = "../../../tests/support/relay_interop.rs"]
mod relay_interop;
use relay_interop::Limits;

/// go-libp2p's Noise handshake and Identify (a signed peer record and its
/// full protocol list) take about 2 KiB per direction before ping runs, so
/// the rust-libp2p gate's 2 KiB limit would cut the circuit first. 64 KiB
/// still differs from the 128 KiB default.
const LIMITS: Limits = Limits {
    duration_secs: 7,
    bytes: 64 * 1024,
};

/// Builds the pinned go-libp2p harness and returns its binary.
fn build_client() -> PathBuf {
    let project = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/interop/go-libp2p");
    let binary = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("go-libp2p-interop{}", std::env::consts::EXE_SUFFIX));
    let status = Command::new("go")
        .args(["build", "-mod=readonly", "-o"])
        .arg(&binary)
        .arg(".")
        .current_dir(project)
        .status()
        .expect("run go build; install Go to run this ignored test");
    assert!(status.success(), "go-libp2p harness build failed: {status}");
    binary
}

/// The destination reserves on the first mesh node and the source dials
/// through the second, so the circuit crosses the backbone.
#[test]
#[ignore = "requires Go, downloads pinned go-libp2p, and opens loopback sockets"]
fn go_libp2p_connects_across_a_relay_mesh() {
    let client = build_client();
    let (mut relays, [first, second], backbones) = relay_interop::mesh(LIMITS);

    let mut command = Command::new(client);
    command
        .arg("relay")
        .arg(first)
        .args(LIMITS.args())
        .arg(second);
    let observed = relay_interop::run_client(&mut relays, command);

    relay_interop::assert_crossed_mesh(observed, &backbones);
}
