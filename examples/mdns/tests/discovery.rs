//! End-to-end check that two `minip2p-mdns` instances find each other.
//!
//! Ignored by default for the same reason as
//! `crates/minip2p/tests/mdns.rs`: it needs real multicast delivery on
//! UDP 5353, which CI containers and many VPN configurations do not give.
//! Run it with `cargo test -p minip2p-mdns-demo -- --ignored`.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Bounded run length handed to both instances, in seconds.
const RUN_FOR: &str = "15";
/// Hard cap on the whole test, comfortably over `RUN_FOR` plus shutdown.
const TEST_DEADLINE: Duration = Duration::from_secs(45);

#[test]
#[ignore = "requires host multicast delivery on UDP 5353"]
fn two_instances_discover_each_other() {
    let bin = env!("CARGO_BIN_EXE_minip2p-mdns");
    let spawn = || {
        Command::new(bin)
            .args(["--for", RUN_FOR])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn minip2p-mdns")
    };

    let a = spawn();
    let b = spawn();

    let start = Instant::now();
    let a = a.wait_with_output().expect("instance a exits");
    let b = b.wait_with_output().expect("instance b exits");
    assert!(
        start.elapsed() < TEST_DEADLINE,
        "instances outlived the test deadline"
    );

    for (name, out) in [("a", &a), ("b", &b)] {
        assert!(
            out.status.success(),
            "instance {name} exited non-zero: {:?}\nstdout:\n{}\nstderr:\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }

    let a_out = String::from_utf8_lossy(&a.stdout);
    let b_out = String::from_utf8_lossy(&b.stdout);
    let a_peer = peer_id(&a_out).expect("instance a prints its peer id");
    let b_peer = peer_id(&b_out).expect("instance b prints its peer id");
    assert_ne!(a_peer, b_peer, "ephemeral identities should differ");

    // Each must have discovered the *other's* id over mDNS — not merely
    // printed a `discovered` line for someone else on the link.
    assert!(
        a_out
            .lines()
            .any(|l| l.contains("discovered peer=") && l.contains(&b_peer)),
        "a should discover b ({b_peer}); a stdout:\n{a_out}",
    );
    assert!(
        b_out
            .lines()
            .any(|l| l.contains("discovered peer=") && l.contains(&a_peer)),
        "b should discover a ({a_peer}); b stdout:\n{b_out}",
    );

    // `--for` ends with goodbyes and a summary rather than being killed.
    for (name, out) in [("a", &a_out), ("b", &b_out)] {
        assert!(
            out.lines().any(|l| l.starts_with("[mdns] done ")),
            "instance {name} should print its shutdown summary; got:\n{out}",
        );
    }
}

/// The `us=<peer-id>` line an instance prints once at startup.
fn peer_id(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .find_map(|l| l.strip_prefix("[mdns] us="))
        .map(|id| id.trim_end().to_string())
}
