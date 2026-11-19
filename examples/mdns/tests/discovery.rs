//! End-to-end check that two `minip2p-mdns` instances find each other.
//!
//! Ignored by default for the same reason as
//! `crates/minip2p/tests/mdns.rs`: it needs real multicast delivery on
//! UDP 5353, which CI containers and many VPN configurations do not give.
//! Run it with `cargo test -p minip2p-mdns-demo -- --ignored`.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
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

    let mut a = spawn();
    let mut b = spawn();

    // Drain *both* streams of both children, each on its own thread:
    // neither can then block on a full pipe while the deadline below is
    // what actually bounds the test, and a startup failure's reason —
    // which goes to stderr — survives into the assertion message.
    let a_stdout = drain(a.stdout.take());
    let a_stderr = drain(a.stderr.take());
    let b_stdout = drain(b.stdout.take());
    let b_stderr = drain(b.stderr.take());

    let deadline = Instant::now() + TEST_DEADLINE;
    let a_status = wait_by(&mut a, deadline);
    let b_status = wait_by(&mut b, deadline);

    let a_out = a_stdout.recv().unwrap_or_default();
    let b_out = b_stdout.recv().unwrap_or_default();
    let a_err = a_stderr.recv().unwrap_or_default();
    let b_err = b_stderr.recv().unwrap_or_default();

    for (name, status, out, err) in [
        ("a", a_status, &a_out, &a_err),
        ("b", b_status, &b_out, &b_err),
    ] {
        assert!(
            status.is_some(),
            "instance {name} outlived the {TEST_DEADLINE:?} deadline;\nstdout:\n{out}\nstderr:\n{err}",
        );
        let status = status.expect("checked immediately above");
        assert!(
            status.success(),
            "instance {name} exited non-zero: {status:?}\nstdout:\n{out}\nstderr:\n{err}",
        );
    }

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

/// Reads one of a child's piped streams to a `String` on its own thread,
/// so a full pipe cannot deadlock the wait below. Every piped stream needs
/// one of these: an undrained pipe blocks the child just as surely whether
/// it is stdout or stderr.
fn drain<R: Read + Send + 'static>(stream: Option<R>) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    let Some(mut stream) = stream else {
        return rx;
    };
    thread::spawn(move || {
        let mut buf = String::new();
        drop(stream.read_to_string(&mut buf));
        drop(tx.send(buf));
    });
    rx
}

/// Waits for `child` until `deadline`, then kills and reaps it. `None`
/// means it had to be killed, which fails the test rather than hanging
/// `just mdns-discovery` forever.
fn wait_by(child: &mut Child, deadline: Instant) -> Option<std::process::ExitStatus> {
    loop {
        if let Some(status) = child.try_wait().expect("waiting for instance") {
            return Some(status);
        }
        if Instant::now() >= deadline {
            drop(child.kill());
            drop(child.wait());
            return None;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// The `us=<peer-id>` line an instance prints once at startup.
fn peer_id(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .find_map(|l| l.strip_prefix("[mdns] us="))
        .map(|id| id.trim_end().to_string())
}
