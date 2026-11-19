//! CI-safe end-to-end test for `minip2p-peer` on loopback, relay-free.
//!
//! Spawns `minip2p-peer listen`, parses its `bound=` line from stdout,
//! then spawns `minip2p-peer dial <addr> --count 3` and asserts the dialer
//! exits successfully after a direct path, three pongs with an
//! unbroken seq sequence, and a complete summary. A second test runs
//! `minip2p-peer id <addr>` against the same listener and asserts the
//! one-shot prints a real Identify result and exits 0. Both processes are
//! killed on drop so a panicking assertion doesn't leave a listener bound
//! to a UDP port on the test host.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use minip2p_example_common::KillOnDrop;

/// Hard cap on the entire flow. The dial itself takes ~3 s (three 1 s
/// pings); the generous timeout absorbs CI jitter.
const TEST_DEADLINE: Duration = Duration::from_secs(20);

#[test]
fn listen_and_dial_complete_counted_ping_run() {
    let bin = env!("CARGO_BIN_EXE_minip2p-peer");

    // --- 1. Spawn the listener and read its peer-addr from stdout. ---
    let mut listener = KillOnDrop(
        Command::new(bin)
            .arg("listen")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn listener"),
    );

    let listener_stdout = listener.0.stdout.take().expect("listener stdout is piped");

    let peer_addr = read_bound_line(listener_stdout, TEST_DEADLINE)
        .expect("listener should print a 'bound=...' line");

    // --- 2. Spawn the dialer, wait for exit, capture stdout. ---
    let dialer = Command::new(bin)
        .arg("dial")
        .arg(&peer_addr)
        .arg("--count")
        .arg("3")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dialer");

    let output = wait_with_deadline(dialer, TEST_DEADLINE)
        .expect("dialer should exit within the test deadline");

    assert!(
        output.status.success(),
        "dialer exited non-zero: status={:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in [
        "path-established path=direct",
        "pong seq=1",
        "pong seq=3",
        "summary sent=3 received=3",
    ] {
        assert!(
            stdout.lines().any(|l| l.contains(needle)),
            "dialer stdout should contain '{needle}'; got:\n{stdout}",
        );
    }

    // A plain direct dial must open its echo stream on the first try: the
    // dial's own queued `ConnectionEstablished` must not be misread as a
    // replacing punch connection (which would reset the stream and log
    // a spurious retry).
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("direct channel setup failed"),
        "direct dial retried its echo stream setup; stderr:\n{stderr}",
    );

    // Listener is killed on drop.
}

#[test]
fn id_prints_the_listener_identify_and_exits() {
    let bin = env!("CARGO_BIN_EXE_minip2p-peer");

    let mut listener = KillOnDrop(
        Command::new(bin)
            .arg("listen")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn listener"),
    );

    let listener_stdout = listener.0.stdout.take().expect("listener stdout is piped");
    let peer_addr = read_bound_line(listener_stdout, TEST_DEADLINE)
        .expect("listener should print a 'bound=...' line");

    let probe = Command::new(bin)
        .arg("id")
        .arg(&peer_addr)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn id");

    let output =
        wait_with_deadline(probe, TEST_DEADLINE).expect("id should exit within the test deadline");

    assert!(
        output.status.success(),
        "id exited non-zero: status={:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in [
        "path-established path=direct",
        "[id] identify peer=",
        // The agent string and the echo protocol come from the listener's
        // own Identify payload, so this is the remote's answer and not
        // something the prober could have printed from its own config.
        "agent=minip2p-peer/0.1.0",
        "/minip2p/echo/1",
        // A standard libp2p protocol in the advertised set: what makes the
        // same command useful against a foreign implementation.
        "/ipfs/ping/1.0.0",
    ] {
        assert!(
            stdout.lines().any(|l| l.contains(needle)),
            "id stdout should contain '{needle}'; got:\n{stdout}",
        );
    }

    // Exactly one Identify line: the result is read back from
    // `peer_readiness` rather than echoed from the event, so a one-shot
    // never prints its answer twice.
    assert_eq!(
        stdout
            .lines()
            .filter(|l| l.contains("[id] identify peer="))
            .count(),
        1,
        "id should print exactly one identify line; got:\n{stdout}",
    );

    // Listener is killed on drop.
}

/// Scans `reader` line-by-line for the listener's `bound=<peer-addr>`
/// advertisement, returning just the `<peer-addr>` value.
fn read_bound_line<R: std::io::Read + Send + 'static>(
    reader: R,
    deadline: Duration,
) -> Option<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let mut buf = BufReader::new(reader);
        let mut line = String::new();
        let mut sent_bound = false;
        loop {
            line.clear();
            if buf.read_line(&mut line).unwrap_or(0) == 0 {
                // EOF: listener died before printing its bound line.
                if !sent_bound && tx.send(None).is_err() {
                    return;
                }
                return;
            }
            if !sent_bound && let Some(rest) = line.strip_prefix("[listen] bound=") {
                if tx.send(Some(rest.trim_end().to_string())).is_err() {
                    return;
                }
                sent_bound = true;
            }
        }
    });

    rx.recv_timeout(deadline).ok().flatten()
}

/// Wait for `child` to exit, but give up after `deadline` and kill it.
fn wait_with_deadline(mut child: Child, deadline: Duration) -> Option<std::process::Output> {
    let start = Instant::now();
    loop {
        if let Ok(Some(_)) = child.try_wait() {
            return child.wait_with_output().ok();
        }
        if start.elapsed() >= deadline {
            // The child may have exited between `try_wait` and cleanup.
            drop(child.kill());
            drop(child.wait());
            return None;
        }
        thread::sleep(Duration::from_millis(20));
    }
}
