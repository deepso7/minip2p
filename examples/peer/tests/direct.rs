//! CI-safe end-to-end test for `minip2p-peer` direct mode.
//!
//! Spawns the `minip2p-peer listen` subprocess, parses its `bound=`
//! line from stdout, then spawns `minip2p-peer dial <addr>` and asserts
//! the dialer exits successfully with a `ping ... rtt=...ms` line on
//! stdout. Both processes are killed on drop so a panicking assertion
//! doesn't leave a listener bound to a UDP port on the test host.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Hard cap on the entire flow. On localhost this completes in well
/// under a second; the generous timeout absorbs CI jitter.
const TEST_DEADLINE: Duration = Duration::from_secs(15);

/// Child process that is killed on drop so a test panic doesn't leak
/// a bound UDP socket.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn direct_listen_and_dial_complete_ping_round_trip() {
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

    let listener_stdout = listener
        .0
        .stdout
        .take()
        .expect("listener stdout is piped");

    let peer_addr = read_bound_line(listener_stdout, TEST_DEADLINE)
        .expect("listener should print a 'bound=...' line");

    // --- 2. Spawn the dialer, wait for exit, capture stdout. ---
    let dialer = Command::new(bin)
        .arg("dial")
        .arg(&peer_addr)
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
    assert!(
        stdout.lines().any(|l| l.contains("rtt=") && l.contains("ping")),
        "dialer stdout should contain a 'ping ... rtt=...' line; got:\n{stdout}",
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
        loop {
            line.clear();
            if buf.read_line(&mut line).unwrap_or(0) == 0 {
                // EOF: listener died before printing its bound line.
                let _ = tx.send(None);
                return;
            }
            if let Some(rest) = line.strip_prefix("[listen] bound=") {
                let _ = tx.send(Some(rest.trim_end().to_string()));
                return;
            }
        }
    });

    rx.recv_timeout(deadline).ok().flatten()
}

/// Wait for `child` to exit, but give up after `deadline` and kill it.
fn wait_with_deadline(
    mut child: Child,
    deadline: Duration,
) -> Option<std::process::Output> {
    let start = Instant::now();
    loop {
        if let Ok(Some(_)) = child.try_wait() {
            return child.wait_with_output().ok();
        }
        if start.elapsed() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        thread::sleep(Duration::from_millis(20));
    }
}
