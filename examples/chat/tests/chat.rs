//! CI-safe end-to-end test for `minip2p-chat` on loopback, relay-free.
//!
//! Spawns a host and two joiners in a star (the joiners only know the
//! host), waits for the floodsub subscription handshakes, then proves the
//! product loop: a line typed on one peer's stdin reaches every other peer
//! — including leaf-to-leaf THROUGH the host — and stdin EOF exits cleanly.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Hard cap on the entire flow; loopback runs finish in a few seconds.
const TEST_DEADLINE: Duration = Duration::from_secs(30);

/// Child process killed on drop so a panicking assertion doesn't leak
/// bound UDP sockets.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A spawned chat peer with its collected stdout lines.
struct Peer {
    child: KillOnDrop,
    stdin: Option<ChildStdin>,
    lines: Arc<Mutex<Vec<String>>>,
    name: &'static str,
}

impl Peer {
    fn spawn(name: &'static str, args: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_minip2p-chat"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {name}: {e}"));

        let stdin = child.stdin.take();
        let stdout = child.stdout.take().expect("stdout is piped");
        let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&lines);
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { return };
                sink.lock().expect("line sink").push(line);
            }
        });
        // Drain stderr so the child never blocks on a full pipe.
        let stderr = child.stderr.take().expect("stderr is piped");
        thread::spawn(move || for _ in BufReader::new(stderr).lines() {});

        Self {
            child: KillOnDrop(child),
            stdin,
            lines,
            name,
        }
    }

    /// Waits until some collected line satisfies `pred`, returning it.
    fn wait_line(&self, deadline: Instant, pred: impl Fn(&str) -> bool) -> String {
        loop {
            if let Some(found) = self
                .lines
                .lock()
                .expect("line sink")
                .iter()
                .find(|line| pred(line))
                .cloned()
            {
                return found;
            }
            assert!(
                Instant::now() < deadline,
                "{}: expected line never arrived; got:\n{}",
                self.name,
                self.all_lines().join("\n")
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn count_lines(&self, pred: impl Fn(&str) -> bool) -> usize {
        self.lines
            .lock()
            .expect("line sink")
            .iter()
            .filter(|line| pred(line))
            .count()
    }

    /// Waits until at least `min` collected lines satisfy `pred`.
    ///
    /// NOT expressible via [`Peer::wait_line`] with a counting predicate:
    /// `wait_line` holds the lines mutex while evaluating predicates, so a
    /// predicate that re-enters `count_lines` would deadlock.
    fn wait_count(&self, deadline: Instant, min: usize, pred: impl Fn(&str) -> bool) {
        loop {
            if self.count_lines(&pred) >= min {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "{}: expected {min} matching lines; got:\n{}",
                self.name,
                self.all_lines().join("\n")
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn all_lines(&self) -> Vec<String> {
        self.lines.lock().expect("line sink").clone()
    }

    fn say(&mut self, text: &str) {
        let stdin = self.stdin.as_mut().expect("stdin still open");
        writeln!(stdin, "{text}").expect("write to child stdin");
    }

    /// Closes stdin (EOF) and waits for a clean exit.
    fn leave(mut self, deadline: Instant) {
        drop(self.stdin.take());
        loop {
            match self.child.0.try_wait() {
                Ok(Some(status)) => {
                    assert!(
                        status.success(),
                        "{} exited non-zero: {status:?}\nstdout:\n{}",
                        self.name,
                        self.all_lines().join("\n")
                    );
                    return;
                }
                Ok(None) => {
                    assert!(
                        Instant::now() < deadline,
                        "{} did not exit after stdin EOF",
                        self.name
                    );
                    thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("{}: try_wait: {e}", self.name),
            }
        }
    }
}

#[test]
fn three_peer_star_chats_end_to_end() {
    let deadline = Instant::now() + TEST_DEADLINE;

    // --- 1. Host binds and prints its join address. ---
    let host = Peer::spawn("host", &["host", "--nick", "hostess"]);
    let bound = host.wait_line(deadline, |line| line.starts_with("[host] bound="));
    let addr = bound.trim_start_matches("[host] bound=").to_string();

    // --- 2. Two joiners dial the host; nobody knows anybody else. ---
    let mut alice = Peer::spawn("alice", &["join", &addr, "--nick", "alice"]);
    let mut bob = Peer::spawn("bob", &["join", &addr, "--nick", "bob"]);

    // --- 3. Subscription handshakes settle (floodsub has no history:
    //        publishing earlier would vanish). ---
    for peer in [&alice, &bob] {
        peer.wait_line(deadline, |line| line.contains("peer-subscribed"));
    }
    host.wait_count(deadline, 2, |line| line.contains("peer-subscribed"));

    // --- 4. Alice speaks: the host hears it directly, bob hears it
    //        THROUGH the host (they share no connection). ---
    alice.say("hello everyone");
    host.wait_line(deadline, |line| line.contains("alice: hello everyone"));
    bob.wait_line(deadline, |line| line.contains("alice: hello everyone"));
    // Alice sees her own line only as the local echo, never re-delivered.
    alice.wait_line(deadline, |line| {
        line.starts_with("[you] alice: hello everyone")
    });
    assert_eq!(
        alice.count_lines(|line| line.starts_with("[chat] alice: hello everyone")),
        0,
        "no self-delivery: {:?}",
        alice.all_lines()
    );
    // Bob got exactly one copy (seen-cache dedup across the star).
    assert_eq!(
        bob.count_lines(|line| line.contains("alice: hello everyone")),
        1
    );

    // --- 5. Bob replies; alice and the host both hear it. ---
    bob.say("hi alice");
    host.wait_line(deadline, |line| line.contains("bob: hi alice"));
    alice.wait_line(deadline, |line| line.contains("bob: hi alice"));

    // --- 6. Everyone leaves cleanly on stdin EOF. ---
    alice.leave(deadline);
    bob.leave(deadline);
    host.leave(deadline);
}
