//! Transport test app for <https://github.com/libp2p/unified-testing>.
//!
//! Contract: `docs/write-a-transport-test-app.md` in that repo. Settings come
//! from env vars; the listener publishes its multiaddr to Redis under
//! `<TEST_KEY>_listener_multiaddr` and serves pings until Docker stops it; the
//! dialer reads that address, connects, and pings twice: the first ping ends
//! `handshake_plus_one_rtt`, the second (on the negotiated stream) is
//! `ping_rtt`. It prints the latency YAML on stdout; everything else goes to
//! stderr.
//!
//! The Redis key is a list (RPUSH / BLPOP), not a string: that is what the
//! reference rust-libp2p image does, whatever the doc says.

use std::env;
use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use minip2p::{ConnectOutcome, Endpoint, EndpointEvent, EndpointWaitOutcome, PeerAddr};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// Both harnesses bound a test at three minutes unless told otherwise.
const DEFAULT_TEST_TIMEOUT: Duration = Duration::from_secs(180);

/// The two harnesses this app can be driven by. They agree on the mechanics —
/// Redis, `RPUSH`/`BLPOP`, one dial and one ping — and differ in how the
/// settings are spelled, which Redis key carries the address, and the shape of
/// the result the dialer prints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Harness {
    /// <https://github.com/libp2p/unified-testing>: upper-case settings, a
    /// per-test Redis key, a YAML result.
    UnifiedTesting,
    /// <https://github.com/libp2p/test-plans>: lower-case settings, the fixed
    /// `listenerAddr` key, a JSON result.
    TestPlans,
}

/// What one harness calls each setting.
struct Names {
    is_dialer: &'static str,
    transport: &'static str,
    security: &'static str,
    muxer: &'static str,
    redis_addr: &'static str,
    ip: &'static str,
}

impl Harness {
    /// Picks the harness from whichever dialer flag is present. Every setting
    /// is spelled differently by the two contracts, so one name settles it.
    fn detect(lookup: &impl Fn(&str) -> Option<String>) -> Result<Self> {
        match (lookup("IS_DIALER"), lookup("is_dialer")) {
            (Some(_), None) => Ok(Self::UnifiedTesting),
            (None, Some(_)) => Ok(Self::TestPlans),
            (Some(_), Some(_)) => {
                Err("IS_DIALER and is_dialer are both set; cannot tell which harness".into())
            }
            (None, None) => Err("neither IS_DIALER (unified-testing) nor                                  is_dialer (test-plans) is set"
                .into()),
        }
    }

    fn names(self) -> Names {
        match self {
            Self::UnifiedTesting => Names {
                is_dialer: "IS_DIALER",
                transport: "TRANSPORT",
                security: "SECURE_CHANNEL",
                muxer: "MUXER",
                redis_addr: "REDIS_ADDR",
                ip: "LISTENER_IP",
            },
            Self::TestPlans => Names {
                is_dialer: "is_dialer",
                transport: "transport",
                security: "security",
                muxer: "muxer",
                redis_addr: "redis_addr",
                ip: "ip",
            },
        }
    }

    /// The dialer's stdout result, in the form its harness parses.
    fn result(self, handshake_plus_one_rtt: Duration, ping_rtt: Duration) -> String {
        let (handshake, ping) = (millis(handshake_plus_one_rtt), millis(ping_rtt));
        match self {
            Self::UnifiedTesting => format!(
                "latency:\n  handshake_plus_one_rtt: {handshake:.3}\n  ping_rtt: {ping:.3}\n  unit: ms"
            ),
            // `pingRTTMilllis` carries three l's in the test-plans spec and in
            // every implementation that follows it; the runner reads that key.
            Self::TestPlans => format!(
                "{{\"handshakePlusOneRTTMillis\": {handshake:.3}, \"pingRTTMilllis\": {ping:.3}}}"
            ),
        }
    }
}

#[derive(Debug)]
struct Config {
    harness: Harness,
    is_dialer: bool,
    redis_addr: String,
    redis_key: String,
    transport: String,
    listen_ip: String,
    timeout: Duration,
    debug: bool,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let config = Config::from_env()?;
    if config.is_dialer {
        dialer(&config)
    } else {
        listener(&config)
    }
}

impl Config {
    fn from_env() -> Result<Self> {
        Self::parse(|name| env::var(name).ok())
    }

    /// Settings come from `lookup` rather than the process environment so the
    /// contract can be exercised without one.
    fn parse(lookup: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let harness = Harness::detect(&lookup)?;
        let names = harness.names();
        let var = |name: &str| lookup(name).ok_or_else(|| format!("{name} is not set"));
        let transport = var(names.transport)?;
        if transport == "tcp" {
            // Standalone transports (quic-v1) get neither setting.
            for (name, supported) in [(names.security, "noise"), (names.muxer, "yamux")] {
                let value = var(name)?;
                if value != supported {
                    return Err(format!("unsupported {name}={value} (only {supported})").into());
                }
            }
        } else if transport != "quic-v1" {
            return Err(format!("unsupported {}={transport}", names.transport).into());
        }
        let timeout = match lookup("test_timeout_seconds") {
            Some(seconds) => Duration::from_secs(seconds.parse()?),
            None => DEFAULT_TEST_TIMEOUT,
        };
        Ok(Self {
            is_dialer: var(names.is_dialer)? == "true",
            redis_addr: match harness {
                // unified-testing always passes it; test-plans leaves it to
                // the compose service name.
                Harness::UnifiedTesting => var(names.redis_addr)?,
                Harness::TestPlans => {
                    lookup(names.redis_addr).unwrap_or_else(|| "redis:6379".to_owned())
                }
            },
            redis_key: match harness {
                Harness::UnifiedTesting => {
                    format!("{}_listener_multiaddr", var("TEST_KEY")?)
                }
                Harness::TestPlans => "listenerAddr".to_owned(),
            },
            harness,
            transport,
            listen_ip: lookup(names.ip).unwrap_or_else(|| "0.0.0.0".to_owned()),
            timeout,
            debug: lookup("DEBUG").is_some_and(|v| v == "true"),
        })
    }

    fn bind_addr(&self) -> String {
        match self.transport.as_str() {
            "tcp" => format!("/ip4/{}/tcp/0", self.listen_ip),
            _ => format!("/ip4/{}/udp/0/quic-v1", self.listen_ip),
        }
    }

    fn log(&self, msg: impl std::fmt::Display) {
        if self.debug {
            eprintln!("[minip2p] {msg}");
        }
    }
}

fn listener(config: &Config) -> Result<()> {
    let mut node = Endpoint::builder().listen_on(config.bind_addr())?.bind()?;
    let addr = node.listen()?.to_string();
    // A wildcard bind cannot be dialled: publish the interface that reaches
    // Redis, which is the one the dialer shares a network with. An address the
    // harness pinned with `ip` is already the right one.
    let addr = if config.listen_ip == "0.0.0.0" {
        let ip = UdpSocket::bind("0.0.0.0:0")
            .and_then(|s| s.connect(&config.redis_addr).and(s.local_addr()))?
            .ip();
        addr.replacen("0.0.0.0", &ip.to_string(), 1)
    } else {
        addr
    };
    config.log(format_args!("listening on {addr}"));

    let mut redis = Redis::connect(&config.redis_addr)?;
    redis.command(&["RPUSH", &config.redis_key, &addr])?;

    // Ping and identify are answered inside the endpoint; just keep it
    // driven until Docker stops the container.
    loop {
        if let EndpointWaitOutcome::Event(event) = node.wait(Duration::from_secs(1))? {
            config.log(format_args!("{event:?}"));
        }
    }
}

fn dialer(config: &Config) -> Result<()> {
    let mut redis = Redis::connect(&config.redis_addr)?;
    let timeout = config.timeout.as_secs().to_string();
    // BLPOP answers [key, value], or a null array on timeout.
    let reply = redis.command(&["BLPOP", &config.redis_key, &timeout])?;
    let addr = reply
        .get(1)
        .ok_or("timed out waiting for the listener address")?;
    config.log(format_args!("dialing {addr}"));
    let target: PeerAddr = addr.parse()?;
    let peer = target.peer_id().clone();

    let mut node = Endpoint::builder().listen_on(config.bind_addr())?.bind()?;

    // Timed like rust-libp2p's interop-tests: the clock starts before the
    // dial and stops at the first ping result, so the two numbers compare.
    let deadline = Instant::now() + config.timeout;
    let handshake_start = Instant::now();
    let connect_id = node.connect(target)?;
    // Set by the first ping result. The first ping also opens and negotiates
    // the ping stream, so `ping_rtt` comes from a second ping on that stream:
    // rust-libp2p's RTT likewise covers only the payload echo.
    let mut handshake_plus_one_rtt = None;
    let mut ping_start = Instant::now();
    loop {
        if Instant::now() >= deadline {
            return Err("test timed out".into());
        }
        let EndpointWaitOutcome::Event(event) = node.wait(deadline)? else {
            continue;
        };
        // Sampled before logging so DEBUG output does not inflate the numbers.
        let now = Instant::now();
        config.log(format_args!("{event:?}"));
        match event {
            EndpointEvent::ConnectSettled {
                connect_id: id,
                outcome,
                ..
            } if id == connect_id => match outcome {
                ConnectOutcome::Connected { .. } => node.ping(&peer)?,
                other => return Err(format!("connect failed: {other:?}").into()),
            },
            EndpointEvent::PingRttMeasured { .. } => {
                let Some(handshake_plus_one_rtt) = handshake_plus_one_rtt else {
                    handshake_plus_one_rtt = Some(now - handshake_start);
                    ping_start = Instant::now();
                    node.ping(&peer)?;
                    continue;
                };
                // `rtt_ms` is whole milliseconds; container RTTs are below
                // that, so time the ping here for sub-ms precision.
                let ping_rtt = now - ping_start;
                println!(
                    "{}",
                    config.harness.result(handshake_plus_one_rtt, ping_rtt)
                );
                return Ok(());
            }
            EndpointEvent::PingFailed { cause, .. } => {
                return Err(format!("ping failed: {cause:?}").into());
            }
            _ => {}
        }
    }
}

fn millis(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// Just enough RESP for RPUSH and BLPOP.
struct Redis {
    reader: BufReader<TcpStream>,
}

impl Redis {
    fn connect(addr: &str) -> Result<Self> {
        // Redis is a global service, but it can still be starting up.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match TcpStream::connect(addr) {
                Ok(stream) => {
                    return Ok(Self {
                        reader: BufReader::new(stream),
                    });
                }
                Err(e) if Instant::now() >= deadline => {
                    return Err(format!("redis {addr}: {e}").into());
                }
                Err(_) => std::thread::sleep(Duration::from_millis(200)),
            }
        }
    }

    /// Sends one command; returns the reply's bulk strings (empty for an
    /// integer, simple-string or null reply).
    fn command(&mut self, args: &[&str]) -> Result<Vec<String>> {
        let mut request = format!("*{}\r\n", args.len());
        for arg in args {
            request.push_str(&format!("${}\r\n{arg}\r\n", arg.len()));
        }
        self.reader.get_mut().write_all(request.as_bytes())?;
        self.read_reply()
    }

    fn read_reply(&mut self) -> Result<Vec<String>> {
        let line = self.read_line()?;
        let (kind, rest) = line.split_at(1);
        match kind {
            "+" | ":" => Ok(Vec::new()),
            "-" => Err(format!("redis: {rest}").into()),
            "$" => Ok(self.read_bulk(rest.parse()?)?.into_iter().collect()),
            "*" => {
                let n: i64 = rest.parse()?;
                let mut items = Vec::new();
                for _ in 0..n.max(0) {
                    let header = self.read_line()?;
                    let len = header
                        .strip_prefix('$')
                        .ok_or("redis: expected bulk string")?;
                    items.extend(self.read_bulk(len.parse()?)?);
                }
                Ok(items)
            }
            _ => Err(format!("redis: unexpected reply {line:?}").into()),
        }
    }

    fn read_bulk(&mut self, len: i64) -> Result<Option<String>> {
        if len < 0 {
            return Ok(None);
        }
        let mut buf = vec![0; usize::try_from(len)? + 2]; // + CRLF
        std::io::Read::read_exact(&mut self.reader, &mut buf)?;
        buf.truncate(buf.len() - 2);
        Ok(Some(String::from_utf8(buf)?))
    }

    fn read_line(&mut self) -> Result<String> {
        let mut line = String::new();
        if self.reader.read_line(&mut line)? == 0 {
            return Err("redis closed the connection".into());
        }
        Ok(line.trim_end_matches("\r\n").to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a lookup over `(name, value)` pairs, as the harness env would.
    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        }
    }

    const UNIFIED_TCP: &[(&str, &str)] = &[
        ("IS_DIALER", "true"),
        ("REDIS_ADDR", "redis:6379"),
        ("TEST_KEY", "deadbeef"),
        ("TRANSPORT", "tcp"),
        ("SECURE_CHANNEL", "noise"),
        ("MUXER", "yamux"),
    ];

    #[test]
    fn unified_testing_tcp_settings_are_read() {
        let config = Config::parse(env(UNIFIED_TCP)).expect("parses");
        assert!(config.is_dialer);
        assert_eq!(config.redis_addr, "redis:6379");
        assert_eq!(config.redis_key, "deadbeef_listener_multiaddr");
        assert_eq!(config.transport, "tcp");
        assert!(!config.debug);
    }

    #[test]
    fn quic_needs_no_secure_channel_or_muxer() {
        let config = Config::parse(env(&[
            ("IS_DIALER", "false"),
            ("REDIS_ADDR", "redis:6379"),
            ("TEST_KEY", "k"),
            ("TRANSPORT", "quic-v1"),
        ]))
        .expect("parses");
        assert!(!config.is_dialer);
        assert_eq!(config.bind_addr(), "/ip4/0.0.0.0/udp/0/quic-v1");
    }

    #[test]
    fn an_unsupported_muxer_is_refused_rather_than_silently_dialled() {
        let err = Config::parse(env(&[
            ("IS_DIALER", "true"),
            ("REDIS_ADDR", "redis:6379"),
            ("TEST_KEY", "k"),
            ("TRANSPORT", "tcp"),
            ("SECURE_CHANNEL", "noise"),
            ("MUXER", "mplex"),
        ]))
        .expect_err("mplex is not supported");
        assert!(err.to_string().contains("MUXER=mplex"), "{err}");
    }

    #[test]
    fn a_missing_setting_names_itself() {
        let err = Config::parse(env(&[
            ("IS_DIALER", "true"),
            ("TEST_KEY", "k"),
            ("TRANSPORT", "quic-v1"),
        ]))
        .expect_err("REDIS_ADDR is missing");
        assert!(err.to_string().contains("REDIS_ADDR"), "{err}");
    }

    const TEST_PLANS_TCP: &[(&str, &str)] = &[
        ("is_dialer", "true"),
        ("transport", "tcp"),
        ("security", "noise"),
        ("muxer", "yamux"),
    ];

    #[test]
    fn test_plans_settings_are_read_with_its_own_defaults() {
        let config = Config::parse(env(TEST_PLANS_TCP)).expect("parses");
        assert_eq!(config.harness, Harness::TestPlans);
        assert!(config.is_dialer);
        // test-plans passes neither of these unless it overrides them.
        assert_eq!(config.redis_addr, "redis:6379");
        assert_eq!(config.listen_ip, "0.0.0.0");
        assert_eq!(config.timeout, DEFAULT_TEST_TIMEOUT);
        // The key is fixed, not derived from a per-test id.
        assert_eq!(config.redis_key, "listenerAddr");
    }

    #[test]
    fn test_plans_overrides_are_honoured() {
        let config = Config::parse(env(&[
            ("is_dialer", "false"),
            ("transport", "quic-v1"),
            ("redis_addr", "127.0.0.1:6379"),
            ("ip", "10.0.0.7"),
            ("test_timeout_seconds", "42"),
        ]))
        .expect("parses");
        assert_eq!(config.redis_addr, "127.0.0.1:6379");
        assert_eq!(config.timeout, Duration::from_secs(42));
        assert_eq!(config.bind_addr(), "/ip4/10.0.0.7/udp/0/quic-v1");
    }

    #[test]
    fn the_harness_is_told_apart_by_its_dialer_flag() {
        assert_eq!(
            Config::parse(env(UNIFIED_TCP)).expect("parses").harness,
            Harness::UnifiedTesting
        );
        let both = Config::parse(env(&[("IS_DIALER", "true"), ("is_dialer", "true")]))
            .expect_err("ambiguous");
        assert!(both.to_string().contains("both"), "{both}");
        let neither = Config::parse(env(&[("transport", "tcp")])).expect_err("no flag");
        assert!(neither.to_string().contains("is_dialer"), "{neither}");
    }

    #[test]
    fn each_harness_prints_the_result_shape_its_runner_parses() {
        let (handshake, ping) = (Duration::from_micros(2618), Duration::from_micros(136));
        assert_eq!(
            Harness::UnifiedTesting.result(handshake, ping),
            "latency:\n  handshake_plus_one_rtt: 2.618\n  ping_rtt: 0.136\n  unit: ms"
        );
        // Three l's in `pingRTTMilllis` is the spec's spelling, not a typo here.
        assert_eq!(
            Harness::TestPlans.result(handshake, ping),
            "{\"handshakePlusOneRTTMillis\": 2.618, \"pingRTTMilllis\": 0.136}"
        );
    }
}
