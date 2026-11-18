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

/// Matches the framework's own per-test timeout ballpark.
const TEST_TIMEOUT: Duration = Duration::from_secs(180);

struct Config {
    is_dialer: bool,
    redis_addr: String,
    redis_key: String,
    transport: String,
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
        let var = |name: &str| env::var(name).map_err(|_| format!("{name} is not set"));
        let transport = var("TRANSPORT")?;
        if transport == "tcp" {
            // Standalone transports (quic-v1) get neither variable.
            for (name, supported) in [("SECURE_CHANNEL", "noise"), ("MUXER", "yamux")] {
                let value = var(name)?;
                if value != supported {
                    return Err(format!("unsupported {name}={value} (only {supported})").into());
                }
            }
        } else if transport != "quic-v1" {
            return Err(format!("unsupported TRANSPORT={transport}").into());
        }
        Ok(Self {
            is_dialer: var("IS_DIALER")? == "true",
            redis_addr: var("REDIS_ADDR")?,
            redis_key: format!("{}_listener_multiaddr", var("TEST_KEY")?),
            transport,
            debug: env::var("DEBUG").is_ok_and(|v| v == "true"),
        })
    }

    fn bind_addr(&self) -> &'static str {
        match self.transport.as_str() {
            "tcp" => "/ip4/0.0.0.0/tcp/0",
            _ => "/ip4/0.0.0.0/udp/0/quic-v1",
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
    // The bound address is the wildcard; publish the interface that reaches
    // Redis, which is the one the dialer shares a network with.
    let ip = UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| s.connect(&config.redis_addr).and(s.local_addr()))?
        .ip();
    let addr = node
        .listen()?
        .to_string()
        .replacen("0.0.0.0", &ip.to_string(), 1);
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
    let timeout = TEST_TIMEOUT.as_secs().to_string();
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
    let deadline = Instant::now() + TEST_TIMEOUT;
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
                println!("latency:");
                println!(
                    "  handshake_plus_one_rtt: {:.3}",
                    millis(handshake_plus_one_rtt)
                );
                println!("  ping_rtt: {:.3}", millis(ping_rtt));
                println!("  unit: ms");
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
