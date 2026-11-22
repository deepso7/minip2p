//! Circuit Relay v2 test app for the `relay` suite of
//! <https://github.com/libp2p/unified-testing>.
//!
//! One image, three roles picked by `ROLE` (relay, listener, dialer), over
//! TCP with Noise and Yamux on one flat Docker network. The contract has no
//! written spec; it is the go reference app's, `relay/images/go/main.go`:
//!
//! - The relay publishes its multiaddr as the string key
//!   `<TEST_KEY>_relay_multiaddr` (`SET`, not a list as in transport).
//! - The listener reserves a slot on the relay, publishes its peer id as
//!   `<TEST_KEY>_listener_peer_id`, and echoes `/relay-echo/1.0.0`.
//! - The dialer reaches the listener through the relay, sends the fixed
//!   11-byte `hello-relay`, and checks it comes back. It prints `status: pass`
//!   and exits 0, or prints `error: …` and `status: fail` and exits 1.
//!
//! Every role prints `error: …` and `status: fail` on failure, so a failing
//! relay or listener reads as clearly in the logs as a failing dialer.
//!
//! DCUtR is off in every role so the echo can only travel over the circuit.
//! minip2p's DCUtR punches only QUIC targets on public addresses by default,
//! so it would not fire here anyway; turning it off keeps the test honest if
//! that changes.

use std::collections::HashSet;
use std::env;
use std::time::{Duration, Instant};

use minip2p::{
    ConnectOutcome, Endpoint, EndpointEvent, EndpointWaitOutcome, NatConfig, NatEvent, PeerAddr,
    PeerId, ReservationPolicy,
};
use minip2p_unified_testing::redis::Redis;
use minip2p_unified_testing::{Result, local_ip_towards};

const ECHO_PROTOCOL: &str = "/relay-echo/1.0.0";
const ECHO_MSG: &[u8] = b"hello-relay";
/// The go reference waits 60 s for each key and 90 s for a circuit dial.
const KEY_TIMEOUT: Duration = Duration::from_secs(60);
const DIAL_TIMEOUT: Duration = Duration::from_secs(90);

struct Config {
    role: String,
    redis_addr: String,
    test_key: String,
    debug: bool,
}

impl Config {
    fn log(&self, msg: impl std::fmt::Display) {
        if self.debug {
            eprintln!("[minip2p {}] {msg}", self.role);
        }
    }

    fn key(&self, name: &str) -> String {
        format!("{}_{name}", self.test_key)
    }

    /// TCP on this container's interface. A concrete address rather than
    /// `0.0.0.0` so the relay announces, and peers dial, a reachable one.
    fn bind_addr(&self) -> Result<String> {
        Ok(format!(
            "/ip4/{}/tcp/0",
            local_ip_towards(&self.redis_addr)?
        ))
    }
}

fn main() {
    let result = Config::from_env().and_then(|config| match config.role.as_str() {
        "relay" => relay(&config),
        "listener" => listener(&config),
        "dialer" => dialer(&config),
        other => Err(format!("unknown ROLE={other}").into()),
    });
    if let Err(e) = result {
        println!("error: {e}");
        println!("status: fail");
        std::process::exit(1);
    }
}

impl Config {
    fn from_env() -> Result<Self> {
        let var = |name: &str| env::var(name).map_err(|_| format!("{name} is not set"));
        Ok(Self {
            role: var("ROLE")?,
            redis_addr: var("REDIS_ADDR")?,
            test_key: var("TEST_KEY")?,
            debug: env::var("DEBUG").is_ok_and(|v| v == "true"),
        })
    }
}

fn relay(config: &Config) -> Result<()> {
    let mut node = Endpoint::builder()
        .listen_on(config.bind_addr()?)?
        .relay_server()
        .bind()?;
    let addr = node.listen()?.to_string();
    config.log(format_args!("relay at {addr}"));
    Redis::connect(&config.redis_addr)?.command(&["SET", &config.key("relay_multiaddr"), &addr])?;
    serve(config, &mut node, |_, _| {})
}

/// Reserves a slot on the relay, publishes the peer id once the reservation
/// is held (the dialer reads it as "reachable through the relay"), and echoes
/// each chunk as it arrives: the go dialer reads its 11 bytes back without
/// first closing its write side.
///
/// The reservation policy is `Always` to make the reservation explicit rather
/// than depend on the default's reachability verdict.
fn listener(config: &Config) -> Result<()> {
    let mut redis = Redis::connect(&config.redis_addr)?;
    let relay: PeerAddr = redis
        .wait_get(&config.key("relay_multiaddr"), KEY_TIMEOUT)?
        .parse()?;
    let mut node = Endpoint::builder()
        .listen_on(config.bind_addr()?)?
        .protocol(ECHO_PROTOCOL)
        .relay(relay)
        .nat_config(NatConfig {
            reservation_policy: ReservationPolicy::Always,
            dcutr: false,
            ..NatConfig::default()
        })
        .bind()?;

    let peer_key = config.key("listener_peer_id");
    let peer_id = node.peer_id().to_string();
    let mut published = false;
    let mut echoes = HashSet::new();
    serve(config, &mut node, |node, event| match event {
        EndpointEvent::Nat(NatEvent::RelayReserved { .. }) if !published => {
            published = redis.command(&["SET", &peer_key, &peer_id]).is_ok();
        }
        EndpointEvent::StreamReady {
            stream,
            protocol_id,
            initiated_locally: false,
            ..
        } if protocol_id == ECHO_PROTOCOL => {
            echoes.insert(*stream);
        }
        EndpointEvent::StreamData { stream, data, .. } if echoes.contains(stream) => {
            if node.send_stream(*stream, data.clone()).is_err() {
                echoes.remove(stream);
            }
        }
        EndpointEvent::StreamRemoteWriteClosed { stream, .. } if echoes.remove(stream) => {
            let _ = node.close_stream_write(*stream);
        }
        EndpointEvent::StreamClosed { stream, .. } => {
            echoes.remove(stream);
        }
        _ => {}
    })
}

/// Drives `node` until Docker stops the container, handing each event to
/// `on_event`.
fn serve(
    config: &Config,
    node: &mut Endpoint,
    mut on_event: impl FnMut(&mut Endpoint, &EndpointEvent),
) -> Result<()> {
    loop {
        if let EndpointWaitOutcome::Event(event) = node.wait(Duration::from_secs(1))? {
            config.log(format_args!("{event:?}"));
            on_event(node, &event);
        }
    }
}

/// Reaches the listener only through the relay (no direct candidates, no
/// punch, no reservation of its own) and checks the echo. A failed circuit
/// dial is retried, as the go reference does, because the reservation can
/// lag the published peer id. A rejected or reset echo stream, or a dropped
/// circuit, fails at once rather than waiting out [`DIAL_TIMEOUT`].
fn dialer(config: &Config) -> Result<()> {
    let mut redis = Redis::connect(&config.redis_addr)?;
    let relay: PeerAddr = redis
        .wait_get(&config.key("relay_multiaddr"), KEY_TIMEOUT)?
        .parse()?;
    let peer: PeerId = redis
        .wait_get(&config.key("listener_peer_id"), KEY_TIMEOUT)?
        .parse()?;
    let mut node = Endpoint::builder()
        .listen_on(config.bind_addr()?)?
        .protocol(ECHO_PROTOCOL)
        .relay(relay)
        .nat_config(NatConfig {
            reservation_policy: ReservationPolicy::Never,
            force_relay: true,
            dcutr: false,
            ..NatConfig::default()
        })
        .bind()?;

    let deadline = Instant::now() + DIAL_TIMEOUT;
    let mut connect_id = node.connect(peer)?;
    let mut echo_stream = None;
    let mut echoed = Vec::new();
    loop {
        if Instant::now() >= deadline {
            return Err("timed out before the echo came back".into());
        }
        let EndpointWaitOutcome::Event(event) = node.wait(deadline)? else {
            continue;
        };
        config.log(format_args!("{event:?}"));
        match event {
            EndpointEvent::ConnectSettled {
                connect_id: id,
                outcome,
                ..
            } if id == connect_id => match outcome {
                ConnectOutcome::Connected { .. } => {
                    echo_stream = Some(node.open_stream(&peer, ECHO_PROTOCOL)?);
                }
                other => {
                    config.log(format_args!("circuit dial failed, retrying: {other:?}"));
                    std::thread::sleep(Duration::from_secs(2));
                    connect_id = node.connect(peer)?;
                }
            },
            EndpointEvent::StreamReady {
                stream,
                initiated_locally: true,
                ..
            } => node.send_stream(stream, ECHO_MSG)?,
            EndpointEvent::StreamData { stream, data, .. } if Some(stream) == echo_stream => {
                echoed.extend_from_slice(&data);
                if echoed.len() >= ECHO_MSG.len() {
                    if echoed != ECHO_MSG {
                        return Err(format!("echo mismatch: got {echoed:?}").into());
                    }
                    println!("status: pass");
                    return Ok(());
                }
            }
            EndpointEvent::StreamClosed { stream, .. } if Some(stream) == echo_stream => {
                return Err(format!("echo stream closed after {} bytes", echoed.len()).into());
            }
            EndpointEvent::ConnectionClosed {
                peer_id, reason, ..
            } if peer_id == peer && echo_stream.is_some() => {
                return Err(format!("circuit closed before the echo: {reason:?}").into());
            }
            EndpointEvent::Error(e) if e.peer_id == Some(peer) && echo_stream.is_some() => {
                return Err(format!("echo stream failed: {}", e.detail).into());
            }
            _ => {}
        }
    }
}
