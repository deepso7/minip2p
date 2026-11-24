//! DCUtR test app for the `hole-punch` suite of
//! <https://github.com/libp2p/unified-testing>.
//!
//! Two peers sit behind their own NAT router and meet through a relay the
//! harness runs. The listener reserves a slot and publishes its peer id; the
//! dialer reaches it over the circuit, and DCUtR upgrades that circuit to a
//! direct connection. The dialer times the upgrade, pings over it, and prints
//! the `latency:` block the harness parses.
//!
//! The contract is the rust reference peer's,
//! `hole-punch/images/rust/v0.56/src/bin/peer.rs`: `IS_DIALER`, `REDIS_ADDR`,
//! `TEST_KEY`, `TRANSPORT`, `DIALER_IP`/`LISTENER_IP`, `DEBUG`; the string
//! keys `<TEST_KEY>_relay_multiaddr` (the relay sets it) and
//! `<TEST_KEY>_listener_peer_id`; and `handshake_plus_one_rtt` measured from
//! the circuit dial to the punch, plus one round trip on the punched path.
//!
//! Three constraints come from minip2p rather than the harness:
//!
//! - **QUIC only.** DCUtR keeps only `/quic-v1` punch candidates and never
//!   punches `/tcp`, so `TRANSPORT=tcp` is refused rather than silently
//!   measured over the relay.
//! - **`allow_private_punch_targets`.** Every testbed address is a private
//!   `10.x`, which the punch path drops by default; both roles need it,
//!   because the initiator dials those targets and the responder blasts UDP
//!   at them.
//! - **Bind the LAN address, never `0.0.0.0`.** Both peers are also attached
//!   to the harness's flat Redis network. A wildcard bind would advertise
//!   that address too, and a "punch" that succeeded over it would never have
//!   crossed a NAT — a false pass.
//!
//! The route to the relay's subnet is added by `run-peer.sh` before this
//! binary starts, from `WAN_SUBNET` and `WAN_ROUTER_IP`; the harness gives
//! the peers no route of their own.

use std::env;
use std::time::{Duration, Instant};

use minip2p::{
    ConnectOutcome, Endpoint, EndpointEvent, EndpointWaitOutcome, NatConfig, NatEvent, Path,
    PeerAddr, PeerId, ReservationPolicy,
};
use minip2p_unified_testing::Result;
use minip2p_unified_testing::redis::Redis;

/// The rust reference polls each key for 60 s.
const KEY_TIMEOUT: Duration = Duration::from_secs(60);
/// A punch is three DCUtR rounds inside a 20 s upgrade budget, after a
/// circuit dial; the harness itself bounds a test at 3 minutes.
const TEST_TIMEOUT: Duration = Duration::from_secs(150);

struct Config {
    is_dialer: bool,
    redis_addr: String,
    test_key: String,
    listen_ip: String,
    debug: bool,
}

impl Config {
    fn from_env() -> Result<Self> {
        let var = |name: &str| env::var(name).map_err(|_| format!("{name} is not set"));
        let is_dialer = var("IS_DIALER")? == "true";
        let transport = var("TRANSPORT")?;
        if transport != "quic-v1" {
            return Err(format!(
                "unsupported TRANSPORT={transport}: minip2p punches only QUIC targets"
            )
            .into());
        }
        let ip = if is_dialer {
            "DIALER_IP"
        } else {
            "LISTENER_IP"
        };
        Ok(Self {
            is_dialer,
            redis_addr: var("REDIS_ADDR")?,
            test_key: var("TEST_KEY")?,
            listen_ip: var(ip)?,
            debug: env::var("DEBUG").is_ok_and(|v| v == "true"),
        })
    }

    fn role(&self) -> &'static str {
        if self.is_dialer { "dialer" } else { "listener" }
    }

    fn log(&self, msg: impl std::fmt::Display) {
        if self.debug {
            eprintln!("[minip2p {}] {msg}", self.role());
        }
    }

    fn key(&self, name: &str) -> String {
        format!("{}_{name}", self.test_key)
    }

    fn bind_addr(&self) -> String {
        format!("/ip4/{}/udp/0/quic-v1", self.listen_ip)
    }

    /// Both roles punch, so both accept the testbed's private targets.
    fn nat_config(&self, reservation_policy: ReservationPolicy) -> NatConfig {
        NatConfig {
            reservation_policy,
            allow_private_punch_targets: true,
            ..NatConfig::default()
        }
    }
}

fn main() {
    let result = Config::from_env().and_then(|config| {
        if config.is_dialer {
            dialer(&config)
        } else {
            listener(&config)
        }
    });
    if let Err(e) = result {
        println!("error: {e}");
        std::process::exit(1);
    }
}

/// Reserves a slot on the relay and publishes the peer id once the
/// reservation is held, which is what the dialer waits on. Then it answers
/// the dialer's circuit and drives the DCUtR rounds: minip2p gives the
/// reservation holder that job (ADR 0017), so the listener is the initiator
/// here even though the dialer is the one being timed.
///
/// `ReservationPolicy::Always` because nothing in this suite runs AutoNAT and
/// the default reserves only once a node is known to be private.
fn listener(config: &Config) -> Result<()> {
    let mut redis = Redis::connect(&config.redis_addr)?;
    let relay: PeerAddr = redis
        .wait_get(&config.key("relay_multiaddr"), KEY_TIMEOUT)?
        .parse()?;
    let mut node = Endpoint::builder()
        .listen_on(config.bind_addr())?
        .relay(relay)
        .nat_config(config.nat_config(ReservationPolicy::Always))
        .bind()?;
    config.log(format_args!("listening on {}", node.listen()?));

    let peer_key = config.key("listener_peer_id");
    let peer_id = node.peer_id().to_string();
    let mut published = false;
    loop {
        if let EndpointWaitOutcome::Event(event) = node.wait(Duration::from_secs(1))? {
            config.log(format_args!("{event:?}"));
            match event {
                EndpointEvent::Nat(NatEvent::RelayReserved { .. }) if !published => {
                    redis.command(&["SET", &peer_key, &peer_id])?;
                    published = true;
                }
                EndpointEvent::Nat(NatEvent::InboundDirectUpgrade { new_conn_id, .. }) => {
                    config.log(format_args!("punched, now direct on {new_conn_id:?}"));
                }
                _ => {}
            }
        }
    }
}

/// Dials the listener through the relay and waits for the circuit to be
/// upgraded by a punch. The clock starts before the circuit dial, as the rust
/// reference's does, and `handshake_plus_one_rtt` is that span plus the one
/// ping that proves the punched path carries traffic.
///
/// Every outcome that makes success impossible is reported instead of waited
/// out: `FellBackToRelay` (the upgrade budget or all three rounds are gone,
/// and a relayed path alone is not a pass for this suite), and a ping that
/// fails or a punched connection that closes before the ping answers — only
/// one ping is sent, so nothing would arrive after either.
///
/// The upgrade is accepted as either `Punched` or `Direct`. A punch whose
/// winning connection is the *peer's* dial arriving inbound carries no local
/// punch record, so it is attributed `Direct` (the same class as #400 and
/// #402, on the circuit-dialer side). What makes this honest is `from`:
/// `PathUpgraded` off a `Relayed` path only comes from the upgrade machinery,
/// and the two peers sit behind separate NATs with no route between their LANs
/// — so a direct connection here can only be the hole punch.
fn dialer(config: &Config) -> Result<()> {
    let mut redis = Redis::connect(&config.redis_addr)?;
    let relay: PeerAddr = redis
        .wait_get(&config.key("relay_multiaddr"), KEY_TIMEOUT)?
        .parse()?;
    let peer: PeerId = redis
        .wait_get(&config.key("listener_peer_id"), KEY_TIMEOUT)?
        .parse()?;
    let mut node = Endpoint::builder()
        .listen_on(config.bind_addr())?
        .relay(relay)
        .nat_config(config.nat_config(ReservationPolicy::Never))
        .bind()?;
    config.log(format_args!("listening on {}", node.listen()?));

    let deadline = Instant::now() + TEST_TIMEOUT;
    let punch_start = Instant::now();
    let connect_id = node.connect(peer)?;
    let mut punched = None;
    let mut ping_start = Instant::now();
    loop {
        if Instant::now() >= deadline {
            return Err("timed out before the hole punch produced a ping".into());
        }
        let EndpointWaitOutcome::Event(event) = node.wait(deadline)? else {
            continue;
        };
        let now = Instant::now();
        config.log(format_args!("{event:?}"));
        match event {
            EndpointEvent::Nat(NatEvent::PathUpgraded {
                connect_id: id,
                to: Path::Punched | Path::Direct,
                new_conn_id,
                ..
            }) if id == connect_id => {
                punched = Some((new_conn_id, now - punch_start));
                ping_start = Instant::now();
                node.ping(&peer)?;
            }
            EndpointEvent::PingRttMeasured { conn_id, .. } => {
                let Some((punched_conn, punch_rtt)) = punched else {
                    continue;
                };
                if conn_id != punched_conn {
                    return Err(format!(
                        "ping answered on {conn_id:?}, not the punched {punched_conn:?}"
                    )
                    .into());
                }
                let ping_rtt = now - ping_start;
                println!("latency:");
                println!(
                    "  handshake_plus_one_rtt: {:.3}",
                    millis(punch_rtt + ping_rtt)
                );
                println!("  ping_rtt: {:.3}", millis(ping_rtt));
                println!("  unit: ms");
                return Ok(());
            }
            EndpointEvent::Nat(NatEvent::FellBackToRelay { reason, .. }) => {
                return Err(format!("no direct upgrade, settled on the relay: {reason:?}").into());
            }
            EndpointEvent::PingFailed { conn_id, cause, .. }
                if punched.is_some_and(|(punched_conn, _)| conn_id == punched_conn) =>
            {
                return Err(format!("ping over the punched path failed: {cause:?}").into());
            }
            EndpointEvent::ConnectionClosed {
                conn_id, reason, ..
            } if punched.is_some_and(|(punched_conn, _)| conn_id == punched_conn) => {
                return Err(
                    format!("punched connection closed before the ping: {reason:?}").into(),
                );
            }
            EndpointEvent::ConnectSettled {
                connect_id: id,
                outcome,
                ..
            } if id == connect_id => {
                if let ConnectOutcome::Connected { .. } = outcome {
                    continue;
                }
                return Err(format!("circuit dial failed: {outcome:?}").into());
            }
            _ => {}
        }
    }
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}
