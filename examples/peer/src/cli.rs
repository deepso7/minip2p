//! Argv parsing and small shared helpers for `minip2p-peer`.
//!
//! The grammar is:
//!
//! ```text
//! minip2p-peer listen [--relay <relay-peer-addr>] [--autonat <peer-addr>] [--key <path>] [--listen <quic-multiaddr>]
//! minip2p-peer dial <target> [--relay <peer-addr>] [--autonat <peer-addr>] [--count <n>] [--key <path>] [--listen <quic-multiaddr>]
//! ```
//!
//! `<target>` is either a circuit address copied from the listener's
//! `circuit=` line (`/…/p2p/<relay>/p2p-circuit/p2p/<peer>`) or a plain
//! peer-addr (`/ip4/…/udp/…/quic-v1/p2p/<peer-id>`) for a directly
//! reachable peer.
//!
//! Keeping the parser hand-rolled avoids pulling in `clap` for the small
//! CLI and keeps the whole example dependency-light.

use std::path::PathBuf;
use std::str::FromStr;

use minip2p::{Event, Multiaddr, PeerAddr, PeerId, Protocol};

/// The modes the CLI dispatches to.
#[derive(Clone, Debug)]
pub enum Mode {
    /// Bind, listen, echo every inbound ping stream. With `--relay`, also
    /// hold a reservation and print the circuit address dialers can use.
    Listen {
        relay: Option<PeerAddr>,
        options: RunOptions,
    },
    /// Connect to `target` through the NAT agent and ping continuously,
    /// tagging each RTT with the current path.
    Dial {
        target: DialTarget,
        relay: Option<PeerAddr>,
        /// Stop after this many pings (graceful exit + summary).
        count: Option<u64>,
        options: RunOptions,
    },
}

/// What `dial <target>` points at.
#[derive(Clone, Debug)]
pub enum DialTarget {
    /// A circuit address: reach `peer` through `relay`, then hole-punch.
    Circuit { relay: PeerAddr, peer: PeerId },
    /// A directly dialable peer address.
    Direct(PeerAddr),
}

/// Runtime options common to both modes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RunOptions {
    /// Optional persistent Ed25519 raw-secret file.
    pub key_path: Option<PathBuf>,
    /// Optional QUIC listen/bind multiaddr. Defaults to dual-stack UDP/0.
    pub listen_addr: Option<Multiaddr>,
    /// Optional AutoNAT server used for reachability probes.
    pub autonat: Option<PeerAddr>,
}

/// Parse error surfaced back to `main` so the binary exits with a readable
/// message rather than a panic.
#[derive(Clone, Debug)]
pub struct CliError(pub String);

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CliError {}

/// Parse argv (exclusive of the binary name) into a [`Mode`].
pub fn parse(mut args: Vec<String>) -> Result<Mode, CliError> {
    if args.is_empty() {
        return Err(CliError(usage()));
    }

    let subcommand = args.remove(0);
    match subcommand.as_str() {
        "listen" => parse_listen(args),
        "dial" => parse_dial(args),
        "-h" | "--help" | "help" => Err(CliError(usage())),
        other => Err(CliError(format!(
            "unknown subcommand '{other}'\n\n{}",
            usage()
        ))),
    }
}

fn parse_listen(args: Vec<String>) -> Result<Mode, CliError> {
    let flags = Flags::from(args.as_slice())?;
    if flags.count.is_some() {
        return Err(CliError("--count is only valid with `dial`".into()));
    }
    Ok(Mode::Listen {
        relay: flags.relay,
        options: flags.options,
    })
}

fn parse_dial(args: Vec<String>) -> Result<Mode, CliError> {
    let mut positional: Vec<String> = Vec::new();
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg.starts_with("--") {
            rest.push(arg.clone());
            let value = args
                .get(i + 1)
                .ok_or_else(|| CliError(format!("flag '{arg}' requires a value")))?;
            rest.push(value.clone());
            i += 2;
        } else {
            positional.push(arg.clone());
            i += 1;
        }
    }

    let flags = Flags::from(rest.as_slice())?;
    match positional.as_slice() {
        [raw] => Ok(Mode::Dial {
            target: parse_dial_target(raw)?,
            relay: flags.relay,
            count: flags.count,
            options: flags.options,
        }),
        [] => Err(CliError("`dial` requires a <target> address".into())),
        many => Err(CliError(format!(
            "expected exactly one positional <target>, got {}",
            many.len()
        ))),
    }
}

/// Parses `dial`'s `<target>`: a circuit address ending in
/// `/p2p/<relay>/p2p-circuit/p2p/<peer>`, or a plain peer-addr.
pub fn parse_dial_target(raw: &str) -> Result<DialTarget, CliError> {
    let addr =
        Multiaddr::from_str(raw).map_err(|e| CliError(format!("invalid target '{raw}': {e}")))?;
    if !addr
        .protocols()
        .iter()
        .any(|protocol| matches!(protocol, Protocol::P2pCircuit))
    {
        let target = PeerAddr::from_str(raw)
            .map_err(|e| CliError(format!("invalid target peer-addr '{raw}': {e}")))?;
        require_quic_transport("target", raw, &target)?;
        return Ok(DialTarget::Direct(target));
    }

    match addr.protocols() {
        [
            prefix @ ..,
            Protocol::P2p(relay_id),
            Protocol::P2pCircuit,
            Protocol::P2p(peer),
        ] if !prefix.is_empty() => {
            let relay = PeerAddr::new(Multiaddr::from_protocols(prefix.to_vec()), relay_id.clone())
                .map_err(|e| CliError(format!("invalid relay address in '{raw}': {e}")))?;
            require_quic_transport("circuit relay", raw, &relay)?;
            Ok(DialTarget::Circuit {
                relay,
                peer: peer.clone(),
            })
        }
        _ => Err(CliError(format!(
            "circuit target must end /p2p/<relay>/p2p-circuit/p2p/<peer>, got '{raw}'"
        ))),
    }
}

/// Accumulated flag values shared by both subcommands.
struct Flags {
    relay: Option<PeerAddr>,
    count: Option<u64>,
    options: RunOptions,
}

impl Flags {
    fn from(args: &[String]) -> Result<Self, CliError> {
        let mut relay: Option<PeerAddr> = None;
        let mut count: Option<u64> = None;
        let mut options = RunOptions::default();

        let mut i = 0;
        while i < args.len() {
            let key = &args[i];

            match key.as_str() {
                "--relay" => {
                    let value = flag_value(args, i, key)?;
                    if relay.is_some() {
                        return Err(CliError("--relay specified twice".into()));
                    }
                    let addr = PeerAddr::from_str(value)
                        .map_err(|e| CliError(format!("invalid --relay '{value}': {e}")))?;
                    require_quic_transport("--relay", value, &addr)?;
                    relay = Some(addr);
                }
                "--count" => {
                    let value = flag_value(args, i, key)?;
                    if count.is_some() {
                        return Err(CliError("--count specified twice".into()));
                    }
                    let n = u64::from_str(value)
                        .map_err(|e| CliError(format!("invalid --count '{value}': {e}")))?;
                    if n == 0 {
                        return Err(CliError("--count must be at least 1".into()));
                    }
                    count = Some(n);
                }
                "--key" => {
                    let value = flag_value(args, i, key)?;
                    if options.key_path.is_some() {
                        return Err(CliError("--key specified twice".into()));
                    }
                    options.key_path = Some(PathBuf::from(value));
                }
                "--listen" => {
                    let value = flag_value(args, i, key)?;
                    if options.listen_addr.is_some() {
                        return Err(CliError("--listen specified twice".into()));
                    }
                    let addr = parse_quic_multiaddr("--listen", value)?;
                    if !matches!(
                        addr.protocols().first(),
                        Some(Protocol::Ip4(_) | Protocol::Ip6(_))
                    ) {
                        return Err(CliError(format!(
                            "--listen requires /ip4 or /ip6 host, got '{value}'"
                        )));
                    }
                    options.listen_addr = Some(addr);
                }
                "--autonat" => {
                    let value = flag_value(args, i, key)?;
                    if options.autonat.is_some() {
                        return Err(CliError("--autonat specified twice".into()));
                    }
                    let addr = PeerAddr::from_str(value).map_err(|e| {
                        CliError(format!("invalid --autonat peer-addr '{value}': {e}"))
                    })?;
                    require_quic_transport("--autonat", value, &addr)?;
                    options.autonat = Some(addr);
                }
                other => {
                    return Err(CliError(format!("unknown flag '{other}'")));
                }
            }
            i += 2;
        }

        Ok(Self {
            relay,
            count,
            options,
        })
    }
}

fn flag_value<'a>(args: &'a [String], i: usize, key: &str) -> Result<&'a String, CliError> {
    args.get(i + 1)
        .ok_or_else(|| CliError(format!("flag '{key}' requires a value")))
}

/// Rejects peer addresses the endpoint could never dial: everything this
/// demo connects to is QUIC, and catching the shape here turns an
/// asynchronous NAT-agent dial failure into an immediate input error.
fn require_quic_transport(what: &str, raw: &str, addr: &PeerAddr) -> Result<(), CliError> {
    if addr.transport().is_quic_transport() {
        Ok(())
    } else {
        Err(CliError(format!(
            "{what} must be on a /ip4|ip6|dns|dns4|dns6/<host>/udp/<port>/quic-v1 transport, got '{raw}'"
        )))
    }
}

fn parse_quic_multiaddr(flag: &str, value: &str) -> Result<Multiaddr, CliError> {
    let addr = Multiaddr::from_str(value)
        .map_err(|e| CliError(format!("invalid {flag} '{value}': {e}")))?;
    if !addr.is_quic_transport() {
        return Err(CliError(format!(
            "{flag} must be /ip4|ip6|dns|dns4|dns6/<host>/udp/<port>/quic-v1, got '{value}'"
        )));
    }
    Ok(addr)
}

/// Prints an [`Event`] in the CLI's one-event-per-line format.
///
/// `role` is the tag shown in brackets at the start of the line
/// (`listen` or `dial`).
pub fn print_event(role: &str, event: &Event) {
    match event {
        Event::ConnectionEstablished { peer_id, .. } => {
            println!("[{role}] connected peer={peer_id}");
        }
        Event::ConnectionClosed { peer_id, .. } => {
            println!("[{role}] disconnected peer={peer_id}");
        }
        Event::IdentifyReceived { peer_id, info } => {
            let agent = info.agent_version.as_deref().unwrap_or("?");
            let nprotos = info.protocols.len();
            let protocols = format_protocols(&info.protocols);
            let observed = info
                .observed_addr
                .as_deref()
                .and_then(|bytes| Multiaddr::from_bytes(bytes).ok())
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "?".into());
            println!(
                "[{role}] identify peer={peer_id} agent={agent} protocols={nprotos} list=[{protocols}] observed={observed}"
            );
        }
        Event::PeerReady { peer_id, protocols } => {
            let protocol_list = format_protocols(protocols);
            println!(
                "[{role}] peer-ready peer={peer_id} protocols={} list=[{}]",
                protocols.len(),
                protocol_list
            );
        }
        Event::PingRttMeasured { peer_id, rtt_ms } => {
            println!("[{role}] ping peer={peer_id} rtt={rtt_ms}ms");
        }
        Event::PingTimeout { peer_id } => {
            println!("[{role}] ping-timeout peer={peer_id}");
        }
        Event::StreamReady {
            peer_id,
            stream_id,
            protocol_id,
            initiated_locally,
            ..
        } => {
            let dir = if *initiated_locally {
                "outbound"
            } else {
                "inbound"
            };
            println!(
                "[{role}] user-stream-ready peer={peer_id} stream={stream_id} \
                 protocol={protocol_id} dir={dir}"
            );
        }
        Event::StreamData {
            peer_id,
            stream_id,
            data,
            ..
        } => {
            println!(
                "[{role}] user-stream-data peer={peer_id} stream={stream_id} bytes={}",
                data.len()
            );
        }
        Event::StreamRemoteWriteClosed {
            peer_id, stream_id, ..
        } => {
            println!("[{role}] user-stream-remote-write-closed peer={peer_id} stream={stream_id}");
        }
        Event::StreamClosed {
            peer_id, stream_id, ..
        } => {
            println!("[{role}] user-stream-closed peer={peer_id} stream={stream_id}");
        }
        Event::Error(error) => {
            eprintln!("[{role}] error {:?}: {}", error.kind, error.detail);
        }
    }
}

fn format_protocols(protocols: &[String]) -> String {
    protocols.join(",")
}

/// Usage text printed on `--help` and parse errors.
pub fn usage() -> String {
    "minip2p-peer -- NAT-aware echo-ping demo for the minip2p stack.

USAGE:
    minip2p-peer listen [--relay <relay-peer-addr>] [--autonat <peer-addr>] [--key <path>] [--listen <quic-multiaddr>]
    minip2p-peer dial   <target> [--relay <peer-addr>] [--autonat <peer-addr>] [--count <n>] [--key <path>] [--listen <quic-multiaddr>]

NOTES:
    <target>           circuit address from the listener's `circuit=` line
                       (/…/p2p/<relay>/p2p-circuit/p2p/<peer>), or a plain
                       peer-addr (/ip4/…/udp/…/quic-v1/p2p/<peer-id>)
    <relay-peer-addr>  full peer-addr of a Circuit Relay v2 server
    --relay            extra relay for the NAT agent (optional in both modes)
    --autonat          AutoNAT server used for reachability probes
    --count            dial only: stop after n pings, print a summary, exit
    --key              persistent Ed25519 raw-secret file (hex)
    --listen           bind multiaddr; default is dual-stack UDP/0

    See examples/peer/README.md for full usage examples."
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    const PEER_ADDR: &str =
        "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N";
    const QUIC_ADDR: &str = "/ip4/0.0.0.0/udp/0/quic-v1";
    const PEER_ID: &str = "QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N";

    fn circuit_addr() -> String {
        format!("{PEER_ADDR}/p2p-circuit/p2p/{PEER_ID}")
    }

    #[test]
    fn empty_argv_returns_usage() {
        let err = parse(v(&[])).unwrap_err();
        assert!(err.0.contains("USAGE"));
    }

    #[test]
    fn listen_without_args() {
        match parse(v(&["listen"])).unwrap() {
            Mode::Listen { relay, options } => {
                assert!(relay.is_none());
                assert_eq!(options, RunOptions::default());
            }
            other => panic!("expected Listen, got {other:?}"),
        }
    }

    #[test]
    fn listen_with_relay_and_autonat() {
        match parse(v(&["listen", "--relay", PEER_ADDR, "--autonat", PEER_ADDR])).unwrap() {
            Mode::Listen { relay, options } => {
                assert_eq!(relay.unwrap().to_string(), PEER_ADDR);
                assert_eq!(options.autonat.unwrap().to_string(), PEER_ADDR);
            }
            other => panic!("expected Listen, got {other:?}"),
        }
    }

    #[test]
    fn listen_accepts_key_and_listen_addr() {
        match parse(v(&["listen", "--key", "./peer.key", "--listen", QUIC_ADDR])).unwrap() {
            Mode::Listen { options, .. } => {
                assert_eq!(options.key_path, Some(PathBuf::from("./peer.key")));
                assert_eq!(options.listen_addr.unwrap().to_string(), QUIC_ADDR);
            }
            other => panic!("expected Listen, got {other:?}"),
        }
    }

    #[test]
    fn listen_rejects_count() {
        let err = parse(v(&["listen", "--count", "3"])).unwrap_err();
        assert!(err.0.contains("--count"));
    }

    #[test]
    fn dial_with_direct_peer_addr() {
        match parse(v(&["dial", PEER_ADDR])).unwrap() {
            Mode::Dial {
                target: DialTarget::Direct(addr),
                relay,
                count,
                ..
            } => {
                assert_eq!(addr.to_string(), PEER_ADDR);
                assert!(relay.is_none());
                assert!(count.is_none());
            }
            other => panic!("expected direct Dial, got {other:?}"),
        }
    }

    #[test]
    fn dial_with_circuit_target_round_trips() {
        match parse(v(&["dial", &circuit_addr()])).unwrap() {
            Mode::Dial {
                target: DialTarget::Circuit { relay, peer },
                ..
            } => {
                assert_eq!(relay.to_string(), PEER_ADDR);
                assert_eq!(peer.to_string(), PEER_ID);
            }
            other => panic!("expected circuit Dial, got {other:?}"),
        }
    }

    #[test]
    fn dial_accepts_count_and_extra_relay() {
        match parse(v(&[
            "dial", PEER_ADDR, "--count", "5", "--relay", PEER_ADDR,
        ]))
        .unwrap()
        {
            Mode::Dial { relay, count, .. } => {
                assert_eq!(count, Some(5));
                assert_eq!(relay.unwrap().to_string(), PEER_ADDR);
            }
            other => panic!("expected Dial, got {other:?}"),
        }
    }

    #[test]
    fn dial_rejects_zero_count() {
        let err = parse(v(&["dial", PEER_ADDR, "--count", "0"])).unwrap_err();
        assert!(err.0.contains("--count"));
    }

    #[test]
    fn dial_rejects_duplicate_count() {
        let err = parse(v(&["dial", PEER_ADDR, "--count", "2", "--count", "3"])).unwrap_err();
        assert!(err.0.contains("twice"));
    }

    #[test]
    fn dial_without_target_errors() {
        let err = parse(v(&["dial"])).unwrap_err();
        assert!(err.0.contains("<target>"));
    }

    #[test]
    fn dial_rejects_multiple_targets() {
        let err = parse(v(&["dial", PEER_ADDR, PEER_ADDR])).unwrap_err();
        assert!(err.0.contains("exactly one"));
    }

    #[test]
    fn circuit_without_target_peer_errors() {
        let raw = format!("{PEER_ADDR}/p2p-circuit");
        let err = parse(v(&["dial", &raw])).unwrap_err();
        assert!(err.0.contains("p2p-circuit"));
    }

    #[test]
    fn circuit_without_relay_peer_errors() {
        let raw = format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p-circuit/p2p/{PEER_ID}");
        let err = parse(v(&["dial", &raw])).unwrap_err();
        assert!(err.0.contains("p2p-circuit"));
    }

    #[test]
    fn dial_rejects_non_quic_direct_target() {
        let raw = format!("/ip4/127.0.0.1/udp/4001/p2p/{PEER_ID}");
        let err = parse(v(&["dial", &raw])).unwrap_err();
        assert!(err.0.contains("quic-v1"));
    }

    #[test]
    fn dial_rejects_non_quic_circuit_relay() {
        let raw = format!("/ip4/127.0.0.1/udp/4001/p2p/{PEER_ID}/p2p-circuit/p2p/{PEER_ID}");
        let err = parse(v(&["dial", &raw])).unwrap_err();
        assert!(err.0.contains("quic-v1"));
    }

    #[test]
    fn relay_flag_rejects_non_quic_transport() {
        let raw = format!("/ip4/127.0.0.1/udp/4001/p2p/{PEER_ID}");
        let err = parse(v(&["listen", "--relay", &raw])).unwrap_err();
        assert!(err.0.contains("quic-v1"));
    }

    #[test]
    fn unknown_subcommand_errors() {
        let err = parse(v(&["frobnicate"])).unwrap_err();
        assert!(err.0.contains("unknown subcommand"));
    }

    #[test]
    fn unknown_flag_errors() {
        let err = parse(v(&["listen", "--external-addr", QUIC_ADDR])).unwrap_err();
        assert!(err.0.contains("unknown flag"));
    }

    #[test]
    fn invalid_target_errors() {
        let err = parse(v(&["dial", "not-a-multiaddr"])).unwrap_err();
        assert!(err.0.contains("invalid target"));
    }
}
