//! Argv parsing for `minip2p-chat`.
//!
//! The grammar is:
//!
//! ```text
//! minip2p-chat host        [--topic <t>] [--nick <n>] [--relay <relay-peer-addr>] [--key <path>] [--listen <quic-multiaddr>]
//! minip2p-chat join <addr> [--topic <t>] [--nick <n>] [--relay <peer-addr>] [--key <path>] [--listen <quic-multiaddr>]
//! ```
//!
//! `<addr>` is either the host's printed `bound=` peer-addr, or its
//! `circuit=` address (`/…/p2p/<relay>/p2p-circuit/p2p/<peer>`) when the
//! host sits behind a NAT. Hand-rolled parser, same rationale as
//! `examples/peer`: no `clap`, dependency-light.

use std::path::PathBuf;
use std::str::FromStr;

use minip2p::{Multiaddr, PeerAddr, PeerId, Protocol};

/// The modes the CLI dispatches to.
#[derive(Clone, Debug)]
pub enum Mode {
    /// Bind, optionally reserve on a relay, and print the address(es)
    /// others join with. The host is an ordinary chat participant that
    /// also forwards between leaves (floodsub does that for free).
    Host {
        relay: Option<PeerAddr>,
        chat: ChatOptions,
    },
    /// Connect to a host (directly or through its relay circuit) and chat.
    Join {
        target: JoinTarget,
        relay: Option<PeerAddr>,
        chat: ChatOptions,
    },
}

/// What `join <addr>` points at.
#[derive(Clone, Debug)]
pub enum JoinTarget {
    /// A circuit address: reach `peer` through `relay`, then hole-punch.
    Circuit { relay: PeerAddr, peer: PeerId },
    /// A directly dialable peer address.
    Direct(PeerAddr),
}

/// Options shared by both modes.
#[derive(Clone, Debug, Default)]
pub struct ChatOptions {
    /// Chat room topic (defaults to `minip2p-chat`).
    pub topic: Option<String>,
    /// Display name (defaults to a peer-id prefix).
    pub nick: Option<String>,
    /// Optional persistent Ed25519 raw-secret file.
    pub key_path: Option<PathBuf>,
    /// Optional QUIC listen/bind multiaddr. Defaults to dual-stack UDP/0.
    pub listen_addr: Option<Multiaddr>,
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
        "host" => {
            let flags = Flags::from(args.as_slice())?;
            Ok(Mode::Host {
                relay: flags.relay,
                chat: flags.chat,
            })
        }
        "join" => parse_join(args),
        "-h" | "--help" | "help" => Err(CliError(usage())),
        other => Err(CliError(format!(
            "unknown subcommand '{other}'\n\n{}",
            usage()
        ))),
    }
}

fn parse_join(args: Vec<String>) -> Result<Mode, CliError> {
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
        [raw] => Ok(Mode::Join {
            target: parse_join_target(raw)?,
            relay: flags.relay,
            chat: flags.chat,
        }),
        [] => Err(CliError("`join` requires an <addr>".into())),
        many => Err(CliError(format!(
            "expected exactly one positional <addr>, got {}",
            many.len()
        ))),
    }
}

/// Parses `join`'s `<addr>`: a circuit address ending in
/// `/p2p/<relay>/p2p-circuit/p2p/<peer>`, or a plain peer-addr.
pub fn parse_join_target(raw: &str) -> Result<JoinTarget, CliError> {
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
        return Ok(JoinTarget::Direct(target));
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
            Ok(JoinTarget::Circuit {
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
    chat: ChatOptions,
}

impl Flags {
    fn from(args: &[String]) -> Result<Self, CliError> {
        let mut relay: Option<PeerAddr> = None;
        let mut chat = ChatOptions::default();

        let mut i = 0;
        while i < args.len() {
            let key = &args[i];

            match key.as_str() {
                "--topic" => {
                    let value = flag_value(args, i, key)?;
                    if chat.topic.is_some() {
                        return Err(CliError("--topic specified twice".into()));
                    }
                    if value.is_empty() {
                        return Err(CliError("--topic must be non-empty".into()));
                    }
                    chat.topic = Some(value.clone());
                }
                "--nick" => {
                    let value = flag_value(args, i, key)?;
                    if chat.nick.is_some() {
                        return Err(CliError("--nick specified twice".into()));
                    }
                    if value.is_empty() || value.contains(':') {
                        return Err(CliError(
                            "--nick must be non-empty and contain no ':'".into(),
                        ));
                    }
                    chat.nick = Some(value.clone());
                }
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
                "--key" => {
                    let value = flag_value(args, i, key)?;
                    if chat.key_path.is_some() {
                        return Err(CliError("--key specified twice".into()));
                    }
                    chat.key_path = Some(PathBuf::from(value));
                }
                "--listen" => {
                    let value = flag_value(args, i, key)?;
                    if chat.listen_addr.is_some() {
                        return Err(CliError("--listen specified twice".into()));
                    }
                    let addr = Multiaddr::from_str(value)
                        .map_err(|e| CliError(format!("invalid --listen '{value}': {e}")))?;
                    if !addr.is_quic_transport()
                        || !matches!(
                            addr.protocols().first(),
                            Some(Protocol::Ip4(_) | Protocol::Ip6(_))
                        )
                    {
                        return Err(CliError(format!(
                            "--listen must be /ip4|ip6/<host>/udp/<port>/quic-v1, got '{value}'"
                        )));
                    }
                    chat.listen_addr = Some(addr);
                }
                other => {
                    return Err(CliError(format!("unknown flag '{other}'")));
                }
            }
            i += 2;
        }

        Ok(Self { relay, chat })
    }
}

fn flag_value<'a>(args: &'a [String], i: usize, key: &str) -> Result<&'a String, CliError> {
    args.get(i + 1)
        .ok_or_else(|| CliError(format!("flag '{key}' requires a value")))
}

/// Rejects peer addresses the endpoint could never dial: everything this
/// demo connects to is QUIC, and catching the shape here turns an
/// asynchronous dial failure into an immediate input error.
fn require_quic_transport(what: &str, raw: &str, addr: &PeerAddr) -> Result<(), CliError> {
    if addr.transport().is_quic_transport() {
        Ok(())
    } else {
        Err(CliError(format!(
            "{what} must be on a /ip4|ip6|dns|dns4|dns6/<host>/udp/<port>/quic-v1 transport, got '{raw}'"
        )))
    }
}

/// Usage text printed on `--help` and parse errors.
pub fn usage() -> String {
    "minip2p-chat -- group chat over floodsub with NAT traversal.

USAGE:
    minip2p-chat host        [--topic <t>] [--nick <n>] [--relay <relay-peer-addr>] [--key <path>] [--listen <quic-multiaddr>]
    minip2p-chat join <addr> [--topic <t>] [--nick <n>] [--relay <peer-addr>] [--key <path>] [--listen <quic-multiaddr>]

NOTES:
    <addr>    the host's printed `bound=` peer-addr, or its `circuit=`
              address (/…/p2p/<relay>/p2p-circuit/p2p/<peer>) when the host
              is behind a NAT (joiners then hole-punch a direct path)
    --topic   chat room name (default: minip2p-chat)
    --nick    display name (default: first 8 chars of the peer id)
    --relay   relay peer-addr for NAT traversal / reservations
    --key     persistent Ed25519 raw-secret file (hex)
    --listen  bind multiaddr; default is dual-stack UDP/0

    Type lines on stdin to chat; EOF (Ctrl-D) exits.

    See examples/chat/README.md for full walkthroughs.
"
    .to_string()
}
