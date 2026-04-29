//! Argv parsing and small shared helpers for `minip2p-peer`.
//!
//! The grammar is:
//!
//! ```text
//! minip2p-peer listen
//! minip2p-peer dial   <peer-addr>
//! minip2p-peer listen --relay <relay-peer-addr>
//! minip2p-peer dial   --relay <relay-peer-addr> --target <peer-id>
//! ```
//!
//! Each `<peer-addr>` is a full libp2p-style string ending in
//! `/p2p/<peer-id>` (e.g. `/ip4/127.0.0.1/udp/4001/quic-v1/p2p/12D3...`).
//! The relay-dialer's `--target` is a bare `PeerId` because we reach B
//! *through* the relay; we don't know B's transport address yet.
//!
//! Keeping the parser hand-rolled avoids pulling in `clap` for the 4-mode
//! CLI and keeps the whole example dependency-light.

use std::str::FromStr;

use minip2p_core::{PeerAddr, PeerId};
use minip2p_swarm::SwarmEvent;

/// The four modes the CLI dispatches to.
#[derive(Clone, Debug)]
pub enum Mode {
    /// Bind a QUIC socket, listen, print our peer-addr, and echo every
    /// inbound ping. No relay involvement.
    DirectListen,
    /// Dial a peer directly, run ping, and exit on the first RTT event.
    DirectDial { target: PeerAddr },
    /// Connect to a relay, reserve a slot, accept an incoming circuit,
    /// then drive DCUtR + hole-punch against whoever calls us.
    RelayListen { relay: PeerAddr },
    /// Connect to a relay, open a circuit to `target`, drive DCUtR as the
    /// initiator, and fall back to relayed ping if hole-punch fails.
    RelayDial { relay: PeerAddr, target: PeerId },
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
    // Supported shapes:
    //   listen
    //   listen --relay <relay-peer-addr>
    let flags = Flags::from(args.as_slice())?;

    if flags.target.is_some() {
        return Err(CliError(
            "--target is only valid with `dial --relay`".into(),
        ));
    }

    match flags.relay {
        None => Ok(Mode::DirectListen),
        Some(relay) => Ok(Mode::RelayListen { relay }),
    }
}

fn parse_dial(args: Vec<String>) -> Result<Mode, CliError> {
    // Supported shapes:
    //   dial <peer-addr>
    //   dial --relay <relay-peer-addr> --target <peer-id>
    //
    // The two shapes are mutually exclusive: the first gives us a full
    // transport address, the second gives us a relay + a bare peer id.
    let mut positional: Vec<String> = Vec::new();
    let mut rest: Vec<String> = Vec::new();
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        if arg.starts_with("--") {
            rest.push(arg);
            if let Some(v) = iter.next() {
                rest.push(v);
            }
        } else {
            positional.push(arg);
        }
    }

    let flags = Flags::from(rest.as_slice())?;

    match (positional.len(), flags.relay, flags.target) {
        (1, None, None) => {
            let raw = &positional[0];
            let target = PeerAddr::from_str(raw)
                .map_err(|e| CliError(format!("invalid peer-addr '{raw}': {e}")))?;
            Ok(Mode::DirectDial { target })
        }
        (0, Some(relay), Some(target)) => Ok(Mode::RelayDial { relay, target }),
        (0, Some(_), None) => Err(CliError(
            "`dial --relay <addr>` requires `--target <peer-id>`".into(),
        )),
        (0, None, Some(_)) => Err(CliError(
            "`--target` requires `--relay <relay-peer-addr>`".into(),
        )),
        (n, _, _) if n > 1 => Err(CliError(format!(
            "expected exactly one positional <peer-addr>, got {n}"
        ))),
        _ => Err(CliError(usage())),
    }
}

/// Accumulated values for the `--relay` / `--target` flags.
struct Flags {
    relay: Option<PeerAddr>,
    target: Option<PeerId>,
}

impl Flags {
    fn from(args: &[String]) -> Result<Self, CliError> {
        let mut relay: Option<PeerAddr> = None;
        let mut target: Option<PeerId> = None;

        let mut i = 0;
        while i < args.len() {
            let key = &args[i];
            let value = args
                .get(i + 1)
                .ok_or_else(|| CliError(format!("flag '{key}' requires a value")))?;

            match key.as_str() {
                "--relay" => {
                    if relay.is_some() {
                        return Err(CliError("--relay specified twice".into()));
                    }
                    relay = Some(
                        PeerAddr::from_str(value)
                            .map_err(|e| CliError(format!("invalid --relay '{value}': {e}")))?,
                    );
                }
                "--target" => {
                    if target.is_some() {
                        return Err(CliError("--target specified twice".into()));
                    }
                    target = Some(PeerId::from_str(value).map_err(|e| {
                        CliError(format!("invalid --target peer id '{value}': {e}"))
                    })?);
                }
                other => {
                    return Err(CliError(format!("unknown flag '{other}'")));
                }
            }
            i += 2;
        }

        Ok(Self { relay, target })
    }
}

/// Prints a [`SwarmEvent`] in the plan's one-event-per-line format.
///
/// `role` is the tag shown in brackets at the start of the line
/// (`listen`, `dial`, `relay-listen`, `relay-dial`).
pub fn print_event(role: &str, event: &SwarmEvent) {
    match event {
        SwarmEvent::ConnectionEstablished { peer_id } => {
            println!("[{role}] connected peer={peer_id}");
        }
        SwarmEvent::ConnectionClosed { peer_id } => {
            println!("[{role}] disconnected peer={peer_id}");
        }
        SwarmEvent::IdentifyReceived { peer_id, info } => {
            let agent = info.agent_version.as_deref().unwrap_or("?");
            let nprotos = info.protocols.len();
            println!("[{role}] identify peer={peer_id} agent={agent} protocols={nprotos}");
        }
        SwarmEvent::PeerReady { peer_id, protocols } => {
            println!(
                "[{role}] peer-ready peer={peer_id} protocols={}",
                protocols.len()
            );
        }
        SwarmEvent::PingRttMeasured { peer_id, rtt_ms } => {
            println!("[{role}] ping peer={peer_id} rtt={rtt_ms}ms");
        }
        SwarmEvent::PingTimeout { peer_id } => {
            println!("[{role}] ping-timeout peer={peer_id}");
        }
        SwarmEvent::UserStreamReady {
            peer_id,
            stream_id,
            protocol_id,
            initiated_locally,
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
        SwarmEvent::UserStreamData {
            peer_id,
            stream_id,
            data,
        } => {
            println!(
                "[{role}] user-stream-data peer={peer_id} stream={stream_id} bytes={}",
                data.len()
            );
        }
        SwarmEvent::UserStreamRemoteWriteClosed { peer_id, stream_id } => {
            println!("[{role}] user-stream-remote-write-closed peer={peer_id} stream={stream_id}");
        }
        SwarmEvent::UserStreamClosed { peer_id, stream_id } => {
            println!("[{role}] user-stream-closed peer={peer_id} stream={stream_id}");
        }
        SwarmEvent::Error(error) => {
            eprintln!("[{role}] error {:?}: {}", error.kind, error.detail);
        }
    }
}

/// Usage text printed on `--help` and parse errors.
pub fn usage() -> String {
    "minip2p-peer -- demo CLI for the full minip2p stack.

USAGE:
    minip2p-peer listen
    minip2p-peer dial   <peer-addr>
    minip2p-peer listen --relay <relay-peer-addr>
    minip2p-peer dial   --relay <relay-peer-addr> --target <peer-id>

NOTES:
    <peer-addr>        full libp2p-style address ending in /p2p/<peer-id>
                       (e.g. /ip4/127.0.0.1/udp/4001/quic-v1/p2p/12D3...)
    <relay-peer-addr>  same format, pointing at the relay server
    <peer-id>          bare libp2p PeerId (12D3... or Qm...)

    See holepunch-plan.md at the repo root for full semantics."
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
    const PEER_ID: &str = "QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N";

    #[test]
    fn empty_argv_returns_usage() {
        let err = parse(v(&[])).unwrap_err();
        assert!(err.0.contains("USAGE"));
    }

    #[test]
    fn listen_without_args() {
        match parse(v(&["listen"])).unwrap() {
            Mode::DirectListen => {}
            other => panic!("expected DirectListen, got {other:?}"),
        }
    }

    #[test]
    fn listen_with_relay() {
        match parse(v(&["listen", "--relay", PEER_ADDR])).unwrap() {
            Mode::RelayListen { .. } => {}
            other => panic!("expected RelayListen, got {other:?}"),
        }
    }

    #[test]
    fn dial_with_positional_peer_addr() {
        match parse(v(&["dial", PEER_ADDR])).unwrap() {
            Mode::DirectDial { .. } => {}
            other => panic!("expected DirectDial, got {other:?}"),
        }
    }

    #[test]
    fn dial_with_relay_and_target() {
        match parse(v(&["dial", "--relay", PEER_ADDR, "--target", PEER_ID])).unwrap() {
            Mode::RelayDial { .. } => {}
            other => panic!("expected RelayDial, got {other:?}"),
        }
    }

    #[test]
    fn dial_with_relay_but_no_target_errors() {
        let err = parse(v(&["dial", "--relay", PEER_ADDR])).unwrap_err();
        assert!(err.0.contains("--target"));
    }

    #[test]
    fn dial_with_target_but_no_relay_errors() {
        let err = parse(v(&["dial", "--target", PEER_ID])).unwrap_err();
        assert!(err.0.contains("--relay"));
    }

    #[test]
    fn listen_rejects_target_flag() {
        let err = parse(v(&["listen", "--target", PEER_ID])).unwrap_err();
        assert!(err.0.contains("--target"));
    }

    #[test]
    fn unknown_subcommand_errors() {
        let err = parse(v(&["frobnicate"])).unwrap_err();
        assert!(err.0.contains("unknown subcommand"));
    }

    #[test]
    fn invalid_peer_addr_errors() {
        let err = parse(v(&["dial", "not-a-multiaddr"])).unwrap_err();
        assert!(err.0.contains("invalid peer-addr"));
    }
}
