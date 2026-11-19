//! `minip2p-mdns`: local-link peer discovery demo.
//!
//! Two copies on one machine, or on one LAN, find each other over mDNS with
//! no bootstrap address, no relay and nothing configured per environment —
//! the one thing in the stack you can try without a second host or a public
//! address.
//!
//! By default discovery also dials what it finds (`auto_dial`, the stack's
//! own default), so a run demonstrates discovery *and* connectivity: a
//! `discovered` line, then `connected`, then `ready` with the peer's
//! advertised protocols. `--no-dial` leaves the book read-only, which is
//! what you want when watching expiry.
//!
//! mDNS claims are unauthenticated: the addresses in a `discovered` line
//! are what a host on the link said about itself, and nothing more. They
//! become trustworthy only once a connection to that peer authenticates
//! its peer id — TLS 1.3 on the default QUIC path, Noise XX over TCP —
//! which is what `connected` reports.

use std::error::Error;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, Instant};

use minip2p::{
    DiscoveryEvent, DiscoverySource, Endpoint, EndpointEvent, EndpointWaitOutcome, Multiaddr,
    PeerDiscoveryConfig,
};
use minip2p_example_common::{CliError, load_keypair};

const AGENT: &str = "minip2p-mdns/0.1.0";
/// How often the loop lets the endpoint make progress.
const TICK: Duration = Duration::from_millis(200);

/// Parsed argv.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Options {
    /// Run for this long, then send mDNS goodbyes and exit 0. Unset runs
    /// until interrupted.
    run_for: Option<Duration>,
    /// Whether discovery may dial the peers it finds.
    no_dial: bool,
    /// Explicit QUIC or TCP bind; default is dual-stack QUIC.
    listen_addr: Option<Multiaddr>,
    /// Persistent Ed25519 secret, so a restart keeps its peer id.
    key_path: Option<PathBuf>,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let options = match parse(args) {
        Ok(options) => options,
        Err(CliError(msg)) => {
            eprintln!("{msg}");
            std::process::exit(2);
        }
    };
    if let Err(e) = run(options) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn parse(args: Vec<String>) -> Result<Options, CliError> {
    let mut options = Options::default();
    let mut args = args.iter();
    while let Some(key) = args.next() {
        match key.as_str() {
            "-h" | "--help" | "help" => return Err(CliError(usage())),
            "--no-dial" => options.no_dial = true,
            "--for" => {
                let value = args
                    .next()
                    .ok_or_else(|| CliError("flag '--for' requires a value".into()))?;
                let secs = u64::from_str(value)
                    .map_err(|e| CliError(format!("invalid --for '{value}': {e}")))?;
                if secs == 0 {
                    return Err(CliError("--for must be at least 1 second".into()));
                }
                options.run_for = Some(Duration::from_secs(secs));
            }
            "--listen" => {
                let value = args
                    .next()
                    .ok_or_else(|| CliError("flag '--listen' requires a value".into()))?;
                let addr = Multiaddr::from_str(value)
                    .map_err(|e| CliError(format!("invalid --listen '{value}': {e}")))?;
                options.listen_addr = Some(addr);
            }
            "--key" => {
                let value = args
                    .next()
                    .ok_or_else(|| CliError("flag '--key' requires a value".into()))?;
                options.key_path = Some(PathBuf::from(value));
            }
            other => {
                return Err(CliError(format!("unknown flag '{other}'\n\n{}", usage())));
            }
        }
    }
    Ok(options)
}

fn usage() -> String {
    "minip2p-mdns -- local-link peer discovery over mDNS.

USAGE:
    minip2p-mdns [--no-dial] [--for <seconds>] [--key <path>] [--listen <transport-multiaddr>]

NOTES:
    --no-dial          only watch the address book; do not dial what mDNS
                       finds. Without it, discovery dials (the stack default)
    --for <seconds>    run for this long, send mDNS goodbyes, exit 0.
                       Without it, runs until interrupted
    --key              persistent Ed25519 raw-secret file (hex), so a restart
                       keeps its peer id
    --listen           QUIC or TCP bind multiaddr; default is dual-stack QUIC

    Run two copies to see anything. See examples/mdns/README.md."
        .to_string()
}

fn run(options: Options) -> Result<(), Box<dyn Error>> {
    let keypair = load_keypair(options.key_path.as_deref(), "mdns")?;
    let builder = Endpoint::builder()
        .identity(keypair)
        .agent_version(AGENT)
        .mdns()
        .peer_discovery_config(PeerDiscoveryConfig {
            auto_dial: !options.no_dial,
            ..PeerDiscoveryConfig::default()
        });
    let mut endpoint = match &options.listen_addr {
        Some(addr) => builder.listen_on_multiaddr(addr)?.bind()?,
        None => builder.listen_default()?.bind()?,
    };

    let addrs = endpoint
        .listen_all()
        .map_err(|e| format!("listen failed: {e}"))?;
    println!("[mdns] us={}", endpoint.peer_id());
    for addr in &addrs {
        println!("[mdns] listen-addr={addr}");
    }
    println!(
        "[mdns] announcing, dial={} ({})",
        if options.no_dial { "off" } else { "on" },
        match options.run_for {
            Some(d) => format!("for {}s", d.as_secs()),
            None => "Ctrl-C to stop".to_string(),
        }
    );

    let start = Instant::now();
    let deadline = options.run_for.map(|d| start + d);
    loop {
        if let Some(deadline) = deadline
            && Instant::now() >= deadline
        {
            break;
        }
        if let EndpointWaitOutcome::Event(event) = endpoint
            .wait(TICK)
            .map_err(|e| format!("swarm poll: {e}"))?
        {
            print_event(&event, start);
        }
    }

    // Goodbyes let the other side print `expired` now instead of waiting
    // out the record's TTL, which is the half of the lifecycle a demo
    // otherwise never shows.
    println!("[mdns] shutting down, sending goodbyes");
    endpoint.shutdown().map_err(|e| format!("shutdown: {e}"))?;
    println!(
        "[mdns] done known-peers={} elapsed={}s",
        endpoint.known_peers().len(),
        start.elapsed().as_secs()
    );
    Ok(())
}

/// One line per event, tagged with the time since start so the discovery
/// and expiry cadence is visible.
fn print_event(event: &EndpointEvent, start: Instant) {
    let t = format!("+{:.1}s", start.elapsed().as_secs_f64());
    match event {
        EndpointEvent::Discovery(DiscoveryEvent::PeerDiscovered {
            peer,
            addrs,
            source,
        }) => {
            println!(
                "[mdns] discovered peer={peer} source={} addrs=[{}] t={t}",
                source_name(source),
                join(addrs)
            );
        }
        EndpointEvent::Discovery(DiscoveryEvent::PeerUpdated {
            peer,
            addrs,
            source,
        }) => {
            println!(
                "[mdns] updated peer={peer} source={} addrs=[{}] t={t}",
                source_name(source),
                join(addrs)
            );
        }
        EndpointEvent::Discovery(DiscoveryEvent::PeerExpired { peer }) => {
            println!("[mdns] expired peer={peer} t={t}");
        }
        EndpointEvent::Discovery(DiscoveryEvent::DialFailed { peer, reason }) => {
            println!("[mdns] dial-failed peer={peer} reason={reason} t={t}");
        }
        EndpointEvent::Discovery(DiscoveryEvent::ProtocolViolation {
            peer,
            source,
            reason,
            suppressed,
        }) => {
            let peer = peer
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "?".into());
            println!(
                "[mdns] violation peer={peer} source={} reason={reason} suppressed={suppressed} t={t}",
                source_name(source)
            );
        }
        // A failing mDNS socket reaches the application here, not as an
        // error from `wait`, so without these a broken network path is
        // indistinguishable from an empty one: the run just goes quiet.
        EndpointEvent::MdnsFailed { error } => {
            println!("[mdns] mdns-failed error={error} t={t}");
        }
        EndpointEvent::MdnsRecovered => {
            println!("[mdns] mdns-recovered t={t}");
        }
        EndpointEvent::ConnectionEstablished { peer_id, .. } => {
            println!("[mdns] connected peer={peer_id} t={t}");
        }
        EndpointEvent::ConnectionClosed {
            peer_id, reason, ..
        } => {
            println!("[mdns] disconnected peer={peer_id} reason={reason} t={t}");
        }
        EndpointEvent::PeerReady {
            peer_id, protocols, ..
        } => {
            println!(
                "[mdns] ready peer={peer_id} protocols={} list=[{}] t={t}",
                protocols.len(),
                protocols.join(",")
            );
        }
        _ => {}
    }
}

fn source_name(source: &DiscoverySource) -> &'static str {
    match source {
        DiscoverySource::Mdns => "mdns",
        DiscoverySource::SignedBeacon => "beacon",
    }
}

fn join(addrs: &[Multiaddr]) -> String {
    addrs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_args_is_the_default_watch_and_dial() {
        assert_eq!(parse(v(&[])).unwrap(), Options::default());
    }

    #[test]
    fn no_dial_turns_auto_dial_off() {
        assert!(parse(v(&["--no-dial"])).unwrap().no_dial);
    }

    #[test]
    fn for_sets_a_bounded_run() {
        assert_eq!(
            parse(v(&["--for", "15"])).unwrap().run_for,
            Some(Duration::from_secs(15))
        );
    }

    #[test]
    fn for_rejects_zero_and_nonsense() {
        assert!(parse(v(&["--for", "0"])).unwrap_err().0.contains("--for"));
        assert!(
            parse(v(&["--for", "soon"]))
                .unwrap_err()
                .0
                .contains("--for")
        );
        assert!(parse(v(&["--for"])).unwrap_err().0.contains("--for"));
    }

    #[test]
    fn listen_and_key_round_trip() {
        let options = parse(v(&[
            "--listen",
            "/ip4/0.0.0.0/udp/0/quic-v1",
            "--key",
            "./mdns.key",
        ]))
        .unwrap();
        assert_eq!(
            options.listen_addr.unwrap().to_string(),
            "/ip4/0.0.0.0/udp/0/quic-v1"
        );
        assert_eq!(options.key_path, Some(PathBuf::from("./mdns.key")));
    }

    #[test]
    fn unknown_flag_shows_usage() {
        let err = parse(v(&["--discover-everything"])).unwrap_err();
        assert!(err.0.contains("unknown flag"));
        assert!(err.0.contains("USAGE"));
    }

    #[test]
    fn help_returns_usage() {
        assert!(parse(v(&["--help"])).unwrap_err().0.contains("USAGE"));
    }
}
