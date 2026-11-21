//! `minip2p-mdns`: local-link peer discovery demo.
//!
//! Run two copies on one machine or LAN: they find each other over mDNS and
//! connect (`--no-dial` stops this copy dialing; peers can still dial in).
//! Addresses in a `discovered` line are unauthenticated claims; `connected`
//! means the peer id was proven.

use std::time::{Duration, Instant};

use minip2p::{
    DiscoveryEvent, Endpoint, EndpointEvent, EndpointWaitOutcome, Multiaddr, PeerDiscoveryConfig,
    WaitDeadline,
};

const USAGE: &str = "usage: minip2p-mdns [--no-dial] [--for <seconds>]

    --no-dial          do not dial what mDNS finds (peers can still dial in)
    --for <seconds>    run this long, send mDNS goodbyes, then exit";

#[derive(Debug, Default, PartialEq)]
struct Options {
    no_dial: bool,
    /// Unset runs until interrupted (and so never sends goodbyes).
    run_for: Option<Duration>,
}

fn main() {
    let options = match parse(std::env::args().skip(1)) {
        Ok(options) => options,
        Err(msg) => {
            eprintln!("{msg}\n\n{USAGE}");
            std::process::exit(2);
        }
    };
    if let Err(e) = run(options) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn parse(mut args: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut options = Options::default();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--no-dial" => options.no_dial = true,
            "--for" => {
                let secs = args
                    .next()
                    .and_then(|v| v.parse::<u64>().ok())
                    .filter(|&s| s > 0)
                    .ok_or("--for needs a positive number of seconds")?;
                options.run_for = Some(Duration::from_secs(secs));
            }
            "-h" | "--help" => return Err("minip2p-mdns: local-link discovery over mDNS".into()),
            other => return Err(format!("unknown argument '{other}'")),
        }
    }
    Ok(options)
}

fn run(options: Options) -> Result<(), Box<dyn std::error::Error>> {
    let mut endpoint = Endpoint::builder()
        .mdns()
        .peer_discovery_config(PeerDiscoveryConfig {
            auto_dial: !options.no_dial,
            ..PeerDiscoveryConfig::default()
        })
        .listen_default()?
        .bind()?;

    println!("[mdns] us={}", endpoint.peer_id());
    for addr in endpoint.listen_all()? {
        println!("[mdns] listen-addr={addr}");
    }

    let start = Instant::now();
    // An out-of-range `--for` is as good as running forever.
    let deadline = options.run_for.and_then(|d| start.checked_add(d));
    while deadline.is_none_or(|d| Instant::now() < d) {
        let wait_until = deadline.map_or(WaitDeadline::NEVER, WaitDeadline::from);
        if let EndpointWaitOutcome::Event(event) = endpoint.wait(wait_until)? {
            print_event(&event, start);
        }
    }

    // Goodbyes let the other side print `expired` now instead of after the
    // record's TTL.
    println!("[mdns] shutting down, sending goodbyes");
    for event in endpoint.close().events {
        print_event(&event, start);
    }
    Ok(())
}

fn print_event(event: &EndpointEvent, start: Instant) {
    let t = start.elapsed().as_secs_f64();
    match event {
        EndpointEvent::Discovery(DiscoveryEvent::PeerDiscovered { peer, addrs, .. }) => {
            println!(
                "[mdns] discovered peer={peer} addrs=[{}] t=+{t:.1}s",
                join(addrs)
            );
        }
        EndpointEvent::Discovery(DiscoveryEvent::PeerUpdated { peer, addrs, .. }) => {
            println!(
                "[mdns] updated peer={peer} addrs=[{}] t=+{t:.1}s",
                join(addrs)
            );
        }
        EndpointEvent::Discovery(DiscoveryEvent::PeerExpired { peer }) => {
            println!("[mdns] expired peer={peer} t=+{t:.1}s");
        }
        EndpointEvent::Discovery(DiscoveryEvent::DialFailed { peer, reason }) => {
            println!("[mdns] dial-failed peer={peer} reason={reason} t=+{t:.1}s");
        }
        // A failing mDNS socket surfaces here, not as a `wait` error; without
        // these a broken network path looks like an empty one.
        EndpointEvent::MdnsFailed { error } => println!("[mdns] mdns-failed error={error}"),
        EndpointEvent::MdnsRecovered => println!("[mdns] mdns-recovered"),
        EndpointEvent::ConnectionEstablished { peer_id, .. } => {
            println!("[mdns] connected peer={peer_id} t=+{t:.1}s");
        }
        EndpointEvent::ConnectionClosed {
            peer_id, reason, ..
        } => {
            println!("[mdns] disconnected peer={peer_id} reason={reason} t=+{t:.1}s");
        }
        EndpointEvent::PeerReady {
            peer_id, protocols, ..
        } => {
            println!(
                "[mdns] ready peer={peer_id} protocols=[{}] t=+{t:.1}s",
                protocols.join(",")
            );
        }
        _ => {}
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

    fn parse_args(args: &[&str]) -> Result<Options, String> {
        parse(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn parses_flags_and_rejects_bad_input() {
        assert_eq!(
            parse_args(&["--no-dial", "--for", "15"]),
            Ok(Options {
                no_dial: true,
                run_for: Some(Duration::from_secs(15)),
            })
        );
        parse_args(&["--for", "0"]).unwrap_err();
        parse_args(&["--for"]).unwrap_err();
        parse_args(&["--bogus"]).unwrap_err();
    }
}
