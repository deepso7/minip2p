mod cli;
mod service;

use std::error::Error;
use std::io::BufRead as _;
use std::sync::mpsc;
use std::time::Duration;

use minip2p::{Ed25519Keypair, Endpoint, EndpointWake, Multiaddr, RelayServerEvent};
use minip2p_example_common::load_keypair;

const STDIN_COMMAND_CAPACITY: usize = 16;
const DEFAULT_IPV4_BIND: &str = "0.0.0.0:19876";
const DEFAULT_IPV6_BIND: &str = "[::]:19876";
const DEFAULT_IPV4_QUIC: &str = "/ip4/0.0.0.0/udp/19876/quic-v1";
const DEFAULT_IPV6_QUIC: &str = "/ip6/::/udp/19876/quic-v1";

#[derive(Clone, Copy, Debug)]
enum AutomaticBind {
    Both,
    Ipv4,
    Ipv6,
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|arg| arg == "service") {
        if let Err(error) = service::run(args.into_iter().skip(1)) {
            eprintln!("relay service: {error}");
            std::process::exit(2);
        }
        return;
    }
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{}", cli::usage());
        return;
    }
    if args.iter().any(|arg| arg == "--version" || arg == "-V") {
        println!("minip2p-relay {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if let Err(error) = run(args) {
        eprintln!("minip2p-relay: {error}");
        std::process::exit(2);
    }
}

fn run(args: Vec<String>) -> Result<(), Box<dyn Error>> {
    let options = cli::parse(args)?;
    let identity = load_keypair(options.key_path.as_deref(), "relay")?;

    let mut endpoint = bind_endpoint(&options, identity)?;
    endpoint.set_relay_server_accepting(options.accepting)?;

    println!(
        "[relay] peer={} accepting={}",
        endpoint.peer_id(),
        options.accepting
    );
    for address in endpoint.listen_all()? {
        println!("[relay] listening={address}");
    }
    println!("[relay] commands on stdin: pause | resume");

    let commands = stdin_commands();
    loop {
        if let Ok(command) = commands.try_recv() {
            match command.trim() {
                "pause" => {
                    endpoint.set_relay_server_accepting(false)?;
                    println!("[relay] accepting=false existing_lifecycles=preserved");
                }
                "resume" => {
                    endpoint.set_relay_server_accepting(true)?;
                    println!("[relay] accepting=true");
                }
                "" => {}
                command => eprintln!("[relay] unknown command {command:?}; use pause or resume"),
            }
        }
        if let EndpointWake::Event(event) = endpoint.next_wake(Duration::from_millis(250))? {
            println!("[endpoint] {event:?}");
        }
        for event in endpoint.take_relay_server_events() {
            print_event(event);
        }
    }
}

fn bind_endpoint(
    options: &cli::Options,
    identity: Ed25519Keypair,
) -> Result<Endpoint, Box<dyn Error>> {
    let automatic = [
        AutomaticBind::Both,
        AutomaticBind::Ipv4,
        AutomaticBind::Ipv6,
    ];
    let modes: &[AutomaticBind] = if options.quic_binds.is_empty() || options.tcp_binds.is_empty() {
        &automatic
    } else {
        &automatic[..1]
    };
    let mut last_error = None;

    for &mode in modes {
        match try_bind(options, identity.clone(), mode) {
            Ok(endpoint) => {
                if !matches!(mode, AutomaticBind::Both) {
                    eprintln!("[relay] dual-stack bind unavailable; using {mode:?}");
                }
                return Ok(endpoint);
            }
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.expect("at least one relay bind layout is attempted"))
}

fn try_bind(
    options: &cli::Options,
    identity: Ed25519Keypair,
    mode: AutomaticBind,
) -> Result<Endpoint, Box<dyn Error>> {
    let mut builder = Endpoint::builder()
        .identity(identity)
        .relay_server_config(options.config.clone())?;

    if options.quic_binds.is_empty() {
        builder = match mode {
            AutomaticBind::Both => {
                let ipv4: Multiaddr = DEFAULT_IPV4_QUIC.parse()?;
                let ipv6: Multiaddr = DEFAULT_IPV6_QUIC.parse()?;
                builder.quic_dual_multiaddr(&ipv4, &ipv6)
            }
            AutomaticBind::Ipv4 => builder.quic(DEFAULT_IPV4_BIND),
            AutomaticBind::Ipv6 => builder.quic(DEFAULT_IPV6_BIND),
        };
    } else {
        match options.quic_binds.as_slice() {
            [address] => builder = builder.quic(address),
            [first, second] => {
                let first = quic_multiaddr(first)?;
                let second = quic_multiaddr(second)?;
                builder = builder.quic_dual_multiaddr(&first, &second);
            }
            _ => return Err("--quic accepts at most one IPv4 and one IPv6 address".into()),
        }
    }

    if options.tcp_binds.is_empty() {
        builder = match mode {
            AutomaticBind::Both => builder.tcp(DEFAULT_IPV4_BIND).tcp(DEFAULT_IPV6_BIND),
            AutomaticBind::Ipv4 => builder.tcp(DEFAULT_IPV4_BIND),
            AutomaticBind::Ipv6 => builder.tcp(DEFAULT_IPV6_BIND),
        };
    } else {
        for address in &options.tcp_binds {
            builder = builder.tcp(address);
        }
    }

    if !options.announce_addrs.is_empty() {
        builder = builder.relay_server_announce_addrs(options.announce_addrs.clone())?;
    }
    Ok(builder.bind()?)
}

fn quic_multiaddr(address: &str) -> Result<Multiaddr, Box<dyn Error>> {
    let address: std::net::SocketAddr = address
        .parse()
        .map_err(|error| format!("invalid dual-stack --quic address {address:?}: {error}"))?;
    let family = if address.is_ipv4() { "ip4" } else { "ip6" };
    Ok(format!("/{family}/{}/udp/{}/quic-v1", address.ip(), address.port()).parse()?)
}

fn stdin_commands() -> mpsc::Receiver<String> {
    // Bound piped input so a producer cannot outrun the operator loop and grow
    // the process without limit.
    let (sender, receiver) = stdin_command_channel();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            match line {
                Ok(line) => {
                    if sender.send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    receiver
}

fn stdin_command_channel() -> (mpsc::SyncSender<String>, mpsc::Receiver<String>) {
    mpsc::sync_channel(STDIN_COMMAND_CAPACITY)
}

fn print_event(event: RelayServerEvent) {
    match event {
        RelayServerEvent::ReservationAccepted {
            peer_id,
            renewed,
            expires_unix_secs,
        } => println!(
            "[relay] reservation accepted peer={peer_id} renewed={renewed} expires_unix_secs={}",
            expires_unix_secs.map_or_else(|| "unavailable".into(), |value| value.to_string())
        ),
        RelayServerEvent::ReservationDenied { peer_id, status } => {
            println!("[relay] reservation denied peer={peer_id} status={status:?}")
        }
        RelayServerEvent::ReservationClosed { peer_id, reason } => {
            println!("[relay] reservation closed peer={peer_id} cause={reason:?}")
        }
        RelayServerEvent::CircuitDenied {
            source_peer_id,
            destination_peer_id,
            status,
        } => println!(
            "[relay] circuit denied source={source_peer_id} destination={destination_peer_id} status={status:?}"
        ),
        RelayServerEvent::CircuitOpened {
            source_peer_id,
            destination_peer_id,
        } => println!(
            "[relay] circuit opened source={source_peer_id} destination={destination_peer_id}"
        ),
        RelayServerEvent::CircuitClosed {
            source_peer_id,
            destination_peer_id,
            bytes,
            reason,
        } => println!(
            "[relay] circuit closed source={source_peer_id} destination={destination_peer_id} source_to_destination_bytes={} destination_to_source_bytes={} cause={reason:?}",
            bytes.source_to_destination, bytes.destination_to_source
        ),
        RelayServerEvent::Error(error) => eprintln!(
            "[relay] operational error kind={:?} peer={} detail={} action=check transport reachability and configured limits",
            error.kind,
            error
                .peer_id
                .map_or_else(|| "unknown".into(), |peer| peer.to_string()),
            error.detail
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdin_command_queue_applies_backpressure() {
        let (sender, _receiver) = stdin_command_channel();
        for index in 0..STDIN_COMMAND_CAPACITY {
            sender.try_send(index.to_string()).unwrap();
        }
        assert!(matches!(
            sender.try_send("overflow".into()),
            Err(mpsc::TrySendError::Full(_))
        ));
    }
}
