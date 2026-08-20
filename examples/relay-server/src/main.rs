mod cli;

use std::error::Error;
use std::io::BufRead as _;
use std::sync::mpsc;
use std::time::Duration;

use minip2p::{Endpoint, RelayServerEvent};
use minip2p_example_common::load_keypair;

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{}", cli::usage());
        return;
    }
    if let Err(error) = run(args) {
        eprintln!("relay-server: {error}");
        std::process::exit(2);
    }
}

fn run(args: Vec<String>) -> Result<(), Box<dyn Error>> {
    let options = cli::parse(args)?;
    let identity = load_keypair(options.key_path.as_deref(), "relay")?;

    // The default is intentionally the documented three-line path; the
    // surrounding calls only apply explicitly requested operator controls.
    let mut builder = Endpoint::builder()
        .identity(identity)
        .relay_server_config(options.config)?
        .quic(options.quic_bind)
        .tcp(options.tcp_bind);
    if !options.announce_addrs.is_empty() {
        builder = builder.relay_server_announce_addrs(options.announce_addrs)?;
    }
    let mut endpoint = builder.bind()?;
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
        if let Some(event) = endpoint.next_relay_server_event(Duration::from_millis(250))? {
            print_event(event);
        }
    }
}

fn stdin_commands() -> mpsc::Receiver<String> {
    let (sender, receiver) = mpsc::channel();
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
