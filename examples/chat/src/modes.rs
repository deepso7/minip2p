//! The chat runner: endpoint construction, host/join startup flows, and
//! the shared stdin-driven chat loop.

use std::error::Error;
use std::io::BufRead;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use minip2p::{
    BeaconConfig, ConnectId, ConnectOutcome, DISCOVERY_TOPIC, DiscoveryEvent, Endpoint,
    EndpointEvent, EndpointWaitOutcome, GossipsubConfig, GossipsubError, GossipsubEvent, NatConfig,
    NatEvent, Path, PeerAddr, PeerDiscoveryConfig, PeerId, PublishError,
};

use minip2p_example_common::{
    circuit_addr, load_keypair, local_dialable_peer_addr, path_name, print_nat_event,
};

use crate::cli::{ChatOptions, JoinTarget};

const AGENT: &str = "minip2p-chat/0.1.0";
const DEFAULT_TOPIC: &str = "minip2p-chat";
/// Budget for the NAT connect (relay leg + punch windows).
const CONNECT_DEADLINE: Duration = Duration::from_secs(65);
/// How long the host waits for its relay reservation before warning.
const RESERVATION_DEADLINE: Duration = Duration::from_secs(30);
/// Budget for waiting until Identify finishes so this demo can treat the
/// peer as mesh-ready; app streams themselves do not require PeerReady.
const READY_DEADLINE: Duration = Duration::from_secs(15);

struct ChatEndpoint {
    endpoint: Endpoint,
}

// --- endpoint construction --------------------------------------------------

fn build_endpoint(
    role: &str,
    relays: &[PeerAddr],
    options: &ChatOptions,
) -> Result<ChatEndpoint, Box<dyn Error>> {
    let keypair = load_keypair(options.key_path.as_deref(), role)?;
    let nat_config = NatConfig {
        force_relay: options.relay_only,
        ..NatConfig::default()
    };
    let mut builder = Endpoint::builder()
        .identity(keypair)
        .agent_version(AGENT)
        .gossipsub_config(GossipsubConfig {
            allow_unsigned: options.allow_unsigned,
            ..GossipsubConfig::default()
        })
        .nat_config(nat_config);
    if !options.no_mesh {
        let room = options
            .topic
            .clone()
            .unwrap_or_else(|| DEFAULT_TOPIC.to_string());
        builder = builder
            .discovery_config(BeaconConfig {
                topic: format!("{room}/{DISCOVERY_TOPIC}"),
                beacon_interval_ms: 2_000,
                ..BeaconConfig::default()
            })?
            .peer_discovery_config(PeerDiscoveryConfig {
                beacon_peer_ttl_ms: 10_000,
                ..PeerDiscoveryConfig::default()
            })?;
    }
    for relay in relays {
        builder = builder.relay(relay.clone());
    }
    let endpoint = match &options.listen_addr {
        Some(addr) => builder
            .listen_on_multiaddr(addr)
            .and_then(|builder| builder.bind())
            .map_err(|e| format!("quic bind {addr}: {e}"))?,
        None => builder
            .listen_default()
            .and_then(|builder| builder.bind())
            .map_err(|e| format!("quic dual-stack bind: {e}"))?,
    };
    Ok(ChatEndpoint { endpoint })
}

fn topic_and_nick(options: &ChatOptions, endpoint: &Endpoint) -> (String, String) {
    let topic = options
        .topic
        .clone()
        .unwrap_or_else(|| DEFAULT_TOPIC.to_string());
    let nick = options.nick.clone().unwrap_or_else(|| {
        let id = endpoint.peer_id().to_base58();
        id.chars().take(8).collect()
    });
    (topic, nick)
}

// --- host -------------------------------------------------------------------

/// Hosts a room: bind, print join addresses, chat until stdin EOF. With
/// `--relay`, also hold a reservation and print the circuit address NAT'd
/// joiners use.
pub fn run_host(relay: Option<PeerAddr>, options: ChatOptions) -> Result<(), Box<dyn Error>> {
    let relays: Vec<PeerAddr> = relay.into_iter().collect();
    let ChatEndpoint { mut endpoint } = build_endpoint("host", &relays, &options)?;
    let peer_addrs = endpoint
        .listen_all()
        .map_err(|e| format!("listen failed: {e}"))?;
    let first = peer_addrs
        .first()
        .ok_or("listen completed without any bound peer addresses")?;
    // `bound=` is same-host pasteable (wildcards rewritten to loopback,
    // which the e2e test relies on); the raw `listen-addr=` lines carry
    // the real binds -- remote joiners substitute this machine's public
    // address for a wildcard host.
    println!("[host] bound={}", local_dialable_peer_addr(first));
    for addr in &peer_addrs {
        println!("[host] listen-addr={addr}");
    }
    println!("[host] us={}", endpoint.peer_id());

    if let Some(relay) = relays.first() {
        wait_for_reservation(&mut endpoint, relay)?;
    }

    let (topic, nick) = topic_and_nick(&options, &endpoint);
    endpoint
        .subscribe(&topic)
        .map_err(|e| format!("subscribe: {e}"))?;
    println!("[host] subscribed topic={topic} nick={nick}");

    run_chat(&mut endpoint, &topic, &nick, "host", relays.first())
}

/// Drives the endpoint until the relay reservation lands, printing the
/// `circuit=` line joiners paste. A miss is a warning, not an error — the
/// host keeps retrying in the background and stays joinable directly.
fn wait_for_reservation(endpoint: &mut Endpoint, relay: &PeerAddr) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + RESERVATION_DEADLINE;
    loop {
        match endpoint
            .wait(deadline)
            .map_err(|e| format!("swarm poll: {e}"))?
        {
            EndpointWaitOutcome::Event(event) => {
                let reserved = matches!(
                    &event,
                    EndpointEvent::Nat(NatEvent::RelayReserved { relay: reserved, .. })
                        if reserved == relay.peer_id()
                );
                // Prints the `circuit=` line for the reservation too.
                handle_event(endpoint, "host", Some(relay), event);
                if reserved {
                    return Ok(());
                }
            }
            EndpointWaitOutcome::Interrupted => {}
            EndpointWaitOutcome::Deadline => {
                eprintln!(
                    "[host] warning: no relay reservation within {}s; still retrying",
                    RESERVATION_DEADLINE.as_secs()
                );
                return Ok(());
            }
        }
    }
}

// --- join -------------------------------------------------------------------

/// Joins a room through the NAT agent, then chats over either a direct or
/// promoted relay-circuit connection until stdin EOF.
pub fn run_join(
    target: JoinTarget,
    relay: Option<PeerAddr>,
    options: ChatOptions,
) -> Result<(), Box<dyn Error>> {
    // The circuit target's relay leads the list; --relay adds a fallback.
    let mut relays: Vec<PeerAddr> = Vec::new();
    if let JoinTarget::Circuit { relay, .. } = &target {
        relays.push(relay.clone());
    }
    if let Some(extra) = relay
        && !relays.iter().any(|r| r.peer_id() == extra.peer_id())
    {
        relays.push(extra);
    }

    let ChatEndpoint { mut endpoint } = build_endpoint("join", &relays, &options)?;
    // Listening seeds the agent's bound addresses — the local half of the
    // DCUtR candidate set.
    endpoint
        .listen_all()
        .map_err(|e| format!("listen failed: {e}"))?;
    println!("[join] us={}", endpoint.peer_id());
    let (topic, nick) = topic_and_nick(&options, &endpoint);
    // The host announces its topic once per connection, and that can land
    // while the joiner is still waiting for a path or Identify.
    let mut host_subscribed = false;

    let (host_peer, connect_id) = match &target {
        JoinTarget::Circuit { relay, peer } => {
            println!("[join] target={peer} via-relay={}", relay.peer_id());
            let id = endpoint
                .connect(peer)
                .map_err(|e| format!("connect failed: {e}"))?;
            (peer.clone(), id)
        }
        JoinTarget::Direct(addr) => {
            println!("[join] target={addr}");
            let id = endpoint
                .connect(addr)
                .map_err(|e| format!("connect failed: {e}"))?;
            (addr.peer_id().clone(), id)
        }
    };

    let path = wait_for_path(
        &mut endpoint,
        &host_peer,
        connect_id,
        &topic,
        &mut host_subscribed,
    )?;
    println!("[join] path={}", path_name(&path));

    let ready_deadline = Instant::now() + READY_DEADLINE;
    while !endpoint.is_peer_ready(&host_peer) {
        match endpoint
            .wait(ready_deadline)
            .map_err(|e| format!("waiting for identify: {e}"))?
        {
            EndpointWaitOutcome::Event(event) => {
                host_subscribed |= is_topic_subscription(&event, &host_peer, &topic);
                handle_event(&endpoint, "join", None, event);
            }
            EndpointWaitOutcome::Interrupted => {}
            EndpointWaitOutcome::Deadline => {
                return Err("identify never completed on the selected connection".into());
            }
        }
    }

    endpoint
        .subscribe(&topic)
        .map_err(|e| format!("subscribe: {e}"))?;
    println!("[join] subscribed topic={topic} nick={nick}");
    if host_subscribed {
        println!("[join] pubsub-ready peer={host_peer} topic={topic}");
    } else {
        wait_for_topic_peer(&mut endpoint, &host_peer, &topic, "join")?;
    }

    run_chat(&mut endpoint, &topic, &nick, "join", None)
}

/// Waits for the attempt's first usable path (the provisional relayed one,
/// when that lands first) while handling unrelated events as the chat loop
/// would. An attempt that settles connected without a path event reports the
/// current path. Records whether the host's `topic` announcement went by.
fn wait_for_path(
    endpoint: &mut Endpoint,
    host_peer: &PeerId,
    connect_id: ConnectId,
    topic: &str,
    host_subscribed: &mut bool,
) -> Result<Path, Box<dyn Error>> {
    let deadline = Instant::now() + CONNECT_DEADLINE;
    loop {
        match endpoint
            .wait(deadline)
            .map_err(|e| format!("waiting for a path: {e}"))?
        {
            EndpointWaitOutcome::Event(EndpointEvent::Nat(NatEvent::PathEstablished {
                connect_id: id,
                path,
                ..
            })) if id == connect_id => return Ok(path),
            EndpointWaitOutcome::Event(EndpointEvent::ConnectSettled {
                connect_id: id,
                outcome,
                ..
            }) if id == connect_id => {
                if matches!(outcome, ConnectOutcome::Connected { .. })
                    && let Some(path) = endpoint.path(host_peer)
                {
                    return Ok(path);
                }
                eprintln!("[join] connect-settled outcome={outcome:?}");
                return Err("no path to the host".into());
            }
            EndpointWaitOutcome::Event(event) => {
                *host_subscribed |= is_topic_subscription(&event, host_peer, topic);
                handle_event(endpoint, "join", None, event);
            }
            EndpointWaitOutcome::Interrupted => {}
            EndpointWaitOutcome::Deadline => return Err("no path to the host".into()),
        }
    }
}

/// Waits until the host's topic announcement has been applied. The
/// gossipsub agent immediately admits an eligible new subscriber while the
/// local mesh is below its low watermark, so observing this event means the
/// joiner has a routing peer before stdin is consumed.
fn wait_for_topic_peer(
    endpoint: &mut Endpoint,
    expected_peer: &PeerId,
    expected_topic: &str,
    role: &str,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + READY_DEADLINE;
    loop {
        let event = match endpoint
            .wait(deadline)
            .map_err(|e| format!("waiting for pubsub readiness: {e}"))?
        {
            EndpointWaitOutcome::Event(event) => event,
            EndpointWaitOutcome::Interrupted => continue,
            EndpointWaitOutcome::Deadline => {
                return Err(format!(
                    "peer {expected_peer} did not announce topic {expected_topic}"
                )
                .into());
            }
        };
        let ready = is_topic_subscription(&event, expected_peer, expected_topic);
        handle_event(endpoint, role, None, event);
        if ready {
            println!("[{role}] pubsub-ready peer={expected_peer} topic={expected_topic}");
            return Ok(());
        }
    }
}

/// Whether `event` is `peer` announcing a subscription to `topic`.
fn is_topic_subscription(event: &EndpointEvent, peer: &PeerId, topic: &str) -> bool {
    matches!(
        event,
        EndpointEvent::Gossipsub(GossipsubEvent::PeerSubscribed { peer: subscriber, topic: subscribed })
            if subscriber == peer && subscribed == topic
    )
}

// --- the chat loop ----------------------------------------------------------

/// Reads stdin lines on a background thread; `None` marks EOF.
fn spawn_stdin_reader() -> mpsc::Receiver<Option<String>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { break };
            if tx.send(Some(line)).is_err() {
                return;
            }
        }
        // EOF is best-effort: the receiver may have exited after an endpoint
        // error, which is already the primary outcome.
        match tx.send(None) {
            Ok(()) | Err(_) => {}
        }
    });
    rx
}

/// The shared steady state: publish stdin lines, print room traffic,
/// surface membership and failures, exit on stdin EOF.
fn run_chat(
    endpoint: &mut Endpoint,
    topic: &str,
    nick: &str,
    role: &str,
    relay: Option<&PeerAddr>,
) -> Result<(), Box<dyn Error>> {
    let input = spawn_stdin_reader();
    eprintln!("[{role}] type to chat; Ctrl-D to leave");

    // A pipe can produce lines faster than a human ever will; bounding the
    // per-tick drain keeps the network pump (`wait` below) live even
    // under a stdin flood.
    const MAX_LINES_PER_TICK: usize = 32;

    loop {
        for _ in 0..MAX_LINES_PER_TICK {
            match input.try_recv() {
                Ok(Some(line)) => {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let payload = format!("{nick}: {line}");
                    match endpoint.publish(topic, payload.clone().into_bytes()) {
                        Ok(()) => println!("[you] {payload}"),
                        Err(GossipsubError::Publish(PublishError::Backpressure)) => {
                            println!("[chat] dropped (slow peer)");
                        }
                        Err(e) => return Err(format!("publish: {e}").into()),
                    }
                }
                Ok(None) | Err(mpsc::TryRecvError::Disconnected) => {
                    println!("[{role}] bye");
                    return Ok(());
                }
                Err(mpsc::TryRecvError::Empty) => break,
            }
        }

        match endpoint.wait(Duration::from_millis(100))? {
            EndpointWaitOutcome::Event(event) => handle_event(endpoint, role, relay, event),
            EndpointWaitOutcome::Deadline | EndpointWaitOutcome::Interrupted => {}
        }
    }
}

/// Prints one endpoint event the way the chat loop surfaces it: membership,
/// failures, room traffic, and NAT/discovery progress. With `relay`, a
/// reservation on it also prints the `circuit=` line joiners paste.
fn handle_event(endpoint: &Endpoint, role: &str, relay: Option<&PeerAddr>, event: EndpointEvent) {
    match event {
        EndpointEvent::ConnectionEstablished { peer_id, .. } => {
            println!("[{role}] connected peer={peer_id}");
        }
        EndpointEvent::ConnectionClosed { peer_id, .. } => {
            println!("[{role}] disconnected peer={peer_id}");
        }
        EndpointEvent::Error(error) => {
            eprintln!("[{role}] error {:?}: {}", error.kind, error.detail);
        }
        EndpointEvent::Gossipsub(event) => print_gossipsub_event(role, event),
        EndpointEvent::Nat(event) => {
            print_nat_event(role, &event);
            // A reservation that lands late (after the startup wait
            // warned) or is re-acquired after a loss still needs its
            // circuit address printed -- joiners have nothing to
            // paste otherwise.
            if let Some(relay) = relay
                && matches!(&event, NatEvent::RelayReserved { relay: reserved, .. }
                    if reserved == relay.peer_id())
            {
                println!(
                    "[{role}] circuit={}",
                    circuit_addr(relay, endpoint.peer_id())
                );
            }
        }
        EndpointEvent::Discovery(event) => print_discovery_event(role, event),
        _ => {}
    }
}

fn print_discovery_event(role: &str, event: DiscoveryEvent) {
    match event {
        DiscoveryEvent::PeerDiscovered {
            peer,
            addrs,
            source,
        } => {
            println!(
                "[{role}] discovered peer={} source={source:?} addrs={}",
                short(&peer),
                addrs.len()
            );
        }
        DiscoveryEvent::PeerUpdated {
            peer,
            addrs,
            source,
        } => {
            println!(
                "[{role}] discovery-updated peer={} source={source:?} addrs={}",
                short(&peer),
                addrs.len()
            );
        }
        DiscoveryEvent::PeerExpired { peer } => {
            println!("[{role}] peer-expired peer={}", short(&peer));
        }
        DiscoveryEvent::DialFailed { peer, reason } => {
            eprintln!(
                "[{role}] mesh-dial-failed peer={} reason={reason}",
                short(&peer)
            );
        }
        DiscoveryEvent::ProtocolViolation {
            peer,
            source,
            reason,
            suppressed,
        } => {
            let peer = peer.as_ref().map(short).unwrap_or_else(|| "unknown".into());
            eprintln!(
                "[{role}] discovery-violation peer={peer} source={source:?} \
                 suppressed={suppressed} reason={reason}"
            );
        }
    }
}

fn print_gossipsub_event(role: &str, event: GossipsubEvent) {
    match event {
        GossipsubEvent::Message { data, from, .. } => {
            println!(
                "[chat] {} ({})",
                String::from_utf8_lossy(&data),
                short(&from)
            );
        }
        GossipsubEvent::PeerSubscribed { peer, topic } => {
            println!("[{role}] peer-subscribed peer={peer} topic={topic}");
        }
        GossipsubEvent::PeerUnsubscribed { peer, topic } => {
            println!("[{role}] peer-unsubscribed peer={peer} topic={topic}");
        }
        GossipsubEvent::OutboundFailure { peer, reason } => {
            eprintln!("[{role}] outbound-failure peer={peer} reason={reason}");
        }
        GossipsubEvent::ProtocolViolation { peer, reason } => {
            eprintln!("[{role}] violation peer={peer} reason={reason}");
        }
    }
}

fn short(peer: &PeerId) -> String {
    const DISPLAY_LEN: usize = 8;

    peer.to_base58()
        .chars()
        .rev()
        .take(DISPLAY_LEN)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use minip2p::Ed25519Keypair;

    #[test]
    fn short_peer_ids_use_the_distinguishing_suffix() {
        let first = Ed25519Keypair::from_secret_key_bytes([1; 32]).peer_id();
        let second = Ed25519Keypair::from_secret_key_bytes([2; 32]).peer_id();

        assert_eq!(short(&first).len(), 8);
        assert_eq!(short(&second).len(), 8);
        assert_ne!(short(&first), short(&second));
        assert!(first.to_base58().ends_with(&short(&first)));
        assert!(second.to_base58().ends_with(&short(&second)));
    }
}
