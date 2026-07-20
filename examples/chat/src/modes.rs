//! The chat runner: endpoint construction, host/join startup flows, and
//! the shared stdin-driven chat loop.

use std::collections::BTreeMap;
use std::error::Error;
use std::io::BufRead;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use minip2p::{
    DISCOVERY_TOPIC, DiscoveryConfig, DiscoveryEvent, Endpoint, Event, FloodsubConfig, NatConfig,
    NatEvent, Path, PeerAddr, PeerId, PublishError, PubsubError, PubsubEvent, StreamId,
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
/// After a relayed path, how long a joiner waits for the hole punch.
const PUNCH_WAIT: Duration = Duration::from_secs(30);
/// Identify must complete before floodsub can open streams.
const READY_DEADLINE: Duration = Duration::from_secs(15);

struct ResponderBridge {
    target_peer: PeerId,
    cleanup_deadline: Instant,
}

struct ChatEndpoint {
    endpoint: Endpoint,
    responder_bridge_lifetime: Duration,
}

// --- endpoint construction --------------------------------------------------

fn build_endpoint(
    role: &str,
    relays: &[PeerAddr],
    options: &ChatOptions,
) -> Result<ChatEndpoint, Box<dyn Error>> {
    let keypair = load_keypair(options.key_path.as_deref(), role)?;
    let nat_config = NatConfig::default();
    let responder_bridge_lifetime = responder_bridge_lifetime(&nat_config);
    let mut builder = Endpoint::builder()
        .identity(keypair)
        .agent_version(AGENT)
        .pubsub_config(FloodsubConfig {
            allow_unsigned: options.allow_unsigned,
            ..FloodsubConfig::default()
        })
        .nat_config(nat_config);
    if !options.no_mesh {
        let room = options
            .topic
            .clone()
            .unwrap_or_else(|| DEFAULT_TOPIC.to_string());
        builder = builder.discovery_config(DiscoveryConfig {
            topic: format!("{room}/{DISCOVERY_TOPIC}"),
            beacon_interval_ms: 2_000,
            peer_ttl_ms: 10_000,
            ..DiscoveryConfig::default()
        })?;
    }
    for relay in relays {
        builder = builder.relay(relay.clone());
    }
    let endpoint = match &options.listen_addr {
        Some(addr) => builder
            .bind_quic_multiaddr(addr)
            .map_err(|e| format!("quic bind {addr}: {e}"))?,
        None => builder
            .bind_quic_dual_stack()
            .map_err(|e| format!("quic dual-stack bind: {e}"))?,
    };
    Ok(ChatEndpoint {
        endpoint,
        responder_bridge_lifetime,
    })
}

fn responder_bridge_lifetime(config: &NatConfig) -> Duration {
    Duration::from_millis(
        config
            .punch_deadline_ms
            .saturating_mul(1 + u64::from(config.punch_max_retries))
            .saturating_add(1_000),
    )
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
    let ChatEndpoint {
        mut endpoint,
        responder_bridge_lifetime,
    } = build_endpoint("host", &relays, &options)?;
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

    run_chat(
        &mut endpoint,
        &topic,
        &nick,
        "host",
        relays.first(),
        responder_bridge_lifetime,
    )
}

/// Drives the endpoint until the relay reservation lands, printing the
/// `circuit=` line joiners paste. A miss is a warning, not an error — the
/// host keeps retrying in the background and stays joinable directly.
fn wait_for_reservation(endpoint: &mut Endpoint, relay: &PeerAddr) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + RESERVATION_DEADLINE;
    loop {
        for event in endpoint.take_nat_events() {
            print_nat_event("host", &event);
            if matches!(&event, NatEvent::RelayReserved { relay: reserved, .. }
                if reserved == relay.peer_id())
            {
                println!("[host] circuit={}", circuit_addr(relay, endpoint.peer_id()));
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            eprintln!("[host] warning: no relay reservation within 30s; still retrying");
            return Ok(());
        }
        let _ = endpoint.next_event(Duration::from_millis(200))?;
    }
}

// --- join -------------------------------------------------------------------

/// Joins a room through the NAT agent, insisting on a direct path (pubsub
/// cannot run over a raw relay bridge; see the README), then chats until
/// stdin EOF.
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

    let ChatEndpoint {
        mut endpoint,
        responder_bridge_lifetime,
    } = build_endpoint("join", &relays, &options)?;
    // Listening seeds the agent's bound addresses — the local half of the
    // DCUtR candidate set.
    endpoint
        .listen_all()
        .map_err(|e| format!("listen failed: {e}"))?;
    println!("[join] us={}", endpoint.peer_id());

    let (host_peer, connect_id) = match &target {
        JoinTarget::Circuit { peer, .. } => {
            println!("[join] target={peer} via-relay={}", relays[0].peer_id());
            let id = endpoint
                .connect(peer)
                .map_err(|e| format!("connect failed: {e}"))?;
            (peer.clone(), id)
        }
        JoinTarget::Direct(addr) => {
            println!("[join] target={addr}");
            let id = endpoint
                .connect_addr(addr)
                .map_err(|e| format!("connect failed: {e}"))?;
            (addr.peer_id().clone(), id)
        }
    };

    let path = endpoint
        .wait_path(connect_id, CONNECT_DEADLINE)
        .map_err(|e| format!("waiting for a path: {e}"))?;
    let Some(path) = path else {
        for event in endpoint.take_nat_events() {
            print_nat_event("join", &event);
        }
        return Err("no path to the host".into());
    };
    println!("[join] path={}", path_name(&path));

    // Floodsub negotiates real streams, which a raw relay bridge cannot
    // carry: hold out for the hole punch.
    if matches!(path, Path::Relayed { .. }) {
        println!("[join] waiting for the hole punch (chat needs a direct path)");
        wait_for_direct_upgrade(&mut endpoint, &host_peer)?;
    }

    endpoint
        .wait_peer_ready(&host_peer, READY_DEADLINE)
        .map_err(|e| format!("waiting for identify: {e}"))?
        .ok_or("identify never completed on the direct connection")?;

    let (topic, nick) = topic_and_nick(&options, &endpoint);
    endpoint
        .subscribe(&topic)
        .map_err(|e| format!("subscribe: {e}"))?;
    println!("[join] subscribed topic={topic} nick={nick}");

    run_chat(
        &mut endpoint,
        &topic,
        &nick,
        "join",
        None,
        responder_bridge_lifetime,
    )
}

fn wait_for_direct_upgrade(
    endpoint: &mut Endpoint,
    host_peer: &PeerId,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + PUNCH_WAIT;
    loop {
        for event in endpoint.take_nat_events() {
            print_nat_event("join", &event);
            if matches!(&event, NatEvent::PathUpgraded { peer, to, .. }
                if peer == host_peer && !matches!(to, Path::Relayed { .. }))
            {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err(
                "the hole punch did not complete; chat cannot run over the relay bridge \
                 (known v1 limitation, see examples/chat/README.md)"
                    .into(),
            );
        }
        let _ = endpoint.next_event(Duration::from_millis(100))?;
    }
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
        let _ = tx.send(None);
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
    responder_bridge_lifetime: Duration,
) -> Result<(), Box<dyn Error>> {
    let input = spawn_stdin_reader();
    eprintln!("[{role}] type to chat; Ctrl-D to leave");

    // A pipe can produce lines faster than a human ever will; bounding the
    // per-tick drain keeps the network pump (next_event below) live even
    // under a stdin flood.
    const MAX_LINES_PER_TICK: usize = 32;

    // QUIC drops a connection after 30 s of silence (the transport's idle
    // timeout), and a quiet room generates no traffic of its own — ping
    // every connected peer well inside that window.
    const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
    let mut last_keepalive = Instant::now();
    let mut responder_bridges: BTreeMap<(PeerId, StreamId), ResponderBridge> = BTreeMap::new();

    loop {
        let expired: Vec<_> = responder_bridges
            .iter()
            .filter(|(_, bridge)| Instant::now() >= bridge.cleanup_deadline)
            .map(|(key, _)| key.clone())
            .collect();
        for (relay_peer, stream_id) in expired {
            let _ = endpoint.abandon_stream(&relay_peer, stream_id);
            responder_bridges.remove(&(relay_peer, stream_id));
        }
        if last_keepalive.elapsed() >= KEEPALIVE_INTERVAL {
            last_keepalive = Instant::now();
            for peer in endpoint.connected_peers() {
                // A peer mid-disconnect can fail the ping; the close event
                // will surface it.
                let _ = endpoint.ping(&peer);
            }
        }

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
                        Err(PubsubError::Publish(PublishError::Backpressure)) => {
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

        if let Some(event) = endpoint.next_event(Duration::from_millis(100))? {
            match &event {
                Event::ConnectionEstablished { peer_id, .. } => {
                    println!("[{role}] connected peer={peer_id}");
                    abandon_responder_bridges(endpoint, &mut responder_bridges, peer_id);
                }
                Event::ConnectionClosed { peer_id, .. } => {
                    println!("[{role}] disconnected peer={peer_id}");
                    responder_bridges.retain(|(relay_peer, _), _| relay_peer != peer_id);
                }
                Event::Error(error) => {
                    eprintln!("[{role}] error {:?}: {}", error.kind, error.detail);
                }
                _ => {}
            }
        }

        for event in endpoint.take_pubsub_events() {
            match event {
                PubsubEvent::Message { data, from, .. } => {
                    println!(
                        "[chat] {} ({})",
                        String::from_utf8_lossy(&data),
                        short(&from)
                    );
                }
                PubsubEvent::PeerSubscribed { peer, topic } => {
                    println!("[{role}] peer-subscribed peer={peer} topic={topic}");
                }
                PubsubEvent::PeerUnsubscribed { peer, topic } => {
                    println!("[{role}] peer-unsubscribed peer={peer} topic={topic}");
                }
                PubsubEvent::OutboundFailure { peer, reason } => {
                    eprintln!("[{role}] outbound-failure peer={peer} reason={reason}");
                }
                PubsubEvent::ProtocolViolation { peer, reason } => {
                    eprintln!("[{role}] violation peer={peer} reason={reason}");
                }
            }
        }

        for event in endpoint.take_nat_events() {
            print_nat_event(role, &event);
            match &event {
                NatEvent::InboundRelayCircuit {
                    peer,
                    relay,
                    stream_id,
                    ..
                } => {
                    responder_bridges.insert(
                        (relay.clone(), *stream_id),
                        ResponderBridge {
                            target_peer: peer.clone(),
                            cleanup_deadline: Instant::now() + responder_bridge_lifetime,
                        },
                    );
                }
                NatEvent::InboundDirectUpgrade { peer } => {
                    abandon_responder_bridges(endpoint, &mut responder_bridges, peer);
                }
                _ => {}
            }
            // A reservation that lands late (after the startup wait warned)
            // or is re-acquired after a loss still needs its circuit
            // address printed -- joiners have nothing to paste otherwise.
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

        for event in endpoint.take_discovery_events() {
            match event {
                DiscoveryEvent::PeerDiscovered { peer, addrs } => {
                    println!(
                        "[{role}] discovered peer={} addrs={}",
                        short(&peer),
                        addrs.len()
                    );
                }
                DiscoveryEvent::PeerUpdated { peer, addrs } => {
                    println!(
                        "[{role}] mesh-updated peer={} addrs={}",
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
                DiscoveryEvent::ProtocolViolation { peer, reason } => {
                    eprintln!(
                        "[{role}] discovery-violation peer={} reason={reason}",
                        short(&peer)
                    );
                }
            }
        }
    }
}

fn abandon_responder_bridges(
    endpoint: &mut Endpoint,
    bridges: &mut BTreeMap<(PeerId, StreamId), ResponderBridge>,
    target: &PeerId,
) {
    let matches: Vec<_> = bridges
        .iter()
        .filter(|(_, bridge)| &bridge.target_peer == target)
        .map(|(key, _)| key.clone())
        .collect();
    for (relay, stream_id) in matches {
        let _ = endpoint.abandon_stream(&relay, stream_id);
        bridges.remove(&(relay, stream_id));
    }
}

fn short(peer: &PeerId) -> String {
    const DISPLAY_LEN: usize = 8;

    let encoded = peer.to_base58();
    // Base58 is ASCII, so this byte offset is always a character boundary.
    encoded[encoded.len().saturating_sub(DISPLAY_LEN)..].to_owned()
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

    #[test]
    fn responder_bridge_lifetime_comes_from_the_endpoint_nat_config() {
        let config = NatConfig {
            punch_deadline_ms: 7,
            punch_max_retries: 4,
            ..NatConfig::default()
        };

        assert_eq!(
            responder_bridge_lifetime(&config),
            Duration::from_millis(1_035)
        );
    }
}
