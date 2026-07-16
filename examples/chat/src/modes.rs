//! The chat runner: endpoint construction, host/join startup flows, and
//! the shared stdin-driven chat loop.

use std::error::Error;
use std::io::BufRead;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use minip2p::{
    Endpoint, Event, NatConfig, NatEvent, Path, PeerAddr, PeerId, PublishError, PubsubError,
    PubsubEvent,
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

// --- endpoint construction --------------------------------------------------

fn build_endpoint(
    role: &str,
    relays: &[PeerAddr],
    options: &ChatOptions,
) -> Result<Endpoint, Box<dyn Error>> {
    let keypair = load_keypair(options.key_path.as_deref(), role)?;
    let mut builder = Endpoint::builder()
        .identity(keypair)
        .agent_version(AGENT)
        .pubsub()
        .nat_config(NatConfig::default());
    for relay in relays {
        builder = builder.relay(relay.clone());
    }
    match &options.listen_addr {
        Some(addr) => builder
            .bind_quic_multiaddr(addr)
            .map_err(|e| format!("quic bind {addr}: {e}").into()),
        None => builder
            .bind_quic_dual_stack()
            .map_err(|e| format!("quic dual-stack bind: {e}").into()),
    }
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
    let mut endpoint = build_endpoint("host", &relays, &options)?;
    let peer_addrs = endpoint
        .listen_all()
        .map_err(|e| format!("listen failed: {e}"))?;
    let first = peer_addrs
        .first()
        .ok_or("listen completed without any bound peer addresses")?;
    println!("[host] bound={}", local_dialable_peer_addr(first));
    println!("[host] us={}", endpoint.peer_id());

    if let Some(relay) = relays.first() {
        wait_for_reservation(&mut endpoint, relay)?;
    }

    let (topic, nick) = topic_and_nick(&options, &endpoint);
    endpoint
        .subscribe(&topic)
        .map_err(|e| format!("subscribe: {e}"))?;
    println!("[host] subscribed topic={topic} nick={nick}");

    run_chat(&mut endpoint, &topic, &nick, "host")
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

    let mut endpoint = build_endpoint("join", &relays, &options)?;
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

    run_chat(&mut endpoint, &topic, &nick, "join")
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
) -> Result<(), Box<dyn Error>> {
    let input = spawn_stdin_reader();
    eprintln!("[{role}] type to chat; Ctrl-D to leave");

    // A pipe can produce lines faster than a human ever will; bounding the
    // per-tick drain keeps the network pump (next_event below) live even
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
                Event::ConnectionEstablished { peer_id } => {
                    println!("[{role}] connected peer={peer_id}");
                }
                Event::ConnectionClosed { peer_id } => {
                    println!("[{role}] disconnected peer={peer_id}");
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
        }
    }
}

fn short(peer: &PeerId) -> String {
    peer.to_base58().chars().take(8).collect()
}
