//! The two NAT-aware runners behind `minip2p-peer listen` / `dial`.
//!
//! Both build the same endpoint shape: QUIC or TCP transport, the echo protocol,
//! and the NAT traversal agent (always on — with no relay configured it
//! simply resolves direct paths). The listener echoes every inbound echo
//! stream byte for byte; the dialer sends one 16-byte ping frame per second
//! and tags each measured RTT with the path it travelled, so a mid-run
//! `relayed → direct` hole-punch upgrade shows up as an RTT drop with an
//! unbroken seq sequence.

use std::collections::{BTreeSet, HashMap};
use std::error::Error;
use std::time::{Duration, Instant};

use minip2p::{
    ConnectId, ConnectOutcome, ConnectionId, Endpoint, EndpointEvent, EndpointWaitOutcome,
    NatConfig, NatEvent, Path, PeerAddr, PeerId, StreamId, StreamWriteError, StreamWriter,
};

use minip2p_example_common::{
    circuit_addr, load_keypair, local_dialable_peer_addr, path_name, print_nat_event,
};

use crate::cli::{DialTarget, RunOptions, print_event};

/// An echo stream: its connection and its id.
type EchoStream = (ConnectionId, StreamId);

/// What an echo stream still owes its peer beyond the writer's pending
/// write: bytes that arrived while that write was pending, and whether the
/// peer's FIN should be mirrored once they are sent.
#[derive(Default)]
struct Echo {
    backlog: Vec<u8>,
    close: bool,
}

/// The listener's echo streams and the writer that finishes their writes.
struct Echoes {
    streams: HashMap<EchoStream, Echo>,
    writer: StreamWriter,
}

impl Default for Echoes {
    fn default() -> Self {
        Self {
            streams: HashMap::new(),
            writer: StreamWriter::new(ECHO_WRITE_BUDGET),
        }
    }
}

const AGENT: &str = "minip2p-peer/0.1.0";
/// Echo protocol: the listener returns every byte unchanged.
const ECHO_PROTOCOL: &str = "/minip2p/echo/1";
/// One ping frame: 8-byte seq (BE) ++ 8-byte send-timestamp millis (BE).
const FRAME_LEN: usize = 16;
/// The most bytes one echo stream may queue behind its pending write; a peer
/// that sends more without reading is reset. Bytes arriving while nothing is
/// pending go straight to the writer, within `ECHO_WRITE_BUDGET`.
const ECHO_STREAM_LIMIT: usize = 64 * 1024;
/// The most echo bytes the writer holds across every stream; a stream it
/// cannot admit is reset like an overflowing one.
const ECHO_WRITE_BUDGET: usize = 16 * 1024 * 1024;
/// The most ping bytes a channel holds while its stream is full: room for
/// every outstanding frame of a long run.
const PING_WRITE_BUDGET: usize = 1024 * 1024;
/// Cadence of the dialer's pings.
const PING_INTERVAL: Duration = Duration::from_secs(1);
/// Outlives the engine's 30 s connect deadline so the path wait can still
/// observe a late `PathEstablished` instead of timing out first.
const CONNECT_DEADLINE: Duration = Duration::from_secs(65);
/// How long the listener waits for its first relay reservation before
/// warning and moving on (the agent keeps retrying in the background).
const RESERVATION_DEADLINE: Duration = Duration::from_secs(30);
/// Post-`--count` grace period for the last pongs to arrive.
const DRAIN_DEADLINE: Duration = Duration::from_secs(3);
/// Ceiling on identify/stream setup after a connection exists.
const SETUP_DEADLINE: Duration = Duration::from_secs(10);

// --- shared plumbing -------------------------------------------------------

/// Builds the endpoint both modes share. The NAT agent is always enabled so
/// `connect` reports a path even with no relay configured.
fn build_endpoint(
    role: &str,
    relays: &[PeerAddr],
    options: &RunOptions,
) -> Result<Endpoint, Box<dyn Error>> {
    let keypair = load_keypair(options.key_path.as_deref(), role)?;
    let mut builder = Endpoint::builder()
        .identity(keypair)
        .agent_version(AGENT)
        .protocol(ECHO_PROTOCOL)
        .nat_config(NatConfig::default());
    for relay in relays {
        builder = builder.relay(relay.clone());
    }
    if let Some(autonat) = &options.autonat {
        builder = builder.autonat_server(autonat.clone());
    }
    match &options.listen_addr {
        Some(addr) => builder
            .listen_on_multiaddr(addr)
            .and_then(|builder| builder.bind())
            .map_err(|e| format!("bind {addr}: {e}").into()),
        None => builder
            .listen_default()
            .and_then(|builder| builder.bind())
            .map_err(|e| format!("quic dual-stack bind: {e}").into()),
    }
}

// --- frame codec -----------------------------------------------------------

fn encode_frame(seq: u64, sent_at_ms: u64) -> [u8; FRAME_LEN] {
    let mut frame = [0u8; FRAME_LEN];
    frame[..8].copy_from_slice(&seq.to_be_bytes());
    frame[8..].copy_from_slice(&sent_at_ms.to_be_bytes());
    frame
}

fn decode_frame(frame: &[u8; FRAME_LEN]) -> (u64, u64) {
    let seq = u64::from_be_bytes(frame[..8].try_into().expect("8-byte slice"));
    let sent_at_ms = u64::from_be_bytes(frame[8..].try_into().expect("8-byte slice"));
    (seq, sent_at_ms)
}

/// Reassembles fixed-size frames out of a QUIC byte stream: the transport
/// may fragment or coalesce writes arbitrarily.
#[derive(Default)]
struct FrameBuf {
    buf: Vec<u8>,
    head: usize,
}

impl FrameBuf {
    fn push(&mut self, data: &[u8]) {
        // Compact at most once per transport chunk. Draining from the front
        // for every 16-byte frame would repeatedly shift the unread suffix.
        if self.head != 0 {
            self.buf.copy_within(self.head.., 0);
            self.buf.truncate(self.buf.len() - self.head);
            self.head = 0;
        }
        self.buf.extend_from_slice(data);
    }

    fn pop(&mut self) -> Option<[u8; FRAME_LEN]> {
        let end = self.head.checked_add(FRAME_LEN)?;
        if end > self.buf.len() {
            return None;
        }
        let mut frame = [0u8; FRAME_LEN];
        frame.copy_from_slice(self.buf.get(self.head..end)?);
        self.head = end;
        if self.head == self.buf.len() {
            self.buf.clear();
            self.head = 0;
        }
        Some(frame)
    }

    fn clear(&mut self) {
        self.buf.clear();
        self.head = 0;
    }
}

// --- listen ----------------------------------------------------------------

/// Runs the listener until interrupted (SIGINT). Echoes every tracked echo
/// stream — direct streams and relayed bridges alike — byte for byte.
pub fn run_listen(relay: Option<PeerAddr>, options: RunOptions) -> Result<(), Box<dyn Error>> {
    let relays: Vec<PeerAddr> = relay.into_iter().collect();
    let mut endpoint = build_endpoint("listen", &relays, &options)?;
    let peer_addrs = endpoint
        .listen_all()
        .map_err(|e| format!("listen failed: {e}"))?;
    let first = peer_addrs
        .first()
        .ok_or("listen completed without any bound peer addresses")?;
    // Stdout: the machine-readable event stream the E2E test scans.
    println!("[listen] bound={}", local_dialable_peer_addr(first));
    for addr in &peer_addrs {
        println!("[listen] listen-addr={addr}");
    }
    println!("[listen] us={}", endpoint.peer_id());

    // Echo streams we own: on the dialing peer's connection for direct
    // streams, on the relay's for bridged circuits.
    let mut echo_streams = Echoes::default();

    if let Some(relay) = relays.first() {
        wait_for_reservation(&mut endpoint, relay, &mut echo_streams)?;
    }
    eprintln!("[listen] echoing on {ECHO_PROTOCOL} (Ctrl-C to stop)");

    loop {
        if let EndpointWaitOutcome::Event(event) = endpoint
            .wait(Duration::from_millis(200))
            .map_err(|e| format!("swarm poll: {e}"))?
        {
            dispatch_listen_event(&mut endpoint, &event, relays.first(), &mut echo_streams);
        }
    }
}

/// Serves events until the first reservation confirms (printing the
/// paste-ready `circuit=` line) or the deadline passes with a warning; the
/// agent keeps retrying either way and renewals re-print via the main loop.
fn wait_for_reservation(
    endpoint: &mut Endpoint,
    relay: &PeerAddr,
    echo_streams: &mut Echoes,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + RESERVATION_DEADLINE;
    loop {
        match endpoint
            .wait(deadline)
            .map_err(|e| format!("swarm poll: {e}"))?
        {
            EndpointWaitOutcome::Event(event) => {
                dispatch_listen_event(endpoint, &event, Some(relay), echo_streams);
                if let EndpointEvent::Nat(NatEvent::RelayReserved { .. }) = event {
                    return Ok(());
                }
            }
            EndpointWaitOutcome::Deadline => {
                eprintln!(
                    "[listen] warning: no relay reservation within {}s; still retrying",
                    RESERVATION_DEADLINE.as_secs()
                );
                return Ok(());
            }
            _ => {}
        }
    }
}

/// Prints one listener event and serves it: `circuit=` lines for
/// reservations and byte-for-byte echo on tracked echo streams.
fn dispatch_listen_event(
    endpoint: &mut Endpoint,
    event: &EndpointEvent,
    relay: Option<&PeerAddr>,
    echo_streams: &mut Echoes,
) {
    print_event("listen", event);
    if let EndpointEvent::Nat(NatEvent::RelayReserved { .. }) = event
        && let Some(relay) = relay
    {
        println!(
            "[listen] circuit={}",
            circuit_addr(relay, endpoint.peer_id())
        );
    }
    handle_listen_event(endpoint, event, echo_streams);
}

fn handle_listen_event(endpoint: &mut Endpoint, event: &EndpointEvent, echoes: &mut Echoes) {
    // The writer follows every event first: it finishes held echoes on
    // Writable and forgets the ones whose stream or connection ended.
    if let Some(done) = echoes.writer.observe(endpoint, event) {
        flush_echo(endpoint, (done.conn_id, done.stream_id), echoes);
    }
    match event {
        EndpointEvent::StreamReady {
            conn_id,
            stream_id,
            protocol_id,
            initiated_locally: false,
            ..
        } if protocol_id == ECHO_PROTOCOL => {
            echoes
                .streams
                .insert((*conn_id, *stream_id), Echo::default());
        }
        EndpointEvent::StreamData {
            conn_id,
            stream_id,
            data,
            ..
        } => {
            let key = (*conn_id, *stream_id);
            if let Some(echo) = echoes.streams.get_mut(&key) {
                if echoes.writer.is_pending(*conn_id, *stream_id)
                    && echo.backlog.len() + data.len() > ECHO_STREAM_LIMIT
                {
                    drop_echo(endpoint, key, echoes, "the peer is not reading its echo");
                } else {
                    echo.backlog.extend_from_slice(data);
                    flush_echo(endpoint, key, echoes);
                }
            }
        }
        EndpointEvent::StreamRemoteWriteClosed {
            conn_id, stream_id, ..
        } => {
            let key = (*conn_id, *stream_id);
            if let Some(echo) = echoes.streams.get_mut(&key) {
                echo.close = true;
                flush_echo(endpoint, key, echoes);
            }
        }
        // A stopped write side can never carry the echo, so drop its backlog.
        EndpointEvent::StreamWriteStopped {
            conn_id, stream_id, ..
        }
        | EndpointEvent::StreamClosed {
            conn_id, stream_id, ..
        } => {
            echoes.streams.remove(&(*conn_id, *stream_id));
        }
        // A closed or replaced connection ends its streams without
        // per-stream `StreamClosed` events, so untrack them all here.
        EndpointEvent::ConnectionClosed { conn_id, .. }
        | EndpointEvent::ConnectionReplaced { old: conn_id, .. } => {
            echoes.streams.retain(|(conn, _), _| conn != conn_id);
        }
        _ => {}
    }
}

/// Sends an echo stream's backlog once its previous write is accepted, then
/// mirrors the peer's FIN behind it. A full stream is not a dead one: the
/// writer holds the unsent tail and this runs again on its acceptance.
fn flush_echo(endpoint: &mut Endpoint, key: EchoStream, echoes: &mut Echoes) {
    let (conn, stream) = key;
    if echoes.writer.is_pending(conn, stream) {
        return;
    }
    let Some(echo) = echoes.streams.get_mut(&key) else {
        return;
    };
    let mut result = Ok(());
    if !echo.backlog.is_empty() {
        result = echoes
            .writer
            .write(endpoint, conn, stream, std::mem::take(&mut echo.backlog))
            .map(drop);
    }
    if result.is_ok() && echo.close {
        result = echoes.writer.close_write(endpoint, conn, stream);
        echoes.streams.remove(&key);
    }
    if let Err(e) = result {
        drop_echo(endpoint, key, echoes, &e.to_string());
    }
}

/// Gives up on an echo stream: resets it, so the peer learns the echo
/// stopped, and forgets what it still owed.
fn drop_echo(endpoint: &mut Endpoint, key: EchoStream, echoes: &mut Echoes, why: &str) {
    let (conn, stream) = key;
    eprintln!("[listen] echo failed conn={conn} stream={stream}: {why}");
    echoes.streams.remove(&key);
    echoes.writer.forget(conn, stream);
    // A stream that is already gone has nothing left to reset.
    match endpoint.reset_stream(conn, stream) {
        Ok(()) | Err(_) => {}
    }
}

// --- dial ------------------------------------------------------------------

/// Where the dialer's ping frames currently travel.
struct Channel {
    conn: ConnectionId,
    stream: StreamId,
    direct: bool,
    /// Holds a frame the stream could not take at once; dropped with the
    /// channel when it is replaced.
    writer: StreamWriter,
}

impl Channel {
    fn name(&self) -> &'static str {
        if self.direct { "direct" } else { "relayed" }
    }

    /// Whether a stream event names this channel's stream.
    fn carries(&self, conn: ConnectionId, stream: StreamId) -> bool {
        conn == self.conn && stream == self.stream
    }

    /// Sends `data`, leaving any unsent tail with the writer. A full stream
    /// is backpressure, not a dead channel.
    fn send(&mut self, endpoint: &mut Endpoint, data: Vec<u8>) -> Result<(), StreamWriteError> {
        self.writer
            .write(endpoint, self.conn, self.stream, data)
            .map(drop)
    }

    /// Half-closes the channel, after any frame the writer still holds.
    fn close_write(&mut self, endpoint: &mut Endpoint) -> Result<(), StreamWriteError> {
        self.writer.close_write(endpoint, self.conn, self.stream)
    }
}

/// Per-path RTT accounting for the final summary.
#[derive(Default)]
struct RttBucket {
    count: u64,
    total_rtt_ms: u64,
}

impl RttBucket {
    fn record(&mut self, rtt_ms: u64) {
        self.count += 1;
        self.total_rtt_ms += rtt_ms;
    }

    fn avg_ms(&self) -> u64 {
        self.total_rtt_ms.checked_div(self.count).unwrap_or(0)
    }
}

#[derive(Default)]
struct PingStats {
    sent: u64,
    received: u64,
    relayed: RttBucket,
    direct: RttBucket,
}

impl PingStats {
    fn print_summary(&self) {
        println!(
            "[dial] summary sent={} received={} relayed-count={} relayed-avg-rtt={}ms \
             direct-count={} direct-avg-rtt={}ms",
            self.sent,
            self.received,
            self.relayed.count,
            self.relayed.avg_ms(),
            self.direct.count,
            self.direct.avg_ms()
        );
    }
}

/// Connects to `target` through the NAT agent and pings once per second
/// until `count` is reached (summary + exit 0) or the channel dies.
pub fn run_dial(
    target: DialTarget,
    relay: Option<PeerAddr>,
    count: Option<u64>,
    options: RunOptions,
) -> Result<(), Box<dyn Error>> {
    // The circuit target's relay leads the list; --relay adds a fallback.
    let mut relays: Vec<PeerAddr> = Vec::new();
    if let DialTarget::Circuit { relay, .. } = &target {
        relays.push(relay.clone());
    }
    if let Some(extra) = relay
        && !relays.iter().any(|r| r.peer_id() == extra.peer_id())
    {
        relays.push(extra);
    }

    let mut endpoint = build_endpoint("dial", &relays, &options)?;
    // Listening seeds the agent's bound addresses — the local half of the
    // DCUtR candidate set.
    endpoint
        .listen_all()
        .map_err(|e| format!("listen failed: {e}"))?;
    println!("[dial] us={}", endpoint.peer_id());

    let start = Instant::now();
    let (peer, connect_id) = match &target {
        DialTarget::Circuit { peer, .. } => {
            let relay = relays
                .first()
                .ok_or("circuit target has no relay configured")?;
            println!("[dial] target={peer} via-relay={}", relay.peer_id());
            let id = endpoint
                .connect(peer)
                .map_err(|e| format!("connect failed: {e}"))?;
            (peer.clone(), id)
        }
        DialTarget::Direct(addr) => {
            println!("[dial] target={addr}");
            let id = endpoint
                .connect(addr)
                .map_err(|e| format!("connect failed: {e}"))?;
            (addr.peer_id().clone(), id)
        }
    };

    let path = wait_for_path(&mut endpoint, &peer, connect_id)?;
    println!(
        "[dial] path-established path={} elapsed={}ms elapsed-us={}",
        path_name(&path),
        start.elapsed().as_millis(),
        micros_since(start)
    );

    let frames = FrameBuf::default();
    let mut channel =
        establish_direct_channel(&mut endpoint, &peer, &BTreeSet::new(), None, start)?;
    // The path can upgrade while the channel is being set up, and its
    // `PathUpgraded` is then printed by the setup waits rather than seen by
    // the ping loop. The State snapshot is authoritative either way.
    channel.direct = !matches!(endpoint.path(&peer), Some(Path::Relayed { .. }));
    println!(
        "[dial] channel-ready path={} elapsed-us={}",
        channel.name(),
        micros_since(start)
    );

    ping_loop(&mut endpoint, &peer, channel, frames, count, start)
}

/// Waits for the attempt's first usable path (the provisional relayed one,
/// when that lands first), printing unrelated events as they arrive. An
/// attempt that settles connected without a path event reports the current
/// path; a failed or cancelled one ends the run.
fn wait_for_path(
    endpoint: &mut Endpoint,
    peer: &PeerId,
    connect_id: ConnectId,
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
            EndpointWaitOutcome::Event(
                event @ EndpointEvent::ConnectSettled { connect_id: id, .. },
            ) if id == connect_id => {
                print_event("dial", &event);
                let connected = matches!(
                    event,
                    EndpointEvent::ConnectSettled {
                        outcome: ConnectOutcome::Connected { .. },
                        ..
                    }
                );
                return connected
                    .then(|| endpoint.path(peer))
                    .flatten()
                    .ok_or_else(|| "no path to the target".into());
            }
            EndpointWaitOutcome::Event(event) => print_event("dial", &event),
            EndpointWaitOutcome::Deadline => return Err("no path to the target".into()),
            _ => {}
        }
    }
}

/// Opens the echo stream on a direct connection. Waiting for Identify first
/// is this demo's policy (early protocol advertisement); the stack allows
/// `open_stream` once connected. The stream must finish negotiating before
/// `deadline`.
fn open_echo_stream(
    endpoint: &mut Endpoint,
    peer: &PeerId,
    deadline: Instant,
) -> Result<(ConnectionId, StreamId), Box<dyn Error>> {
    while !endpoint.is_peer_ready(peer) {
        match endpoint
            .wait(deadline)
            .map_err(|e| format!("waiting for identify: {e}"))?
        {
            EndpointWaitOutcome::Event(event) => print_event("dial", &event),
            EndpointWaitOutcome::Deadline => {
                return Err("identify never completed on the direct connection".into());
            }
            _ => {}
        }
    }
    let (conn, stream) = endpoint
        .open_stream(peer, ECHO_PROTOCOL)
        .map_err(|e| format!("open echo stream: {e}"))?;
    loop {
        let event = match endpoint
            .wait(deadline)
            .map_err(|e| format!("waiting for echo stream: {e}"))?
        {
            EndpointWaitOutcome::Event(event) => event,
            EndpointWaitOutcome::Deadline => return Err("echo stream never became ready".into()),
            _ => continue,
        };
        match &event {
            EndpointEvent::StreamReady {
                peer_id,
                conn_id,
                stream_id,
                ..
            } if peer_id == peer && *conn_id == conn && *stream_id == stream => {
                return Ok((conn, stream));
            }
            EndpointEvent::ConnectionReplaced { peer_id, old, .. }
                if peer_id == peer && *old == conn =>
            {
                print_event("dial", &event);
                // A second punch connection just replaced the one this
                // stream was opened on; the stream ended with it, so its
                // `StreamReady` will never arrive. Let the caller retry on
                // the new connection right away.
                return Err("connection replaced during echo stream setup".into());
            }
            _ => print_event("dial", &event),
        }
    }
}

/// [`open_direct_channel`] with retries: a hole punch is a connection race,
/// and the losing connection can take a just-opened stream down with it —
/// mid-setup or right after. Each retry runs on whatever connection
/// survived.
fn establish_direct_channel(
    endpoint: &mut Endpoint,
    peer: &PeerId,
    outstanding: &BTreeSet<u64>,
    drain_deadline: Option<Instant>,
    start: Instant,
) -> Result<Channel, Box<dyn Error>> {
    let mut attempts = 5u32;
    loop {
        match open_direct_channel(endpoint, peer, outstanding, drain_deadline, start) {
            Ok(channel) => return Ok(channel),
            Err(e) if attempts > 0 => {
                attempts -= 1;
                eprintln!("[dial] direct channel setup failed ({e}); retrying");
            }
            Err(e) => return Err(e),
        }
    }
}

/// Opens (or reopens) the direct echo channel and resends every
/// outstanding seq with a fresh timestamp, so the sequence stays unbroken
/// and RTTs stay honest. During the post-count drain the grace period
/// bounds the setup, and the new stream is immediately half-closed —
/// the final counted ping already went out.
fn open_direct_channel(
    endpoint: &mut Endpoint,
    peer: &PeerId,
    outstanding: &BTreeSet<u64>,
    drain_deadline: Option<Instant>,
    start: Instant,
) -> Result<Channel, Box<dyn Error>> {
    let setup = Instant::now() + SETUP_DEADLINE;
    let deadline = drain_deadline.map_or(setup, |drain| drain.min(setup));
    let (conn, stream) = open_echo_stream(endpoint, peer, deadline)?;
    let mut channel = Channel {
        conn,
        stream,
        direct: true,
        writer: StreamWriter::new(PING_WRITE_BUDGET),
    };
    // One write, so the stream's single pending write can hold it all.
    let resend: Vec<u8> = outstanding
        .iter()
        .flat_map(|&missing| encode_frame(missing, millis_since(start)))
        .collect();
    if !resend.is_empty() {
        channel
            .send(endpoint, resend)
            .map_err(|e| format!("resend on direct channel: {e}"))?;
    }
    if drain_deadline.is_some() {
        channel
            .close_write(endpoint)
            .map_err(|e| format!("close after channel switch: {e}"))?;
    }
    Ok(channel)
}

/// The dialer's steady state: one ping per second, pongs measured as they
/// return, and a live channel switch when the agent upgrades the path.
fn ping_loop(
    endpoint: &mut Endpoint,
    peer: &PeerId,
    mut channel: Channel,
    mut frames: FrameBuf,
    count: Option<u64>,
    start: Instant,
) -> Result<(), Box<dyn Error>> {
    let mut stats = PingStats::default();
    let mut outstanding: BTreeSet<u64> = BTreeSet::new();
    let mut seq: u64 = 0;
    let mut next_ping = Instant::now();
    // Set once the final counted ping went out; the loop then only drains.
    let mut drain_deadline: Option<Instant> = None;
    // A hole punch is a connection race: when both simultaneous-open dials
    // land, the swarm keeps the last connection and a stream opened on the
    // first dies moments after the upgrade. Reopening is routine, but cap
    // it so a genuinely broken peer cannot loop us forever.
    let mut reopens_left: u32 = 3;

    loop {
        let wait_until = drain_deadline.unwrap_or(next_ping);
        let event = match endpoint
            .wait(wait_until)
            .map_err(|e| format!("swarm poll: {e}"))?
        {
            EndpointWaitOutcome::Event(event) => Some(event),
            EndpointWaitOutcome::Deadline => None,
            _ => continue,
        };
        let Some(event) = event else {
            // Deadline tick.
            if let Some(deadline) = drain_deadline {
                if Instant::now() >= deadline {
                    stats.print_summary();
                    return Ok(());
                }
                continue;
            }
            if channel.writer.is_pending(channel.conn, channel.stream) {
                // The previous frame is still being accepted; skip a beat
                // rather than queue behind it.
                next_ping = next_ping_deadline(Instant::now());
                continue;
            }
            seq += 1;
            outstanding.insert(seq);
            let frame = encode_frame(seq, millis_since(start));
            if let Err(e) = channel.send(endpoint, frame.to_vec()) {
                if !channel.direct || reopens_left == 0 {
                    stats.print_summary();
                    return Err(format!("ping send: {e}").into());
                }
                // A punch race can replace the direct connection moments
                // after the upgrade; the stream dies silently and this send
                // is the first to notice. Reopen on the surviving connection
                // — the reopen resends every outstanding seq, this one
                // included.
                eprintln!("[dial] ping send failed ({e}); reopening the channel");
                reopens_left -= 1;
                frames.clear();
                channel = match establish_direct_channel(
                    endpoint,
                    peer,
                    &outstanding,
                    drain_deadline,
                    start,
                ) {
                    Ok(channel) => channel,
                    Err(e) => {
                        stats.print_summary();
                        return Err(e);
                    }
                };
                println!(
                    "[dial] channel-reopened path=direct outstanding-resent={}",
                    outstanding.len()
                );
            }
            stats.sent += 1;
            println!("[dial] ping seq={seq} path={}", channel.name());
            // Schedule from the actual send time. Long-lived event handling
            // (notably a direct-channel upgrade) must not turn missed ticks
            // into a burst of catch-up pings.
            next_ping = next_ping_deadline(Instant::now());
            if count == Some(seq) {
                // Graceful teardown: half-close so the listener echoes
                // everything already sent, then mirrors the close.
                channel
                    .close_write(endpoint)
                    .map_err(|e| format!("close after final ping: {e}"))?;
                drain_deadline = Some(Instant::now() + DRAIN_DEADLINE);
            }
            continue;
        };

        // A Writable finishes a held frame (and a deferred close behind it).
        let _ = channel.writer.observe(endpoint, &event);
        match &event {
            EndpointEvent::StreamData {
                conn_id,
                stream_id,
                data,
                ..
            } if channel.carries(*conn_id, *stream_id) => {
                frames.push(data);
                while let Some(frame) = frames.pop() {
                    let (pong_seq, sent_at_ms) = decode_frame(&frame);
                    let rtt_ms = millis_since(start).saturating_sub(sent_at_ms);
                    outstanding.remove(&pong_seq);
                    stats.received += 1;
                    if channel.direct {
                        stats.direct.record(rtt_ms);
                    } else {
                        stats.relayed.record(rtt_ms);
                    }
                    println!(
                        "[dial] pong seq={pong_seq} rtt={rtt_ms}ms path={}",
                        channel.name()
                    );
                    if stats.received.is_multiple_of(10) {
                        stats.print_summary();
                    }
                }
                if drain_deadline.is_some() && outstanding.is_empty() {
                    stats.print_summary();
                    return Ok(());
                }
            }
            EndpointEvent::StreamRemoteWriteClosed {
                conn_id, stream_id, ..
            }
            | EndpointEvent::StreamClosed {
                conn_id, stream_id, ..
            } if channel.carries(*conn_id, *stream_id) => {
                print_event("dial", &event);
                if drain_deadline.is_some() {
                    stats.print_summary();
                    return Ok(());
                }
                if channel.direct && reopens_left > 0 {
                    // Same punch race as the send-failure path, noticed via
                    // the stream event instead of a failed write.
                    reopens_left -= 1;
                    frames.clear();
                    channel = match establish_direct_channel(
                        endpoint,
                        peer,
                        &outstanding,
                        drain_deadline,
                        start,
                    ) {
                        Ok(channel) => channel,
                        Err(e) => {
                            stats.print_summary();
                            return Err(e);
                        }
                    };
                    println!(
                        "[dial] channel-reopened path=direct outstanding-resent={}",
                        outstanding.len()
                    );
                    continue;
                }
                stats.print_summary();
                return Err("ping channel closed".into());
            }
            // Connection lifecycle is connection-scoped, while this channel
            // is peer-scoped. During a QUIC Connection replacement the old circuit can
            // close just before the replacement direct connection is
            // delivered. The matching StreamClosed event (or a failed send)
            // is the authoritative signal that this channel itself died.
            EndpointEvent::Nat(nat_event) => {
                print_nat_event("dial", nat_event);
                if let NatEvent::PathUpgraded { peer: upgraded, .. } = nat_event
                    && upgraded == peer
                    && !channel.direct
                {
                    println!(
                        "[dial] path-upgraded path=direct-punched elapsed-us={}",
                        micros_since(start)
                    );
                    // The old bridge is already reset by the agent — never
                    // touch it again. Pongs in flight on it are gone; the
                    // reopen resends their seqs on the new stream.
                    frames.clear();
                    channel = match establish_direct_channel(
                        endpoint,
                        peer,
                        &outstanding,
                        drain_deadline,
                        start,
                    ) {
                        Ok(channel) => channel,
                        Err(e) if drain_deadline.is_some() => {
                            // The remaining pongs could only have arrived on
                            // the replacement stream; the run is over.
                            eprintln!("[dial] channel switch during drain failed: {e}");
                            stats.print_summary();
                            return Ok(());
                        }
                        Err(e) => return Err(e),
                    };
                    println!(
                        "[dial] channel-switched path=direct outstanding-resent={} elapsed-us={}",
                        outstanding.len(),
                        micros_since(start)
                    );
                }
            }
            _ => print_event("dial", &event),
        }
    }
}

fn millis_since(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn micros_since(start: Instant) -> u128 {
    start.elapsed().as_micros()
}

fn next_ping_deadline(sent_at: Instant) -> Instant {
    sent_at + PING_INTERVAL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_buffer_drains_coalesced_frames_without_per_frame_compaction() {
        let frames = 4_096;
        let mut input = Vec::with_capacity(frames * FRAME_LEN);
        for seq in 0..frames as u64 {
            input.extend_from_slice(&encode_frame(seq, seq + 1));
        }

        let mut buffer = FrameBuf::default();
        buffer.push(&input);
        for expected in 0..frames - 1 {
            let frame = buffer.pop().expect("complete coalesced frame");
            assert_eq!(decode_frame(&frame), (expected as u64, expected as u64 + 1));
        }

        // Popping advances a cursor; the allocation is not shifted or
        // shortened once per frame.
        assert_eq!(buffer.buf.len(), input.len());
        assert_eq!(buffer.head, (frames - 1) * FRAME_LEN);

        let last = buffer.pop().expect("last coalesced frame");
        assert_eq!(decode_frame(&last), (frames as u64 - 1, frames as u64));
        assert!(buffer.buf.is_empty());
        assert_eq!(buffer.head, 0);
    }

    #[test]
    fn delayed_ping_schedules_one_interval_from_actual_send() {
        let old_deadline = Instant::now();
        let delayed_send = old_deadline + PING_INTERVAL * 5;
        let next = next_ping_deadline(delayed_send);

        assert_eq!(next.duration_since(delayed_send), PING_INTERVAL);
        assert!(next > old_deadline + PING_INTERVAL);
    }
}
