//! The two NAT-aware runners behind `minip2p-peer listen` / `dial`.
//!
//! Both build the same endpoint shape: QUIC or TCP transport, the echo protocol,
//! and the NAT traversal agent (always on — with no relay configured it
//! simply resolves direct paths). The listener echoes every inbound echo
//! stream byte for byte; the dialer sends one 16-byte ping frame per second
//! and tags each measured RTT with the path it travelled, so a mid-run
//! `relayed → direct` hole-punch upgrade shows up as an RTT drop with an
//! unbroken seq sequence.

use std::collections::{BTreeSet, HashSet};
use std::error::Error;
use std::time::{Duration, Instant};

use minip2p::{
    BindError, ConnectId, ConnectOutcome, Endpoint, EndpointEvent, EndpointWaitOutcome, NatEvent,
    Path, PeerAddr, PeerId, SendError, StreamKey,
};

use minip2p_example_common::{
    circuit_addr, load_keypair, local_dialable_peer_addr, path_name, print_nat_event,
};

use crate::cli::{DialTarget, RunOptions, print_event};

/// The listener's echo streams. The endpoint's write queue holds what a
/// stream cannot take yet, in order, with the mirrored FIN behind it.
type Echoes = HashSet<StreamKey>;

const AGENT: &str = "minip2p-peer/0.1.0";
/// Echo protocol: the listener returns every byte unchanged.
const ECHO_PROTOCOL: &str = "/minip2p/echo/1";
/// One ping frame: 8-byte seq (BE) ++ 8-byte send-timestamp millis (BE).
const FRAME_LEN: usize = 16;
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
/// Ceiling on identify/stream setup after a connection exists: the
/// first-Identify deadline, then the echo stream's negotiation.
const SETUP_DEADLINE: Duration =
    Duration::from_millis(minip2p::IDENTIFY_TIMEOUT_MS + minip2p::OUTBOUND_NEGOTIATION_TIMEOUT_MS);

/// Builds the endpoint both modes share. A relay or an AutoNAT server turns
/// the NAT agent on; `connect` reports a path either way.
fn build_endpoint(
    role: &str,
    relays: &[PeerAddr],
    options: &RunOptions,
) -> Result<Endpoint, Box<dyn Error>> {
    let keypair = load_keypair(options.key_path.as_deref(), role)?;
    let mut builder = Endpoint::builder()
        .identity(keypair)
        .agent_version(AGENT)
        .protocol(ECHO_PROTOCOL);
    for relay in relays {
        builder = builder.relay(relay.clone());
    }
    if let Some(autonat) = &options.autonat {
        builder = builder.autonat_server(autonat.clone());
    }
    match &options.listen_addr {
        Some(addr) => builder
            .listen_on_multiaddr(addr)
            .map_err(BindError::from)
            .and_then(|builder| builder.bind())
            .map_err(|e| format!("bind {addr}: {e}").into()),
        None => builder
            .listen_default()
            .map_err(BindError::from)
            .and_then(|builder| builder.bind())
            .map_err(|e| format!("quic dual-stack bind: {e}").into()),
    }
}

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
    println!("[listen] bound={}", local_dialable_peer_addr(first));
    for addr in &peer_addrs {
        println!("[listen] listen-addr={addr}");
    }
    println!("[listen] us={}", endpoint.peer_id());

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
    match event {
        EndpointEvent::StreamReady {
            stream,
            protocol_id,
            initiated_locally: false,
            ..
        } if protocol_id == ECHO_PROTOCOL => {
            echoes.insert(*stream);
        }
        EndpointEvent::StreamData { stream, data, .. } if echoes.contains(stream) => {
            if let Err(e) = endpoint.send_stream(*stream, data.clone()) {
                drop_echo(endpoint, *stream, echoes, &e.to_string());
            }
        }
        EndpointEvent::StreamRemoteWriteClosed { stream, .. } if echoes.remove(stream) => {
            if let Err(e) = endpoint.close_stream_write(*stream) {
                drop_echo(endpoint, *stream, echoes, &e.to_string());
            }
        }
        EndpointEvent::StreamWriteStopped { stream, .. }
        | EndpointEvent::StreamClosed { stream, .. } => {
            echoes.remove(stream);
        }
        EndpointEvent::ConnectionClosed { conn_id, .. }
        | EndpointEvent::ConnectionReplaced { old: conn_id, .. } => {
            echoes.retain(|stream| stream.conn_id() != *conn_id);
        }
        _ => {}
    }
}

/// Gives up on an echo stream: resets it, so the peer learns the echo
/// stopped, and drops what the endpoint still held for it.
fn drop_echo(endpoint: &mut Endpoint, stream: StreamKey, echoes: &mut Echoes, why: &str) {
    eprintln!("[listen] echo failed stream={stream}: {why}");
    echoes.remove(&stream);
    match endpoint.reset_stream(stream) {
        Ok(()) | Err(_) => {}
    }
}

/// Where the dialer's ping frames currently travel. A frame the stream
/// cannot take at once waits in the endpoint's write queue.
struct Channel {
    stream: StreamKey,
    direct: bool,
}

impl Channel {
    fn name(&self) -> &'static str {
        if self.direct { "direct" } else { "relayed" }
    }

    /// Sends `data`, leaving any unsent tail in the write queue. A full
    /// stream is backpressure, not a dead channel.
    fn send(&self, endpoint: &mut Endpoint, data: Vec<u8>) -> Result<(), SendError> {
        endpoint.send_stream(self.stream, data)
    }

    /// Half-closes the channel, after any frame the queue still holds.
    fn close_write(&self, endpoint: &mut Endpoint) -> Result<(), minip2p::Error> {
        endpoint.close_stream_write(self.stream)
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
            (*peer, id)
        }
        DialTarget::Direct(addr) => {
            println!("[dial] target={addr}");
            let id = endpoint
                .connect(addr)
                .map_err(|e| format!("connect failed: {e}"))?;
            (*addr.peer_id(), id)
        }
    };

    let path = wait_for_path(&mut endpoint, connect_id)?;
    println!(
        "[dial] path-established path={} elapsed={}ms elapsed-us={}",
        path_name(&path),
        start.elapsed().as_millis(),
        micros_since(start)
    );

    let frames = FrameBuf::default();
    let mut channel =
        establish_direct_channel(&mut endpoint, &peer, &BTreeSet::new(), None, start)?;
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
/// attempt that settles connected without a path event reports the path it
/// settled on; a failed or cancelled one ends the run.
fn wait_for_path(endpoint: &mut Endpoint, connect_id: ConnectId) -> Result<Path, Box<dyn Error>> {
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
                return match event {
                    EndpointEvent::ConnectSettled {
                        outcome: ConnectOutcome::Connected { path, .. },
                        ..
                    } => Ok(path),
                    _ => Err("no path to the target".into()),
                };
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
) -> Result<StreamKey, Box<dyn Error>> {
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
    let stream = endpoint
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
                stream: ready,
                ..
            } if peer_id == peer && *ready == stream => {
                return Ok(stream);
            }
            EndpointEvent::ConnectionReplaced { peer_id, old, .. }
                if peer_id == peer && *old == stream.conn_id() =>
            {
                print_event("dial", &event);
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
    let channel = Channel {
        stream: open_echo_stream(endpoint, peer, deadline)?,
        direct: true,
    };
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
    let mut drain_deadline: Option<Instant> = None;
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
            if let Some(deadline) = drain_deadline {
                if Instant::now() >= deadline {
                    stats.print_summary();
                    return Ok(());
                }
                continue;
            }
            if endpoint.is_write_pending(channel.stream) {
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
            next_ping = next_ping_deadline(Instant::now());
            if count == Some(seq) {
                channel
                    .close_write(endpoint)
                    .map_err(|e| format!("close after final ping: {e}"))?;
                drain_deadline = Some(Instant::now() + DRAIN_DEADLINE);
            }
            continue;
        };

        match &event {
            EndpointEvent::StreamData { stream, data, .. } if *stream == channel.stream => {
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
            EndpointEvent::StreamRemoteWriteClosed { stream, .. }
            | EndpointEvent::StreamClosed { stream, .. }
                if *stream == channel.stream =>
            {
                print_event("dial", &event);
                if drain_deadline.is_some() {
                    stats.print_summary();
                    return Ok(());
                }
                if channel.direct && reopens_left > 0 {
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
            EndpointEvent::Nat(nat_event) => {
                print_nat_event("dial", nat_event);
                if let NatEvent::PathUpgraded { peer: upgraded, .. } = nat_event
                    && upgraded == peer
                    && !channel.direct
                {
                    println!(
                        "[dial] path-upgraded path=punched elapsed-us={}",
                        micros_since(start)
                    );
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
