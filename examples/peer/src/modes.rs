//! The two NAT-aware runners behind `minip2p-peer listen` / `dial`.
//!
//! Both build the same endpoint shape: QUIC transport, the echo protocol,
//! and the NAT traversal agent (always on — with no relay configured it
//! simply resolves direct paths). The listener echoes every inbound echo
//! stream byte for byte; the dialer sends one 16-byte ping frame per second
//! and tags each measured RTT with the path it travelled, so a mid-run
//! `relayed → direct` hole-punch upgrade shows up as an RTT drop with an
//! unbroken seq sequence.

use std::collections::{BTreeSet, HashSet};
use std::error::Error;
use std::time::{Duration, Instant};

use minip2p::{Endpoint, Event, NatConfig, NatEvent, Path, PeerAddr, PeerId, StreamId};

use minip2p_example_common::{
    circuit_addr, load_keypair, local_dialable_peer_addr, path_name, print_nat_event,
};

use crate::cli::{DialTarget, RunOptions, print_event};

const AGENT: &str = "minip2p-peer/0.1.0";
/// Echo protocol: the listener returns every byte unchanged.
const ECHO_PROTOCOL: &str = "/minip2p/echo/1";
/// One ping frame: 8-byte seq (BE) ++ 8-byte send-timestamp millis (BE).
const FRAME_LEN: usize = 16;
/// Cadence of the dialer's pings.
const PING_INTERVAL: Duration = Duration::from_secs(1);
/// Outlives the agent's 60 s connect deadline so `wait_path` sees the
/// terminal `ConnectFailed` instead of timing out first.
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
/// `connect`/`wait_path` work even with no relay configured.
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
            .bind_quic_multiaddr(addr)
            .map_err(|e| format!("quic bind {addr}: {e}").into()),
        None => builder
            .bind_quic_dual_stack()
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
struct FrameBuf {
    buf: Vec<u8>,
    head: usize,
}

impl FrameBuf {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            head: 0,
        }
    }

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
        frame.copy_from_slice(&self.buf[self.head..end]);
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

    // Echo streams we own, keyed by the peer the stream lives on — the
    // dialing peer for direct streams, the relay for bridged circuits.
    let mut echo_streams: HashSet<(PeerId, StreamId)> = HashSet::new();

    if let Some(relay) = relays.first() {
        wait_for_reservation(&mut endpoint, relay)?;
    }
    eprintln!("[listen] echoing on {ECHO_PROTOCOL} (Ctrl-C to stop)");

    loop {
        for nat_event in endpoint.take_nat_events() {
            print_nat_event("listen", &nat_event);
            handle_listen_nat_event(&mut endpoint, &nat_event, relays.first());
        }
        let Some(event) = endpoint
            .next_event(Duration::from_millis(200))
            .map_err(|e| format!("swarm poll: {e}"))?
        else {
            continue;
        };
        print_event("listen", &event);
        handle_listen_event(&mut endpoint, &event, &mut echo_streams);
    }
}

/// Pumps NAT events until the first reservation confirms (printing the
/// paste-ready `circuit=` line) or the deadline passes with a warning; the
/// agent keeps retrying either way and renewals re-print via the main loop.
fn wait_for_reservation(endpoint: &mut Endpoint, relay: &PeerAddr) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + RESERVATION_DEADLINE;
    loop {
        let Some(event) = endpoint
            .next_nat_event(deadline)
            .map_err(|e| format!("swarm poll: {e}"))?
        else {
            eprintln!(
                "[listen] warning: no relay reservation within {}s; still retrying",
                RESERVATION_DEADLINE.as_secs()
            );
            return Ok(());
        };
        print_nat_event("listen", &event);
        let reserved = matches!(event, NatEvent::RelayReserved { .. });
        handle_listen_nat_event(endpoint, &event, Some(relay));
        if reserved {
            return Ok(());
        }
    }
}

fn handle_listen_nat_event(endpoint: &mut Endpoint, event: &NatEvent, relay: Option<&PeerAddr>) {
    if let NatEvent::RelayReserved { .. } = event
        && let Some(relay) = relay
    {
        println!(
            "[listen] circuit={}",
            circuit_addr(relay, endpoint.peer_id())
        );
    }
}

fn handle_listen_event(
    endpoint: &mut Endpoint,
    event: &Event,
    echo_streams: &mut HashSet<(PeerId, StreamId)>,
) {
    match event {
        Event::StreamReady {
            peer_id,
            stream_id,
            protocol_id,
            initiated_locally: false,
            ..
        } if protocol_id == ECHO_PROTOCOL => {
            echo_streams.insert((peer_id.clone(), *stream_id));
        }
        Event::StreamData {
            peer_id,
            stream_id,
            data,
            ..
        } if echo_streams.contains(&(peer_id.clone(), *stream_id)) => {
            echo_bytes(endpoint, peer_id, *stream_id, data, echo_streams);
        }
        Event::StreamRemoteWriteClosed {
            peer_id, stream_id, ..
        } if echo_streams.contains(&(peer_id.clone(), *stream_id)) => {
            let _ = endpoint.close_stream_write(peer_id, *stream_id);
            echo_streams.remove(&(peer_id.clone(), *stream_id));
        }
        Event::StreamClosed {
            peer_id, stream_id, ..
        } => {
            echo_streams.remove(&(peer_id.clone(), *stream_id));
        }
        _ => {}
    }
}

/// Echoes `data` back on a tracked stream; a failed send means the stream
/// died under us, so it is just untracked.
fn echo_bytes(
    endpoint: &mut Endpoint,
    peer: &PeerId,
    stream: StreamId,
    data: &[u8],
    echo_streams: &mut HashSet<(PeerId, StreamId)>,
) {
    if let Err(e) = endpoint.send_stream(peer, stream, data.to_vec()) {
        eprintln!("[listen] echo failed peer={peer} stream={stream}: {e}");
        echo_streams.remove(&(peer.clone(), stream));
    }
}

// --- dial ------------------------------------------------------------------

/// Where the dialer's ping frames currently travel.
struct Channel {
    /// Peer addressed in `send_stream`: the relay for a bridge, the target
    /// itself for a direct stream.
    send_peer: PeerId,
    stream: StreamId,
    direct: bool,
}

impl Channel {
    fn name(&self) -> &'static str {
        if self.direct { "direct" } else { "relayed" }
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

struct PingStats {
    sent: u64,
    received: u64,
    relayed: RttBucket,
    direct: RttBucket,
}

impl PingStats {
    fn new() -> Self {
        Self {
            sent: 0,
            received: 0,
            relayed: RttBucket::default(),
            direct: RttBucket::default(),
        }
    }

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
            println!("[dial] target={peer} via-relay={}", relays[0].peer_id());
            let id = endpoint
                .connect(peer)
                .map_err(|e| format!("connect failed: {e}"))?;
            (peer.clone(), id)
        }
        DialTarget::Direct(addr) => {
            println!("[dial] target={addr}");
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
        // ConnectFailed (if any) is still queued; surface its error.
        for event in endpoint.take_nat_events() {
            print_nat_event("dial", &event);
        }
        return Err("no path to the target".into());
    };
    println!(
        "[dial] path-established path={} elapsed={}ms",
        path_name(&path),
        start.elapsed().as_millis()
    );

    let relayed = matches!(path, Path::Relayed { .. });
    let frames = FrameBuf::new();
    let mut channel =
        establish_direct_channel(&mut endpoint, &peer, &BTreeSet::new(), None, start)?;
    channel.direct = !relayed;

    ping_loop(&mut endpoint, &peer, channel, frames, count, start)
}

/// Opens the echo stream on a direct connection: identify must have
/// completed (protocol routing) and the stream must finish negotiating,
/// all before `deadline`.
fn open_echo_stream(
    endpoint: &mut Endpoint,
    peer: &PeerId,
    deadline: Instant,
) -> Result<StreamId, Box<dyn Error>> {
    if !endpoint.is_peer_ready(peer) {
        endpoint
            .wait_peer_ready(peer, deadline)
            .map_err(|e| format!("waiting for identify: {e}"))?
            .ok_or("identify never completed on the direct connection")?;
    }
    let stream = endpoint
        .open_stream(peer, ECHO_PROTOCOL)
        .map_err(|e| format!("open echo stream: {e}"))?;
    loop {
        let event = endpoint
            .next_event(deadline)
            .map_err(|e| format!("waiting for echo stream: {e}"))?
            .ok_or("echo stream never became ready")?;
        match &event {
            Event::StreamReady {
                peer_id, stream_id, ..
            } if peer_id == peer && *stream_id == stream => return Ok(stream),
            Event::ConnectionEstablished { peer_id, .. } if peer_id == peer => {
                print_event("dial", &event);
                // A second punch connection just replaced the one this
                // stream was opened on — the swarm keeps the newcomer and
                // silently drops the stream, so its `StreamReady` will
                // never arrive. Abandon it and let the caller retry on the
                // settled connection. (The caller drained stale
                // establishments before opening, so this only fires for a
                // genuine replacement racing the setup.)
                let _ = endpoint.reset_stream(peer, stream);
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
    // `wait_path` and `PathUpgraded` report on NAT events; the connection's
    // own `ConnectionEstablished` may still sit in the swarm queue. Drain
    // what is already queued before opening the stream, so a stale
    // establishment cannot masquerade as a superseding punch connection —
    // that would burn the stream and force a needless retry on every plain
    // direct dial.
    while let Some(event) = endpoint
        .next_event(Duration::ZERO)
        .map_err(|e| format!("draining queued events: {e}"))?
    {
        print_event("dial", &event);
    }
    let stream = open_echo_stream(endpoint, peer, deadline)?;
    let channel = Channel {
        send_peer: peer.clone(),
        stream,
        direct: true,
    };
    for &missing in outstanding {
        let frame = encode_frame(missing, millis_since(start));
        endpoint
            .send_stream(&channel.send_peer, channel.stream, frame.to_vec())
            .map_err(|e| format!("resend on direct channel: {e}"))?;
    }
    if drain_deadline.is_some() {
        endpoint
            .close_stream_write(&channel.send_peer, channel.stream)
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
    let mut stats = PingStats::new();
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
        for nat_event in endpoint.take_nat_events() {
            print_nat_event("dial", &nat_event);
            if let NatEvent::PathUpgraded { peer: upgraded, .. } = &nat_event
                && upgraded == peer
                && !channel.direct
            {
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
                    "[dial] channel-switched path=direct outstanding-resent={}",
                    outstanding.len()
                );
            }
        }

        let wait_until = drain_deadline.unwrap_or(next_ping);
        let event = endpoint
            .next_event(wait_until)
            .map_err(|e| format!("swarm poll: {e}"))?;
        let Some(event) = event else {
            // Deadline tick.
            if let Some(deadline) = drain_deadline {
                if Instant::now() >= deadline {
                    stats.print_summary();
                    return Ok(());
                }
                continue;
            }
            seq += 1;
            outstanding.insert(seq);
            let frame = encode_frame(seq, millis_since(start));
            if let Err(e) = endpoint.send_stream(&channel.send_peer, channel.stream, frame.to_vec())
            {
                if !channel.direct || reopens_left == 0 {
                    stats.print_summary();
                    return Err(format!("ping send: {e}").into());
                }
                // A punch race can supersede the direct connection moments
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
                endpoint
                    .close_stream_write(&channel.send_peer, channel.stream)
                    .map_err(|e| format!("close after final ping: {e}"))?;
                drain_deadline = Some(Instant::now() + DRAIN_DEADLINE);
            }
            continue;
        };

        match &event {
            Event::StreamData {
                peer_id,
                stream_id,
                data,
                ..
            } if *peer_id == channel.send_peer && *stream_id == channel.stream => {
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
            Event::StreamRemoteWriteClosed {
                peer_id, stream_id, ..
            }
            | Event::StreamClosed {
                peer_id, stream_id, ..
            } if *peer_id == channel.send_peer && *stream_id == channel.stream => {
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
            Event::ConnectionClosed { peer_id, .. } if *peer_id == channel.send_peer => {
                print_event("dial", &event);
                stats.print_summary();
                if drain_deadline.is_some() {
                    return Ok(());
                }
                return Err("connection carrying the ping channel closed".into());
            }
            _ => print_event("dial", &event),
        }
    }
}

fn millis_since(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
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

        let mut buffer = FrameBuf::new();
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
