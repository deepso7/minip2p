//! Bulk throughput and handshakes over an emulated link (`support::delay`):
//! a rate cap and a round-trip delay between two loopback Endpoints, so
//! flow-control windows are measured at a real RTT (#361).
//!
//! By default (the per-PR bench) it measures one-way goodput over QUIC and
//! over TCP + Yamux on the 100 Mbit/s, 100 ms profile with the default
//! limits: per case, a fresh connection, a warm-up transfer, then
//! [`PR_RUNS`] timed transfers of 32 MiB on fresh streams, reporting the
//! median as `endpoint_rtt/{quic,tcp}/100m_100ms` `mb_per_s` in
//! `target/bench-results/custom/endpoint_rtt.json`. The TCP case measures
//! Yamux credit at the RTT, not kernel TCP (see `support::delay`).
//!
//! With `MINIP2P_RTT_SWEEP` set it instead runs one window sweep and appends
//! a JSON line per measurement to
//! `target/bench-results/rtt/<sweep>-<profile>.jsonl`, then prints a summary
//! with the value #361's rule picks. `scripts/rtt-sweep.sh` runs the whole
//! procedure. Sweeps, by `MINIP2P_RTT_SWEEP`:
//!
//! - `quic-stream`: one stream; the stream window varies, the connection and
//!   send windows stay large.
//! - `quic-connection`: four streams at `MINIP2P_RTT_STREAM`; the connection
//!   window varies, the send window stays large.
//! - `quic-send`: four streams at `MINIP2P_RTT_STREAM`; the send window
//!   varies, the connection window stays large.
//! - `quic-check`: the windows in `MINIP2P_RTT_{STREAM,CONNECTION,SEND}`
//!   (QUIC defaults when unset, and the default budget) against large ones,
//!   at one and four streams.
//! - `yamux`: one TCP stream; the Yamux receive window varies.
//! - `retry`: handshakes with Retry on and off (see [`retry`]).
//!
//! Every window sweep also measures a large reference window, interleaved
//! with the candidates, and picks the smallest candidate whose median
//! goodput reaches 90% of the reference's median. The candidates either
//! side of that cutoff get as many runs again before the pick, which is
//! flagged when their spread straddles the cutoff, for a person to judge.
//! Each point gets a fresh connection with a warm-up transfer before its
//! timed one, and the point order rotates every run.
//!
//! Every measurement also calibrates the link: the idle ping RTT, the ping
//! RTT the target sees during the transfer, datagrams lost each way (QUIC),
//! the up direction's peak held bytes and queueing delay, and the busiest
//! proxy thread's CPU share. A sweep reports no pick when its reference
//! reaches under 85% of the link, anything was lost, the idle RTT is 20%
//! off the profile's, or a proxy thread used over 80% of a core. `MINIP2P_RTT_PROFILE` picks the profile
//! (`100m_100ms` by default, or `1g_20ms`), `MINIP2P_RTT_RUNS` the runs per
//! point (default 5), and `MINIP2P_RTT_TOTAL_MB` the bytes per timed
//! transfer (default: 2.5 s at the link rate, at least 32 MiB).
//!
//! An MB here is 2^20 bytes.

mod support;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, atomic::Ordering};
use std::thread;
use std::time::{Duration, Instant};

use minip2p::{ConnectOutcome, Endpoint, EndpointEvent, PeerAddr, PeerId, QuicLimits, TcpConfig};
use minip2p_quic::datagram_counters;
use support::bulk::{self, CHUNK, Load};
use support::delay::{LinkStats, Profile, TcpProxy, UdpProxy};
use support::{Driven, SETUP_TIMEOUT, bind_on, next_event};

const PROTOCOL: &str = "/minip2p/bench/sink/1";
const MB: u64 = 1 << 20;
/// Timed transfers per case in the per-PR bench.
const PR_RUNS: usize = 3;
/// Bytes per timed transfer in the per-PR bench.
const PR_TOTAL: u64 = 32 * MB;
/// Share of the reference goodput a picked window must reach.
const CUTOFF: f64 = 0.9;
/// How often the target pings the client during a transfer.
const PING_INTERVAL: Duration = Duration::from_millis(100);
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

#[derive(Clone, Copy, Debug, PartialEq)]
enum Transport {
    Quic,
    Tcp,
}

/// One configuration a sweep measures.
#[derive(Clone)]
struct Point {
    /// What the summary groups by: the swept value, or `reference`.
    label: String,
    transport: Transport,
    streams: usize,
    quic: QuicLimits,
    tcp: TcpConfig,
}

/// One timed transfer over an emulated link, with the link's calibration.
struct Sample {
    mb_per_s: f64,
    /// Goodput over the link rate.
    utilization: f64,
    /// Ping round trip on the idle connection, before the warm-up.
    unloaded_rtt_ms: f64,
    /// Ping round trips the target measured during the transfer.
    ping_ms: Vec<u64>,
    /// Datagrams sent one way that the far end never read (QUIC only).
    lost_up: u64,
    lost_down: u64,
    /// Peak bytes the client-to-target direction held, queued or in flight.
    held_high_water: u64,
    /// Longest FIFO wait in the client-to-target direction.
    max_queue_delay_ms: f64,
    /// The busiest proxy thread's CPU time over the transfer's wall time.
    proxy_cpu: f64,
}

/// What makes a sweep's measurements untrustworthy: the reference falling
/// short of the link, loss, an idle RTT off the profile's, or a proxy thread
/// near a full core.
const MIN_REFERENCE_UTILIZATION: f64 = 0.85;
const MAX_RTT_ERROR: f64 = 0.2;
const MAX_PROXY_CPU: f64 = 0.8;

fn main() {
    match std::env::var("MINIP2P_RTT_SWEEP") {
        Ok(sweep) => run_sweep(&sweep),
        Err(_) => pr_bench(),
    }
}

/// The per-PR rows: default limits on the 100 Mbit/s, 100 ms profile.
fn pr_bench() {
    let profile = Profile::M100_100MS;
    let mut rows = Vec::new();
    for (case, transport) in [("quic", Transport::Quic), ("tcp", Transport::Tcp)] {
        let point = Point {
            label: "default".into(),
            transport,
            streams: 1,
            quic: QuicLimits::default(),
            tcp: TcpConfig::default(),
        };
        let samples = measure(profile, &point, PR_TOTAL, PR_RUNS);
        let rates: Vec<f64> = samples.iter().map(|sample| sample.mb_per_s).collect();
        let median = median(&rates);
        println!(
            "endpoint_rtt/{case}/{}: {median:.2} MB/s median of {rates:.2?} ({:.0}% of the link)",
            profile.name,
            100.0 * median * MB as f64 / profile.bytes_per_s()
        );
        rows.push(format!(
            r#"{{"tier":"rust-wall","name":"endpoint_rtt/{case}/{}","metric":"mb_per_s","value":{median}}}"#,
            profile.name
        ));
    }
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/bench-results/custom"
    );
    std::fs::create_dir_all(dir).expect("create custom results directory");
    std::fs::write(
        format!("{dir}/endpoint_rtt.json"),
        format!("[{}]\n", rows.join(",")),
    )
    .expect("write custom rows");
}

/// Stops the bench over a bad setting, without a panic's backtrace.
fn invalid(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(2)
}

fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name).map_or(default, |value| {
        value
            .parse()
            .unwrap_or_else(|_| invalid(&format!("{name} is not valid: {value}")))
    })
}

/// `percent` of `bytes`, rounded to a whole number of 64 KiB, at least one.
fn window(bytes: u64, percent: u64) -> usize {
    const UNIT: u64 = 64 * 1024;
    let scaled = bytes * percent / 100;
    usize::try_from(((scaled + UNIT / 2) / UNIT).max(1) * UNIT).expect("window fits usize")
}

fn run_sweep(sweep: &str) {
    let profile_name: String = env_or("MINIP2P_RTT_PROFILE", Profile::M100_100MS.name.to_owned());
    let profile = Profile::named(&profile_name)
        .unwrap_or_else(|| invalid(&format!("unknown MINIP2P_RTT_PROFILE {profile_name}")));
    let runs = env_or("MINIP2P_RTT_RUNS", 5_usize);
    if sweep == "retry" {
        retry(profile, runs);
        return;
    }
    // 2.5 s at the link rate.
    let default_total = (profile.rate_bits_per_s / 8 * 5 / 2).div_ceil(MB);
    let total = env_or("MINIP2P_RTT_TOTAL_MB", default_total.max(32)) * MB;
    let points = sweep_points(sweep, profile);
    let bdp = profile.bdp_bytes();
    println!(
        "sweep {sweep} on {} (BDP {} KiB): {} points × {runs} runs, {} MiB each",
        profile.name,
        bdp / 1024,
        points.len(),
        total / MB
    );

    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/bench-results/rtt"
    );
    std::fs::create_dir_all(dir).expect("create sweep results directory");
    let path = format!("{dir}/{sweep}-{}.jsonl", profile.name);
    let mut lines = Vec::new();
    let mut results: Vec<(Point, Vec<Sample>)> = points
        .iter()
        .map(|point| (point.clone(), Vec::new()))
        .collect();
    let mut sample_point = |results: &mut Vec<(Point, Vec<Sample>)>, index: usize, run: usize| {
        let Some((point, samples)) = results.get_mut(index) else {
            return;
        };
        let sample = measure(profile, point, total, 1).remove(0);
        println!(
            "  run {run} {:>10}: {:7.2} MB/s ({:3.0}%), idle RTT {:.0} ms{}, lost {}/{} up/down, \
             held ≤ {} KiB, queue ≤ {:.1} ms, proxy CPU {:.0}%",
            point.label,
            sample.mb_per_s,
            100.0 * sample.utilization,
            sample.unloaded_rtt_ms,
            ping_summary(&sample.ping_ms),
            sample.lost_up,
            sample.lost_down,
            sample.held_high_water / 1024,
            sample.max_queue_delay_ms,
            100.0 * sample.proxy_cpu,
        );
        lines.push(json_line(sweep, profile, run, point, &sample));
        std::fs::write(&path, lines.join("\n") + "\n").expect("write sweep results");
        samples.push(sample);
    };
    let count = results.len();
    for run in 0..runs {
        // Rotate the order each run, so drift over the sweep does not
        // always land on the same points.
        for offset in 0..count {
            sample_point(&mut results, (offset + run) % count, run);
        }
    }
    // The candidates either side of the cutoff decide the pick: give them
    // as many runs again, interleaved.
    if let Some((pick, below)) = pick(&results) {
        let boundary: Vec<usize> = below.into_iter().chain([pick]).collect();
        println!("boundary: {} more runs each for {boundary:?}", runs);
        for run in runs..2 * runs {
            for &index in &boundary {
                sample_point(&mut results, index, run);
            }
        }
    }
    summarize(sweep, profile, &results);
    println!("results: {path}");
}

/// The points of a window sweep: candidates from the BDP, plus a large
/// reference. `quic-check` instead pairs the configured windows with the
/// reference at one and four streams.
fn sweep_points(sweep: &str, profile: Profile) -> Vec<Point> {
    let bdp = profile.bdp_bytes();
    let large = window(16 * MB, 100).max(window(bdp, 800));
    let defaults = QuicLimits::default();
    let stream = env_or("MINIP2P_RTT_STREAM", defaults.stream_receive_window);
    let connection = env_or("MINIP2P_RTT_CONNECTION", defaults.connection_receive_window);
    let send = env_or("MINIP2P_RTT_SEND", defaults.send_window);
    // Windows the budget never limits: a sweep measures flow control only.
    let quic = |stream, connection, send| QuicLimits {
        stream_receive_window: stream,
        connection_receive_window: connection,
        send_window: send,
        memory_budget_bytes: 8 << 30,
        ..QuicLimits::default()
    };
    let point = |label: String, transport, streams, quic, tcp| Point {
        label,
        transport,
        streams,
        quic,
        tcp,
    };
    let quic_point = |label, streams, limits| {
        point(
            label,
            Transport::Quic,
            streams,
            limits,
            TcpConfig::default(),
        )
    };
    // Candidate windows, in percent of the BDP.
    let candidates = |percents: &[u64]| -> Vec<usize> {
        percents
            .iter()
            .map(|&percent| window(bdp, percent))
            .collect()
    };
    let label = |bytes: usize| format!("{}K", bytes / 1024);
    let mut points: Vec<Point> = match sweep {
        "quic-stream" => candidates(&[75, 100, 125, 150, 200, 300])
            .into_iter()
            .map(|value| quic_point(label(value), 1, quic(value, large, large)))
            .chain([quic_point("reference".into(), 1, quic(large, large, large))])
            .collect(),
        "quic-connection" => candidates(&[100, 125, 150, 200, 300, 400])
            .into_iter()
            .map(|value| quic_point(label(value), 4, quic(stream, value, large)))
            .chain([quic_point(
                "reference".into(),
                4,
                quic(stream, large, large),
            )])
            .collect(),
        "quic-send" => candidates(&[100, 125, 150, 200, 300, 400])
            .into_iter()
            .map(|value| quic_point(label(value), 4, quic(stream, large, value)))
            .chain([quic_point(
                "reference".into(),
                4,
                quic(stream, large, large),
            )])
            .collect(),
        "quic-check" => [1, 4]
            .into_iter()
            .flat_map(|streams| {
                let mut chosen = quic(stream, connection, send);
                chosen.memory_budget_bytes = defaults.memory_budget_bytes;
                [
                    quic_point(format!("chosen×{streams}"), streams, chosen),
                    quic_point(
                        format!("reference×{streams}"),
                        streams,
                        quic(large, large, large),
                    ),
                ]
            })
            .collect(),
        "yamux" => {
            let tcp = |window: usize| {
                let mut config = TcpConfig::default();
                config.yamux.receive_window = u32::try_from(window).expect("window fits u32");
                config
            };
            candidates(&[100, 150, 200, 250, 300, 400])
                .into_iter()
                .map(|value| (label(value), value))
                .chain([("reference".to_owned(), large)])
                .map(|(label, value)| {
                    point(label, Transport::Tcp, 1, QuicLimits::default(), tcp(value))
                })
                .collect()
        }
        other => invalid(&format!(
            "unknown MINIP2P_RTT_SWEEP {other}: quic-stream, quic-connection, quic-send, quic-check, yamux or retry"
        )),
    };
    points.dedup_by(|a, b| a.label == b.label);
    points
}

/// The median goodput a candidate must reach: [`CUTOFF`] of the reference's.
fn cutoff(results: &[(Point, Vec<Sample>)]) -> Option<f64> {
    results
        .iter()
        .find(|(point, _)| point.label == "reference")
        .map(|(_, samples)| CUTOFF * median(&rates(samples)))
}

/// The index of the smallest candidate whose median reaches the cutoff, and
/// of the candidate just below it. Candidates run smallest first.
fn pick(results: &[(Point, Vec<Sample>)]) -> Option<(usize, Option<usize>)> {
    let cutoff = cutoff(results)?;
    let mut below = None;
    for (index, (point, samples)) in results.iter().enumerate() {
        if point.label == "reference" {
            continue;
        }
        if median(&rates(samples)) >= cutoff {
            return Some((index, below));
        }
        below = Some(index);
    }
    None
}

/// Why a sweep's link cannot be trusted, if it cannot.
fn calibration_problems(profile: Profile, results: &[(Point, Vec<Sample>)]) -> Vec<String> {
    let samples: Vec<&Sample> = results.iter().flat_map(|(_, samples)| samples).collect();
    let mut problems = Vec::new();
    let lost: u64 = samples.iter().map(|s| s.lost_up + s.lost_down).sum();
    if lost > 0 {
        problems.push(format!("{lost} datagrams lost"));
    }
    let rtt = median(
        &samples
            .iter()
            .map(|s| s.unloaded_rtt_ms)
            .collect::<Vec<_>>(),
    );
    let expected = profile.rtt.as_secs_f64() * 1000.0;
    if (rtt - expected).abs() > MAX_RTT_ERROR * expected {
        problems.push(format!("idle RTT {rtt:.0} ms, not {expected:.0} ms"));
    }
    let cpu = samples.iter().map(|s| s.proxy_cpu).fold(0.0, f64::max);
    if cpu > MAX_PROXY_CPU {
        problems.push(format!("a proxy thread used {:.0}% of a core", 100.0 * cpu));
    }
    for (point, samples) in results {
        let utilization = median(&samples.iter().map(|s| s.utilization).collect::<Vec<_>>());
        if point.label.starts_with("reference") && utilization < MIN_REFERENCE_UTILIZATION {
            problems.push(format!(
                "{} reached only {:.0}% of the link",
                point.label,
                100.0 * utilization
            ));
        }
    }
    problems
}

/// Prints each point's median and spread, the link's calibration, and for a
/// window sweep the pick: the smallest candidate whose median reaches
/// [`CUTOFF`] of the reference's, flagged when the runs straddle the cutoff.
fn summarize(sweep: &str, profile: Profile, results: &[(Point, Vec<Sample>)]) {
    println!("summary ({sweep}): median MB/s [min, max], % of reference median, loaded ping");
    let reference = cutoff(results).map(|cutoff| cutoff / CUTOFF);
    for (point, samples) in results {
        let rates = rates(samples);
        let share = reference.map_or(String::new(), |reference| {
            format!(", {:.0}%", 100.0 * median(&rates) / reference)
        });
        let pings: Vec<u64> = samples
            .iter()
            .flat_map(|s| s.ping_ms.iter().copied())
            .collect();
        println!(
            "  {:>14}: {:7.2} [{:.2}, {:.2}] ×{}{share}{}",
            point.label,
            median(&rates),
            min(&rates),
            max(&rates),
            rates.len(),
            ping_summary(&pings),
        );
    }
    let problems = calibration_problems(profile, results);
    if !problems.is_empty() {
        println!("calibration: INVALID: {}", problems.join("; "));
        if reference.is_some() {
            println!("pick: invalid calibration, no pick");
        }
        return;
    }
    println!("calibration: ok");
    let Some(cutoff) = cutoff(results) else {
        return;
    };
    let Some((pick, below)) = pick(results) else {
        println!("pick: none of the candidates reaches {cutoff:.2} MB/s; widen the sweep");
        return;
    };
    let rates_at = |index: usize| results.get(index).map(|(_, samples)| rates(samples));
    // Ambiguous when the pick's own runs dip below the cutoff, or the next
    // smaller candidate's runs reach it.
    let straddles = rates_at(pick).is_some_and(|rates| min(&rates) < cutoff)
        || below
            .and_then(rates_at)
            .is_some_and(|rates| max(&rates) >= cutoff);
    let label = results
        .get(pick)
        .map_or("", |(point, _)| point.label.as_str());
    println!(
        "pick: {label} (cutoff {cutoff:.2} MB/s){}",
        if straddles {
            "; FLAG: run-to-run spread straddles the cutoff, a person should judge"
        } else {
            ""
        }
    );
}

fn rates(samples: &[Sample]) -> Vec<f64> {
    samples.iter().map(|sample| sample.mb_per_s).collect()
}

/// The median, or NaN for no values.
fn median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let mid = sorted.len() / 2;
    let upper = sorted.get(mid).copied().unwrap_or(f64::NAN);
    match mid.checked_sub(1).and_then(|lower| sorted.get(lower)) {
        Some(lower) if sorted.len().is_multiple_of(2) => (lower + upper) / 2.0,
        _ => upper,
    }
}

fn min(values: &[f64]) -> f64 {
    values.iter().copied().fold(f64::INFINITY, f64::min)
}

fn max(values: &[f64]) -> f64 {
    values.iter().copied().fold(f64::NEG_INFINITY, f64::max)
}

fn ping_summary(ping_ms: &[u64]) -> String {
    if ping_ms.is_empty() {
        return String::new();
    }
    let mut sorted = ping_ms.to_vec();
    sorted.sort_unstable();
    let rank = |percent: usize| {
        let index = (sorted.len() * percent / 100).min(sorted.len() - 1);
        sorted.get(index).copied().unwrap_or_default()
    };
    format!(", ping p50 {} ms p99 {} ms", rank(50), rank(99))
}

fn json_line(sweep: &str, profile: Profile, run: usize, point: &Point, sample: &Sample) -> String {
    format!(
        concat!(
            r#"{{"sweep":"{}","profile":"{}","run":{},"label":"{}","transport":"{:?}","streams":{},"#,
            r#""stream_window":{},"connection_window":{},"send_window":{},"yamux_window":{},"#,
            r#""mb_per_s":{},"utilization":{},"unloaded_rtt_ms":{},"ping_ms":{:?},"#,
            r#""lost_up":{},"lost_down":{},"held_high_water":{},"max_queue_delay_ms":{},"#,
            r#""proxy_cpu":{}}}"#
        ),
        sweep,
        profile.name,
        run,
        point.label,
        point.transport,
        point.streams,
        point.quic.stream_receive_window,
        point.quic.connection_receive_window,
        point.quic.send_window,
        point.tcp.yamux.receive_window,
        sample.mb_per_s,
        sample.utilization,
        sample.unloaded_rtt_ms,
        sample.ping_ms,
        sample.lost_up,
        sample.lost_down,
        sample.held_high_water,
        sample.max_queue_delay_ms,
        sample.proxy_cpu,
    )
}

/// The loopback socket address of a PeerAddr's transport.
fn socket_addr(addr: &PeerAddr) -> SocketAddr {
    let text = addr.transport().to_string();
    let mut parts = text.split('/');
    // The component after `udp` or `tcp` is the port.
    parts.find(|part| matches!(*part, "udp" | "tcp"));
    let port = parts
        .next()
        .and_then(|port| port.parse().ok())
        .expect("address has a port");
    SocketAddr::new(LOOPBACK, port)
}

/// A target listening on `transport` with `point`'s limits, a client, and a
/// proxy between them; the client is connected through the proxy and both
/// sides have finished Identify.
struct Linked {
    target: Endpoint,
    client: Endpoint,
    target_peer: PeerId,
    /// Client to target, and back.
    up: Arc<LinkStats>,
    down: Arc<LinkStats>,
    /// Median of a few pings on the idle connection.
    unloaded_rtt_ms: f64,
    _proxy: Box<dyn Send>,
}

/// Pings the idle connection a few times and returns the median round trip
/// in ms, timed around `ping()` and its `PingRttMeasured`.
fn idle_rtt_ms(client: &mut Endpoint, target: &mut Endpoint, target_peer: &PeerId) -> f64 {
    let mut rtts = Vec::new();
    for _ in 0..3 {
        let start = Instant::now();
        client.ping(target_peer).expect("ping");
        loop {
            assert!(start.elapsed() < SETUP_TIMEOUT, "idle ping timed out");
            next_event(target, Duration::from_millis(1));
            if let Some(EndpointEvent::PingRttMeasured { .. }) =
                next_event(client, Duration::from_millis(1))
            {
                break;
            }
        }
        rtts.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    median(&rtts)
}

fn link(profile: Profile, point: &Point) -> Linked {
    let listen = match point.transport {
        Transport::Quic => "/ip4/127.0.0.1/udp/0/quic-v1",
        Transport::Tcp => "/ip4/127.0.0.1/tcp/0",
    };
    let builder = || {
        Endpoint::builder()
            .protocol(PROTOCOL)
            .quic_limits(point.quic.clone())
            .tcp_config(point.tcp.clone())
    };
    let mut target = bind_on(builder(), listen);
    let target_addr = target.listen().expect("target listens");
    let target_peer = target_addr.peer_id().clone();
    let (proxy_addr, up, down, proxy): (PeerAddr, _, _, Box<dyn Send>) = match point.transport {
        Transport::Quic => {
            let proxy = UdpProxy::spawn(socket_addr(&target_addr), profile);
            let addr = PeerAddr::quic_v1(LOOPBACK, proxy.addr.port(), target_peer.clone());
            let (up, down) = (Arc::clone(&proxy.up), Arc::clone(&proxy.down));
            (addr, up, down, Box::new(proxy))
        }
        Transport::Tcp => {
            let proxy = TcpProxy::spawn(socket_addr(&target_addr), profile);
            let addr = PeerAddr::tcp(LOOPBACK, proxy.addr.port(), target_peer.clone());
            let (up, down) = (Arc::clone(&proxy.up), Arc::clone(&proxy.down));
            (addr, up, down, Box::new(proxy))
        }
    };
    let mut client = bind_on(builder(), listen);
    client.connect(&proxy_addr).expect("connect");
    let deadline = Instant::now() + SETUP_TIMEOUT;
    let mut ready = false;
    while !ready {
        assert!(
            Instant::now() < deadline,
            "connect through the proxy timed out"
        );
        next_event(&mut target, Duration::from_millis(1));
        ready = matches!(
            next_event(&mut client, Duration::from_millis(1)),
            Some(EndpointEvent::PeerReady { peer_id, .. }) if peer_id == target_peer
        );
    }
    let unloaded_rtt_ms = idle_rtt_ms(&mut client, &mut target, &target_peer);
    Linked {
        target,
        client,
        target_peer,
        up,
        down,
        unloaded_rtt_ms,
        _proxy: proxy,
    }
}

/// CPU time of the busiest proxy thread across both directions, in µs.
fn proxy_cpu_us(links: [&LinkStats; 2]) -> [u64; 4] {
    let cpu = |stats: &LinkStats| {
        [
            stats.reader_cpu_us.load(Ordering::Relaxed),
            stats.writer_cpu_us.load(Ordering::Relaxed),
        ]
    };
    let ([a, b], [c, d]) = (cpu(links[0]), cpu(links[1]));
    [a, b, c, d]
}

/// `runs` timed transfers of `total` bytes over one fresh connection, after
/// a warm-up transfer that opens the congestion window. The target pings the
/// client throughout, for the loaded RTT.
fn measure(profile: Profile, point: &Point, total: u64, runs: usize) -> Vec<Sample> {
    let Linked {
        target,
        mut client,
        target_peer,
        up,
        down,
        unloaded_rtt_ms,
        _proxy,
    } = link(profile, point);
    let client_peer = client.peer_id().clone();
    let pings = Arc::new(Mutex::new(Vec::new()));
    let on_event = {
        let (pings, client_peer) = (Arc::clone(&pings), client_peer.clone());
        let mut next_ping = Instant::now();
        move |endpoint: &mut Endpoint, event: &EndpointEvent| {
            if let EndpointEvent::PingRttMeasured { rtt_ms, .. } = event {
                pings.lock().expect("pings").push(*rtt_ms);
            }
            if Instant::now() >= next_ping {
                // A ping still outstanding is not an error worth stopping for.
                drop(endpoint.ping(&client_peer));
                next_ping = Instant::now() + PING_INTERVAL;
            }
        }
    };
    let unit = (point.streams * CHUNK) as u64;
    let total = total.div_ceil(unit) * unit;
    let (_sink, sink) = bulk::spawn_sink(target, &client, PROTOCOL, Instant::now, on_event);
    let windows = point.quic.stream_receive_window as u64 * point.streams as u64
        + point.quic.connection_receive_window as u64
        + point.quic.send_window as u64
        + u64::from(point.tcp.yamux.receive_window);
    let load = Load {
        total,
        streams: point.streams,
        in_flight: (32 * MB).max(2 * windows),
    };
    let warm_up = Load {
        total: (total / 4).div_ceil(unit) * unit,
        ..load
    };
    bulk::transfer(
        &mut client,
        &target_peer,
        PROTOCOL,
        &sink,
        warm_up,
        Instant::now,
    );

    let mut samples = Vec::new();
    for _ in 0..runs {
        up.reset();
        pings.lock().expect("pings").clear();
        let counted = point.transport == Transport::Quic;
        let before = (
            datagram_counters(&client_peer),
            datagram_counters(&target_peer),
        );
        let cpu_before = proxy_cpu_us([&up, &down]);
        let (start, end) = bulk::transfer(
            &mut client,
            &target_peer,
            PROTOCOL,
            &sink,
            load,
            Instant::now,
        );
        let seconds = (end - start).as_secs_f64();
        let cpu_after = proxy_cpu_us([&up, &down]);
        let proxy_cpu = cpu_before
            .iter()
            .zip(cpu_after)
            .map(|(before, after)| after.saturating_sub(*before))
            .max()
            .unwrap_or_default() as f64
            / 1e6
            / seconds;
        // Count loss once nothing is left on the link. The client is not
        // driven while the up direction drains, so it sends nothing new;
        // then it is driven while the down direction drains, so it reads
        // what the target sent up to that point.
        thread::sleep(profile.rtt * 2);
        let target_sent = datagram_counters(&target_peer).since(&before.1).sent;
        let lost_up = datagram_counters(&client_peer)
            .since(&before.0)
            .sent
            .saturating_sub(datagram_counters(&target_peer).since(&before.1).received);
        let drained = Instant::now() + profile.rtt * 2;
        while Instant::now() < drained {
            drop(client.wait(drained).expect("drive client"));
        }
        let lost_down =
            target_sent.saturating_sub(datagram_counters(&client_peer).since(&before.0).received);
        samples.push(Sample {
            mb_per_s: total as f64 / MB as f64 / seconds,
            utilization: total as f64 / seconds / profile.bytes_per_s(),
            unloaded_rtt_ms,
            ping_ms: pings.lock().expect("pings").clone(),
            lost_up: if counted { lost_up } else { 0 },
            lost_down: if counted { lost_down } else { 0 },
            held_high_water: up.held_high_water.load(Ordering::Relaxed),
            max_queue_delay_ms: up.max_queue_delay_us.load(Ordering::Relaxed) as f64 / 1000.0,
            proxy_cpu,
        });
    }
    samples
}

/// Handshakes through the emulated link with Retry on and off:
///
/// - `single`: one client at a time; time to the transport connection
///   (`ConnectSettled`) and to `PeerReady` (after Identify).
/// - `concurrent`: 16 clients dialing at once, each through its own proxy;
///   time to each one's connection, and the process CPU time the burst took.
/// - `refused`: a target whose budget fits one connection; time until a
///   second client's dial settles (Retry on: `CONNECTION_REFUSED`; off:
///   silence until the client gives up, capped at 20 s).
///
/// It also prints the margin left in DCUtR's 3 s punch window after a
/// handshake with Retry on.
fn retry(profile: Profile, runs: usize) {
    const CONCURRENT: usize = 16;
    const REFUSAL_CAP: Duration = Duration::from_secs(20);
    let limits = |retry| QuicLimits {
        require_address_validation: retry,
        ..QuicLimits::default()
    };
    println!("retry on {} ({runs} runs)", profile.name);
    let mut connected_on = Vec::new();
    for retry in [true, false] {
        let (mut connected, mut ready) = (Vec::new(), Vec::new());
        for _ in 0..runs {
            let (connect, peer_ready) = handshake(profile, limits(retry));
            connected.push(connect.as_secs_f64() * 1000.0);
            ready.push(peer_ready.as_secs_f64() * 1000.0);
        }
        println!(
            "  single, Retry {}: connected {:.0} ms median [{:.0}, {:.0}], PeerReady {:.0} ms median",
            on_off(retry),
            median(&connected),
            min(&connected),
            max(&connected),
            median(&ready)
        );
        if retry {
            connected_on = connected;
        }
    }
    for retry in [true, false] {
        for _ in 0..runs.min(3) {
            let (times, cpu) = concurrent_handshakes(profile, limits(retry), CONCURRENT);
            println!(
                "  concurrent ×{CONCURRENT}, Retry {}: connected p50 {:.0} ms, max {:.0} ms, CPU {:.0} ms",
                on_off(retry),
                median(&times),
                max(&times),
                cpu.as_secs_f64() * 1000.0
            );
        }
    }
    for retry in [true, false] {
        for _ in 0..runs.min(3) {
            let (elapsed, outcome) = refused(profile, limits(retry), REFUSAL_CAP);
            println!(
                "  refused, Retry {}: {outcome} after {:.0} ms",
                on_off(retry),
                elapsed.as_secs_f64() * 1000.0
            );
        }
    }
    if !connected_on.is_empty() {
        println!(
            "  punch window margin with Retry on: {:.0} ms of 3000 ms left after a median handshake",
            3000.0 - median(&connected_on)
        );
    }
}

fn on_off(retry: bool) -> &'static str {
    if retry { "on " } else { "off" }
}

/// A target bound with `limits` and driven on its own thread.
fn driven_target(limits: QuicLimits) -> (Driven, PeerAddr) {
    let mut target = bind_on(
        Endpoint::builder().protocol(PROTOCOL).quic_limits(limits),
        "/ip4/127.0.0.1/udp/0/quic-v1",
    );
    let addr = target.listen().expect("target listens");
    (Driven::spawn(target, |_, _| {}), addr)
}

/// Dials `target` through a fresh proxy and returns the time to the
/// connection and to `PeerReady`.
fn handshake(profile: Profile, limits: QuicLimits) -> (Duration, Duration) {
    let (_target, addr) = driven_target(limits);
    let proxy = UdpProxy::spawn(socket_addr(&addr), profile);
    let mut client = bind_on(Endpoint::builder(), "/ip4/127.0.0.1/udp/0/quic-v1");
    let start = Instant::now();
    client
        .connect(PeerAddr::quic_v1(
            LOOPBACK,
            proxy.addr.port(),
            addr.peer_id().clone(),
        ))
        .expect("connect");
    let mut connected = None;
    loop {
        assert!(start.elapsed() < SETUP_TIMEOUT, "handshake timed out");
        match next_event(&mut client, Duration::from_millis(1)) {
            Some(EndpointEvent::ConnectSettled { outcome, .. }) => {
                assert!(
                    matches!(outcome, ConnectOutcome::Connected { .. }),
                    "handshake failed: {outcome:?}"
                );
                connected = Some(start.elapsed());
            }
            Some(EndpointEvent::PeerReady { .. }) => {
                return (connected.expect("connected before ready"), start.elapsed());
            }
            _ => {}
        }
    }
}

/// `count` clients dial one target at once, each through its own proxy.
/// Returns each client's time to its connection in ms, and the process CPU
/// time from the first dial to the last connection.
fn concurrent_handshakes(
    profile: Profile,
    limits: QuicLimits,
    count: usize,
) -> (Vec<f64>, Duration) {
    let (_target, addr) = driven_target(limits);
    let clients: Vec<_> = (0..count)
        .map(|_| {
            let proxy = UdpProxy::spawn(socket_addr(&addr), profile);
            let client = bind_on(Endpoint::builder(), "/ip4/127.0.0.1/udp/0/quic-v1");
            let target = PeerAddr::quic_v1(LOOPBACK, proxy.addr.port(), addr.peer_id().clone());
            (proxy, client, target)
        })
        .collect();
    let cpu = cpu_time::ProcessTime::now();
    let start = Instant::now();
    let (tx, rx) = std::sync::mpsc::channel();
    let mut drivers = Vec::new();
    for (proxy, mut client, target) in clients {
        client.connect(&target).expect("connect");
        let tx = tx.clone();
        let mut reported = false;
        drivers.push((
            proxy,
            Driven::spawn(client, move |_, event| {
                if let EndpointEvent::ConnectSettled { outcome, .. } = event
                    && !reported
                {
                    reported = true;
                    drop(tx.send((start.elapsed(), outcome)));
                }
            }),
        ));
    }
    let mut times = Vec::new();
    for _ in 0..count {
        let (elapsed, outcome) = rx.recv_timeout(SETUP_TIMEOUT).expect("handshake settles");
        assert!(
            matches!(outcome, ConnectOutcome::Connected { .. }),
            "concurrent handshake failed: {outcome:?}"
        );
        times.push(elapsed.as_secs_f64() * 1000.0);
    }
    let cpu = cpu.elapsed();
    drop(drivers);
    (times, cpu)
}

/// A target whose budget fits one connection: one client connects, then a
/// second dials. Returns how long the second dial took to settle and how.
fn refused(profile: Profile, limits: QuicLimits, cap: Duration) -> (Duration, String) {
    // Small streams, so the slack for the first connection's streams cannot
    // admit a second connection.
    let stream_receive_window = 64 * 1024;
    let limits = QuicLimits {
        stream_receive_window,
        memory_budget_bytes: limits.datagram_queue_reservation_bytes()
            + limits.connection_reservation_bytes()
            + 16 * stream_receive_window,
        ..limits
    };
    let (_target, addr) = driven_target(limits);
    let _first = connected_client(profile, &addr);
    let proxy = UdpProxy::spawn(socket_addr(&addr), profile);
    let mut client = bind_on(Endpoint::builder(), "/ip4/127.0.0.1/udp/0/quic-v1");
    let start = Instant::now();
    client
        .connect(PeerAddr::quic_v1(
            LOOPBACK,
            proxy.addr.port(),
            addr.peer_id().clone(),
        ))
        .expect("connect");
    while start.elapsed() < cap {
        if let Some(EndpointEvent::ConnectSettled { outcome, .. }) =
            next_event(&mut client, Duration::from_millis(5))
        {
            let outcome = match outcome {
                ConnectOutcome::Failed(failure) => format!("failed ({failure})"),
                other => format!("{other:?}"),
            };
            return (start.elapsed(), outcome);
        }
    }
    (start.elapsed(), "still unsettled at the cap".into())
}

/// A fresh client connected to `addr` through a fresh proxy, driven until
/// dropped (the first connection of [`refused`]).
fn connected_client(profile: Profile, addr: &PeerAddr) -> (Driven, UdpProxy) {
    let proxy = UdpProxy::spawn(socket_addr(addr), profile);
    let mut client = bind_on(Endpoint::builder(), "/ip4/127.0.0.1/udp/0/quic-v1");
    client
        .connect(PeerAddr::quic_v1(
            LOOPBACK,
            proxy.addr.port(),
            addr.peer_id().clone(),
        ))
        .expect("connect");
    let deadline = Instant::now() + SETUP_TIMEOUT;
    loop {
        assert!(Instant::now() < deadline, "first connection timed out");
        if let Some(EndpointEvent::PeerReady { .. }) =
            next_event(&mut client, Duration::from_millis(1))
        {
            return (Driven::spawn(client, |_, _| {}), proxy);
        }
    }
}
