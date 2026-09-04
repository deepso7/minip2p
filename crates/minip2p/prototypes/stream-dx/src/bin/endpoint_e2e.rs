//! THROWAWAY Endpoint -> Swarm -> TransportSet -> StdTcpProvider -> Noise/Yamux.
#![forbid(unsafe_code)]
use minip2p::{ConnectionId, Endpoint, Event, StreamId};
use minip2p_tcp::TcpConfig;
use std::{
    fs::File,
    io::{Read, Write},
    time::{Duration, Instant},
};
#[cfg(feature = "alloc-stats")]
#[global_allocator]
static ALLOC: &stats_alloc::StatsAlloc<std::alloc::System> = &stats_alloc::INSTRUMENTED_SYSTEM;
const CHUNK: usize = 65536;
const PROTOCOL: &str = "/prototype/consumption/1";
type Stream = (ConnectionId, StreamId);
fn poll(ep: &mut Endpoint) -> Vec<Event> {
    let events = ep.poll().unwrap();
    for e in &events {
        if let Event::Error(e) = e {
            panic!("Endpoint error: {e:?}");
        }
    }
    events
}
fn setup() -> (Endpoint, Endpoint, Vec<Stream>, Vec<Stream>) {
    let mut config = TcpConfig::default();
    config.yamux.max_frame_len = CHUNK as u32;
    let mut a = Endpoint::builder()
        .protocol(PROTOCOL)
        .tcp_config(config.clone())
        .bind_tcp("127.0.0.1:0")
        .unwrap();
    let mut b = Endpoint::builder()
        .protocol(PROTOCOL)
        .tcp_config(config)
        .bind_tcp("127.0.0.1:0")
        .unwrap();
    let address = b.listen_all().unwrap().remove(0);
    a.dial(&address).unwrap();
    let start = Instant::now();
    while a.connected_peers().is_empty() || b.connected_peers().is_empty() {
        poll(&mut a);
        poll(&mut b);
        assert!(start.elapsed() < Duration::from_secs(5));
    }
    let peer = b.peer_id().clone();
    let aa: Vec<_> = (0..3)
        .map(|_| a.open_stream_with_connection(&peer, PROTOCOL).unwrap())
        .collect();
    let mut bb = Vec::new();
    let mut ready = 0;
    while ready < 3 || bb.len() < 3 {
        for event in poll(&mut a) {
            if let Event::StreamReady { .. } = event {
                ready += 1;
            }
        }
        for event in poll(&mut b) {
            if let Event::StreamReady {
                conn_id, stream_id, ..
            } = event
            {
                bb.push((conn_id, stream_id));
            }
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "protocol negotiation stalled"
        );
    }
    bb.sort_by_key(|s| s.1);
    for &(c, s) in &aa {
        a.prototype_enable(c, s).unwrap();
    }
    for &(c, s) in &bb {
        b.prototype_enable(c, s).unwrap();
    }
    (a, b, aa, bb)
}
// These are the two caller contracts being compared. Each call consumes at most one frame.
fn consume(
    ep: &mut Endpoint,
    stream: Stream,
    owned: bool,
    scratch: &mut [u8],
    sink: &mut impl Write,
) -> Option<usize> {
    let (c, s) = stream;
    if owned {
        let chunk = ep.prototype_chunk(c, s).unwrap()?;
        let n = chunk.data().len();
        sink.write_all(chunk.data()).unwrap();
        ep.prototype_release(chunk).unwrap();
        Some(n)
    } else {
        let n = ep.prototype_read(c, s, scratch).unwrap()?;
        sink.write_all(&scratch[..n]).unwrap();
        Some(n)
    }
}
// Untimed misuse/continuation checks on a fresh negotiated connection.
fn edge_cases(owned: bool) {
    let (mut a, mut b, aa, bb) = setup();
    let data = vec![7; 8 * CHUNK];
    let mut accepted = 0;
    while accepted < data.len() {
        let n = a
            .prototype_write(aa[0].0, aa[0].1, &data[accepted..])
            .unwrap();
        if n == 0 {
            break;
        }
        accepted += n;
    }
    assert!(accepted > 4 * CHUNK);
    let deadline = Instant::now() + Duration::from_secs(2);
    while b.prototype_held(bb[0].0, bb[0].1).unwrap() < 3 * CHUNK {
        poll(&mut a);
        poll(&mut b);
        assert!(Instant::now() < deadline);
    }
    if owned {
        let mut held = Vec::new();
        for _ in 0..100 {
            poll(&mut a);
            poll(&mut b);
            while let Some(chunk) = b.prototype_chunk(bb[0].0, bb[0].1).unwrap() {
                held.push(chunk);
            }
        }
        let bytes: usize = held.iter().map(|c| c.data().len()).sum();
        assert!((3 * CHUNK..=4 * CHUNK).contains(&bytes));
        for _ in 0..100 {
            poll(&mut a);
            poll(&mut b);
            assert!(b.prototype_chunk(bb[0].0, bb[0].1).unwrap().is_none());
        }
        for chunk in held {
            b.prototype_release(chunk).unwrap();
        }
        let chunk = loop {
            poll(&mut a);
            poll(&mut b);
            if let Some(c) = b.prototype_chunk(bb[0].0, bb[0].1).unwrap() {
                break c;
            }
            assert!(Instant::now() < deadline, "release failed to resume sender");
        };
        b.reset_stream(a.peer_id(), bb[0].1).unwrap();
        assert!(
            b.prototype_release(chunk).is_err(),
            "reset must invalidate outstanding credit"
        );
    } else {
        let mut seven = [0; 7];
        assert_eq!(
            b.prototype_read(bb[0].0, bb[0].1, &mut seven).unwrap(),
            Some(7)
        );
        // Yield and resume with no new readiness event required.
        poll(&mut b);
        assert_eq!(
            b.prototype_read(bb[0].0, bb[0].1, &mut seven).unwrap(),
            Some(7)
        );
        assert_eq!(seven, [7; 7]);
        b.reset_stream(a.peer_id(), bb[0].1).unwrap();
        assert!(b.prototype_read(bb[0].0, bb[0].1, &mut seven).is_err());
    }
    // The other negotiated stream survives resetting the first.
    assert_eq!(a.prototype_write(aa[1].0, aa[1].1, b"survives").unwrap(), 8);
    let mut sink = Vec::new();
    let mut scratch = vec![0; CHUNK];
    while sink.len() < 8 {
        poll(&mut a);
        poll(&mut b);
        consume(&mut b, bb[1], owned, &mut scratch, &mut sink);
        assert!(Instant::now() < deadline);
    }
    assert_eq!(sink, b"survives");
}
fn p99(v: &mut [u64]) -> u64 {
    v.sort_unstable();
    v.get((v.len().saturating_sub(1) * 99) / 100)
        .copied()
        .unwrap_or(0)
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        5,
        "endpoint-e2e pull|chunk input-file output-dir pause_ms"
    );
    let owned = match args[1].as_str() {
        "chunk" => true,
        "pull" => false,
        _ => panic!("mode"),
    };
    let pause = Duration::from_millis(args[4].parse().unwrap());
    let expected = std::fs::read(&args[2]).unwrap();
    let mut sources = [File::open(&args[2]).unwrap(), File::open(&args[2]).unwrap()];
    let paths = [
        format!("{}/fast.bin", args[3]),
        format!("{}/slow.bin", args[3]),
    ];
    let mut sinks = [
        File::create(&paths[0]).unwrap(),
        File::create(&paths[1]).unwrap(),
    ];
    let (mut a, mut b, aa, bb) = setup();
    let bpeer = b.peer_id().clone();
    let mut buffers = [vec![0; CHUNK], vec![0; CHUNK]];
    let mut cursor = [0; 2];
    let mut filled = [0; 2];
    let mut fin = [false; 2];
    let mut eof = [false; 2];
    let mut received = [0; 2];
    let mut scratch = vec![0; CHUNK];
    let mut peak = 0;
    let mut fast_us = 0;
    let mut probe = 0u64;
    let mut probe_start = None;
    let mut probe_last = Instant::now();
    let mut echo = Vec::with_capacity(8);
    let mut reply = Vec::with_capacity(8);
    let mut rtts = Vec::with_capacity(4096);
    let mut turns = 0;
    #[cfg(feature = "alloc-stats")]
    let region = stats_alloc::Region::new(ALLOC);
    let start = Instant::now();
    while !eof.iter().all(|v| *v) || probe_start.is_some() {
        for j in 0..2 {
            let i = (turns + j) % 2;
            if !fin[i] {
                if cursor[i] == filled[i] {
                    filled[i] = sources[i].read(&mut buffers[i]).unwrap();
                    cursor[i] = 0;
                    if filled[i] == 0 {
                        a.close_stream_write(&bpeer, aa[i].1).unwrap();
                        fin[i] = true;
                        continue;
                    }
                }
                cursor[i] += a
                    .prototype_write(aa[i].0, aa[i].1, &buffers[i][cursor[i]..filled[i]])
                    .unwrap();
            }
        }
        if !eof.iter().all(|v| *v)
            && probe_start.is_none()
            && probe_last.elapsed() >= Duration::from_millis(1)
        {
            probe += 1;
            let bytes = probe.to_le_bytes();
            assert_eq!(a.prototype_write(aa[2].0, aa[2].1, &bytes).unwrap(), 8);
            probe_start = Some(Instant::now());
            probe_last = Instant::now();
        }
        for event in poll(&mut a).into_iter().chain(poll(&mut b)) {
            assert!(
                !matches!(event, Event::StreamData { .. }),
                "payload escaped through old events"
            );
        }
        let held = b.prototype_held(bb[0].0, bb[0].1).unwrap()
            + b.prototype_held(bb[1].0, bb[1].1).unwrap();
        peak = peak.max(held);
        assert!(
            held <= 2 * 262144,
            "receive credit exceeded two stream windows"
        );
        for i in 0..2 {
            if !eof[i] && (i == 0 || start.elapsed() >= pause) {
                if let Some(n) = consume(&mut b, bb[i], owned, &mut scratch, &mut sinks[i]) {
                    eof[i] = n == 0;
                    received[i] += n;
                }
                if i == 0 && eof[0] {
                    fast_us = start.elapsed().as_micros();
                }
            }
        }
        consume(&mut b, bb[2], owned, &mut scratch, &mut echo);
        if echo.len() == 8 {
            assert_eq!(b.prototype_write(bb[2].0, bb[2].1, &echo).unwrap(), 8);
            echo.clear();
        }
        poll(&mut b);
        poll(&mut a);
        consume(&mut a, aa[2], owned, &mut scratch, &mut reply);
        if reply.len() == 8 {
            assert_eq!(reply, probe.to_le_bytes());
            rtts.push(probe_start.take().unwrap().elapsed().as_micros() as u64);
            reply.clear();
        }
        turns += 1;
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "stalled {received:?}"
        );
        if fin.iter().all(|v| *v) && start.elapsed() < pause {
            std::thread::sleep(Duration::from_micros(50));
        }
    }
    let ms = start.elapsed().as_secs_f64() * 1000.;
    #[cfg(feature = "alloc-stats")]
    let (allocs, bytes) = {
        let s = region.change();
        (s.allocations, s.bytes_allocated)
    };
    #[cfg(not(feature = "alloc-stats"))]
    let (allocs, bytes) = (0, 0);
    for (i, path) in paths.iter().enumerate() {
        sinks[i].flush().unwrap();
        assert_eq!(std::fs::read(path).unwrap(), expected);
    }
    assert_eq!(received, [expected.len(); 2]);
    edge_cases(owned);
    println!(
        "{},{},{},{:.3},{:.3},{},{},{},{},{},{}",
        args[1],
        pause.as_millis(),
        cfg!(feature = "alloc-stats"),
        ms,
        2. * expected.len() as f64 / 1048576. / (ms / 1000.),
        fast_us,
        peak,
        rtts.len(),
        p99(&mut rtts),
        allocs,
        bytes
    );
}
