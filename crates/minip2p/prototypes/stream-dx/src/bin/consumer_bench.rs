//! THROWAWAY measurement of current Endpoint versus consumption credit.
//! Compiles unchanged against main without the e2e feature for a real baseline.
#![forbid(unsafe_code)]
use minip2p::{ConnectionId, Endpoint, Error, Event, PeerId, StreamId, TransportError};
use minip2p_tcp::TcpConfig;
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};
#[cfg(feature = "alloc-stats")]
#[global_allocator]
static ALLOC: &stats_alloc::StatsAlloc<std::alloc::System> = &stats_alloc::INSTRUMENTED_SYSTEM;
const FRAME: usize = 65536;
const WINDOW: usize = 262144;
const PROTOCOL: &str = "/prototype/consumer-bench/1";
type Stream = (ConnectionId, StreamId);
#[derive(Default)]
struct Queue {
    parts: VecDeque<(Vec<u8>, usize)>,
    bytes: usize,
    eof: bool,
}
impl Queue {
    fn push(&mut self, data: Vec<u8>) {
        self.bytes += data.len();
        self.parts.push_back((data, 0));
    }
    fn copy(&mut self, out: &mut [u8]) -> usize {
        let mut n = 0;
        while n < out.len() {
            let Some((data, at)) = self.parts.front_mut() else {
                break;
            };
            let take = (out.len() - n).min(data.len() - *at);
            out[n..n + take].copy_from_slice(&data[*at..*at + take]);
            n += take;
            *at += take;
            self.bytes -= take;
            if *at == data.len() {
                self.parts.pop_front();
            }
        }
        n
    }
    // The current owned caller can process its Vec directly, with no pull copy.
    fn verify(&mut self, limit: usize, offset: usize, stream: usize, expected: &mut [u8]) -> usize {
        let mut n = 0;
        while n < limit {
            let Some((data, at)) = self.parts.front_mut() else {
                break;
            };
            let take = (limit - n).min(data.len() - *at);
            fill(&mut expected[..take], offset + n, stream);
            assert_eq!(
                &data[*at..*at + take],
                &expected[..take],
                "payload mismatch"
            );
            n += take;
            *at += take;
            self.bytes -= take;
            if *at == data.len() {
                self.parts.pop_front();
            }
        }
        n
    }
}
struct Host {
    ep: Endpoint,
    streams: Vec<Stream>,
    queues: Vec<Queue>,
    ready: usize,
}
impl Host {
    fn new() -> Self {
        let mut config = TcpConfig::default();
        config.yamux.max_frame_len = FRAME as u32;
        let ep = Endpoint::builder()
            .tcp_config(config)
            .protocol(PROTOCOL)
            .bind_tcp("127.0.0.1:0")
            .unwrap();
        Self {
            ep,
            streams: Vec::new(),
            queues: (0..3).map(|_| Queue::default()).collect(),
            ready: 0,
        }
    }
    fn poll(&mut self) -> usize {
        let mut bytes = 0;
        for event in self.ep.poll().unwrap() {
            match event {
                Event::Error(e) => panic!("Endpoint error: {e:?}"),
                Event::StreamReady {
                    conn_id,
                    stream_id,
                    initiated_locally,
                    ..
                } => {
                    self.ready += 1;
                    if !initiated_locally {
                        self.streams.push((conn_id, stream_id));
                        self.streams.sort_by_key(|s| s.1);
                    }
                }
                Event::StreamData {
                    stream_id, data, ..
                } => {
                    let i = self
                        .streams
                        .iter()
                        .position(|s| s.1 == stream_id)
                        .expect("registered application stream");
                    bytes += data.len();
                    self.queues[i].push(data);
                }
                Event::StreamRemoteWriteClosed { stream_id, .. } => {
                    if let Some(i) = self.streams.iter().position(|s| s.1 == stream_id) {
                        self.queues[i].eof = true;
                    }
                }
                _ => {}
            }
        }
        bytes
    }
}
fn fill(out: &mut [u8], offset: usize, stream: usize) {
    for (i, b) in out.iter_mut().enumerate() {
        let x = ((offset + i) as u64)
            .wrapping_mul(0x9e3779b97f4a7c15)
            .rotate_left(17);
        *b = (x >> 56) as u8 ^ (stream as u8).wrapping_mul(137);
    }
}
fn send(ep: &mut Endpoint, peer: &PeerId, stream: StreamId, data: &[u8]) -> bool {
    match ep.send_stream(peer, stream, data.to_vec()) {
        Ok(()) => true,
        Err(Error::Transport(TransportError::StreamSendFailed { reason, .. }))
            if reason.contains("Yamux send buffer is full") =>
        {
            false
        }
        Err(e) => panic!("unexpected send rejection: {e}"),
    }
}
fn setup() -> (Host, Host) {
    let mut a = Host::new();
    let mut b = Host::new();
    let addr = b.ep.listen_all().unwrap().remove(0);
    a.ep.dial(&addr).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while a.ep.connected_peers().is_empty() || b.ep.connected_peers().is_empty() {
        a.poll();
        b.poll();
        assert!(Instant::now() < deadline);
    }
    a.streams = (0..3)
        .map(|_| {
            a.ep.open_stream_with_connection(b.ep.peer_id(), PROTOCOL)
                .unwrap()
        })
        .collect();
    while a.ready < 3 || b.ready < 3 {
        a.poll();
        b.poll();
        assert!(Instant::now() < deadline);
    }
    (a, b)
}
fn percentile(v: &[u64], p: usize) -> u64 {
    v.get(v.len().saturating_sub(1) * p / 100)
        .copied()
        .unwrap_or(0)
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        6,
        "consumer-bench current|pull|ack|pause bytes_per_stream pause_ms slow_bytes_per_second idle_us"
    );
    let mode = args[1].as_str();
    assert!(["current", "pull", "ack", "pause"].contains(&mode));
    #[cfg(not(feature = "e2e"))]
    assert_ne!(mode, "pull", "main baseline has no prototype methods");
    let size: usize = args[2].parse().unwrap();
    assert!(size > 0);
    let pause = Duration::from_millis(args[3].parse().unwrap());
    let rate: usize = args[4].parse().unwrap();
    let idle = Duration::from_micros(args[5].parse().unwrap());
    let (mut a, mut b) = setup();
    #[cfg(feature = "e2e")]
    if mode == "pull" {
        for &(c, s) in &b.streams[..2] {
            b.ep.prototype_enable(c, s).unwrap();
        }
    }
    let peer_a = a.ep.peer_id().clone();
    let peer_b = b.ep.peer_id().clone();
    let mut sources = [vec![0; FRAME], vec![0; FRAME]];
    for (i, source) in sources.iter_mut().enumerate() {
        fill(source, 0, i);
    }
    #[cfg(feature = "e2e")]
    let mut scratch = vec![0; FRAME];
    let mut expected = vec![0; FRAME];
    let mut sent = [0usize; 2];
    let mut received = [0usize; 2];
    let mut acknowledged = [0usize; 2];
    let mut ack_sent = [0usize; 2];
    let mut ack_rx = [[0u8; 8]; 2];
    let mut ack_at = [0usize; 2];
    let mut fin = [false; 2];
    let mut eof = [false; 2];
    let mut completed = [0u64; 2];
    let mut retry_at = [Instant::now(); 2];
    let mut rejected = 0;
    let mut polls = 0;
    let mut sleeps = 0;
    let mut peak_payload = 0;
    let mut peak_slow = 0;
    let mut skip_polls = 0;
    let mut rtts = Vec::with_capacity(20000);
    let mut probe_seq = 0u64;
    let mut probe_started: Option<Instant> = None;
    let mut next_probe = Instant::now();
    let mut request = [0; 8];
    let mut request_at = 0;
    let mut reply = [0; 8];
    let mut reply_at = 0;
    let mut last_reply = Instant::now();
    let mut max_probe_gap = 0;
    #[cfg(feature = "alloc-stats")]
    let region = stats_alloc::Region::new(ALLOC);
    #[cfg(feature = "alloc-stats")]
    let mut heap_peak = 0i128;
    let start = Instant::now();
    while !eof.iter().all(|v| *v) || probe_started.is_some() {
        let mut progress = 0;
        // Public send_stream is identical in all modes. Rejection retains caller bytes.
        if !eof.iter().all(|v| *v) && probe_started.is_none() && Instant::now() >= next_probe {
            probe_seq += 1;
            let data = probe_seq.to_le_bytes();
            assert!(send(&mut a.ep, &peer_b, a.streams[2].1, &data));
            probe_started = Some(Instant::now());
            next_probe = Instant::now() + Duration::from_millis(2);
            progress += 8;
        }
        for j in 0..2 {
            let i = (polls + j) % 2;
            if sent[i] < size {
                let n = FRAME.min(size - sent[i]);
                if Instant::now() >= retry_at[i]
                    && (mode != "ack" || sent[i] + n - acknowledged[i] <= WINDOW)
                {
                    if send(&mut a.ep, &peer_b, a.streams[i].1, &sources[i][..n]) {
                        sent[i] += n;
                        progress += n;
                        if sent[i] < size {
                            fill(&mut sources[i], sent[i], i);
                        }
                    } else {
                        rejected += 1;
                        retry_at[i] = Instant::now() + Duration::from_millis(1);
                    }
                }
            } else if !fin[i] {
                a.ep.close_stream_write(&peer_b, a.streams[i].1).unwrap();
                fin[i] = true;
            }
        }
        progress += a.poll();
        // Existing-interface workaround: stop polling the entire receiver at a queue threshold.
        if mode == "pause" && b.queues[..2].iter().map(|q| q.bytes).sum::<usize>() >= WINDOW {
            skip_polls += 1;
        } else {
            progress += b.poll();
        }
        polls += 1;
        let held = [b.queues[0].bytes, b.queues[1].bytes];
        #[cfg(feature = "e2e")]
        let held = if mode == "pull" {
            core::array::from_fn(|i| {
                let (c, s) = b.streams[i];
                held[i] + b.ep.prototype_stream_buffered(c, s)
            })
        } else {
            held
        };
        peak_payload = peak_payload.max(held.iter().sum::<usize>());
        peak_slow = peak_slow.max(held[1]);
        #[cfg(feature = "alloc-stats")]
        {
            let s = region.change();
            heap_peak = heap_peak.max(s.bytes_allocated as i128 - s.bytes_deallocated as i128);
        }
        for i in 0..2 {
            if eof[i] {
                continue;
            }
            let allowed = if i == 0 {
                size
            } else if start.elapsed() < pause {
                0
            } else if rate == 0 {
                size
            } else {
                ((start.elapsed() - pause).as_secs_f64() * rate as f64) as usize
            };
            // Pace complete processing batches, not byte-sized work on every poll.
            let allowed = if i == 1 && rate != 0 {
                allowed / FRAME * FRAME
            } else {
                allowed
            };
            let limit = FRAME
                .min(allowed.saturating_sub(received[i]))
                .min(size - received[i]);
            if limit > 0 {
                let n;
                #[cfg(feature = "e2e")]
                if mode == "pull" {
                    let (c, s) = b.streams[i];
                    n =
                        b.ep.prototype_read(c, s, &mut scratch[..limit])
                            .unwrap()
                            .unwrap_or(0);
                    fill(&mut expected[..n], received[i], i);
                    assert_eq!(&scratch[..n], &expected[..n]);
                } else {
                    n = b.queues[i].verify(limit, received[i], i, &mut expected);
                }
                #[cfg(not(feature = "e2e"))]
                {
                    n = b.queues[i].verify(limit, received[i], i, &mut expected);
                }
                received[i] += n;
                progress += n;
            }
            if mode == "ack"
                && (received[i] - ack_sent[i] >= FRAME
                    || (received[i] == size && ack_sent[i] < size))
            {
                assert!(send(
                    &mut b.ep,
                    &peer_a,
                    b.streams[i].1,
                    &(received[i] as u64).to_le_bytes()
                ));
                ack_sent[i] = received[i];
                progress += 8;
            }
            if received[i] == size {
                #[cfg(feature = "e2e")]
                if mode == "pull" {
                    let (c, s) = b.streams[i];
                    eof[i] = b.ep.prototype_read(c, s, &mut scratch[..1]).unwrap() == Some(0);
                } else {
                    eof[i] = b.queues[i].eof;
                }
                #[cfg(not(feature = "e2e"))]
                {
                    eof[i] = b.queues[i].eof;
                }
                if eof[i] {
                    completed[i] = start.elapsed().as_micros() as u64;
                }
            }
        }
        for i in 0..2 {
            if mode == "ack" {
                ack_at[i] += a.queues[i].copy(&mut ack_rx[i][ack_at[i]..]);
                if ack_at[i] == 8 {
                    let n = u64::from_le_bytes(ack_rx[i]) as usize;
                    assert!(n >= acknowledged[i] && n <= sent[i]);
                    acknowledged[i] = n;
                    ack_at[i] = 0;
                    progress += 8;
                }
            }
        }
        request_at += b.queues[2].copy(&mut request[request_at..]);
        if request_at == 8 {
            assert!(send(&mut b.ep, &peer_a, b.streams[2].1, &request));
            request_at = 0;
            progress += 8;
        }
        reply_at += a.queues[2].copy(&mut reply[reply_at..]);
        if reply_at == 8 {
            assert_eq!(reply, probe_seq.to_le_bytes());
            rtts.push(probe_started.take().unwrap().elapsed().as_micros() as u64);
            reply_at = 0;
            progress += 8;
            max_probe_gap = max_probe_gap.max(last_reply.elapsed().as_micros() as u64);
            last_reply = Instant::now();
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "stalled {mode} sent={sent:?} received={received:?} eof={eof:?}"
        );
        if progress == 0 {
            std::thread::sleep(idle);
            sleeps += 1;
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    #[cfg(feature = "alloc-stats")]
    let (allocs, allocated, live_peak) = {
        let s = region.change();
        (s.allocations, s.bytes_allocated, heap_peak)
    };
    #[cfg(not(feature = "alloc-stats"))]
    let (allocs, allocated, live_peak) = (0, 0, 0);
    assert_eq!(received, [size; 2]);
    rtts.sort_unstable();
    println!(
        "{},{},{},{},{},{:.3},{:.3},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        mode,
        size,
        pause.as_millis(),
        rate,
        cfg!(feature = "alloc-stats"),
        elapsed * 1000.,
        2. * size as f64 / 1048576. / elapsed,
        completed[0],
        completed[1],
        peak_payload,
        peak_slow,
        rtts.len(),
        percentile(&rtts, 50),
        percentile(&rtts, 99),
        rtts.last().unwrap_or(&0),
        max_probe_gap,
        polls,
        sleeps,
        skip_polls,
        rejected,
        allocs,
        allocated,
        live_peak
    );
}
