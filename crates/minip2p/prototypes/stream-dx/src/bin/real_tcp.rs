//! THROWAWAY localhost TCP + real multistream/Noise/Yamux experiment.
//! This deliberately bypasses Endpoint and StdTcpProvider to isolate stream I/O.
#![forbid(unsafe_code)]
use minip2p_identity::Ed25519Keypair;
use minip2p_secure_mux::{
    SecureMuxSession, SessionConfig, SessionError, SessionOutput, SessionRole, YamuxConfig,
    YamuxError,
};
use minip2p_transport::StreamId;
use std::{
    collections::{BTreeMap, VecDeque},
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    time::{Duration, Instant},
};

#[cfg(feature = "alloc-stats")]
#[global_allocator]
static ALLOC: &stats_alloc::StatsAlloc<std::alloc::System> = &stats_alloc::INSTRUMENTED_SYSTEM;

const CHUNK: usize = 64 * 1024;

struct Wire {
    socket: TcpStream,
    session: SecureMuxSession,
    outgoing: VecDeque<(Vec<u8>, usize)>,
    wire_bytes: usize,
    owned: BTreeMap<StreamId, VecDeque<(Vec<u8>, usize)>>,
    owned_bytes: usize,
    incoming: usize,
}

impl Wire {
    fn new(socket: TcpStream, role: SessionRole, pull: bool) -> Self {
        socket.set_nonblocking(true).unwrap();
        socket.set_nodelay(true).unwrap();
        // Real OS entropy; never ship fixed Noise secrets from a benchmark.
        let mut random = std::fs::File::open("/dev/urandom").unwrap();
        let mut static_secret = [0; 32];
        let mut ephemeral_secret = [0; 32];
        random.read_exact(&mut static_secret).unwrap();
        random.read_exact(&mut ephemeral_secret).unwrap();
        let mut session = SecureMuxSession::new(SessionConfig {
            role,
            identity: Ed25519Keypair::generate(),
            static_secret,
            ephemeral_secret,
            expected_peer: None,
            yamux: YamuxConfig {
                prototype_pull_reads: pull,
                max_streams: 8,
                max_frame_len: CHUNK as u32,
                ..Default::default()
            },
        });
        session.start().unwrap();
        Self {
            socket,
            session,
            outgoing: VecDeque::new(),
            wire_bytes: 0,
            owned: BTreeMap::new(),
            owned_bytes: 0,
            incoming: 0,
        }
    }

    fn collect(&mut self) {
        while let Some(output) = self.session.poll_output() {
            match output {
                SessionOutput::Write(bytes) => {
                    self.wire_bytes += bytes.len();
                    assert!(
                        self.wire_bytes < 8 * 1024 * 1024,
                        "socket queue exceeded experiment guard"
                    );
                    self.outgoing.push_back((bytes, 0));
                }
                SessionOutput::StreamData { stream, data } => {
                    self.owned_bytes += data.len();
                    self.owned.entry(stream).or_default().push_back((data, 0));
                }
                SessionOutput::IncomingStream { .. } => self.incoming += 1,
                SessionOutput::Established { .. } => {}
                other => {
                    panic!("unexpected lifecycle output during open-stream workload: {other:?}")
                }
            }
        }
    }

    fn flush(&mut self) -> usize {
        let mut moved = 0;
        for _ in 0..4 {
            let Some((bytes, offset)) = self.outgoing.front_mut() else {
                break;
            };
            match self.socket.write(&bytes[*offset..]) {
                Ok(0) => panic!("socket closed"),
                Ok(n) => {
                    *offset += n;
                    self.wire_bytes -= n;
                    moved += n;
                    if *offset == bytes.len() {
                        self.outgoing.pop_front();
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("TCP write: {e}"),
            }
        }
        moved
    }

    fn drive(&mut self, scratch: &mut [u8]) -> usize {
        self.collect();
        let mut moved = self.flush();
        for _ in 0..4 {
            match self.socket.read(scratch) {
                Ok(0) => panic!("unexpected TCP EOF"),
                Ok(n) => {
                    self.session.handle_input(scratch[..n].to_vec()).unwrap();
                    moved += n;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("TCP read: {e}"),
            }
        }
        self.collect();
        moved + self.flush()
    }

    fn send(&mut self, stream: StreamId, data: &[u8], pull: bool) -> usize {
        if self.wire_bytes >= 256 * 1024 {
            return 0;
        }
        if pull {
            self.session.prototype_try_write(stream, data).unwrap()
        } else {
            match self.session.send(stream, data.to_vec()) {
                Ok(()) => data.len(),
                Err(SessionError::Yamux(YamuxError::SendBufferFull { .. })) => 0,
                Err(e) => panic!("send: {e}"),
            }
        }
    }

    fn consume(
        &mut self,
        stream: StreamId,
        expected: &[u8],
        offset: &mut usize,
        pull: bool,
        runnable: &mut bool,
        scratch: &mut [u8],
    ) -> usize {
        if pull {
            *runnable |= self.session.prototype_read_ready(stream);
            if !*runnable {
                return 0;
            }
            match self.session.prototype_try_read(stream, scratch).unwrap() {
                Some(n) if n > 0 => {
                    assert_eq!(
                        &scratch[..n],
                        &expected[*offset..*offset + n],
                        "file data changed"
                    );
                    *offset += n;
                    n
                }
                None => {
                    *runnable = false;
                    0
                }
                Some(_) => panic!("unexpected EOF"),
            }
        } else {
            let Some(queue) = self.owned.get_mut(&stream) else {
                return 0;
            };
            let mut read = 0;
            while read < scratch.len() {
                let Some((bytes, at)) = queue.front_mut() else {
                    break;
                };
                let n = (scratch.len() - read).min(bytes.len() - *at);
                assert_eq!(
                    &bytes[*at..*at + n],
                    &expected[*offset..*offset + n],
                    "file data changed"
                );
                *offset += n;
                *at += n;
                read += n;
                self.owned_bytes -= n;
                if *at == bytes.len() {
                    queue.pop_front();
                }
            }
            read
        }
    }

    fn read_probe(&mut self, stream: StreamId, out: &mut [u8], pull: bool) -> usize {
        if out.is_empty() {
            return 0;
        }
        if pull {
            self.session
                .prototype_try_read(stream, out)
                .unwrap()
                .unwrap_or(0)
        } else {
            let Some(queue) = self.owned.get_mut(&stream) else {
                return 0;
            };
            let mut n = 0;
            while n < out.len() {
                let Some((bytes, at)) = queue.front_mut() else {
                    break;
                };
                let take = (out.len() - n).min(bytes.len() - *at);
                out[n..n + take].copy_from_slice(&bytes[*at..*at + take]);
                n += take;
                *at += take;
                self.owned_bytes -= take;
                if *at == bytes.len() {
                    queue.pop_front();
                }
            }
            n
        }
    }

    fn held_bytes(&self) -> usize {
        self.owned_bytes + self.session.prototype_received_bytes()
    }
}

fn percentile(values: &mut [u64], pct: usize) -> u64 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    values[((values.len() - 1) * pct) / 100]
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert!(args.len() == 4, "real-tcp owned|pull file pause_ms");
    let pull = match args[1].as_str() {
        "pull" => true,
        "owned" => false,
        _ => panic!("invalid mode"),
    };
    let file = std::fs::read(&args[2]).unwrap();
    assert!(!file.is_empty());
    let pause = Duration::from_millis(args[3].parse().unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client_socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server_socket, _) = listener.accept().unwrap();
    drop(listener);
    let mut client = Wire::new(client_socket, SessionRole::Initiator, pull);
    let mut server = Wire::new(server_socket, SessionRole::Responder, pull);
    let mut wire_scratch = vec![0; CHUNK];
    let mut read_scratch = vec![0; CHUNK];
    let setup = Instant::now();
    while !client.session.is_established() || !server.session.is_established() {
        client.drive(&mut wire_scratch);
        server.drive(&mut wire_scratch);
        assert!(
            setup.elapsed() < Duration::from_secs(5),
            "handshake stalled"
        );
    }
    assert!(client.session.peer().is_some() && server.session.peer().is_some());
    let streams: Vec<_> = (0..3)
        .map(|_| client.session.open_stream().unwrap())
        .collect();
    while server.incoming < 3 {
        client.drive(&mut wire_scratch);
        server.drive(&mut wire_scratch);
        assert!(
            setup.elapsed() < Duration::from_secs(5),
            "stream open stalled"
        );
    }
    let mut sent = [0usize; 2];
    let mut received = [0usize; 2];
    let mut read_runnable = [true; 2];
    let mut rtts = Vec::with_capacity(4096);
    let mut turns = Vec::with_capacity(200_000);
    let mut peak_held = 0;
    let mut peak_wire = 0;
    let mut paused_held = 0;
    let mut fast_done_us = 0;
    let mut seq = 0u64;
    let mut probe_started: Option<Instant> = None;
    let mut probe_tx = [0u8; 8];
    let mut probe_tx_at = 8;
    let mut probe_echo = [0u8; 8];
    let mut echo_received = 0;
    let mut echo_sent = 0;
    let mut probe_reply = [0u8; 8];
    let mut reply_received = 0;
    let mut last_probe = Instant::now();
    let mut blocked_writes = 0;
    let mut turn = 0;
    #[cfg(feature = "alloc-stats")]
    let allocation_region = stats_alloc::Region::new(ALLOC);
    let start = Instant::now();
    loop {
        let tick = Instant::now();
        // Rotate bulk source order; probe traffic gets one opportunity each turn.
        for j in 0..2 {
            let i = (turn + j) % 2;
            if sent[i] < file.len() {
                let end = (sent[i] + CHUNK).min(file.len());
                let n = client.send(streams[i], &file[sent[i]..end], pull);
                sent[i] += n;
                if n == 0 {
                    blocked_writes += 1;
                }
            }
        }
        if received.iter().any(|n| *n < file.len())
            && probe_started.is_none()
            && last_probe.elapsed() >= Duration::from_millis(1)
        {
            seq += 1;
            probe_tx = seq.to_le_bytes();
            probe_tx_at = 0;
            probe_started = Some(Instant::now());
            last_probe = Instant::now();
        }
        if probe_tx_at < 8 {
            probe_tx_at += client.send(streams[2], &probe_tx[probe_tx_at..], pull);
        }
        let mut moved = client.drive(&mut wire_scratch) + server.drive(&mut wire_scratch);
        peak_held = peak_held.max(server.held_bytes());
        peak_wire = peak_wire.max(client.wire_bytes + server.wire_bytes);
        if start.elapsed() < pause {
            paused_held = paused_held.max(server.held_bytes());
        }
        for i in 0..2 {
            if received[i] < file.len() && (i == 0 || start.elapsed() >= pause) {
                moved += server.consume(
                    streams[i],
                    &file,
                    &mut received[i],
                    pull,
                    &mut read_runnable[i],
                    &mut read_scratch,
                );
            }
        }
        if received[0] == file.len() && fast_done_us == 0 {
            fast_done_us = start.elapsed().as_micros() as u64;
        }
        echo_received += server.read_probe(streams[2], &mut probe_echo[echo_received..], pull);
        if echo_received == 8 {
            echo_sent += server.send(streams[2], &probe_echo[echo_sent..], pull);
            if echo_sent == 8 {
                echo_received = 0;
                echo_sent = 0;
            }
        }
        moved += server.drive(&mut wire_scratch) + client.drive(&mut wire_scratch);
        reply_received += client.read_probe(streams[2], &mut probe_reply[reply_received..], pull);
        if reply_received == 8 {
            assert_eq!(probe_reply, probe_tx, "probe changed");
            rtts.push(probe_started.take().unwrap().elapsed().as_micros() as u64);
            reply_received = 0;
        }
        turns.push(tick.elapsed().as_micros() as u64);
        turn += 1;
        if received.iter().all(|n| *n == file.len()) && probe_started.is_none() {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "transfer stalled: sent={sent:?}, received={received:?}"
        );
        if moved == 0 {
            std::thread::sleep(Duration::from_micros(50));
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    #[cfg(feature = "alloc-stats")]
    let (allocations, reallocations, allocated_bytes) = {
        let s = allocation_region.change();
        (s.allocations, s.reallocations, s.bytes_allocated)
    };
    #[cfg(not(feature = "alloc-stats"))]
    let (allocations, reallocations, allocated_bytes) = (0, 0, 0);
    let samples = rtts.len();
    let p50 = percentile(&mut rtts, 50);
    let p99 = percentile(&mut rtts, 99);
    let turn99 = percentile(&mut turns, 99);
    println!(
        "{},{},{},{:.3},{:.3},{},{},{},{},{},{},{},{},{},{},{},{}",
        args[1],
        pause.as_millis(),
        cfg!(feature = "alloc-stats"),
        elapsed * 1000.0,
        (2 * file.len()) as f64 / 1048576.0 / elapsed,
        fast_done_us,
        peak_held,
        paused_held,
        peak_wire,
        samples,
        p50,
        p99,
        turn99,
        allocations,
        reallocations,
        allocated_bytes,
        blocked_writes
    );
}
