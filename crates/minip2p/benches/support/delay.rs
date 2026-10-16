//! A userspace emulated link for the Endpoint benches: loopback proxies that
//! cap the rate and add delay, so a bench measures flow control at a real
//! RTT without `tc netem` (Fargate grants no `NET_ADMIN`).
//!
//! Each direction of a link is shaped on its own: a packet (UDP) or read
//! (TCP) waits in an unbounded FIFO until the link is free, takes
//! `len × 8 / rate` to serialize, then arrives `rtt / 2` later. Nothing is
//! ever dropped and there is no burst allowance: the benches tune
//! flow-control windows, not congestion control, so loss and bufferbloat are
//! out of scope. Rates count UDP payload or TCP stream bytes, without IP or
//! transport headers.
//!
//! [`UdpProxy`] forwards QUIC datagrams between one client and one target.
//! [`TcpProxy`] terminates TCP on both sides and forwards the byte stream,
//! so kernel TCP (ACK timing, congestion window, buffering) only sees two
//! loopback legs: over it a bench measures Yamux credit at the RTT, not TCP
//! itself, and its numbers make no claim about TCP over a real WAN.
//!
//! The proxies' threads and buffers live in the bench process, so their
//! allocations show up in process-wide allocation counters.

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc,
};
use std::thread;
use std::time::{Duration, Instant};

/// How often a blocked proxy thread checks whether it should stop.
const POLL: Duration = Duration::from_millis(20);
/// Largest UDP datagram a proxy forwards.
const MAX_DATAGRAM: usize = 65_535;
/// Bytes a TCP proxy reads at a time, each read shaped as one unit.
const TCP_READ: usize = 16 * 1024;
/// Receive buffer a proxy asks for on each socket, so a burst the forwarding
/// thread has not read yet is not dropped by the kernel.
const SOCKET_BUFFER: usize = 8 * 1024 * 1024;

/// A link's rate, in bits per second each way, and round-trip delay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    pub rate_bits_per_s: u64,
    pub rtt: Duration,
}

impl Profile {
    /// The profile the window defaults are tuned against (#361).
    pub const M100_100MS: Self = Self {
        rate_bits_per_s: 100_000_000,
        rtt: Duration::from_millis(100),
    };
    /// A fat, short path, recorded to show what the defaults give up there.
    pub const G1_20MS: Self = Self {
        rate_bits_per_s: 1_000_000_000,
        rtt: Duration::from_millis(20),
    };

    /// The profile's name: the rate in Mbit/s (`m`) or Gbit/s (`g`) and the
    /// RTT in ms, such as `100m_100ms` or `1g_20ms`.
    pub fn name(&self) -> String {
        let rate = if self.rate_bits_per_s.is_multiple_of(1_000_000_000) {
            format!("{}g", self.rate_bits_per_s / 1_000_000_000)
        } else {
            format!("{}m", self.rate_bits_per_s / 1_000_000)
        };
        format!("{rate}_{}ms", self.rtt.as_millis())
    }

    /// Parses a [`name`](Self::name), so any rate and RTT can be measured.
    pub fn named(name: &str) -> Option<Self> {
        let (rate, rtt) = name.split_once('_')?;
        let rtt_ms: u64 = rtt.strip_suffix("ms")?.parse().ok()?;
        let rate_bits_per_s = if let Some(gbit) = rate.strip_suffix('g') {
            gbit.parse::<u64>().ok()?.checked_mul(1_000_000_000)?
        } else {
            rate.strip_suffix('m')?
                .parse::<u64>()
                .ok()?
                .checked_mul(1_000_000)?
        };
        (rate_bits_per_s > 0 && rtt_ms > 0).then(|| Self {
            rate_bits_per_s,
            rtt: Duration::from_millis(rtt_ms),
        })
    }

    /// The link rate in bytes per second.
    pub fn bytes_per_s(&self) -> f64 {
        self.rate_bits_per_s as f64 / 8.0
    }

    /// The bandwidth-delay product: bytes in flight that keep the link busy.
    pub fn bdp_bytes(&self) -> u64 {
        u64::try_from(u128::from(self.rate_bits_per_s) * self.rtt.as_micros() / 8_000_000)
            .expect("BDP fits u64")
    }

    fn one_way(&self) -> Duration {
        self.rtt / 2
    }

    fn serialization(&self, len: usize) -> Duration {
        Duration::from_nanos((len as u64 * 8).saturating_mul(1_000_000_000) / self.rate_bits_per_s)
    }
}

/// Counters for one direction of a link.
#[derive(Debug, Default)]
pub struct LinkStats {
    /// Packets (UDP) or reads (TCP) forwarded.
    pub units: AtomicU64,
    /// Bytes forwarded.
    pub bytes: AtomicU64,
    held: AtomicU64,
    /// Most bytes held at once, queued or on the wire.
    pub held_high_water: AtomicU64,
    /// Longest time a unit waited in the FIFO before it started serializing,
    /// in microseconds: queueing delay on top of the base RTT.
    pub max_queue_delay_us: AtomicU64,
    /// CPU time the direction's reader and writer threads have used so far,
    /// in microseconds; not reset, so a caller takes differences.
    pub reader_cpu_us: AtomicU64,
    pub writer_cpu_us: AtomicU64,
}

impl LinkStats {
    /// Resets the traffic counters, for example between a warm-up and a timed
    /// pass.
    pub fn reset(&self) {
        for counter in [
            &self.units,
            &self.bytes,
            &self.held_high_water,
            &self.max_queue_delay_us,
        ] {
            counter.store(0, Ordering::Relaxed);
        }
        self.held_high_water
            .store(self.held.load(Ordering::Relaxed), Ordering::Relaxed);
    }
}

/// The departure schedule of one direction.
struct Shaper {
    profile: Profile,
    free_at: Instant,
    stats: Arc<LinkStats>,
}

impl Shaper {
    fn new(profile: Profile, stats: Arc<LinkStats>) -> Self {
        Self {
            profile,
            free_at: Instant::now(),
            stats,
        }
    }

    /// Queues `len` bytes that arrived `now` and returns when they reach the
    /// far end.
    fn admit(&mut self, now: Instant, len: usize) -> Instant {
        let start = self.free_at.max(now);
        self.free_at = start + self.profile.serialization(len);
        let waited = (start - now).as_micros() as u64;
        self.stats
            .max_queue_delay_us
            .fetch_max(waited, Ordering::Relaxed);
        let held = self.stats.held.fetch_add(len as u64, Ordering::Relaxed) + len as u64;
        self.stats
            .held_high_water
            .fetch_max(held, Ordering::Relaxed);
        self.stats
            .reader_cpu_us
            .store(thread_cpu_us(), Ordering::Relaxed);
        self.free_at + self.profile.one_way()
    }
}

/// Delivers each unit from `units` at its due time through `deliver`; ends
/// when the sender side hangs up or `deliver` fails.
fn deliver_loop(
    units: mpsc::Receiver<(Instant, Vec<u8>)>,
    stats: Arc<LinkStats>,
    mut deliver: impl FnMut(&[u8]) -> std::io::Result<()>,
) {
    for (due, unit) in units {
        let now = Instant::now();
        if due > now {
            thread::sleep(due - now);
        }
        stats.held.fetch_sub(unit.len() as u64, Ordering::Relaxed);
        if deliver(&unit).is_err() {
            return;
        }
        stats.units.fetch_add(1, Ordering::Relaxed);
        stats.bytes.fetch_add(unit.len() as u64, Ordering::Relaxed);
        stats
            .writer_cpu_us
            .store(thread_cpu_us(), Ordering::Relaxed);
    }
}

/// CPU time the calling thread has used, in microseconds.
fn thread_cpu_us() -> u64 {
    u64::try_from(cpu_time::ThreadTime::now().as_duration().as_micros()).unwrap_or(u64::MAX)
}

/// Threads a proxy owns; stopped and joined on drop.
struct Threads {
    stop: Arc<AtomicBool>,
    handles: Vec<thread::JoinHandle<()>>,
}

impl Drop for Threads {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for handle in self.handles.drain(..) {
            // A forwarding thread panicking is a bench bug; surface it.
            if let Err(payload) = handle.join()
                && !thread::panicking()
            {
                std::panic::resume_unwind(payload);
            }
        }
    }
}

fn grow_receive_buffer(socket: impl Into<socket2::Socket>) -> socket2::Socket {
    let socket = socket.into();
    // Best effort: the host may cap it, which calibration then shows as loss.
    if let Err(error) = socket.set_recv_buffer_size(SOCKET_BUFFER) {
        eprintln!("proxy receive buffer stays at the default: {error}");
    }
    if let Err(error) = socket.set_send_buffer_size(SOCKET_BUFFER) {
        eprintln!("proxy send buffer stays at the default: {error}");
    }
    socket
}

/// Forwards UDP datagrams between the first client that sends to
/// [`addr`](Self::addr) and a fixed target, shaping each direction.
pub struct UdpProxy {
    /// Where the client sends; the target sees the proxy's other socket.
    pub addr: SocketAddr,
    /// Client to target.
    pub up: Arc<LinkStats>,
    /// Target to client.
    pub down: Arc<LinkStats>,
    _threads: Threads,
}

impl UdpProxy {
    pub fn spawn(target: SocketAddr, profile: Profile) -> Self {
        let bind = |_| -> UdpSocket {
            let socket = UdpSocket::bind("127.0.0.1:0").expect("bind proxy socket");
            let socket: UdpSocket = grow_receive_buffer(socket).into();
            socket.set_read_timeout(Some(POLL)).expect("read timeout");
            socket
        };
        let (front, back) = (bind(()), bind(()));
        let addr = front.local_addr().expect("proxy address");
        let client = Arc::new(Mutex::new(None::<SocketAddr>));
        let stop = Arc::new(AtomicBool::new(false));
        let (up, down) = (Arc::default(), Arc::default());

        let mut handles = Vec::new();
        for (from, to, stats, upward) in [
            (&front, &back, Arc::clone(&up), true),
            (&back, &front, Arc::clone(&down), false),
        ] {
            let (tx, rx) = mpsc::channel();
            let from = from.try_clone().expect("clone proxy socket");
            let to = to.try_clone().expect("clone proxy socket");
            let (reader_stop, seen, read_stats) =
                (Arc::clone(&stop), Arc::clone(&client), Arc::clone(&stats));
            handles.push(thread::spawn(move || {
                let mut shaper = Shaper::new(profile, read_stats);
                let mut buf = vec![0; MAX_DATAGRAM];
                while !reader_stop.load(Ordering::Relaxed) {
                    let (len, source) = match from.recv_from(&mut buf) {
                        Ok(received) => received,
                        Err(error)
                            if matches!(
                                error.kind(),
                                ErrorKind::WouldBlock | ErrorKind::TimedOut
                            ) =>
                        {
                            continue;
                        }
                        Err(error) => {
                            // The bench then times out on the stalled link.
                            eprintln!("proxy receive failed: {error}");
                            return;
                        }
                    };
                    if upward {
                        seen.lock().expect("client lock").get_or_insert(source);
                    } else if source != target {
                        continue;
                    }
                    let due = shaper.admit(Instant::now(), len);
                    if tx
                        .send((due, buf.get(..len).expect("read fits the buffer").to_vec()))
                        .is_err()
                    {
                        return;
                    }
                }
            }));
            let client = Arc::clone(&client);
            handles.push(thread::spawn(move || {
                deliver_loop(rx, stats, |datagram| {
                    let destination = if upward {
                        target
                    } else {
                        client.lock().expect("client lock").expect("client known")
                    };
                    // A refused send (nothing listening yet) is loss the
                    // bench's calibration reports, not a reason to stop.
                    drop(to.send_to(datagram, destination));
                    Ok(())
                });
            }));
        }
        Self {
            addr,
            up,
            down,
            _threads: Threads { stop, handles },
        }
    }
}

/// Accepts one TCP connection on [`addr`](Self::addr), connects it to a
/// fixed target, and forwards the byte stream both ways, shaping each
/// direction. See the module docs for what this does not emulate.
pub struct TcpProxy {
    pub addr: SocketAddr,
    /// Client to target.
    pub up: Arc<LinkStats>,
    /// Target to client.
    pub down: Arc<LinkStats>,
    _threads: Threads,
}

impl TcpProxy {
    pub fn spawn(target: SocketAddr, profile: Profile) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let addr = listener.local_addr().expect("proxy address");
        let stop = Arc::new(AtomicBool::new(false));
        let (up, down) = (Arc::<LinkStats>::default(), Arc::<LinkStats>::default());
        let (accept_stop, accept_up, accept_down) =
            (Arc::clone(&stop), Arc::clone(&up), Arc::clone(&down));
        let accept = thread::spawn(move || {
            let client = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        if accept_stop.load(Ordering::Relaxed) {
                            return;
                        }
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => {
                        eprintln!("proxy accept failed: {error}");
                        return;
                    }
                }
            };
            client.set_nonblocking(false).expect("blocking client leg");
            let server = TcpStream::connect(target).expect("proxy connects to target");
            let mut pipes = Vec::new();
            for (from, to, stats) in [
                (&client, &server, accept_up),
                (&server, &client, accept_down),
            ] {
                let from = from.try_clone().expect("clone proxy stream");
                let to = to.try_clone().expect("clone proxy stream");
                pipes.extend(tcp_pipe(from, to, profile, stats, Arc::clone(&accept_stop)));
            }
            for pipe in pipes {
                pipe.join().expect("proxy pipe");
            }
        });
        Self {
            addr,
            up,
            down,
            _threads: Threads {
                stop,
                handles: vec![accept],
            },
        }
    }
}

/// The reader and writer threads of one TCP direction.
fn tcp_pipe(
    mut from: TcpStream,
    mut to: TcpStream,
    profile: Profile,
    stats: Arc<LinkStats>,
    stop: Arc<AtomicBool>,
) -> [thread::JoinHandle<()>; 2] {
    for stream in [&from, &to] {
        stream.set_nodelay(true).expect("nodelay");
    }
    from.set_read_timeout(Some(POLL)).expect("read timeout");
    // A far end that stopped reading must not keep a drop waiting forever.
    to.set_write_timeout(Some(Duration::from_secs(10)))
        .expect("write timeout");
    let (tx, rx) = mpsc::channel();
    let read_stats = Arc::clone(&stats);
    let reader = thread::spawn(move || {
        let mut shaper = Shaper::new(profile, read_stats);
        let mut buf = vec![0; TCP_READ];
        while !stop.load(Ordering::Relaxed) {
            match from.read(&mut buf) {
                Ok(0) => return,
                Ok(len) => {
                    let due = shaper.admit(Instant::now(), len);
                    if tx
                        .send((due, buf.get(..len).expect("read fits the buffer").to_vec()))
                        .is_err()
                    {
                        return;
                    }
                }
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(_) => return,
            }
        }
    });
    let writer = thread::spawn(move || {
        deliver_loop(rx, stats, |bytes| to.write_all(bytes));
        // Pass the end of the stream on once everything before it arrived.
        drop(to.shutdown(Shutdown::Write));
    });
    [reader, writer]
}
