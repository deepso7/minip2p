//! Raw quiche (no minip2p adapter) throughput, optionally with quinn-udp
//! GSO/GRO underneath: consecutive same-size packets to one destination are
//! sent as one GSO train. Args: [MB] [--gso]
use std::collections::HashMap;
use std::io::IoSliceMut;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Instant;

use boring::pkey::PKey;
use boring::ssl::{SslContextBuilder, SslMethod, SslVerifyMode};
use boring::x509::X509;
use minip2p_identity::Ed25519Keypair;
use probe::Waiter;

const MAX_PAYLOAD: usize = 1350;

fn config(key: &Ed25519Keypair) -> quiche::Config {
    let mut b = SslContextBuilder::new(SslMethod::tls()).unwrap();
    b.set_verify_callback(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT, |_, _| true);
    let (c, k) = minip2p_tls::generate_certificate(key).unwrap();
    b.set_certificate(&X509::from_der(&c).unwrap()).unwrap();
    b.set_private_key(&PKey::private_key_from_der(&k).unwrap()).unwrap();
    let mut cfg = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, b).unwrap();
    cfg.set_application_protos(&[b"libp2p"]).unwrap();
    cfg.set_initial_max_data(10_000_000);
    cfg.set_initial_max_stream_data_bidi_local(1_000_000);
    cfg.set_initial_max_stream_data_bidi_remote(1_000_000);
    cfg.set_max_stream_window(1_000_000);
    cfg.set_max_connection_window(10_000_000);
    cfg.set_initial_max_streams_bidi(256);
    cfg.set_max_idle_timeout(30_000);
    cfg.set_max_recv_udp_payload_size(MAX_PAYLOAD);
    cfg.set_max_send_udp_payload_size(MAX_PAYLOAD);
    cfg
}

struct Io {
    socket: UdpSocket,
    udp: Option<quinn_udp::UdpSocketState>,
    out: Vec<u8>,
    recv: Vec<u8>,
}

impl Io {
    fn new(gso: bool) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let udp = gso.then(|| quinn_udp::UdpSocketState::new((&socket).into()).unwrap());
        Self { socket, udp, out: vec![0; 64 * 1024], recv: vec![0; 64 * 1024] }
    }

    /// Drains quiche into the socket, batching same-size packets into GSO trains.
    fn flush(&mut self, conn: &mut quiche::Connection) {
        let max_segs = self.udp.as_ref().map_or(1, |u| u.max_gso_segments().min(10));
        loop {
            let mut len = 0;
            let mut seg = 0;
            let mut dest = None;
            while len / MAX_PAYLOAD.max(1) < max_segs && len + MAX_PAYLOAD <= self.out.len() {
                match conn.send(&mut self.out[len..len + MAX_PAYLOAD]) {
                    Ok((n, info)) => {
                        dest = Some(info.to);
                        if seg == 0 { seg = n }
                        len += n;
                        if n != seg { break } // a short packet ends the train
                    }
                    Err(quiche::Error::Done) => break,
                    Err(e) => panic!("send: {e}"),
                }
                if max_segs == 1 { break }
            }
            let Some(dest) = dest else { return };
            self.send(len, seg, dest);
        }
    }

    fn send(&mut self, len: usize, seg: usize, dest: SocketAddr) {
        loop {
            let r = match &self.udp {
                Some(u) => u.try_send((&self.socket).into(), &quinn_udp::Transmit {
                    destination: dest, ecn: None, contents: &self.out[..len],
                    segment_size: (len > seg).then_some(seg), src_ip: None,
                }),
                None => self.socket.send_to(&self.out[..len], dest).map(|_| ()),
            };
            match r {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::yield_now(),
                _ => return,
            }
        }
    }

    /// Receives a bounded batch, feeding each datagram to `on`.
    /// Returns true if the batch cap was hit (input may still be queued).
    fn recv(&mut self, mut on: impl FnMut(&mut [u8], SocketAddr, SocketAddr)) -> bool {
        let local = self.socket.local_addr().unwrap();
        for _ in 0..128 {
            let (len, from, stride) = match &self.udp {
                Some(u) => {
                    let mut meta = [quinn_udp::RecvMeta::default()];
                    let mut bufs = [IoSliceMut::new(&mut self.recv)];
                    match u.recv((&self.socket).into(), &mut bufs, &mut meta) {
                        Ok(_) => (meta[0].len, meta[0].addr, meta[0].stride),
                        Err(_) => return false,
                    }
                }
                None => match self.socket.recv_from(&mut self.recv) {
                    Ok((n, f)) => (n, f, n),
                    Err(_) => return false,
                },
            };
            for chunk in self.recv[..len].chunks_mut(stride) {
                on(chunk, from, local);
            }
        }
        true
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mb: u64 = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(256);
    let gso = args.iter().any(|a| a == "--gso");
    let total = mb << 20;
    let received = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();

    let server = {
        let (received, stop) = (received.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut cfg = config(&Ed25519Keypair::generate());
            let mut io = Io::new(gso);
            tx.send(io.socket.local_addr().unwrap()).unwrap();
            let mut waiter = Waiter::new(&io.socket);
            let mut conns: HashMap<SocketAddr, quiche::Connection> = HashMap::new();
            let mut buf = vec![0u8; 65535];
            while !stop.load(Ordering::Relaxed) {
                let saturated = io.recv(|pkt, from, local| {
                    let conn = conns.entry(from).or_insert_with(|| {
                        let hdr = quiche::Header::from_slice(pkt, quiche::MAX_CONN_ID_LEN).unwrap();
                        let scid = quiche::ConnectionId::from_vec(vec![9; 16]);
                        let _ = hdr;
                        quiche::accept(&scid, None, local, from, &mut cfg).unwrap()
                    });
                    let _ = conn.recv(pkt, quiche::RecvInfo { from, to: local });
                });
                let mut timeout = None;
                for conn in conns.values_mut() {
                    if conn.timeout().is_some_and(|t| t.is_zero()) { conn.on_timeout() }
                    for s in conn.readable() {
                        while let Ok((n, _)) = conn.stream_recv(s, &mut buf) {
                            received.fetch_add(n as u64, Ordering::Relaxed);
                        }
                    }
                    io.flush(conn);
                    timeout = conn.timeout();
                }
                if !saturated { waiter.wait(timeout.map(|t| Instant::now() + t)); }
            }
        })
    };

    let server_addr = rx.recv().unwrap();
    let mut cfg = config(&Ed25519Keypair::generate());
    let mut io = Io::new(gso);
    let mut waiter = Waiter::new(&io.socket);
    let local = io.socket.local_addr().unwrap();
    let scid = quiche::ConnectionId::from_vec(vec![7; 16]);
    let mut conn = quiche::connect(None, &scid, local, server_addr, &mut cfg).unwrap();
    let chunk = vec![0xABu8; 64 * 1024];
    let (mut written, mut off, mut started) = (0u64, 0usize, None);
    loop {
        let saturated = io.recv(|pkt, from, to| { let _ = conn.recv(pkt, quiche::RecvInfo { from, to }); });
        if conn.timeout().is_some_and(|t| t.is_zero()) { conn.on_timeout() }
        if conn.is_established() {
            started.get_or_insert_with(Instant::now);
            while written < total {
                match conn.stream_send(0, &chunk[off..], false) {
                    Ok(n) => { written += n as u64; off = (off + n) % chunk.len(); if n == 0 { break } }
                    Err(quiche::Error::Done) => break,
                    Err(e) => panic!("{e}"),
                }
            }
        }
        io.flush(&mut conn);
        if received.load(Ordering::Relaxed) >= total { break }
        if !saturated { waiter.wait(conn.timeout().map(|t| Instant::now() + t)); }
    }
    let elapsed = started.unwrap().elapsed();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();
    println!("raw quiche{}: {mb} MB in {elapsed:?} = {:.1} MB/s", if gso { "+quinn-udp GSO/GRO" } else { "+std-udp" },
        total as f64 / (1 << 20) as f64 / elapsed.as_secs_f64());
}
