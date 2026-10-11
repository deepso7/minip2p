//! One-way throughput: client and server on their own threads, each driving a
//! quinn-proto peer caller-style. Args: [MB] [--quinn-udp] [--retry]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Instant;

use bytes::Bytes;
use minip2p_identity::Ed25519Keypair;
use probe::Waiter;
use probe::peer::{Options, Peer};
use quinn_proto::{Dir, Event, StreamEvent};

const CHUNK: usize = 64 * 1024;

#[global_allocator]
static A: probe::Counting = probe::Counting;

fn main() {
    let base = Instant::now();
    let args: Vec<String> = std::env::args().collect();
    let mb: u64 = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(256);
    let quinn_udp = args.iter().any(|a| a == "--quinn-udp");
    let retry = args.iter().any(|a| a == "--retry");
    let total = mb << 20;

    let server_key = Ed25519Keypair::generate();
    let client_key = Ed25519Keypair::generate();
    let expected_server = server_key.peer_id();
    let expected_client = client_key.peer_id();

    let received = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let (addr_tx, addr_rx) = mpsc::channel();
    let (tok_tx, tok_rx) = mpsc::channel();

    let server = {
        let received = received.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            let mut peer = Peer::new(&server_key, "127.0.0.1:0", Options { quinn_udp, require_address_validation: retry });
            addr_tx.send(peer.local_addr()).unwrap();
            let mut waiter = Waiter::new(&peer.socket);
            let mut stats_peer = None;
            while !stop.load(Ordering::Relaxed) {
                let now = probe::clock(base);
                peer.drive(now);
                while let Some((ch, event)) = peer.events.pop_front() {
                    match event {
                        Event::Connected => {
                            assert_eq!(peer.peer_id(ch), Some(expected_client.clone()));
                            tok_tx.send(peer.connection_token(ch)).unwrap();
                        }
                        Event::Stream(StreamEvent::Opened { dir: Dir::Bi }) => {
                            // A new stream's first frame raises only Opened: scan it now.
                            while let Some(id) = peer.conn(ch).streams().accept(Dir::Bi) {
                                peer.events.push_back((ch, Event::Stream(StreamEvent::Readable { id })));
                            }
                        }
                        Event::Stream(StreamEvent::Readable { id }) => {
                            let conn = peer.conn(ch);
                            let mut stream = conn.recv_stream(id);
                            let Ok(mut chunks) = stream.read(true) else { continue };
                            let mut n = 0;
                            while let Ok(Some(chunk)) = chunks.next(usize::MAX) {
                                n += chunk.bytes.len() as u64;
                            }
                            let _ = chunks.finalize();
                            received.fetch_add(n, Ordering::Relaxed);
                            peer.kick(ch, now);
                        }
                        _ => {}
                    }
                }
                stats_peer = Some(peer.stats);
                let deadline = peer.next_timeout();
                waiter.wait(deadline);
            }
            stats_peer
        })
    };

    let server_addr = addr_rx.recv().unwrap();
    let mut peer = Peer::new(&client_key, "127.0.0.1:0", Options { quinn_udp, require_address_validation: false });
    let mut waiter = Waiter::new(&peer.socket);
    let t_hs = Instant::now();
    let ch = peer.connect(probe::clock(base), server_addr);
    let chunk = Bytes::from(vec![0xAB; CHUNK]);
    let mut stream = None;
    let mut written = 0u64;
    let mut pending: Option<Bytes> = None;
    let mut started = None;
    let mut finished = false;
    loop {
        let now = probe::clock(base);
        peer.drive(now);
        while let Some((_, event)) = peer.events.pop_front() {
            match event {
                Event::Connected => {
                    println!("handshake: {:?}", t_hs.elapsed());
                    assert_eq!(peer.peer_id(ch), Some(expected_server.clone()));
                    let token = peer.connection_token(ch);
                    assert_eq!(Some(token), tok_rx.recv().ok(), "tokens agree");
                    stream = peer.conn(ch).streams().open(Dir::Bi);
                    started = Some(Instant::now());
                    probe::ALLOCS.store(0, Ordering::Relaxed);
                }
                Event::ConnectionLost { reason } => panic!("lost: {reason}"),
                _ => {}
            }
        }
        if let Some(id) = stream {
            let mut progressed = false;
            while written < total {
                let mut data = [pending.take().unwrap_or_else(|| chunk.clone())];
                match peer.conn(ch).send_stream(id).write_chunks(&mut data) {
                    Ok(w) => {
                        written += w.bytes as u64;
                        progressed |= w.bytes > 0;
                        if !data[0].is_empty() {
                            pending = Some(data[0].clone());
                            break;
                        }
                    }
                    Err(quinn_proto::WriteError::Blocked) => {
                        pending = Some(data[0].clone());
                        break;
                    }
                    Err(e) => panic!("write: {e}"),
                }
            }
            if written >= total && !finished {
                peer.conn(ch).send_stream(id).finish().unwrap();
                finished = true;
                progressed = true;
            }
            if progressed {
                peer.kick(ch, now);
            }
        }
        if received.load(Ordering::Relaxed) >= total {
            break;
        }
        let deadline = peer.next_timeout();
        waiter.wait(deadline);
    }
    let elapsed = started.unwrap().elapsed();
    println!("allocs/MB: {:.0}", probe::ALLOCS.load(Ordering::Relaxed) as f64 / mb as f64);
    stop.store(true, Ordering::Relaxed);
    let server_stats = server.join().unwrap();
    let mbps = total as f64 / (1 << 20) as f64 / elapsed.as_secs_f64();
    println!(
        "quinn-proto{}{}: {mb} MB in {:?} = {:.1} MB/s",
        if quinn_udp { "+quinn-udp" } else { "+std-udp" },
        if retry { "+retry" } else { "" },
        elapsed,
        mbps
    );
    println!("client stats: {:?}", peer.stats);
    println!("server stats: {:?}", server_stats);
    println!("client conn stats: {:?}", peer.conn(ch).stats().path);
}
