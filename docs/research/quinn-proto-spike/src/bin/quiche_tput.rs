//! Same harness as quinn_tput, over today's quiche-based minip2p QuicTransport.
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use minip2p_core::PeerAddr;
use minip2p_identity::Ed25519Keypair;
use minip2p_platform::Now;
use minip2p_quic::{QuicNodeConfig, QuicTransport};
use minip2p_transport::{BlockingTransport, Bytes, Transport, TransportError, TransportEvent};

const CHUNK: usize = 64 * 1024;

fn now(base: Instant) -> Now {
    Now::from_millis(base.elapsed().as_millis() as u64)
}

fn wait(t: &mut QuicTransport, base: Instant) {
    let timeout = t
        .next_deadline()
        .map(|d| Duration::from_millis(d.as_millis().saturating_sub(base.elapsed().as_millis() as u64)))
        .unwrap_or(Duration::from_millis(50))
        .min(Duration::from_millis(50));
    if !timeout.is_zero() {
        let _ = t.wait_for_input(timeout);
    }
}

#[global_allocator]
static A: probe::Counting = probe::Counting;

fn main() {
    let mb: u64 = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(256);
    let total = mb << 20;
    let base = Instant::now();
    let server_key = Ed25519Keypair::generate();
    let received = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let (addr_tx, addr_rx) = mpsc::channel();

    let server = {
        let (received, stop) = (received.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut t = QuicTransport::new(QuicNodeConfig::new(server_key), "127.0.0.1:0").unwrap();
            addr_tx.send(t.local_peer_addr().unwrap()).unwrap();
            t.listen_on_bound_addr().unwrap();
            while !stop.load(Ordering::Relaxed) {
                for ev in t.poll(now(base)).unwrap() {
                    if let TransportEvent::StreamData { id, stream_id, data } = ev {
                        received.fetch_add(data.len() as u64, Ordering::Relaxed);
                        t.ack_stream(id, stream_id, data.len()).unwrap();
                    }
                }
                wait(&mut t, base);
            }
        })
    };

    let addr: PeerAddr = addr_rx.recv().unwrap();
    let mut t = QuicTransport::new(QuicNodeConfig::generate(), "127.0.0.1:0").unwrap();
    let t_hs = Instant::now();
    let conn = t.dial(&addr).unwrap();
    let chunk = Bytes::from(vec![0xAB; CHUNK]);
    let (mut stream, mut written, mut pending, mut started, mut blocked) = (None, 0u64, None::<Bytes>, None, false);
    loop {
        for ev in t.poll(now(base)).unwrap() {
            match ev {
                TransportEvent::Connected { .. } => {
                    println!("handshake: {:?}", t_hs.elapsed());
                    stream = Some(t.open_stream(conn).unwrap());
                    started = Some(Instant::now());
                    probe::ALLOCS.store(0, Ordering::Relaxed);
                }
                TransportEvent::StreamWritable { .. } => blocked = false,
                _ => {}
            }
        }
        if let Some(s) = stream {
            while written < total && !blocked {
                let data = pending.take().unwrap_or_else(|| chunk.clone());
                let len = data.len() as u64;
                match t.send_stream(conn, s, data) {
                    Ok(()) => written += len,
                    Err(TransportError::Full { unsent, .. }) => {
                        written += len - unsent.len() as u64;
                        pending = Some(unsent);
                        blocked = true;
                    }
                    Err(e) => panic!("{e}"),
                }
            }
        }
        if received.load(Ordering::Relaxed) >= total {
            break;
        }
        wait(&mut t, base);
    }
    let elapsed = started.unwrap().elapsed();
    println!("allocs/MB: {:.0}", probe::ALLOCS.load(Ordering::Relaxed) as f64 / mb as f64);
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();
    println!(
        "quiche (minip2p QuicTransport): {mb} MB in {elapsed:?} = {:.1} MB/s",
        total as f64 / (1 << 20) as f64 / elapsed.as_secs_f64()
    );
}
