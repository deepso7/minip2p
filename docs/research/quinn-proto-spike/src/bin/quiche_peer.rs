//! Today's quiche QuicTransport as an interop peer.
//! `quiche_peer listen` | `quiche_peer dial <multiaddr-with-p2p>`
use std::time::{Duration, Instant};

use minip2p_core::PeerAddr;
use minip2p_platform::Now;
use minip2p_quic::{QuicNodeConfig, QuicTransport};
use minip2p_transport::{BlockingTransport, Transport, TransportEvent};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let base = Instant::now();
    let mut t = QuicTransport::new(QuicNodeConfig::generate(), "127.0.0.1:0").unwrap();
    match args.get(1).map(String::as_str) {
        Some("listen") => {
            t.listen_on_bound_addr().unwrap();
            println!("LISTEN {}", t.local_peer_addr().unwrap());
        }
        Some("dial") => {
            let addr: PeerAddr = args[2].parse().expect("peer addr");
            t.dial(&addr).unwrap();
        }
        _ => panic!("usage"),
    }
    let mut ok = false;
    while base.elapsed() < Duration::from_secs(8) {
        for ev in t.poll(Now::from_millis(base.elapsed().as_millis() as u64)).unwrap() {
            match ev {
                TransportEvent::Connected { endpoint, .. } => {
                    println!("CONNECTED remote={:?} token={:?}", endpoint.peer_id().map(|p| p.to_string()), endpoint.token());
                    ok = true;
                }
                TransportEvent::Error { message, .. } => println!("ERROR {message}"),
                TransportEvent::Closed { .. } => println!("CLOSED"),
                _ => {}
            }
        }
        let _ = t.wait_for_input(Duration::from_millis(20));
    }
    println!("RESULT {}", if ok { "ok" } else { "fail" });
}
