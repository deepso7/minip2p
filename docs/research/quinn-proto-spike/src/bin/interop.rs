//! quinn-proto spike peer for interop with other libp2p QUIC stacks.
//! `interop dial <ip:port> <peer-id>` | `interop listen`
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use minip2p_identity::Ed25519Keypair;
use probe::Waiter;
use probe::peer::{Options, Peer};
use quinn_proto::Event;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let key = Ed25519Keypair::generate();
    let mut peer = Peer::new(&key, "127.0.0.1:0", Options { quinn_udp: true, require_address_validation: true });
    let mut waiter = Waiter::new(&peer.socket);
    let mut expected = None;
    match args.get(1).map(String::as_str) {
        Some("dial") => {
            let addr: SocketAddr = args[2].parse().unwrap();
            expected = Some(args[3].clone());
            peer.connect(Instant::now(), addr);
        }
        Some("listen") => {
            let a = peer.local_addr();
            println!("LISTEN /ip4/{}/udp/{}/quic-v1/p2p/{}", a.ip(), a.port(), key.peer_id());
        }
        _ => panic!("usage"),
    }
    let end = Instant::now() + Duration::from_secs(8);
    let mut ok = false;
    while Instant::now() < end {
        peer.drive(Instant::now());
        while let Some((ch, ev)) = peer.events.pop_front() {
            match ev {
                Event::Connected => {
                    let id = peer.peer_id(ch).map(|p| p.to_string());
                    println!("CONNECTED remote={id:?}");
                    if let Some(e) = &expected {
                        assert_eq!(id.as_deref(), Some(e.as_str()), "peer id");
                    }
                    ok = true;
                }
                Event::ConnectionLost { reason } => println!("LOST {reason}"),
                Event::Stream(s) => println!("STREAM {s:?}"),
                _ => {}
            }
        }
        let d = peer.next_timeout();
        waiter.wait(d);
    }
    println!("RESULT {}", if ok { "ok" } else { "fail" });
}
