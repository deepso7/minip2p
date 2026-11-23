//! A listener that runs out of file descriptors recovers on its own timer.
//!
//! Its own test binary, because lowering `RLIMIT_NOFILE` affects the whole
//! process.

#![cfg(all(feature = "std", unix))]

use minip2p_core::platform::{Deadline, Now, StdEntropy};
use minip2p_identity::Ed25519Keypair;
use minip2p_tcp::{StdTcpProvider, TcpTransport};
use minip2p_transport::{Transport, TransportError, TransportEvent};
use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

/// Holds the descriptor limit at zero until dropped.
struct NoDescriptors(Rlimit);

impl NoDescriptors {
    fn new() -> Self {
        let original = getrlimit(Resource::Nofile);
        setrlimit(
            Resource::Nofile,
            Rlimit {
                current: Some(0),
                maximum: original.maximum,
            },
        )
        .expect("lower the descriptor limit");
        Self(original)
    }
}

impl Drop for NoDescriptors {
    fn drop(&mut self) {
        setrlimit(Resource::Nofile, self.0).expect("restore the descriptor limit");
    }
}

#[test]
fn an_exhausted_listener_retries_on_a_timer_and_drains_its_backlog() {
    let mut transport = TcpTransport::new(
        StdTcpProvider::new(),
        Ed25519Keypair::from_secret_key_bytes([7; 32]),
        StdEntropy,
    );
    let bound = transport
        .listen(&"/ip4/127.0.0.1/tcp/0".parse().expect("address"))
        .expect("listen");
    transport
        .poll(Now::from_millis(0))
        .expect("drain Listening");
    let target = bound.to_string().replace("/ip4/", "").replace("/tcp/", ":");
    let _peers: Vec<_> = (0..3)
        .map(|_| std::net::TcpStream::connect(&target).expect("peer connects"))
        .collect();

    let exhausted = NoDescriptors::new();
    let events = transport.poll(Now::from_millis(0)).expect("poll");
    assert!(
        matches!(
            events.as_slice(),
            [TransportEvent::ListenerError { addr, error }]
                if *addr == bound
                    && matches!(**error, TransportError::Io { operation: "accepting a connection", .. })
        ),
        "{events:?}"
    );
    assert_eq!(
        transport.next_deadline(),
        Some(Deadline::from_millis(100)),
        "the backlog raises no further edge, so a retry is scheduled"
    );

    let events = transport.poll(Now::from_millis(50)).expect("poll");
    assert!(events.is_empty(), "a repeat is not reported: {events:?}");
    drop(exhausted);

    let retry = transport.next_deadline().expect("a retry is owed");
    let events = transport
        .poll(Now::from_millis(retry.as_millis()))
        .expect("poll");
    let accepted = events
        .iter()
        .filter(|event| matches!(event, TransportEvent::IncomingConnection { .. }))
        .count();
    let recovered: Vec<_> = events
        .iter()
        .filter(|event| matches!(event, TransportEvent::ListenerRecovered { .. }))
        .collect();
    assert_eq!(accepted, 3, "the queued peers are accepted: {events:?}");
    assert_eq!(
        recovered,
        [&TransportEvent::ListenerRecovered { addr: bound }],
        "{events:?}"
    );
}
