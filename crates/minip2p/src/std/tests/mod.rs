//! The std endpoint's unit tests: binding, routing, the blocking wait,
//! and close.

use super::builder::*;
use super::*;
#[cfg(feature = "discovery")]
use crate::BeaconConfig;
#[cfg(feature = "relay")]
use crate::CircuitLimits;
use crate::ConnectionCloseReason;
#[cfg(feature = "discovery")]
use crate::GossipsubError;
#[cfg(feature = "pubsub")]
use crate::GossipsubEvent;
#[cfg(feature = "mdns")]
use crate::MdnsConfig;
#[cfg(feature = "relay")]
use crate::NatEvent;
#[cfg(feature = "mdns")]
use crate::PeerDiscoveryConfig;
#[cfg(feature = "relay")]
use crate::ReachabilityState;
#[cfg(all(feature = "relay-server", feature = "quic"))]
use crate::RelayMeshConfig;
use crate::SwarmEvent;
#[cfg(feature = "tcp")]
use crate::TcpConfig;
use crate::{Bytes, ConnectId, Multiaddr, PeerId, Protocol, SwarmTimeouts, TransportKind};
use crate::{ConnectFailure, ConnectOutcome};
use crate::{ConnectionId, StreamId, Transport};
#[cfg(feature = "relay-server")]
use crate::{RelayServerAddressError, RelayServerAddressErrorKind};
#[cfg(feature = "relay-server")]
use crate::{RelayServerEvent, RelayServerRuntimeError, RelayServerRuntimeErrorKind};
#[cfg(any(feature = "quic", feature = "tcp"))]
use minip2p_transport::ConnectionNamespace;
#[cfg(any(feature = "tcp", feature = "relay"))]
use minip2p_transport::InvalidLimit;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// A QUIC listen address in TEST-NET-1, never a local address, so binding it
/// fails: a build refused before binding proves validation ran first.
const UNBINDABLE_QUIC: &str = "/ip4/192.0.2.1/udp/0/quic-v1";

/// Drives `endpoint` on a thread until the returned guard is dropped.
///
/// A peer that is not being driven answers nothing, so anything asserting
/// on a connection needs the other end alive for as long as the assertion
/// takes.
struct Driven {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Driven {
    fn new(mut endpoint: Endpoint) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                endpoint
                    .next_event(Duration::from_millis(20))
                    .expect("drive peer");
            }
        });
        Self {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Driven {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            drop(thread.join());
        }
    }
}

/// Drives `endpoint` until an event `wanted` accepts, or gives up.
///
/// A connection produces more than the event a test is waiting for --
/// identify, ping, readiness -- and an earlier connection keeps producing
/// them, so taking whatever arrives next is a race rather than an
/// assertion.
#[expect(
    clippy::panic,
    reason = "A timed-out test must include the unexpected event trace."
)]
fn wait_for(
    endpoint: &mut Endpoint,
    what: &str,
    mut wanted: impl FnMut(&EndpointEvent) -> bool,
) -> EndpointEvent {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut seen = Vec::new();
    while std::time::Instant::now() < deadline {
        let Some(event) = endpoint
            .next_event(Duration::from_millis(50))
            .expect("drive endpoint")
        else {
            continue;
        };
        if wanted(&event) {
            return event;
        }
        seen.push(event);
    }
    panic!("no {what} arrived; saw {seen:?}");
}

#[expect(
    clippy::panic,
    reason = "A timed-out test must include the unexpected event."
)]
fn connect_outcome(endpoint: &mut Endpoint, id: ConnectId) -> ConnectOutcome {
    match wait_for(
        endpoint,
        "connect settled",
        |event| matches!(event, EndpointEvent::ConnectSettled { connect_id, .. } if *connect_id == id),
    ) {
        EndpointEvent::ConnectSettled { outcome, .. } => outcome,
        other => panic!("expected ConnectSettled, got {other:?}"),
    }
}

fn tcp_peer_addr(peer: PeerId, port: u16) -> PeerAddr {
    PeerAddr::new(
        Multiaddr::from_protocols(vec![Protocol::Ip4([127, 0, 0, 1]), Protocol::Tcp(port)]),
        peer,
    )
    .expect("peer addr")
}

#[cfg(feature = "tcp")]
#[expect(
    clippy::panic,
    reason = "A malformed fixture address is a test setup failure."
)]
fn tcp_port(addr: &PeerAddr) -> u16 {
    match addr.transport().protocols() {
        [_, Protocol::Tcp(port)] => *port,
        other => panic!("not a /tcp address: {other:?}"),
    }
}

fn quic_endpoint() -> Endpoint {
    Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind")
}

/// The `localhost` leaf and key from the QUIC transport's CA fixtures.
#[cfg(feature = "quic")]
const CA_LEAF: &[u8] =
    include_bytes!("../../../../../transports/quic/tests/fixtures/ca/localhost.pem");

#[cfg(feature = "quic")]
const CA_KEY: &[u8] =
    include_bytes!("../../../../../transports/quic/tests/fixtures/ca/localhost.key");

mod bind;
mod builder;
#[cfg(any(feature = "discovery", feature = "mdns"))]
mod capabilities;
mod close;
mod connect;
mod streams;
mod wait;
