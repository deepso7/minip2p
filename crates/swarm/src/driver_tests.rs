use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::events::SwarmErrorKind;
use minip2p_core::{Multiaddr, PeerAddr};
use minip2p_identify::IDENTIFY_PROTOCOL_ID;
use minip2p_identity::Ed25519Keypair;
use minip2p_multistream_select::{MultistreamOutput, MultistreamSelect};
use minip2p_ping::PING_PROTOCOL_ID;
use minip2p_transport::mio::{self, Registry, Waker, event::Event};
use minip2p_transport::{
    ConnectionEndpoint, TokenSpace, Transport, TransportError, TransportEvent,
};
use std::sync::Arc;

/// A fixture with no socket: attaching and dispatching do nothing.
macro_rules! socketless {
    ($transport:ty) => {
        impl PollSource for $transport {
            fn attach(&mut self, _: Registry, _: TokenSpace, _: Arc<Waker>) -> std::io::Result<()> {
                Ok(())
            }

            fn dispatch(&mut self, _: &Event) {}
        }
    };
}

/// Transport that never produces events; counts `poll()` calls so tests
/// can assert how often an expired wait touches the transport.
#[derive(Default)]
struct IdleTransport {
    poll_calls: usize,
    /// Every time sample the driver handed to `poll`.
    samples: Vec<Now>,
    /// Reported verbatim from `next_deadline`.
    deadline: Option<minip2p_core::platform::Deadline>,
    /// Socket-less input from other threads, announced on the shared
    /// `Waker` this keeps from `attach`.
    inbox: Option<std::sync::mpsc::Receiver<TransportEvent>>,
    waker: Option<Arc<Waker>>,
    /// Events returned by the first `poll`, so a test can make the core
    /// emit actions during the polls it is counting.
    initial_events: Vec<TransportEvent>,
    /// Stream ids handed out by `open_stream`.
    next_stream_id: u64,
    /// Streams the driver opened while dispatching actions.
    opened_streams: usize,
    /// Reported verbatim from `local_addresses_revision`.
    address_revision: Option<u64>,
}

impl Transport for IdleTransport {
    fn ack_stream(
        &mut self,
        _id: ConnectionId,
        _stream_id: StreamId,
        _bytes: usize,
    ) -> Result<(), TransportError> {
        Ok(())
    }

    fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
        Err(TransportError::Unsupported { operation: "dial" })
    }

    fn listen(&mut self, _: &Multiaddr) -> Result<Multiaddr, TransportError> {
        Err(TransportError::Unsupported {
            operation: "listen",
        })
    }

    fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
        self.next_stream_id += 1;
        self.opened_streams += 1;
        Ok(StreamId::new(self.next_stream_id))
    }

    fn send_stream(
        &mut self,
        _: ConnectionId,
        _: StreamId,
        _: Bytes,
    ) -> Result<(), TransportError> {
        Ok(())
    }

    fn close_stream_write(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Ok(())
    }

    fn reset_stream(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Err(TransportError::Unsupported {
            operation: "reset_stream",
        })
    }

    fn close(&mut self, _: ConnectionId) -> Result<(), TransportError> {
        Err(TransportError::Unsupported { operation: "close" })
    }

    fn poll(&mut self, now: Now) -> Result<Vec<TransportEvent>, TransportError> {
        self.poll_calls += 1;
        self.samples.push(now);
        let mut events = std::mem::take(&mut self.initial_events);
        if let Some(inbox) = &self.inbox {
            events.extend(inbox.try_iter());
        }
        Ok(events)
    }

    fn local_addresses_revision(&self) -> Option<u64> {
        self.address_revision
    }

    fn next_deadline(&self) -> Option<minip2p_core::platform::Deadline> {
        self.deadline
    }
}

impl PollSource for IdleTransport {
    fn attach(&mut self, _: Registry, _: TokenSpace, waker: Arc<Waker>) -> std::io::Result<()> {
        self.waker = Some(waker);
        Ok(())
    }

    fn dispatch(&mut self, _: &Event) {}
}

/// Deterministic transport that surfaces two connections to the same
/// peer on consecutive polls and records which connections the driver
/// opens streams on and closes.
struct ReplacementTransport {
    event_batches: VecDeque<Vec<TransportEvent>>,
    next_stream: u64,
    open_calls: Vec<ConnectionId>,
    close_calls: Vec<ConnectionId>,
}

impl ReplacementTransport {
    fn new(peer_id: PeerId, original: ConnectionId, replacement: ConnectionId) -> Self {
        let endpoint = || ConnectionEndpoint::with_peer_id(Multiaddr::new(), peer_id);
        Self {
            event_batches: VecDeque::from([
                vec![TransportEvent::Connected {
                    id: original,
                    endpoint: Box::new(endpoint()),
                }],
                vec![TransportEvent::Connected {
                    id: replacement,
                    endpoint: Box::new(endpoint()),
                }],
            ]),
            next_stream: 1,
            open_calls: Vec::new(),
            close_calls: Vec::new(),
        }
    }
}

impl Transport for ReplacementTransport {
    fn ack_stream(
        &mut self,
        _id: ConnectionId,
        _stream_id: StreamId,
        _bytes: usize,
    ) -> Result<(), TransportError> {
        Ok(())
    }

    fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
        Err(TransportError::Unsupported { operation: "dial" })
    }

    fn listen(&mut self, _: &Multiaddr) -> Result<Multiaddr, TransportError> {
        Err(TransportError::Unsupported {
            operation: "listen",
        })
    }

    fn open_stream(&mut self, conn_id: ConnectionId) -> Result<StreamId, TransportError> {
        self.open_calls.push(conn_id);
        let stream_id = StreamId::new(self.next_stream);
        self.next_stream += 1;
        Ok(stream_id)
    }

    fn send_stream(
        &mut self,
        _: ConnectionId,
        _: StreamId,
        _: Bytes,
    ) -> Result<(), TransportError> {
        Ok(())
    }

    fn close_stream_write(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Ok(())
    }

    fn reset_stream(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Ok(())
    }

    fn close(&mut self, conn_id: ConnectionId) -> Result<(), TransportError> {
        self.close_calls.push(conn_id);
        Ok(())
    }

    fn poll(&mut self, _now: Now) -> Result<Vec<TransportEvent>, TransportError> {
        Ok(self.event_batches.pop_front().unwrap_or_default())
    }
}

socketless!(ReplacementTransport);

fn replacement_swarm(
    remote_peer: PeerId,
    original: ConnectionId,
    replacement: ConnectionId,
) -> Swarm<ReplacementTransport> {
    let keypair = Ed25519Keypair::generate();
    let transport = ReplacementTransport::new(remote_peer, original, replacement);
    let identify = IdentifyConfig {
        protocol_version: "test/1".into(),
        agent_version: "test/1".into(),
        protocols: Vec::new(),
        public_key: keypair.public_key().encode_protobuf(),
    };
    Swarm::new(
        transport,
        identify,
        SwarmTimeouts::default(),
        keypair.peer_id(),
    )
    .expect("swarm attaches its transport")
}

/// Transport whose `open_stream` fails on exactly one (1-based) call and
/// succeeds otherwise, returning the call index as the stream id.
struct FailingUserOpenTransport {
    events: VecDeque<TransportEvent>,
    open_calls: usize,
    fail_on_call: usize,
}

impl FailingUserOpenTransport {
    fn connected(peer_id: PeerId, fail_on_call: usize) -> Self {
        let endpoint = ConnectionEndpoint::with_peer_id(Multiaddr::new(), peer_id);
        Self {
            events: VecDeque::from([TransportEvent::Connected {
                id: ConnectionId::new(1),
                endpoint: Box::new(endpoint),
            }]),
            open_calls: 0,
            fail_on_call,
        }
    }
}

impl Transport for FailingUserOpenTransport {
    fn ack_stream(
        &mut self,
        _id: ConnectionId,
        _stream_id: StreamId,
        _bytes: usize,
    ) -> Result<(), TransportError> {
        Ok(())
    }

    fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
        Err(TransportError::Unsupported { operation: "dial" })
    }

    fn listen(&mut self, _: &Multiaddr) -> Result<Multiaddr, TransportError> {
        Err(TransportError::Unsupported {
            operation: "listen",
        })
    }

    fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
        self.open_calls += 1;
        if self.open_calls == self.fail_on_call {
            Err(TransportError::ResourceExhausted {
                resource: "test stream capacity",
            })
        } else {
            Ok(StreamId::new(self.open_calls as u64))
        }
    }

    fn send_stream(
        &mut self,
        _: ConnectionId,
        _: StreamId,
        _: Bytes,
    ) -> Result<(), TransportError> {
        Ok(())
    }

    fn close_stream_write(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Ok(())
    }

    fn reset_stream(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Ok(())
    }

    fn close(&mut self, _: ConnectionId) -> Result<(), TransportError> {
        Ok(())
    }

    fn poll(&mut self, _now: Now) -> Result<Vec<TransportEvent>, TransportError> {
        Ok(self.events.drain(..).collect())
    }
}

socketless!(FailingUserOpenTransport);

/// Swarm over an [`IdleTransport`] with throwaway identity and defaults.
fn idle_swarm() -> Swarm<IdleTransport> {
    let keypair = Ed25519Keypair::generate();
    let identify = IdentifyConfig {
        protocol_version: "test/1".into(),
        agent_version: "test/1".into(),
        protocols: Vec::new(),
        public_key: keypair.public_key().encode_protobuf(),
    };
    Swarm::new(
        IdleTransport::default(),
        identify,
        SwarmTimeouts::default(),
        keypair.peer_id(),
    )
    .expect("swarm attaches its transport")
}

#[test]
fn one_drive_iteration_takes_one_clock_sample() {
    let clock = CountingClock::default();
    let reads = clock.reads.clone();

    let keypair = Ed25519Keypair::generate();
    let identify = IdentifyConfig {
        protocol_version: "test/1".into(),
        agent_version: "test/1".into(),
        protocols: Vec::new(),
        public_key: keypair.public_key().encode_protobuf(),
    };
    let transport = IdleTransport {
        initial_events: vec![TransportEvent::Connected {
            id: ConnectionId::new(1),
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                "/ip4/198.51.100.4/udp/4001/quic-v1"
                    .parse()
                    .expect("endpoint"),
                Ed25519Keypair::generate().peer_id(),
            )),
        }],
        ..IdleTransport::default()
    };
    let mut swarm = Swarm::with_clock(
        transport,
        identify,
        SwarmTimeouts::default(),
        keypair.peer_id(),
        Box::new(clock),
    )
    .expect("swarm attaches its transport");

    swarm.poll().expect("poll");
    assert!(
        swarm.core().transport().opened_streams > 0,
        "fixture must dispatch an action for this test to mean anything"
    );
    assert_eq!(
        reads.load(Ordering::SeqCst),
        1,
        "the transport, the core's tick, and every dispatched action must \
         share one sample; a second read means they can disagree about now"
    );

    swarm.poll().expect("poll");
    assert_eq!(reads.load(Ordering::SeqCst), 2);

    let samples: Vec<u64> = swarm
        .core()
        .transport()
        .samples
        .iter()
        .map(|sample| sample.monotonic_ms)
        .collect();
    assert_eq!(samples, vec![1_000, 2_000]);
}

#[test]
fn transport_deadline_caps_the_idle_wait_budget() {
    const DEADLINE_MS: u64 = 40;

    let clock = Arc::new(TestClock::default());
    clock.advance(1_000);

    let keypair = Ed25519Keypair::generate();
    let identify = IdentifyConfig {
        protocol_version: "test/1".into(),
        agent_version: "test/1".into(),
        protocols: Vec::new(),
        public_key: keypair.public_key().encode_protobuf(),
    };
    let transport = IdleTransport {
        deadline: Some(minip2p_core::platform::Deadline::from_millis(
            1_000 + DEADLINE_MS,
        )),
        ..IdleTransport::default()
    };

    let mut swarm = Swarm::with_clock(
        transport,
        identify,
        SwarmTimeouts::default(),
        keypair.peer_id(),
        Box::new(SharedClock(clock.clone())),
    )
    .expect("swarm attaches its transport");

    let interrupt = swarm.wait_handle();
    swarm.simulated_wait = Some(Box::new(move |_| interrupt.interrupt()));

    let outcome = swarm
        .poll_next_interruptible(Duration::from_secs(30))
        .expect("interruptible wait");
    assert!(matches!(outcome, PollNext::Interrupted));

    assert_eq!(swarm.wait_budgets, vec![Duration::from_millis(DEADLINE_MS)]);
}

#[test]
fn external_addresses_merge_into_the_identify_snapshot() {
    let mut swarm = idle_swarm();
    let external: Multiaddr = "/ip4/203.0.113.9/udp/4001/quic-v1".parse().unwrap();
    let circuit: Multiaddr = "/ip4/203.0.113.1/udp/4001/quic-v1/p2p-circuit"
        .parse()
        .unwrap();

    assert_eq!(swarm.core().external_addresses_revision(), 0);
    swarm
        .core_mut()
        .set_external_addresses(vec![external.clone(), circuit.clone()]);
    assert_eq!(swarm.core().external_addresses_revision(), 1);
    swarm
        .core_mut()
        .set_external_addresses(vec![external.clone(), circuit.clone()]);
    assert_eq!(
        swarm.core().external_addresses_revision(),
        1,
        "an identical replacement is not a change"
    );
    swarm.poll().unwrap();
    assert_eq!(swarm.core().local_addresses(), &[external.clone(), circuit]);

    swarm.core_mut().set_external_addresses(Vec::new());
    swarm.poll().unwrap();
    assert!(swarm.core().local_addresses().is_empty());
}

/// The advertised snapshot is rebuilt only when one of its inputs moved:
/// a busy poll with unchanged addresses costs no rebuild, and a
/// transport that cannot report a revision is re-read every time.
#[test]
fn the_address_snapshot_is_rebuilt_only_when_an_input_moves() {
    let mut swarm = idle_swarm();
    swarm.core_mut().transport_mut().address_revision = Some(0);
    swarm.poll().unwrap();
    assert_eq!(swarm.core().address_rebuilds, 1, "the first poll builds it");
    for _ in 0..3 {
        swarm.poll().unwrap();
    }
    assert_eq!(swarm.core().address_rebuilds, 1, "nothing moved");

    let external: Multiaddr = "/ip4/203.0.113.9/tcp/4001".parse().unwrap();
    swarm
        .core_mut()
        .set_external_addresses(vec![external.clone()]);
    swarm.poll().unwrap();
    assert_eq!(swarm.core().address_rebuilds, 2, "the external set moved");
    assert_eq!(
        swarm.core().local_addresses(),
        std::slice::from_ref(&external)
    );
    swarm.core_mut().set_external_addresses(vec![external]);
    swarm.poll().unwrap();
    assert_eq!(
        swarm.core().address_rebuilds,
        2,
        "an identical set is no move"
    );

    swarm.core_mut().transport_mut().address_revision = Some(1);
    swarm.poll().unwrap();
    assert_eq!(swarm.core().address_rebuilds, 3, "the transport moved");

    swarm.core_mut().transport_mut().address_revision = None;
    swarm.poll().unwrap();
    swarm.poll().unwrap();
    assert_eq!(swarm.core().address_rebuilds, 5, "no revision, no cache");
}

/// Reports two bound addresses and refuses the second listen, so a
/// partially applied `listen_on_bound_addrs` batch can be observed.
#[derive(Default)]
struct PartialListenTransport {
    listens: usize,
}

impl Transport for PartialListenTransport {
    fn ack_stream(
        &mut self,
        _id: ConnectionId,
        _stream_id: StreamId,
        _bytes: usize,
    ) -> Result<(), TransportError> {
        Ok(())
    }

    fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
        Err(TransportError::Unsupported { operation: "dial" })
    }

    fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, TransportError> {
        self.listens += 1;
        if self.listens == 2 {
            Err(TransportError::Unsupported {
                operation: "listen",
            })
        } else {
            Ok(addr.clone())
        }
    }

    fn local_addresses(&self) -> Vec<Multiaddr> {
        vec![
            "/ip4/127.0.0.1/tcp/4001".parse().unwrap(),
            "/ip4/127.0.0.1/tcp/4002".parse().unwrap(),
        ]
    }

    fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
        Err(TransportError::Unsupported {
            operation: "open_stream",
        })
    }

    fn send_stream(
        &mut self,
        _: ConnectionId,
        _: StreamId,
        _: Bytes,
    ) -> Result<(), TransportError> {
        Ok(())
    }

    fn close_stream_write(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Ok(())
    }

    fn reset_stream(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Err(TransportError::Unsupported {
            operation: "reset_stream",
        })
    }

    fn close(&mut self, _: ConnectionId) -> Result<(), TransportError> {
        Err(TransportError::Unsupported { operation: "close" })
    }

    fn poll(&mut self, _: Now) -> Result<Vec<TransportEvent>, TransportError> {
        Ok(Vec::new())
    }
}

socketless!(PartialListenTransport);

#[test]
fn listened_addrs_revision_counts_each_successful_listen() {
    let keypair = Ed25519Keypair::generate();
    let identify = IdentifyConfig {
        protocol_version: "test/1".into(),
        agent_version: "test/1".into(),
        protocols: Vec::new(),
        public_key: keypair.public_key().encode_protobuf(),
    };
    let mut swarm = Swarm::new(
        PartialListenTransport::default(),
        identify,
        SwarmTimeouts::default(),
        keypair.peer_id(),
    )
    .expect("swarm attaches its transport");

    assert_eq!(swarm.core().listened_addrs_revision(), 0);
    swarm
        .core_mut()
        .listen_on_bound_addrs()
        .expect_err("second bind fails");
    assert_eq!(swarm.core().listened_addrs_revision(), 1);
    assert_eq!(
        swarm.core().listened_addrs(),
        ["/ip4/127.0.0.1/tcp/4001".parse().unwrap()]
    );
}

#[test]
fn replaced_connection_closes_after_public_event_is_returned() {
    let remote_peer = Ed25519Keypair::generate().peer_id();
    let original = ConnectionId::new(41);
    let replacement = ConnectionId::new(42);
    let mut swarm = replacement_swarm(remote_peer, original, replacement);

    let first = swarm.poll().expect("original connection poll");
    assert!(matches!(
        first.as_slice(),
        [SwarmEvent::ConnectionEstablished { conn_id, .. }] if *conn_id == original
    ));

    let replaced = swarm.poll().expect("replacement connection poll");
    assert!(matches!(
        replaced.as_slice(),
        [SwarmEvent::ConnectionReplaced { old, new, .. }]
            if *old == original && *new == replacement
    ));
    assert!(
        swarm.core().transport().close_calls.is_empty(),
        "the old transport must remain open until the event is returned"
    );

    let later = swarm.poll().expect("post-delivery poll");
    assert!(later.is_empty());
    assert_eq!(swarm.core().transport().close_calls, vec![original]);
    assert_eq!(swarm.core().connected_peers(), vec![remote_peer]);
}

#[test]
fn replaced_connection_close_waits_for_poll_next_delivery() {
    let remote_peer = Ed25519Keypair::generate().peer_id();
    let original = ConnectionId::new(51);
    let replacement = ConnectionId::new(52);
    let mut swarm = replacement_swarm(remote_peer, original, replacement);

    let _ = swarm.poll().expect("original connection poll");
    let replaced = swarm
        .poll_next(Duration::ZERO)
        .expect("replacement connection poll")
        .expect("replacement event");
    assert!(matches!(
        replaced,
        SwarmEvent::ConnectionReplaced { old, new, .. }
            if old == original && new == replacement
    ));
    assert!(swarm.core().transport().close_calls.is_empty());

    let later = swarm.poll().expect("post-delivery poll");
    assert!(later.is_empty());
    assert_eq!(swarm.core().transport().close_calls, vec![original]);
}

#[test]
fn replaced_connection_close_waits_for_the_buffer_to_drain_across_commands() {
    let remote_peer = Ed25519Keypair::generate().peer_id();
    let other_peer = Ed25519Keypair::generate().peer_id();
    let original = ConnectionId::new(61);
    let replacement = ConnectionId::new(62);
    let other = ConnectionId::new(63);
    let mut swarm = replacement_swarm(remote_peer, original, replacement);
    swarm.core_mut().transport_mut().event_batches[1].push(TransportEvent::Connected {
        id: other,
        endpoint: Box::new(ConnectionEndpoint::with_peer_id(
            Multiaddr::new(),
            other_peer,
        )),
    });

    let _ = swarm.poll().expect("original connection poll");
    let replaced = swarm
        .poll_next(Duration::ZERO)
        .expect("poll")
        .expect("event");
    assert!(matches!(replaced, SwarmEvent::ConnectionReplaced { old, .. } if old == original));

    let opens_before = swarm.core().transport().open_calls.len();
    swarm.ping(&remote_peer).expect("ping the replacement");
    assert_eq!(
        swarm.core().transport().open_calls[opens_before..],
        [replacement],
        "the ping opens its stream on the replacement without waiting",
    );
    assert!(swarm.core().transport().close_calls.is_empty());

    let established = swarm
        .poll_next(Duration::ZERO)
        .expect("poll")
        .expect("event");
    assert!(matches!(
        established,
        SwarmEvent::ConnectionEstablished { conn_id, .. } if conn_id == other
    ));
    assert!(swarm.core().transport().close_calls.is_empty());

    swarm.ping(&other_peer).expect("ping the other peer");
    assert_eq!(swarm.core().transport().close_calls, vec![original]);
}

#[test]
fn deadline_earliest_picks_the_sooner_deadline() {
    let soon = WaitDeadline::from(Duration::from_millis(10));
    let later = WaitDeadline::from(Duration::from_secs(60));
    assert_eq!(soon.earliest(later), soon);
    assert_eq!(later.earliest(soon), soon);
    assert_eq!(WaitDeadline::NEVER.earliest(soon), soon);
    assert_eq!(soon.earliest(WaitDeadline::NEVER), soon);
    assert_eq!(
        WaitDeadline::NEVER.earliest(WaitDeadline::NEVER),
        WaitDeadline::NEVER
    );
}

#[test]
fn deadline_conversions_cover_instant_duration_and_never() {
    let relative: WaitDeadline = Duration::from_secs(1).into();
    assert!(!relative.is_expired_at(Instant::now()));
    assert!(relative.remaining_at(Instant::now()).is_some());

    let unbounded: WaitDeadline = Duration::MAX.into();
    assert_eq!(unbounded, WaitDeadline::NEVER);

    assert!(!WaitDeadline::NEVER.is_expired_at(Instant::now()));
    assert_eq!(WaitDeadline::NEVER.remaining_at(Instant::now()), None);

    let past = WaitDeadline::from(Instant::now());
    assert!(past.is_expired_at(Instant::now() + Duration::from_millis(1)));
}

#[test]
fn poll_next_with_never_deadline_returns_buffered_event() {
    let peer_id = Ed25519Keypair::generate().peer_id();
    let mut swarm = idle_swarm();
    swarm
        .core
        .state
        .events
        .push_back(SwarmEvent::ConnectionEstablished {
            peer_id,
            conn_id: ConnectionId::new(1),
        });

    let event = swarm
        .poll_next(WaitDeadline::NEVER)
        .expect("poll")
        .expect("buffered event");
    assert!(matches!(
        event,
        SwarmEvent::ConnectionEstablished { peer_id: p, .. } if p == peer_id
    ));
}

#[test]
fn run_until_preserves_non_matching_events() {
    let target_peer_id = Ed25519Keypair::generate().peer_id();
    let mut swarm = idle_swarm();
    swarm
        .core
        .state
        .events
        .push_back(SwarmEvent::ConnectionEstablished {
            peer_id: target_peer_id,
            conn_id: ConnectionId::new(1),
        });
    swarm.core.state.events.push_back(SwarmEvent::PeerReady {
        peer_id: target_peer_id,
        conn_id: ConnectionId::new(1),
        protocols: Vec::new(),
    });

    let found = swarm
        .run_until(Instant::now() + Duration::from_secs(1), |event| {
            matches!(event, SwarmEvent::PeerReady { .. })
        })
        .expect("wait")
        .expect("matching event");
    assert!(matches!(found, SwarmEvent::PeerReady { .. }));

    let restored = swarm
        .poll_next(Instant::now())
        .expect("poll")
        .expect("restored event");
    assert!(matches!(
        restored,
        SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == target_peer_id
    ));
}

#[test]
fn run_until_does_not_treat_interrupt_as_deadline() {
    let mut swarm = idle_swarm();
    swarm.wait_handle().interrupt();
    swarm.wake_handle().wake();

    let started = Instant::now();
    let found = swarm
        .run_until(Duration::from_millis(100), |_| false)
        .expect("wait");

    assert!(found.is_none());
    assert!(started.elapsed() >= Duration::from_millis(100));
    assert!(
        !swarm.wait_budgets.is_empty(),
        "the wait must resume, and block, after consuming the interrupt"
    );
}

/// A buffered event the next wait returns before anything else.
fn buffer_event(swarm: &mut Swarm<IdleTransport>) {
    swarm
        .core
        .state
        .events
        .push_back(SwarmEvent::ConnectionEstablished {
            peer_id: Ed25519Keypair::generate().peer_id(),
            conn_id: ConnectionId::new(1),
        });
}

#[test]
fn interrupts_coalesce_and_survive_events_and_harvests() {
    let mut swarm = idle_swarm();
    swarm.wait_handle().interrupt();
    swarm.wait_handle().interrupt();
    swarm.poll().expect("non-blocking poll harvests");
    buffer_event(&mut swarm);
    assert!(matches!(
        swarm.poll_next_interruptible(WaitDeadline::NEVER),
        Ok(PollNext::Event(_))
    ));
    assert!(matches!(
        swarm.poll_next_interruptible(WaitDeadline::NEVER),
        Ok(PollNext::Interrupted)
    ));
    let mut outcome = swarm.poll_next_interruptible(Duration::from_millis(20));
    if matches!(outcome, Ok(PollNext::Woken)) {
        outcome = swarm.poll_next_interruptible(Duration::from_millis(20));
    }
    assert!(matches!(outcome, Ok(PollNext::Deadline)), "{outcome:?}");

    swarm.wait_handle().interrupt();
    assert!(matches!(
        swarm.poll_next_interruptible(Instant::now()),
        Ok(PollNext::Interrupted)
    ));
    let mut outcome = swarm.poll_next_interruptible(Instant::now());
    if matches!(outcome, Ok(PollNext::Woken)) {
        outcome = swarm.poll_next_interruptible(Instant::now());
    }
    assert!(matches!(outcome, Ok(PollNext::Deadline)), "{outcome:?}");
}

#[test]
fn an_interrupt_wakes_a_blocked_wait_promptly() {
    let mut swarm = idle_swarm();
    let handle = swarm.wait_handle();
    let interrupter = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        handle.interrupt();
    });
    let started = Instant::now();
    let outcome = swarm.poll_next_interruptible(Duration::from_secs(10));
    interrupter.join().expect("interrupter");
    assert!(matches!(outcome, Ok(PollNext::Interrupted)), "{outcome:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn a_wake_is_woken_not_interrupted_and_survives_a_competing_event() {
    let mut swarm = idle_swarm();
    swarm.wake_handle().wake();
    swarm.poll().expect("the harvest records the wake");
    buffer_event(&mut swarm);
    assert!(matches!(
        swarm.poll_next_interruptible(WaitDeadline::NEVER),
        Ok(PollNext::Event(_))
    ));
    assert!(matches!(
        swarm.poll_next_interruptible(WaitDeadline::NEVER),
        Ok(PollNext::Woken)
    ));
    assert!(matches!(
        swarm.poll_next_interruptible(Duration::from_millis(20)),
        Ok(PollNext::Deadline)
    ));
}

/// A host-owned source: one UDP socket the swarm only wakes for.
struct HostSocket(mio::net::UdpSocket);

impl PollSource for HostSocket {
    fn attach(
        &mut self,
        registry: Registry,
        tokens: TokenSpace,
        _: Arc<Waker>,
    ) -> std::io::Result<()> {
        let token = tokens.token(0).expect("a token");
        registry.register(&mut self.0, token, mio::Interest::READABLE)
    }

    fn dispatch(&mut self, _: &Event) {
        panic!("a host source is serviced by its host, never dispatched to");
    }
}

#[test]
fn readiness_on_a_host_source_ends_a_long_wait_as_woken() {
    let mut swarm = idle_swarm();
    let mut source =
        HostSocket(mio::net::UdpSocket::bind("127.0.0.1:0".parse().expect("addr")).expect("bind"));
    swarm.attach_host_source(&mut source).expect("attach");
    let to = source.0.local_addr().expect("addr");
    let sender = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        std::net::UdpSocket::bind("127.0.0.1:0")
            .expect("bind")
            .send_to(b"mdns", to)
            .expect("send");
    });
    let started = Instant::now();
    let outcome = swarm.poll_next_interruptible(Duration::from_secs(10));
    sender.join().expect("sender");
    assert!(matches!(outcome, Ok(PollNext::Woken)), "{outcome:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn socketless_input_a_wake_and_an_interrupt_share_one_waker_without_loss() {
    let (input, inbox) = std::sync::mpsc::channel();
    let mut swarm = idle_swarm();
    swarm.core_mut().transport_mut().inbox = Some(inbox);
    let waker = swarm
        .core()
        .transport()
        .waker
        .clone()
        .expect("attached on construction");

    let wake = swarm.wake_handle();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        input.send(event(9)).expect("send");
        waker.wake().expect("wake");
        wake.wake();
    });
    let mut seen = Vec::new();
    while seen.len() < 2 {
        match swarm.poll_next_interruptible(Duration::from_secs(5)) {
            Ok(PollNext::Event(_)) => seen.push("event"),
            Ok(PollNext::Woken) => seen.push("woken"),
            other => panic!("unexpected {other:?} after {seen:?}"),
        }
    }
    assert_eq!(seen, ["event", "woken"]);

    let (input, inbox) = std::sync::mpsc::channel();
    swarm.core_mut().transport_mut().inbox = Some(inbox);
    input.send(event(10)).expect("send");
    swarm
        .core()
        .transport()
        .waker
        .as_ref()
        .expect("waker")
        .wake()
        .expect("wake");
    swarm.wake_handle().wake();
    swarm.wait_handle().interrupt();
    let mut seen = Vec::new();
    loop {
        match swarm.poll_next_interruptible(Duration::from_millis(50)) {
            Ok(PollNext::Event(_)) => seen.push("event"),
            Ok(PollNext::Interrupted) => seen.push("interrupted"),
            Ok(PollNext::Woken) => seen.push("woken"),
            Ok(PollNext::Deadline) => break,
            Err(error) => panic!("{error}"),
        }
    }
    assert_eq!(seen, ["event", "interrupted", "woken"]);

    fn event(id: u64) -> TransportEvent {
        TransportEvent::Connected {
            id: ConnectionId::new(id),
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                Multiaddr::new(),
                Ed25519Keypair::generate().peer_id(),
            )),
        }
    }
}

#[test]
fn run_until_honors_expired_deadline_with_buffered_events() {
    let peer_id = Ed25519Keypair::generate().peer_id();
    let mut swarm = idle_swarm();
    swarm
        .core
        .state
        .events
        .push_back(SwarmEvent::ConnectionEstablished {
            peer_id,
            conn_id: ConnectionId::new(1),
        });
    swarm.core.state.events.push_back(SwarmEvent::PeerReady {
        peer_id,
        conn_id: ConnectionId::new(1),
        protocols: Vec::new(),
    });

    let found = swarm
        .run_until(Instant::now(), |event| {
            matches!(event, SwarmEvent::PingRttMeasured { .. })
        })
        .expect("wait");
    assert!(found.is_none(), "no buffered event matches the predicate");
    assert_eq!(
        swarm.core().transport().poll_calls,
        1,
        "an expired wait must poll the transport at most once"
    );
    assert_eq!(swarm.core.state.events.len(), 2, "events must be preserved");
    assert!(matches!(
        swarm.core.state.events.front(),
        Some(SwarmEvent::ConnectionEstablished { .. })
    ));
    assert!(matches!(
        swarm.core.state.events.back(),
        Some(SwarmEvent::PeerReady { .. })
    ));
}

#[test]
fn run_until_finds_buffered_match_in_second_position_past_deadline() {
    let peer_id = Ed25519Keypair::generate().peer_id();
    let mut swarm = idle_swarm();
    swarm
        .core
        .state
        .events
        .push_back(SwarmEvent::ConnectionEstablished {
            peer_id,
            conn_id: ConnectionId::new(1),
        });
    swarm.core.state.events.push_back(SwarmEvent::PeerReady {
        peer_id,
        conn_id: ConnectionId::new(1),
        protocols: Vec::new(),
    });

    let past = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("fresh instant is at least one second after its origin");
    let found = swarm
        .run_until(past, |event| matches!(event, SwarmEvent::PeerReady { .. }))
        .expect("wait")
        .expect("buffered match must be found past the deadline");
    assert!(matches!(found, SwarmEvent::PeerReady { .. }));

    assert_eq!(swarm.core.state.events.len(), 1);
    assert!(matches!(
        swarm.core.state.events.front(),
        Some(SwarmEvent::ConnectionEstablished { peer_id: restored, .. }) if *restored == peer_id
    ));
}

/// Swarm over a [`FailingUserOpenTransport`] that has already processed
/// the initial `Connected` event (which consumes `open_stream` call 1
/// for the auto-opened identify stream).
fn connected_swarm(
    remote_peer: &PeerId,
    protocol: &str,
    fail_on_call: usize,
) -> Swarm<FailingUserOpenTransport> {
    let keypair = Ed25519Keypair::generate();
    let identify = IdentifyConfig {
        protocol_version: "test/1".into(),
        agent_version: "test/1".into(),
        protocols: vec![protocol.into()],
        public_key: keypair.public_key().encode_protobuf(),
    };
    let transport = FailingUserOpenTransport::connected(*remote_peer, fail_on_call);
    let mut swarm = Swarm::new(
        transport,
        identify,
        SwarmTimeouts::default(),
        keypair.peer_id(),
    )
    .expect("swarm attaches its transport");
    swarm
        .core_mut()
        .add_protocol(protocol)
        .expect("test protocol id is not reserved");
    swarm.poll().expect("process connected event");
    swarm
}

fn buffered_open_failures(swarm: &Swarm<FailingUserOpenTransport>) -> usize {
    swarm
        .core
        .state
        .events
        .iter()
        .filter(|event| {
            matches!(
                event,
                SwarmEvent::Error(error) if error.kind == SwarmErrorKind::OpenStreamFailed
            ) || matches!(
                event,
                SwarmEvent::PingFailed {
                    cause: crate::PingFailure::OpenFailed,
                    ..
                }
            )
        })
        .count()
}

#[test]
fn stream_open_preserves_transport_error_type() {
    const PROTOCOL: &str = "/test/1.0.0";
    let remote_peer = Ed25519Keypair::generate().peer_id();
    let mut swarm = connected_swarm(&remote_peer, PROTOCOL, 2);

    let error = swarm
        .open_stream(&remote_peer, PROTOCOL)
        .expect_err("transport must reject user stream");
    assert!(matches!(
        error,
        DriverError::Transport(TransportError::ResourceExhausted {
            resource: "test stream capacity"
        })
    ));
    assert!(
        swarm.core.state.is_idle(),
        "failed open must clear core state"
    );
    assert_eq!(
        buffered_open_failures(&swarm),
        0,
        "synchronous Err must suppress the duplicate buffered event"
    );
}

#[test]
fn stream_open_not_misattributed_to_queued_failure() {
    const PROTOCOL: &str = "/test/1.0.0";
    let remote_peer = Ed25519Keypair::generate().peer_id();
    let mut swarm = connected_swarm(&remote_peer, PROTOCOL, 2);

    swarm
        .core
        .state
        .ping(&remote_peer, [0; minip2p_ping::PING_PAYLOAD_LEN], 0)
        .expect("queue stale open");

    let (_, stream_id) = swarm
        .open_stream(&remote_peer, PROTOCOL)
        .expect("the caller's own open succeeds; the stale failure is not its error");
    assert_eq!(stream_id, StreamId::new(3), "caller gets its own stream id");

    assert_eq!(
        buffered_open_failures(&swarm),
        1,
        "asynchronous failure must surface exactly once"
    );
}

/// Transport that completes multistream negotiation for every locally
/// opened stream (identify, ping, and one user protocol) and then
/// rejects payload sends on the stream that negotiated the user
/// protocol.
struct FailingSendTransport {
    events: VecDeque<TransportEvent>,
    negotiators: BTreeMap<StreamId, MultistreamSelect>,
    next_stream: u64,
    user_protocol: String,
    failing_stream: Option<StreamId>,
    reset_calls: usize,
}

impl FailingSendTransport {
    fn connected(peer_id: PeerId, user_protocol: &str) -> Self {
        let endpoint = ConnectionEndpoint::with_peer_id(Multiaddr::new(), peer_id);
        Self {
            events: VecDeque::from([TransportEvent::Connected {
                id: ConnectionId::new(1),
                endpoint: Box::new(endpoint),
            }]),
            negotiators: BTreeMap::new(),
            next_stream: 1,
            user_protocol: user_protocol.to_string(),
            failing_stream: None,
            reset_calls: 0,
        }
    }
}

impl Transport for FailingSendTransport {
    fn ack_stream(
        &mut self,
        _id: ConnectionId,
        _stream_id: StreamId,
        _bytes: usize,
    ) -> Result<(), TransportError> {
        Ok(())
    }

    fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
        Err(TransportError::Unsupported { operation: "dial" })
    }

    fn listen(&mut self, _: &Multiaddr) -> Result<Multiaddr, TransportError> {
        Err(TransportError::Unsupported {
            operation: "listen",
        })
    }

    fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
        let stream_id = StreamId::new(self.next_stream);
        self.next_stream += 1;
        let mut listener = MultistreamSelect::listener(vec![
            IDENTIFY_PROTOCOL_ID.to_string(),
            PING_PROTOCOL_ID.to_string(),
            self.user_protocol.clone(),
        ]);
        listener.start();
        self.negotiators.insert(stream_id, listener);
        Ok(stream_id)
    }

    fn send_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
    ) -> Result<(), TransportError> {
        let Some(negotiator) = self.negotiators.get_mut(&stream_id) else {
            if self.failing_stream == Some(stream_id) {
                return Err(TransportError::ResourceExhausted {
                    resource: "test send capacity",
                });
            }
            return Ok(());
        };
        negotiator.on_data(&data);
        let mut negotiated_protocol = None;
        let mut outbound = Vec::new();
        while let Some(output) = negotiator.poll_output() {
            match output {
                MultistreamOutput::OutboundData(bytes) => outbound.push(bytes),
                MultistreamOutput::Negotiated { protocol } => {
                    negotiated_protocol = Some(protocol);
                }
                other => {
                    return Err(TransportError::PollError {
                        reason: format!("unexpected multistream output: {other:?}"),
                    });
                }
            }
        }
        if let Some(protocol) = negotiated_protocol {
            self.negotiators.remove(&stream_id);
            if protocol == self.user_protocol {
                self.failing_stream = Some(stream_id);
            }
        }
        for data in outbound {
            self.events.push_back(TransportEvent::StreamData {
                id,
                stream_id,
                data: Bytes::from(data),
            });
        }
        Ok(())
    }

    fn close_stream_write(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Ok(())
    }

    fn reset_stream(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        self.reset_calls += 1;
        Err(TransportError::ResourceExhausted {
            resource: "test reset capacity",
        })
    }

    fn close(&mut self, _: ConnectionId) -> Result<(), TransportError> {
        Ok(())
    }

    fn poll(&mut self, _now: Now) -> Result<Vec<TransportEvent>, TransportError> {
        Ok(self.events.drain(..).collect())
    }
}

socketless!(FailingSendTransport);

fn ready_user_swarm(
    protocol: &str,
) -> (Swarm<FailingSendTransport>, PeerId, ConnectionId, StreamId) {
    let remote_peer = Ed25519Keypair::generate().peer_id();
    let keypair = Ed25519Keypair::generate();
    let identify = IdentifyConfig {
        protocol_version: "test/1".into(),
        agent_version: "test/1".into(),
        protocols: vec![protocol.into()],
        public_key: keypair.public_key().encode_protobuf(),
    };
    let transport = FailingSendTransport::connected(remote_peer, protocol);
    let mut swarm = Swarm::new(
        transport,
        identify,
        SwarmTimeouts::default(),
        keypair.peer_id(),
    )
    .expect("swarm attaches its transport");
    swarm
        .core_mut()
        .add_protocol(protocol)
        .expect("test protocol id is not reserved");
    swarm.poll().expect("process connected event");

    let (conn_id, stream_id) = swarm
        .open_stream(&remote_peer, protocol)
        .expect("open user stream");
    let mut ready = false;
    for _ in 0..5 {
        for event in swarm.poll().expect("drive negotiation") {
            if matches!(
                &event,
                SwarmEvent::StreamReady { stream_id: sid, initiated_locally: true, .. }
                    if *sid == stream_id
            ) {
                ready = true;
            }
        }
        if ready {
            break;
        }
    }
    assert!(ready, "user stream must finish multistream negotiation");
    (swarm, remote_peer, conn_id, stream_id)
}

#[test]
fn send_stream_transport_failure_is_a_synchronous_error() {
    const PROTOCOL: &str = "/test/1.0.0";
    let (mut swarm, remote_peer, conn_id, stream_id) = ready_user_swarm(PROTOCOL);

    let error = swarm
        .send_stream(
            &remote_peer,
            conn_id,
            stream_id,
            Bytes::from_static(b"payload"),
        )
        .expect_err("transport must reject the payload send");
    assert!(matches!(
        error,
        DriverError::Transport(TransportError::ResourceExhausted {
            resource: "test send capacity"
        })
    ));
    assert!(
        !swarm.core.state.events.iter().any(|event| matches!(
            event,
            SwarmEvent::Error(e) if e.kind == SwarmErrorKind::Transport
        )),
        "synchronous Err must suppress the duplicate buffered event"
    );
}

#[test]
fn transport_reset_failure_remains_retryable() {
    const PROTOCOL: &str = "/test/1.0.0";
    let (mut swarm, remote_peer, conn_id, stream_id) = ready_user_swarm(PROTOCOL);

    swarm
        .reset_stream(&remote_peer, conn_id, stream_id)
        .expect("reset dispatch is asynchronous");
    swarm
        .reset_stream(&remote_peer, conn_id, stream_id)
        .expect("failed reset must remain retryable");

    assert_eq!(swarm.core().transport().reset_calls, 2);
}

/// A `StreamData` event whose stream id encodes its position, so tests
/// can assert restoration order after `run_until` skips it.
fn indexed_stream_data(peer_id: &PeerId, index: u64) -> SwarmEvent {
    SwarmEvent::StreamData {
        peer_id: *peer_id,
        conn_id: ConnectionId::new(1),
        stream_id: StreamId::new(index),
        data: Bytes::from(vec![0u8; 8]),
    }
}

fn assert_indexed_order(swarm: &Swarm<IdleTransport>, expected_len: usize) {
    assert_eq!(
        swarm.core.state.events.len(),
        expected_len,
        "every skipped event must be restored"
    );
    for (i, event) in swarm.core.state.events.iter().enumerate() {
        assert!(
            matches!(
                event,
                SwarmEvent::StreamData { stream_id, .. } if *stream_id == StreamId::new(i as u64)
            ),
            "restored event {i} is out of order: {event:?}"
        );
    }
}

#[test]
fn run_until_overflow_returns_error_and_restores_events_in_order() {
    let peer_id = Ed25519Keypair::generate().peer_id();
    let mut swarm = idle_swarm();
    let total = RUN_UNTIL_SKIP_LIMIT + 5;
    for i in 0..total {
        swarm
            .core
            .state
            .events
            .push_back(indexed_stream_data(&peer_id, i as u64));
    }

    let error = swarm
        .run_until(WaitDeadline::NEVER, |event| {
            matches!(event, SwarmEvent::PingFailed { .. })
        })
        .expect_err("skip cap must abort an unbounded wait");
    assert!(matches!(
        error,
        DriverError::EventBacklogExceeded { limit } if limit == RUN_UNTIL_SKIP_LIMIT
    ));

    assert_indexed_order(&swarm, total);
}

#[test]
fn run_until_overflow_applies_to_expired_deadline_scan() {
    let peer_id = Ed25519Keypair::generate().peer_id();
    let mut swarm = idle_swarm();
    let total = RUN_UNTIL_SKIP_LIMIT + 3;
    for i in 0..total {
        swarm
            .core
            .state
            .events
            .push_back(indexed_stream_data(&peer_id, i as u64));
    }

    let past = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("fresh instant is at least one second after its origin");
    let error = swarm
        .run_until(past, |event| matches!(event, SwarmEvent::PingFailed { .. }))
        .expect_err("skip cap must bound the expired-deadline scan");
    assert!(matches!(
        error,
        DriverError::EventBacklogExceeded { limit } if limit == RUN_UNTIL_SKIP_LIMIT
    ));

    assert_indexed_order(&swarm, total);
}

#[test]
fn run_until_under_cap_still_finds_match() {
    let peer_id = Ed25519Keypair::generate().peer_id();
    let mut swarm = idle_swarm();
    for i in 0..RUN_UNTIL_SKIP_LIMIT - 1 {
        swarm
            .core
            .state
            .events
            .push_back(indexed_stream_data(&peer_id, i as u64));
    }
    swarm.core.state.events.push_back(SwarmEvent::PeerReady {
        peer_id,
        conn_id: ConnectionId::new(1),
        protocols: Vec::new(),
    });

    let found = swarm
        .run_until(WaitDeadline::NEVER, |event| {
            matches!(event, SwarmEvent::PeerReady { .. })
        })
        .expect("wait")
        .expect("match just under the cap");
    assert!(matches!(found, SwarmEvent::PeerReady { .. }));
    assert_indexed_order(&swarm, RUN_UNTIL_SKIP_LIMIT - 1);
}

/// Deterministic, manually advanced clock shared between the swarm
/// driver and a mock transport.
#[derive(Default)]
struct TestClock {
    now_ms: AtomicU64,
}

impl TestClock {
    fn advance(&self, ms: u64) {
        self.now_ms.fetch_add(ms, Ordering::SeqCst);
    }

    fn now_ms(&self) -> u64 {
        self.now_ms.load(Ordering::SeqCst)
    }
}

/// Clock that jumps a full second on every read and counts reads, so a
/// test can tell one sample per drive iteration from several.
#[derive(Clone, Default)]
struct CountingClock {
    reads: Arc<AtomicU64>,
}

impl Clock for CountingClock {
    fn now(&mut self) -> Now {
        let read = self.reads.fetch_add(1, Ordering::SeqCst);
        Now::from_millis((read + 1) * 1_000)
    }
}

/// Adapts a shared [`TestClock`] to the platform [`Clock`] trait.
///
/// `Clock::now` takes `&mut self`, so the swarm owns one of these while
/// the test (and any mock transport) keeps its own handle on the same
/// underlying timeline.
#[derive(Clone)]
struct SharedClock(Arc<TestClock>);

impl Clock for SharedClock {
    fn now(&mut self) -> Now {
        Now::from_millis(self.0.now_ms())
    }
}

/// Readiness-capable transport simulating a remote peer that accepts any
/// multistream-select negotiation but never sends protocol data, so an
/// outbound ping dangles until its timeout.
struct NeverRespondTransport {
    events: VecDeque<TransportEvent>,
    negotiators: BTreeMap<StreamId, MultistreamSelect>,
    next_stream: u64,
}

impl NeverRespondTransport {
    fn connected(peer_id: PeerId) -> Self {
        let endpoint = ConnectionEndpoint::with_peer_id(Multiaddr::new(), peer_id);
        Self {
            events: VecDeque::from([TransportEvent::Connected {
                id: ConnectionId::new(1),
                endpoint: Box::new(endpoint),
            }]),
            negotiators: BTreeMap::new(),
            next_stream: 1,
        }
    }
}

impl Transport for NeverRespondTransport {
    fn ack_stream(
        &mut self,
        _id: ConnectionId,
        _stream_id: StreamId,
        _bytes: usize,
    ) -> Result<(), TransportError> {
        Ok(())
    }

    fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
        Err(TransportError::Unsupported { operation: "dial" })
    }

    fn listen(&mut self, _: &Multiaddr) -> Result<Multiaddr, TransportError> {
        Err(TransportError::Unsupported {
            operation: "listen",
        })
    }

    fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
        let stream_id = StreamId::new(self.next_stream);
        self.next_stream += 1;
        let mut listener = MultistreamSelect::listener(vec![
            IDENTIFY_PROTOCOL_ID.to_string(),
            PING_PROTOCOL_ID.to_string(),
        ]);
        listener.start();
        self.negotiators.insert(stream_id, listener);
        Ok(stream_id)
    }

    fn send_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
    ) -> Result<(), TransportError> {
        let Some(negotiator) = self.negotiators.get_mut(&stream_id) else {
            return Ok(());
        };
        negotiator.on_data(&data);
        let mut negotiated = false;
        let mut outbound = Vec::new();
        while let Some(output) = negotiator.poll_output() {
            match output {
                MultistreamOutput::OutboundData(bytes) => outbound.push(bytes),
                MultistreamOutput::Negotiated { .. } => negotiated = true,
                other => {
                    return Err(TransportError::PollError {
                        reason: format!("unexpected multistream output: {other:?}"),
                    });
                }
            }
        }
        if negotiated {
            self.negotiators.remove(&stream_id);
        }
        for data in outbound {
            self.events.push_back(TransportEvent::StreamData {
                id,
                stream_id,
                data: Bytes::from(data),
            });
        }
        Ok(())
    }

    fn close_stream_write(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Ok(())
    }

    fn reset_stream(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Ok(())
    }

    fn close(&mut self, _: ConnectionId) -> Result<(), TransportError> {
        Ok(())
    }

    fn poll(&mut self, _now: Now) -> Result<Vec<TransportEvent>, TransportError> {
        Ok(self.events.drain(..).collect())
    }
}

socketless!(NeverRespondTransport);

#[test]
fn poll_next_budget_respects_core_ping_timer() {
    const PING_TIMEOUT_MS: u64 = 5_000;

    let remote_peer = Ed25519Keypair::generate().peer_id();
    let keypair = Ed25519Keypair::generate();
    let identify = IdentifyConfig {
        protocol_version: "test/1".into(),
        agent_version: "test/1".into(),
        protocols: Vec::new(),
        public_key: keypair.public_key().encode_protobuf(),
    };
    let clock = Arc::new(TestClock::default());
    let transport = NeverRespondTransport::connected(remote_peer);
    let mut swarm = Swarm::with_clock(
        transport,
        identify,
        SwarmTimeouts {
            ping_ms: PING_TIMEOUT_MS,
            ..SwarmTimeouts::default()
        },
        keypair.peer_id(),
        Box::new(SharedClock(clock.clone())),
    )
    .expect("swarm attaches its transport");

    for _ in 0..5 {
        swarm.poll().expect("setup poll");
    }
    swarm.ping(&remote_peer).expect("queue ping");
    for _ in 0..5 {
        swarm.poll().expect("negotiate ping stream");
    }
    assert_eq!(
        swarm
            .core
            .state
            .next_deadline(Now::from_millis(clock.now_ms())),
        Some(minip2p_core::platform::Deadline::from_millis(
            clock.now_ms() + PING_TIMEOUT_MS
        )),
        "ping must be in flight with an armed core timer"
    );

    swarm.core.state.events.clear();
    let jumped = clock.clone();
    swarm.simulated_wait = Some(Box::new(move |_| jumped.advance(PING_TIMEOUT_MS + 1_000)));
    let event = swarm
        .poll_next(WaitDeadline::NEVER)
        .expect("poll")
        .expect("ping timeout event");
    assert!(matches!(
        event,
        SwarmEvent::PingFailed { peer_id, .. } if peer_id == remote_peer
    ));

    let waits = &swarm.wait_budgets;
    assert_eq!(waits.len(), 1, "one blocking wait resolves the timer");
    assert_eq!(
        waits[0],
        Duration::from_millis(PING_TIMEOUT_MS),
        "wait budget must shrink to the core's ping deadline instead of MAX_IDLE_WAIT"
    );
}
