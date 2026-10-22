//! A real DCUtR punch whose connection is settled on ahead of its own event.
//!
//! Two loopback Endpoints punch through the loopback relay, and a gate under
//! the initiator's QUIC transport makes both punch dials land in one
//! transport batch. The batch replaces the circuit with the first punch, then
//! that punch with the second. Seeing the first replacement, the Connection
//! engine settles on the second punch, which already holds the peer's slot,
//! before its own event is ingested. NAT records that punch only on that
//! event, so the settle is `Punched` only if the Endpoint names its path
//! after NAT has seen it.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use minip2p_core::platform::{Deadline, Now};
use minip2p_core::{Bytes, Multiaddr, Path, PeerAddr, PeerId, TransportKind};
use minip2p_quic::{QuicNodeConfig, QuicTransport};
use minip2p_transport::{
    ConnectionId, StreamId, Transport, TransportError, TransportEvent, TransportSet,
};

use super::NextEvent;
use super::nat_tests::relay_support;
use crate::{
    ConnectOutcome, Ed25519Keypair, Endpoint, EndpointEvent, NatConfig, NatEvent, ReservationPolicy,
};

/// What the gate held and the order it let the punches through in.
#[derive(Default)]
struct GateState {
    /// Connections dialed to the gated peer.
    dialed: BTreeSet<ConnectionId>,
    held: Vec<TransportEvent>,
    /// Set once both punches went through: the replaced one, then the kept.
    released: Option<[ConnectionId; 2]>,
}

/// Holds every event of the dials to `peer` until two of them are
/// connected, then hands both to the swarm in one poll, the higher token
/// first: the swarm keeps the lower token of two same-direction dials, so
/// the second replaces the first.
struct PunchGate<T> {
    inner: T,
    peer: PeerId,
    state: Arc<Mutex<GateState>>,
}

impl<T> PunchGate<T> {
    fn state(&self) -> MutexGuard<'_, GateState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The connection an event is about, if any.
fn event_connection(event: &TransportEvent) -> Option<ConnectionId> {
    match event {
        TransportEvent::Connected { id, .. }
        | TransportEvent::StreamOpened { id, .. }
        | TransportEvent::IncomingStream { id, .. }
        | TransportEvent::StreamData { id, .. }
        | TransportEvent::StreamWritable { id, .. }
        | TransportEvent::StreamRemoteWriteClosed { id, .. }
        | TransportEvent::StreamWriteStopped { id, .. }
        | TransportEvent::StreamClosed { id, .. }
        | TransportEvent::Closed { id, .. }
        | TransportEvent::Error { id, .. }
        | TransportEvent::IncomingConnection { id, .. }
        | TransportEvent::PeerIdentityVerified { id, .. } => Some(*id),
        TransportEvent::Listening { .. } => None,
    }
}

impl<T: Transport> Transport for PunchGate<T> {
    fn dial(&mut self, addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        let id = self.inner.dial(addr)?;
        if *addr.peer_id() == self.peer {
            self.state().dialed.insert(id);
        }
        Ok(id)
    }
    fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, TransportError> {
        self.inner.listen(addr)
    }
    fn open_stream(&mut self, id: ConnectionId) -> Result<StreamId, TransportError> {
        self.inner.open_stream(id)
    }
    fn send_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
    ) -> Result<(), TransportError> {
        self.inner.send_stream(id, stream_id, data)
    }
    fn close_stream_write(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        self.inner.close_stream_write(id, stream_id)
    }
    fn reset_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        self.inner.reset_stream(id, stream_id)
    }
    fn ack_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        bytes: usize,
    ) -> Result<(), TransportError> {
        self.inner.ack_stream(id, stream_id, bytes)
    }
    fn set_control_stream(&mut self, id: ConnectionId, stream_id: StreamId, control: bool) {
        self.inner.set_control_stream(id, stream_id, control);
    }
    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        self.inner.close(id)
    }
    fn poll(&mut self, now: Now) -> Result<Vec<TransportEvent>, TransportError> {
        let events = self.inner.poll(now)?;
        let mut state = self.state();
        if state.released.is_some() {
            return Ok(events);
        }
        let (held, mut events): (Vec<_>, Vec<_>) = events.into_iter().partition(|event| {
            event_connection(event).is_some_and(|id| state.dialed.contains(&id))
        });
        state.held.extend(held);
        let mut connected: Vec<_> = state
            .held
            .iter()
            .filter_map(|event| match event {
                TransportEvent::Connected { id, endpoint } => Some((endpoint.token(), *id)),
                _ => None,
            })
            .collect();
        connected.sort_by_key(|&(token, _)| core::cmp::Reverse(token));
        if let [(_, replaced), (_, kept)] = connected[..] {
            let mut held = core::mem::take(&mut state.held);
            // Both connections come up first, replaced then kept; the rest
            // keeps its order behind them.
            held.sort_by_key(|event| match event {
                TransportEvent::Connected { id, .. } => usize::from(*id == kept),
                _ => 2,
            });
            events.extend(held);
            state.released = Some([replaced, kept]);
        }
        Ok(events)
    }
    fn next_deadline(&self) -> Option<Deadline> {
        self.inner.next_deadline()
    }
    fn local_addresses(&self) -> Vec<Multiaddr> {
        self.inner.local_addresses()
    }
    fn local_addresses_revision(&self) -> Option<u64> {
        self.inner.local_addresses_revision()
    }
    fn active_inbound_connection_sources(&self) -> Vec<Multiaddr> {
        self.inner.active_inbound_connection_sources()
    }
    fn send_datagram(&mut self, target: &Multiaddr, payload: &[u8]) -> Result<(), TransportError> {
        self.inner.send_datagram(target, payload)
    }
}

impl<T: minip2p_transport::PollSource> minip2p_transport::PollSource for PunchGate<T> {
    fn attach(
        &mut self,
        registry: minip2p_transport::mio::Registry,
        tokens: minip2p_transport::TokenSpace,
        waker: Arc<minip2p_transport::mio::Waker>,
    ) -> std::io::Result<()> {
        self.inner.attach(registry, tokens, waker)
    }
    fn dispatch(&mut self, event: &minip2p_transport::mio::event::Event) {
        self.inner.dispatch(event);
    }
}

/// Loopback is not global unicast: both sides must opt in to punch it.
fn punch_config(reservation_policy: ReservationPolicy) -> NatConfig {
    NatConfig {
        reservation_policy,
        allow_private_punch_targets: true,
        ..NatConfig::default()
    }
}

/// Both loopback families, so the responder advertises two punch targets
/// and the initiator can dial both.
const LOOPBACK_QUIC_ADDRS: [&str; 2] = ["/ip4/127.0.0.1/udp/0/quic-v1", "/ip6/::1/udp/0/quic-v1"];

/// An initiator whose dials to `peer` go through a [`PunchGate`].
fn gated_initiator(relay: PeerAddr, peer: PeerId) -> (Endpoint, Arc<Mutex<GateState>>) {
    let keypair = Ed25519Keypair::generate();
    let addrs: Vec<Multiaddr> = LOOPBACK_QUIC_ADDRS
        .iter()
        .map(|a| a.parse().expect("addr"))
        .collect();
    let quic = QuicTransport::bind(QuicNodeConfig::new(keypair.clone()), &addrs).expect("bind");
    let namespaces = quic.namespaces();
    let state = Arc::default();
    let gate = PunchGate {
        inner: quic,
        peer,
        state: Arc::clone(&state),
    };
    let mut set = TransportSet::new();
    set.insert(TransportKind::Quic, namespaces, Box::new(gate))
        .map_err(|rejected| rejected.error().clone())
        .expect("member");
    let builder = Endpoint::builder()
        .relay(relay)
        .nat_config(punch_config(ReservationPolicy::Never));
    let mut endpoint = super::build_endpoint(builder, keypair, set).expect("builds");
    endpoint
        .engine
        .core
        .listen_on_bound_addrs()
        .expect("listens");
    (endpoint, state)
}

#[test]
fn a_punch_settled_on_ahead_of_its_event_is_punched() {
    let relay = relay_support::RelayServer::spawn();
    let mut responder = LOOPBACK_QUIC_ADDRS
        .iter()
        .try_fold(
            Endpoint::builder()
                .relay(relay.addr().clone())
                .nat_config(punch_config(ReservationPolicy::Always)),
            |builder, addr| builder.listen_on(*addr),
        )
        .expect("listen addresses")
        .bind()
        .expect("bind responder");
    let responder_peer = responder.peer_id().clone();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        assert!(Instant::now() < deadline, "responder did not reserve");
        if let Some(EndpointEvent::Nat(NatEvent::RelayReserved { .. })) = responder
            .next_event(Duration::from_millis(20))
            .expect("drive responder")
        {
            break;
        }
        relay.assert_healthy();
    }

    let (mut initiator, gate_state) = gated_initiator(relay.addr().clone(), responder_peer.clone());
    // No candidates: every dial to the responder is a punch.
    let connect_id = initiator.connect(&responder_peer).expect("connect starts");
    let mut trace = Vec::new();
    let mut upgraded_to = None;
    let outcome = loop {
        assert!(
            Instant::now() < deadline,
            "connect did not settle:\n{trace:#?}"
        );
        if let Some(event) = initiator
            .next_event(Duration::from_millis(20))
            .expect("drive initiator")
        {
            trace.push(format!("initiator: {event:?}"));
            match event {
                EndpointEvent::Nat(NatEvent::PathUpgraded {
                    connect_id: id,
                    to: Path::Punched,
                    new_conn_id,
                    ..
                }) if id == connect_id => upgraded_to = Some(new_conn_id),
                EndpointEvent::ConnectSettled {
                    connect_id: id,
                    outcome,
                    ..
                } if id == connect_id => break outcome,
                _ => {}
            }
        }
        if let Some(event) = responder
            .next_event(Duration::from_millis(20))
            .expect("drive responder")
        {
            trace.push(format!("responder: {event:?}"));
        }
        relay.assert_healthy();
    };

    let gate_state = gate_state.lock().unwrap_or_else(PoisonError::into_inner);
    let [replaced, kept] = gate_state
        .released
        .unwrap_or_else(|| panic!("the two punches never landed together:\n{trace:#?}"));
    assert_eq!(
        upgraded_to,
        Some(replaced),
        "NAT should report the first punch replacing the circuit:\n{trace:#?}"
    );
    assert_eq!(
        outcome,
        ConnectOutcome::Connected {
            conn_id: kept,
            path: Path::Punched,
        },
        "{trace:#?}"
    );
    assert_eq!(initiator.path(&responder_peer), Some(Path::Punched));
}
