//! Std wiring that pumps a sans-I/O [`NatAgent`] against the endpoint's
//! swarm: clock sampling, action execution, stream-event interception, and
//! circuit-address advertising.
//!
//! Available behind the `nat` cargo feature; see the `nat` methods on
//! [`Endpoint`](crate::Endpoint) and [`EndpointBuilder`](crate::EndpointBuilder).

use std::collections::VecDeque;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use minip2p_core::{Multiaddr, PeerId, Protocol};
use minip2p_nat::{NatAction, NatAgent, NatEvent, Now};
use minip2p_quic::QuicEndpoint;
use minip2p_swarm::{Swarm, SwarmEvent};
use minip2p_transport::StreamId;

/// Drives a [`NatAgent`] against the endpoint's swarm.
pub(crate) struct NatDriver {
    pub(crate) agent: NatAgent,
    /// NAT events awaiting the application (drained via
    /// `Endpoint::take_nat_events` / `next_nat_event` / `wait_path`).
    pub(crate) events: VecDeque<NatEvent>,
    /// Monotonic epoch for the agent's `mono_ms` clock.
    epoch: Instant,
    /// Relays we hold a reservation on, for circuit-address advertising.
    reserved_relays: Vec<(PeerId, Multiaddr)>,
    /// Relay transport addresses by peer, captured at construction.
    relay_addrs: Vec<(PeerId, Multiaddr)>,
}

impl NatDriver {
    pub(crate) fn new(agent: NatAgent, relay_addrs: Vec<(PeerId, Multiaddr)>) -> Self {
        Self {
            agent,
            events: VecDeque::new(),
            epoch: Instant::now(),
            reserved_relays: Vec::new(),
            relay_addrs,
        }
    }

    /// Samples the driver's clocks for the agent.
    pub(crate) fn now(&self) -> Now {
        Now {
            mono_ms: self.epoch.elapsed().as_millis() as u64,
            unix_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs()),
        }
    }

    /// Feeds one swarm event to the agent and executes its cascade.
    ///
    /// Returns `true` when the event belongs to an agent-owned stream and
    /// must not be forwarded to the application. Ownership is checked both
    /// before and after the agent runs, so a stream claimed *during* the
    /// event (an inbound STOP) and one released *by* the event (a close)
    /// are both consumed.
    pub(crate) fn ingest(&mut self, event: &SwarmEvent, swarm: &mut Swarm<QuicEndpoint>) -> bool {
        let owned_before =
            stream_key(event).is_some_and(|(peer, stream)| self.agent.owns_stream(peer, stream));
        let now = self.now();
        self.agent.handle_event(event, now);
        let owned_after =
            stream_key(event).is_some_and(|(peer, stream)| self.agent.owns_stream(peer, stream));
        self.pump(swarm);
        owned_before || owned_after
    }

    /// Advances the agent's timers and executes any resulting work.
    pub(crate) fn tick(&mut self, swarm: &mut Swarm<QuicEndpoint>) {
        self.agent.handle_tick(self.now());
        self.pump(swarm);
    }

    /// Drains agent actions into swarm calls (echoing synchronous results
    /// back) and collects application-visible NAT events.
    pub(crate) fn pump(&mut self, swarm: &mut Swarm<QuicEndpoint>) {
        loop {
            let mut progressed = false;
            while let Some(action) = self.agent.poll_action() {
                progressed = true;
                self.execute(action, swarm);
            }
            while let Some(event) = self.agent.poll_event() {
                progressed = true;
                self.observe(&event, swarm);
                self.events.push_back(event);
            }
            if !progressed {
                break;
            }
        }
    }

    fn execute(&mut self, action: NatAction, swarm: &mut Swarm<QuicEndpoint>) {
        let now = self.now();
        match action {
            NatAction::Dial { token, addr } => {
                let result = swarm.dial(&addr).map_err(|e| e.to_string());
                self.agent.dial_result(token, result, now);
            }
            NatAction::OpenStream {
                token,
                peer,
                protocol_id,
            } => {
                let result = swarm
                    .open_stream(&peer, &protocol_id)
                    .map_err(|e| e.to_string());
                self.agent.stream_open_result(token, result, now);
            }
            NatAction::SendStream {
                peer,
                stream_id,
                data,
            } => {
                // Failures surface through the agent's own timeouts and the
                // swarm's error events; nothing to echo synchronously.
                let _ = swarm.send_stream(&peer, stream_id, data);
            }
            NatAction::CloseStreamWrite { peer, stream_id } => {
                let _ = swarm.close_stream_write(&peer, stream_id);
            }
            NatAction::ResetStream { peer, stream_id } => {
                let _ = swarm.reset_stream(&peer, stream_id);
            }
            NatAction::Disconnect { peer } => {
                let _ = swarm.disconnect(&peer);
            }
            NatAction::SendRandomUdp {
                target,
                payload_len,
            } => {
                let mut payload = vec![0u8; payload_len];
                if getrandom::fill(&mut payload).is_ok() {
                    let _ = swarm.transport().send_raw_udp(&target, &payload);
                }
            }
        }
    }

    /// Keeps Identify's advertised set in sync with reservation state: a
    /// held reservation advertises `<relay>/p2p/<relay-id>/p2p-circuit`.
    fn observe(&mut self, event: &NatEvent, swarm: &mut Swarm<QuicEndpoint>) {
        match event {
            NatEvent::RelayReserved { relay, .. } => {
                if self.reserved_relays.iter().any(|(peer, _)| peer == relay) {
                    return; // renewal — already advertised
                }
                let Some((_, transport)) = self.relay_addrs.iter().find(|(p, _)| p == relay) else {
                    return;
                };
                let mut circuit = transport.clone();
                circuit.push(Protocol::P2p(relay.clone()));
                circuit.push(Protocol::P2pCircuit);
                self.reserved_relays.push((relay.clone(), circuit));
                self.advertise(swarm);
            }
            NatEvent::RelayReservationLost { relay } => {
                let before = self.reserved_relays.len();
                self.reserved_relays.retain(|(peer, _)| peer != relay);
                if self.reserved_relays.len() != before {
                    self.advertise(swarm);
                }
            }
            _ => {}
        }
    }

    fn advertise(&self, swarm: &mut Swarm<QuicEndpoint>) {
        swarm.set_external_addresses(
            self.reserved_relays
                .iter()
                .map(|(_, addr)| addr.clone())
                .collect(),
        );
    }
}

/// The (peer, stream) a stream-scoped swarm event refers to.
fn stream_key(event: &SwarmEvent) -> Option<(&PeerId, StreamId)> {
    match event {
        SwarmEvent::StreamReady {
            peer_id, stream_id, ..
        }
        | SwarmEvent::StreamData {
            peer_id, stream_id, ..
        }
        | SwarmEvent::StreamRemoteWriteClosed { peer_id, stream_id }
        | SwarmEvent::StreamClosed { peer_id, stream_id } => Some((peer_id, *stream_id)),
        _ => None,
    }
}
