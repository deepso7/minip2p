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
    /// Direct public addresses confirmed by AutoNAT.
    public_addrs: Vec<Multiaddr>,
}

impl NatDriver {
    pub(crate) fn new(agent: NatAgent, relay_addrs: Vec<(PeerId, Multiaddr)>) -> Self {
        Self {
            agent,
            events: VecDeque::new(),
            epoch: Instant::now(),
            reserved_relays: Vec::new(),
            relay_addrs,
            public_addrs: Vec::new(),
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
    /// Returns `true` when the event belongs to the NAT control plane and
    /// must not be forwarded to the application. The agent's disposition is
    /// authoritative even when handling claims or releases the stream.
    pub(crate) fn ingest(&mut self, event: &SwarmEvent, swarm: &mut Swarm<QuicEndpoint>) -> bool {
        let now = self.now();
        let handled = self.agent.handle_event_with_disposition(event, now);
        self.pump(swarm);
        handled
    }

    /// Advances timers only when the agent reports a due deadline, then
    /// executes any resulting work.
    pub(crate) fn tick(&mut self, swarm: &mut Swarm<QuicEndpoint>) {
        let now = self.now();
        if self.agent.next_timeout(now.mono_ms) != Some(0) {
            return;
        }
        self.agent.handle_tick(now);
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
            NatEvent::ReachabilityChanged {
                confirmed_addrs, ..
            } => {
                if self.public_addrs != *confirmed_addrs {
                    self.public_addrs = confirmed_addrs.clone();
                    self.advertise(swarm);
                }
            }
            NatEvent::PublicAddressesChanged { addrs } if self.public_addrs != *addrs => {
                self.public_addrs = addrs.clone();
                self.advertise(swarm);
            }
            _ => {}
        }
    }

    fn advertise(&self, swarm: &mut Swarm<QuicEndpoint>) {
        let mut addrs = self.public_addrs.clone();
        for (_, addr) in &self.reserved_relays {
            if !addrs.contains(addr) {
                addrs.push(addr.clone());
            }
        }
        swarm.set_external_addresses(addrs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Endpoint, NatConfig, ReachabilityState};

    #[test]
    fn confirmed_public_addresses_are_advertised_and_cleared() {
        let mut endpoint = Endpoint::builder()
            .nat_config(NatConfig::default())
            .bind_quic("127.0.0.1:0")
            .expect("bind endpoint");
        let public: Multiaddr = "/ip4/203.0.113.9/udp/4001/quic-v1"
            .parse()
            .expect("public addr");
        let Endpoint { swarm, nat, .. } = &mut endpoint;
        let driver = nat.as_mut().expect("NAT configured");

        driver.observe(
            &NatEvent::ReachabilityChanged {
                old: ReachabilityState::Unknown,
                new: ReachabilityState::Public,
                confirmed_addrs: vec![public.clone()],
            },
            swarm,
        );
        swarm.poll().expect("refresh identify addresses");
        assert!(swarm.core().local_addresses().contains(&public));

        driver.observe(
            &NatEvent::ReachabilityChanged {
                old: ReachabilityState::Public,
                new: ReachabilityState::Private,
                confirmed_addrs: Vec::new(),
            },
            swarm,
        );
        swarm.poll().expect("refresh identify addresses");
        assert!(!swarm.core().local_addresses().contains(&public));
    }
}
