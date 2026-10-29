//! Drives the caller-driven relay-server service against the endpoint's
//! swarm, on either endpoint. Like every other capability it takes the
//! host's time sample and needs only `alloc`. The agent runs its commands on
//! the swarm itself (`SwarmCore` implements `RelaySwarm`), so the driver only
//! routes events and ticks and collects what the agent emits.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use minip2p_core::platform::{EntropySource, Now};
use minip2p_relay_server::{RelayServerAgent, RelayServerEvent};
use minip2p_swarm::{SwarmCore, SwarmEvent};
use minip2p_transport::Transport;

/// Synchronous relay-server runtime control failure.
#[derive(Debug, thiserror::Error)]
pub enum RelayServerControlError {
    /// This endpoint was not built with relay-server enablement.
    #[error("relay server is not configured")]
    NotConfigured,
    /// The complete replacement contained an invalid address and was not applied.
    #[error("invalid relay-server address: {0}")]
    InvalidAddress(#[source] minip2p_relay_server::RelayServerAddressError),
}

pub(crate) struct RelayServerDriver {
    pub(crate) agent: RelayServerAgent,
    pub(crate) events: VecDeque<RelayServerEvent>,
}

impl RelayServerDriver {
    pub(crate) fn new(agent: RelayServerAgent) -> Self {
        Self {
            agent,
            events: VecDeque::new(),
        }
    }

    /// Feeds one swarm event to the agent; returns whether it claimed it.
    pub(crate) fn ingest<T: Transport, E: EntropySource>(
        &mut self,
        event: &SwarmEvent,
        swarm: &mut SwarmCore<T, E>,
        now: Now,
    ) -> bool {
        let is_circuit = match event {
            SwarmEvent::ConnectionEstablished { conn_id, .. }
            | SwarmEvent::ConnectionClosed { conn_id, .. }
            | SwarmEvent::StreamReady { conn_id, .. }
            | SwarmEvent::StreamData { conn_id, .. }
            | SwarmEvent::StreamRemoteWriteClosed { conn_id, .. }
            | SwarmEvent::StreamWriteStopped { conn_id, .. }
            | SwarmEvent::StreamClosed { conn_id, .. } => conn_id.is_circuit(),
            // The agent's flag describes the connection taking the slot.
            SwarmEvent::ConnectionReplaced { new, .. } => new.is_circuit(),
            _ => false,
        };
        // The first event at this time sample runs the agent's deadline sweep
        // before dispatch, preserving deadline-first ordering for the batch.
        let claimed = self.agent.handle_event(swarm, event, is_circuit, now);
        self.collect_agent_events();
        claimed
    }

    /// Runs the agent's due deadlines.
    pub(crate) fn tick<T: Transport, E: EntropySource>(
        &mut self,
        swarm: &mut SwarmCore<T, E>,
        now: Now,
    ) {
        if self
            .agent
            .next_deadline(now)
            .is_some_and(|due| due.is_expired_at(now))
        {
            self.agent.handle_tick(swarm, now);
            self.collect_agent_events();
        }
    }

    /// Moves the events the agent queued (including outside an ingest or
    /// tick, such as an address refresh's `AddrsRejected`) into the
    /// driver's queue.
    pub(crate) fn collect_agent_events(&mut self) {
        while let Some(event) = self.agent.poll_event() {
            self.events.push_back(event);
        }
    }
}

/// The bound addresses a relay server may announce: wildcards are dropped,
/// since a peer cannot dial `0.0.0.0` or `::`.
pub(crate) fn concrete_relay_listener_addrs(
    addrs: Vec<minip2p_core::Multiaddr>,
) -> Vec<minip2p_core::Multiaddr> {
    use minip2p_core::Protocol;
    addrs
        .into_iter()
        .filter(|address| {
            !matches!(address.iter().next(), Some(Protocol::Ip4(ip)) if *ip == [0; 4])
                && !matches!(address.iter().next(), Some(Protocol::Ip6(ip)) if *ip == [0; 16])
        })
        .collect()
}
