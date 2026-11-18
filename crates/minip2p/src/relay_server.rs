//! Drives the caller-driven relay-server service against the endpoint's
//! swarm, on either endpoint. Like every other capability it takes the
//! host's time sample and needs only `alloc`. The agent runs its commands on
//! the swarm itself (`SwarmCore` implements `RelaySwarm`), so the driver only
//! routes events and ticks and collects what the agent emits.
//!
//! A relay-mesh node (std with QUIC) also owns its [`Backbone`] here: the
//! agent then runs over a `MeshSwarm` of the public and backbone swarms, and
//! the driver polls the backbone each batch and feeds its events to the
//! agent too.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use minip2p_core::platform::{Deadline, EntropySource, Now};
#[cfg(feature = "quic")]
use minip2p_relay_server::mesh::MeshSwarm;
use minip2p_relay_server::{RelayServerAgent, RelayServerEvent};
#[cfg(feature = "quic")]
use minip2p_swarm::DriverError;
use minip2p_swarm::{SwarmCore, SwarmEvent};
use minip2p_transport::Transport;

#[cfg(feature = "quic")]
use crate::EndpointEvent;
#[cfg(feature = "quic")]
use crate::relay_mesh::Backbone;

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
    /// The transport address revision the listener addresses were last
    /// taken at.
    pub(crate) listeners_revision: Option<u64>,
    /// A relay-mesh node's backbone swarm.
    #[cfg(feature = "quic")]
    pub(crate) backbone: Option<Backbone>,
    /// Member links that came up or went down, queued after the agent's
    /// events.
    #[cfg(feature = "quic")]
    pub(crate) mesh_events: Vec<EndpointEvent>,
}

impl RelayServerDriver {
    pub(crate) fn new(agent: RelayServerAgent) -> Self {
        Self {
            agent,
            events: VecDeque::new(),
            listeners_revision: None,
            #[cfg(feature = "quic")]
            backbone: None,
            #[cfg(feature = "quic")]
            mesh_events: Vec::new(),
        }
    }

    /// Feeds one swarm event to the agent; returns whether it claimed it.
    /// A mesh node's backbone events come through here too.
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
        #[cfg(feature = "quic")]
        let claimed = match self.backbone.as_mut() {
            Some(backbone) => self.agent.handle_event(
                &mut MeshSwarm::new(swarm, &mut backbone.core),
                event,
                is_circuit,
                now,
            ),
            None => self.agent.handle_event(swarm, event, is_circuit, now),
        };
        #[cfg(not(feature = "quic"))]
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
            #[cfg(feature = "quic")]
            match self.backbone.as_mut() {
                Some(backbone) => self
                    .agent
                    .handle_tick(&mut MeshSwarm::new(swarm, &mut backbone.core), now),
                None => self.agent.handle_tick(swarm, now),
            }
            #[cfg(not(feature = "quic"))]
            self.agent.handle_tick(swarm, now);
            self.collect_agent_events();
        }
    }

    /// A mesh node's backbone batch: redials the members that are due, then
    /// feeds one backbone poll's events to the link bookkeeping and the
    /// agent. Nothing on the backbone reaches the application but member
    /// links coming up and going down.
    #[cfg(feature = "quic")]
    pub(crate) fn drive_backbone<T: Transport, E: EntropySource>(
        &mut self,
        swarm: &mut SwarmCore<T, E>,
        now: Now,
    ) -> Result<(), DriverError> {
        let Some(backbone) = self.backbone.as_mut() else {
            return Ok(());
        };
        self.events.extend(
            backbone
                .redial(now)
                .into_iter()
                .map(RelayServerEvent::Error),
        );
        let Some(backbone) = self.backbone.as_mut() else {
            return Ok(());
        };
        for event in backbone.core.poll(now)? {
            if let Some(backbone) = self.backbone.as_mut()
                && let Some(change) = backbone.observe(&event, now)
            {
                self.mesh_events.push(change);
            }
            self.ingest(&event, swarm, now);
        }
        Ok(())
    }

    /// When the agent's timers or a mesh member's redial are next due. The
    /// backbone swarm's own timers are [`Self::backbone_swarm_deadline`].
    pub(crate) fn next_deadline(&self, now: Now) -> Option<Deadline> {
        let agent = self.agent.next_deadline(now);
        #[cfg(feature = "quic")]
        let agent = Deadline::earliest_opt(
            agent,
            self.backbone.as_ref().and_then(Backbone::redial_deadline),
        );
        agent
    }

    /// When a mesh node's backbone swarm next has due work (a QUIC
    /// retransmission or keepalive, say), scheduled like the public swarm's.
    #[cfg(feature = "quic")]
    pub(crate) fn backbone_swarm_deadline(&self, now: Now) -> Option<Deadline> {
        self.backbone
            .as_ref()
            .and_then(|backbone| backbone.core.next_deadline(now))
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
