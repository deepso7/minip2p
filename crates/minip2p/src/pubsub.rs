//! Std wiring that pumps a sans-I/O [`PubsubAgent`] against the
//! endpoint's swarm: clock sampling, action execution, and stream-event
//! interception. Mirrors the NAT driver (`crate::nat`).
//!
//! Available behind the `pubsub` cargo feature; see the pubsub methods on
//! [`Endpoint`](crate::Endpoint) and
//! [`EndpointBuilder::pubsub`](crate::EndpointBuilder::pubsub).

use std::collections::VecDeque;
use std::time::Instant;

use minip2p_pubsub::{PubsubAction, PubsubAgent, PubsubEvent};
use minip2p_swarm::SwarmEvent;

use crate::EndpointSwarm;

use crate::Error;

/// Errors from the [`Endpoint`](crate::Endpoint) pubsub methods.
///
/// The facade's [`Error`] is a re-exported swarm type and cannot grow
/// variants, so pubsub failures get their own enum wrapping it.
#[derive(Debug, thiserror::Error)]
pub enum PubsubError {
    /// Pubsub was not enabled on this endpoint
    /// ([`EndpointBuilder::pubsub`](crate::EndpointBuilder::pubsub)).
    #[error("pubsub is not enabled on this endpoint (EndpointBuilder::pubsub)")]
    NotEnabled,
    /// The topic is owned by the active discovery driver and cannot be
    /// withdrawn independently.
    #[error("cannot unsubscribe from the discovery topic while discovery is enabled")]
    DiscoveryTopicReserved,
    /// The publish was refused (topic validation, size, backpressure).
    #[error(transparent)]
    Publish(#[from] minip2p_pubsub::PublishError),
    /// The topic failed validation.
    #[error(transparent)]
    Topic(#[from] minip2p_pubsub::TopicError),
    /// The endpoint failed while driving the swarm.
    #[error(transparent)]
    Driver(#[from] Error),
}

/// Drives the configured [`PubsubAgent`] against the endpoint's swarm.
pub(crate) struct PubsubDriver {
    pub(crate) agent: PubsubAgent,
    /// Pubsub events awaiting the application (drained via
    /// `Endpoint::take_pubsub_events` / `next_pubsub_event`).
    pub(crate) events: VecDeque<PubsubEvent>,
    /// Monotonic epoch for the agent's `now_ms` clock.
    epoch: Instant,
}

impl PubsubDriver {
    pub(crate) fn new(agent: PubsubAgent) -> Self {
        Self {
            agent,
            events: VecDeque::new(),
            epoch: Instant::now(),
        }
    }

    /// Samples the driver's monotonic clock for the agent.
    pub(crate) fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// Feeds one swarm event to the agent and executes its cascade.
    ///
    /// Returns `true` when the event belongs to a pubsub stream and must
    /// not be forwarded to the application.
    pub(crate) fn ingest(&mut self, event: &SwarmEvent, swarm: &mut EndpointSwarm) -> bool {
        let handled = self.agent.handle_event(event, self.now_ms());
        self.pump(swarm);
        handled
    }

    /// Advances timers only when the agent reports a due deadline, then
    /// executes any resulting work.
    pub(crate) fn tick(&mut self, swarm: &mut EndpointSwarm) {
        let now_ms = self.now_ms();
        if self.agent.next_timeout(now_ms) != Some(0) {
            return;
        }
        self.agent.handle_tick(now_ms);
        self.pump(swarm);
    }

    /// Drains agent actions into swarm calls (echoing synchronous results
    /// back) and collects application-visible pubsub events.
    pub(crate) fn pump(&mut self, swarm: &mut EndpointSwarm) {
        loop {
            let mut progressed = false;
            while let Some(action) = self.agent.poll_action() {
                progressed = true;
                self.execute(action, swarm);
            }
            while let Some(event) = self.agent.poll_event() {
                progressed = true;
                self.events.push_back(event);
            }
            if !progressed {
                break;
            }
        }
    }

    fn execute(&mut self, action: PubsubAction, swarm: &mut EndpointSwarm) {
        match action {
            PubsubAction::OpenStream {
                token,
                peer,
                protocol_id,
            } => {
                let result = swarm
                    .open_stream(&peer, &protocol_id)
                    .map_err(|e| e.to_string());
                let now_ms = self.now_ms();
                self.agent.stream_open_result(&peer, token, result, now_ms);
            }
            PubsubAction::SendStream {
                token,
                peer,
                stream_id,
                data,
            } => {
                // A synchronously rejected write must reach the agent:
                // otherwise the stream's eventual close would commit work
                // whose frame was never accepted.
                let result = swarm
                    .send_stream(&peer, stream_id, data)
                    .map_err(|e| e.to_string());
                let now_ms = self.now_ms();
                self.agent
                    .send_result(&peer, stream_id, token, result, now_ms);
            }
            // A failed half-close after an accepted write is left to the
            // send deadline / close machinery: the frame may well have
            // been delivered, so failing the work here could double-report.
            PubsubAction::CloseStreamWrite { peer, stream_id } => {
                let _ = swarm.close_stream_write(&peer, stream_id);
            }
            PubsubAction::ResetStream { peer, stream_id } => {
                let _ = swarm.reset_stream(&peer, stream_id);
            }
        }
    }
}
