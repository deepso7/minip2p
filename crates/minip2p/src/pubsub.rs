//! Caller-driven Gossipsub capability shared by standard and portable
//! Endpoints. Time is supplied by the host; I/O runs through SwarmRuntime.

use alloc::collections::VecDeque;
use alloc::string::ToString;
use alloc::vec::Vec;

use minip2p_platform::EntropySource;
use minip2p_pubsub::{GossipsubAction, GossipsubAgent, GossipsubEvent, PublishError, TopicError};
#[cfg(any(feature = "std", feature = "smoltcp"))]
use minip2p_swarm::SwarmEvent;
use minip2p_swarm::{DriverError, SwarmRuntime};
use minip2p_transport::Transport;

/// Errors from endpoint pubsub methods.
///
/// The endpoint's [`DriverError`] is a re-exported swarm type and cannot grow
/// variants, so pubsub failures get their own enum wrapping it.
#[derive(Debug, thiserror::Error)]
pub enum GossipsubError {
    /// Gossipsub was not enabled on this endpoint.
    #[cfg(any(feature = "std", feature = "smoltcp"))]
    #[error("gossipsub is not enabled on this endpoint (gossipsub or discovery builder opt-in)")]
    NotEnabled,
    /// The topic is owned by the active discovery driver and cannot be
    /// withdrawn independently.
    #[error("cannot unsubscribe from the discovery topic while discovery is enabled")]
    DiscoveryTopicReserved,
    /// The publish was refused (topic validation, size, backpressure).
    #[error(transparent)]
    Publish(#[from] PublishError),
    /// The topic failed validation.
    #[error(transparent)]
    Topic(#[from] TopicError),
    /// The endpoint failed while driving the swarm.
    #[error(transparent)]
    Driver(#[from] DriverError),
}

/// Drives the configured [`GossipsubAgent`] against the endpoint's swarm.
pub(crate) struct GossipsubDriver {
    pub(crate) agent: GossipsubAgent,
    /// Gossipsub events awaiting the Endpoint event stream.
    pub(crate) events: VecDeque<GossipsubEvent>,
}

/// The `std`/`smoltcp` gates keep portable-mDNS-only builds from carrying
/// endpoint-facing methods nothing calls there; a `DiscoveryDriver` sweep
/// still names the type in its signature.
impl GossipsubDriver {
    #[cfg(any(feature = "std", feature = "smoltcp"))]
    pub(crate) fn new(agent: GossipsubAgent) -> Self {
        Self {
            agent,
            events: VecDeque::new(),
        }
    }

    /// How long the caller may idle before [`Self::tick`] has work: `0` when
    /// queued events or agent timers are due, `None` when nothing is.
    #[cfg(any(feature = "std", feature = "smoltcp"))]
    pub(crate) fn next_timeout(&self, now_ms: u64) -> Option<u64> {
        if !self.events.is_empty() {
            Some(0)
        } else {
            self.agent.next_timeout(now_ms)
        }
    }

    /// Subscribes to a topic and immediately flushes the announcement.
    /// Returns `Ok(false)` when already subscribed.
    #[cfg(any(feature = "std", feature = "smoltcp"))]
    pub(crate) fn subscribe<T: Transport, R: EntropySource>(
        &mut self,
        topic: &str,
        swarm: &mut SwarmRuntime<T, R>,
        now_ms: u64,
    ) -> Result<bool, TopicError> {
        let newly = self.agent.subscribe(topic, now_ms)?;
        self.pump(swarm, now_ms);
        Ok(newly)
    }

    /// Withdraws a subscription and flushes the change. Returns `false` when
    /// not subscribed. `reserved` names a driver-owned topic (discovery's
    /// beacon topic) that applications cannot withdraw or publish to.
    #[cfg(any(feature = "std", feature = "smoltcp"))]
    pub(crate) fn unsubscribe<T: Transport, R: EntropySource>(
        &mut self,
        topic: &str,
        reserved: Option<&str>,
        swarm: &mut SwarmRuntime<T, R>,
        now_ms: u64,
    ) -> Result<bool, GossipsubError> {
        if reserved == Some(topic) {
            return Err(GossipsubError::DiscoveryTopicReserved);
        }
        let removed = self.agent.unsubscribe(topic, now_ms);
        self.pump(swarm, now_ms);
        Ok(removed)
    }

    /// Publishes one message and flushes its outbound frames. `reserved`
    /// names a driver-owned topic applications cannot publish to.
    pub(crate) fn publish<T: Transport, R: EntropySource>(
        &mut self,
        topic: &str,
        data: Vec<u8>,
        reserved: Option<&str>,
        swarm: &mut SwarmRuntime<T, R>,
        now_ms: u64,
    ) -> Result<(), GossipsubError> {
        if reserved == Some(topic) {
            return Err(GossipsubError::DiscoveryTopicReserved);
        }
        self.agent.publish(topic, data, now_ms)?;
        self.pump(swarm, now_ms);
        Ok(())
    }

    /// Removes every queued event `f` claims, returning `true` when it
    /// claimed any. Cross-driver sweeps lift their traffic out of the
    /// application queue with this before the Endpoint drains it.
    #[cfg(any(feature = "discovery", feature = "mdns", feature = "portable-mdns"))]
    pub(crate) fn extract_events(&mut self, mut f: impl FnMut(&GossipsubEvent) -> bool) -> bool {
        let mut claimed = false;
        let mut retained = VecDeque::new();
        while let Some(event) = self.events.pop_front() {
            if f(&event) {
                claimed = true;
            } else {
                retained.push_back(event);
            }
        }
        self.events = retained;
        claimed
    }

    /// Feeds one swarm event to the agent and executes its cascade.
    ///
    /// Returns `true` when the event belongs to a pubsub stream and must
    /// not be forwarded to the application.
    #[cfg(any(feature = "std", feature = "smoltcp"))]
    pub(crate) fn ingest<T: Transport, R: EntropySource>(
        &mut self,
        event: &SwarmEvent,
        swarm: &mut SwarmRuntime<T, R>,
        now_ms: u64,
    ) -> bool {
        let handled = self.agent.handle_event(event, now_ms);
        self.pump(swarm, now_ms);
        handled
    }

    /// Advances timers only when the agent reports a due deadline, then
    /// executes any resulting work.
    #[cfg(any(feature = "std", feature = "smoltcp"))]
    pub(crate) fn tick<T: Transport, R: EntropySource>(
        &mut self,
        swarm: &mut SwarmRuntime<T, R>,
        now_ms: u64,
    ) {
        if self.agent.next_timeout(now_ms) != Some(0) {
            return;
        }
        self.agent.handle_tick(now_ms);
        self.pump(swarm, now_ms);
    }

    /// Moves events still inside the agent into the queue. Terminal
    /// shutdown calls this before draining: collecting needs no swarm turn.
    #[cfg(feature = "smoltcp")]
    pub(crate) fn collect_agent_events(&mut self) {
        while let Some(event) = self.agent.poll_event() {
            self.events.push_back(event);
        }
    }

    /// Drains agent actions into swarm calls (echoing synchronous results
    /// back) and collects application-visible pubsub events.
    pub(crate) fn pump<T: Transport, R: EntropySource>(
        &mut self,
        swarm: &mut SwarmRuntime<T, R>,
        now_ms: u64,
    ) {
        loop {
            let mut progressed = false;
            while let Some(action) = self.agent.poll_action() {
                progressed = true;
                self.execute(action, swarm, now_ms);
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

    fn execute<T: Transport, R: EntropySource>(
        &mut self,
        action: GossipsubAction,
        swarm: &mut SwarmRuntime<T, R>,
        now_ms: u64,
    ) {
        match action {
            GossipsubAction::OpenStream {
                token,
                peer,
                protocol_id,
            } => {
                let result = swarm
                    .open_stream(&peer, &protocol_id, now_ms)
                    .map_err(|e| e.to_string());
                self.agent.stream_open_result(&peer, token, result, now_ms);
            }
            GossipsubAction::SendStream {
                token,
                peer,
                stream_id,
                data,
            } => {
                // A synchronously rejected write must reach the agent:
                // otherwise the stream's eventual close would commit work
                // whose frame was never accepted.
                let result = swarm
                    .send_stream(&peer, stream_id, data, now_ms)
                    .map_err(|e| e.to_string());
                self.agent
                    .send_result(&peer, stream_id, token, result, now_ms);
            }
            // A failed half-close after an accepted write is left to the
            // send deadline / close machinery: the frame may well have
            // been delivered, so failing the work here could double-report.
            GossipsubAction::CloseStreamWrite { peer, stream_id } => {
                match swarm.close_stream_write(&peer, stream_id, now_ms) {
                    Ok(()) | Err(_) => {}
                }
            }
            GossipsubAction::ResetStream { peer, stream_id } => {
                // A reset races ordinary teardown, so an already-closed
                // stream is successful cleanup rather than a second error.
                match swarm.reset_stream(&peer, stream_id, now_ms) {
                    Ok(()) | Err(_) => {}
                }
            }
        }
    }
}
