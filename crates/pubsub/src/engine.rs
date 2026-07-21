//! Static dispatch across the supported pubsub routing engines.

use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::PeerId;
use minip2p_identity::Ed25519Keypair;
use minip2p_swarm::SwarmEvent;
use minip2p_transport::StreamId;

use crate::{
    FLOODSUB_PROTOCOL_ID, FloodsubAgent, FloodsubConfig, GossipsubAgent, GossipsubConfig,
    MESHSUB_PROTOCOL_ID_V10, MESHSUB_PROTOCOL_ID_V11, PublishError, PubsubAction,
    PubsubConfigError, PubsubEvent, PubsubToken, TopicError,
};

const FLOODSUB_PROTOCOLS: &[&str] = &[FLOODSUB_PROTOCOL_ID];
const GOSSIPSUB_PROTOCOLS: &[&str] = &[MESHSUB_PROTOCOL_ID_V11, MESHSUB_PROTOCOL_ID_V10];

/// Selects and configures the pubsub routing engine.
#[derive(Clone, Debug)]
pub enum PubsubConfig {
    /// Mesh-based gossipsub routing.
    Gossipsub(GossipsubConfig),
    /// Flood-to-all-subscribers floodsub routing.
    Floodsub(FloodsubConfig),
}

impl Default for PubsubConfig {
    fn default() -> Self {
        Self::Gossipsub(GossipsubConfig::default())
    }
}

impl From<GossipsubConfig> for PubsubConfig {
    fn from(config: GossipsubConfig) -> Self {
        Self::Gossipsub(config)
    }
}

impl From<FloodsubConfig> for PubsubConfig {
    fn from(config: FloodsubConfig) -> Self {
        Self::Floodsub(config)
    }
}

impl PubsubConfig {
    /// Protocol ids this engine must advertise, in preference order.
    pub fn protocol_ids(&self) -> &'static [&'static str] {
        match self {
            Self::Gossipsub(_) => GOSSIPSUB_PROTOCOLS,
            Self::Floodsub(_) => FLOODSUB_PROTOCOLS,
        }
    }

    /// Validates engine-specific configuration.
    pub fn validate(&self) -> Result<(), PubsubConfigError> {
        match self {
            Self::Gossipsub(config) => config.validate(),
            Self::Floodsub(_) => Ok(()),
        }
    }
}

/// A statically dispatched pubsub router.
// Keeping both concrete agents inline preserves the no-allocation dispatch
// contract; their size difference is modest and this object is long-lived.
#[allow(clippy::large_enum_variant)]
pub enum PubsubAgent {
    /// Gossipsub router.
    Gossipsub(GossipsubAgent),
    /// Floodsub router.
    Floodsub(FloodsubAgent),
}

impl PubsubAgent {
    /// Validates `config` and constructs its selected engine.
    pub fn new(
        keypair: Ed25519Keypair,
        config: PubsubConfig,
        initial_seqno: u64,
        entropy_seed: u64,
    ) -> Result<Self, PubsubConfigError> {
        config.validate()?;
        Ok(match config {
            PubsubConfig::Gossipsub(config) => Self::Gossipsub(GossipsubAgent::new(
                keypair,
                config,
                initial_seqno,
                entropy_seed,
            )),
            PubsubConfig::Floodsub(config) => {
                let _ = entropy_seed;
                Self::Floodsub(FloodsubAgent::new(keypair, config, initial_seqno))
            }
        })
    }

    /// The peer id this agent publishes as.
    pub fn local_peer_id(&self) -> &PeerId {
        match self {
            Self::Gossipsub(agent) => agent.local_peer_id(),
            Self::Floodsub(agent) => agent.local_peer_id(),
        }
    }

    /// Our current subscriptions.
    pub fn subscriptions(&self) -> Vec<String> {
        match self {
            Self::Gossipsub(agent) => agent.subscriptions(),
            Self::Floodsub(agent) => agent.subscriptions(),
        }
    }

    /// Subscribes to a topic.
    pub fn subscribe(&mut self, topic: &str, now_ms: u64) -> Result<bool, TopicError> {
        match self {
            Self::Gossipsub(agent) => agent.subscribe(topic, now_ms),
            Self::Floodsub(agent) => agent.subscribe(topic, now_ms),
        }
    }

    /// Unsubscribes from a topic.
    pub fn unsubscribe(&mut self, topic: &str, now_ms: u64) -> bool {
        match self {
            Self::Gossipsub(agent) => agent.unsubscribe(topic, now_ms),
            Self::Floodsub(agent) => agent.unsubscribe(topic, now_ms),
        }
    }

    /// Publishes a message.
    pub fn publish(&mut self, topic: &str, data: Vec<u8>, now_ms: u64) -> Result<(), PublishError> {
        match self {
            Self::Gossipsub(agent) => agent.publish(topic, data, now_ms),
            Self::Floodsub(agent) => agent.publish(topic, data, now_ms),
        }
    }

    /// Feeds a swarm event.
    pub fn handle_event(&mut self, event: &SwarmEvent, now_ms: u64) -> bool {
        match self {
            Self::Gossipsub(agent) => agent.handle_event(event, now_ms),
            Self::Floodsub(agent) => agent.handle_event(event, now_ms),
        }
    }

    /// Echoes an outbound stream-open result.
    pub fn stream_open_result(
        &mut self,
        peer: &PeerId,
        token: PubsubToken,
        result: Result<StreamId, String>,
        now_ms: u64,
    ) {
        match self {
            Self::Gossipsub(agent) => agent.stream_open_result(peer, token, result, now_ms),
            Self::Floodsub(agent) => agent.stream_open_result(peer, token, result, now_ms),
        }
    }

    /// Echoes a synchronous stream-write result.
    pub fn send_result(
        &mut self,
        peer: &PeerId,
        stream_id: StreamId,
        token: PubsubToken,
        result: Result<(), String>,
        now_ms: u64,
    ) {
        match self {
            Self::Gossipsub(agent) => agent.send_result(peer, stream_id, token, result, now_ms),
            Self::Floodsub(agent) => agent.send_result(peer, stream_id, token, result, now_ms),
        }
    }

    /// Advances engine timers.
    pub fn handle_tick(&mut self, now_ms: u64) {
        match self {
            Self::Gossipsub(agent) => agent.handle_tick(now_ms),
            Self::Floodsub(agent) => agent.handle_tick(now_ms),
        }
    }

    /// Milliseconds until the next due timer.
    pub fn next_timeout(&self, now_ms: u64) -> Option<u64> {
        match self {
            Self::Gossipsub(agent) => agent.next_timeout(now_ms),
            Self::Floodsub(agent) => agent.next_timeout(now_ms),
        }
    }

    /// Next driver action.
    pub fn poll_action(&mut self) -> Option<PubsubAction> {
        match self {
            Self::Gossipsub(agent) => agent.poll_action(),
            Self::Floodsub(agent) => agent.poll_action(),
        }
    }

    /// Next application event.
    pub fn poll_event(&mut self) -> Option<PubsubEvent> {
        match self {
            Self::Gossipsub(agent) => agent.poll_event(),
            Self::Floodsub(agent) => agent.poll_event(),
        }
    }

    /// Whether this engine owns a stream lifecycle.
    pub fn owns_stream(&self, peer: &PeerId, stream_id: StreamId) -> bool {
        match self {
            Self::Gossipsub(agent) => agent.owns_stream(peer, stream_id),
            Self::Floodsub(agent) => agent.owns_stream(peer, stream_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_selects_only_meshsub_protocols() {
        assert_eq!(PubsubConfig::default().protocol_ids(), GOSSIPSUB_PROTOCOLS);
        assert_eq!(
            PubsubConfig::from(FloodsubConfig::default()).protocol_ids(),
            FLOODSUB_PROTOCOLS
        );
    }

    #[test]
    fn constructor_rejects_invalid_gossipsub_config() {
        let config = GossipsubConfig {
            heartbeat_interval_ms: 0,
            ..GossipsubConfig::default()
        };
        let error = PubsubAgent::new(
            Ed25519Keypair::from_secret_key_bytes([1; 32]),
            config.into(),
            1,
            2,
        )
        .err()
        .expect("invalid config");
        assert_eq!(error.field, "heartbeat_interval_ms");
    }
}
