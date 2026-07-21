//! Gossipsub router configuration and validation.

/// Invalid gossipsub configuration.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid gossipsub config field `{field}`: {reason}")]
pub struct PubsubConfigError {
    /// Name of the invalid field.
    pub field: &'static str,
    /// Actionable description of the violated constraint.
    pub reason: &'static str,
}

/// Tunables for [`GossipsubAgent`](crate::GossipsubAgent).
#[derive(Clone, Debug)]
pub struct GossipsubConfig {
    /// Target mesh degree.
    pub d: usize,
    /// Mesh degree below which peers are grafted.
    pub d_low: usize,
    /// Mesh degree above which peers are pruned.
    pub d_high: usize,
    /// Minimum number of non-mesh peers selected for gossip.
    pub d_lazy: usize,
    /// Heartbeat interval in milliseconds.
    pub heartbeat_interval_ms: u64,
    /// Number of heartbeat windows retained in the message cache.
    pub mcache_len: usize,
    /// Number of newest cache windows advertised through IHAVE.
    pub mcache_gossip: usize,
    /// Hard cap on cached messages.
    pub max_mcache_messages: usize,
    /// Fanout reuse lifetime in milliseconds; zero disables reuse.
    pub fanout_ttl_ms: u64,
    /// Default prune backoff in milliseconds.
    pub prune_backoff_ms: u64,
    /// Backoff sent when leaving a topic, in milliseconds.
    pub unsubscribe_backoff_ms: u64,
    /// Clamp for remotely supplied backoffs, in milliseconds.
    pub max_backoff_ms: u64,
    /// Maximum ids accepted or emitted in one IHAVE item.
    pub max_ihave_length: usize,
    /// Maximum IHAVE items processed per peer per heartbeat.
    pub max_ihave_messages_per_heartbeat: usize,
    /// Maximum ids requested through IWANT per heartbeat.
    pub max_iwant_ids_per_heartbeat: usize,
    /// Maximum cached messages served per peer per heartbeat.
    pub max_iwant_serves_per_heartbeat: usize,
    /// Seen-cache retention in milliseconds.
    pub seen_ttl_ms: u64,
    /// Hard cap on seen-cache entries.
    pub max_seen_messages: usize,
    /// Hard cap on queued message RPCs per peer.
    pub max_pending_per_peer: usize,
    /// Hard cap on remote subscriptions tracked per peer.
    pub max_topics_per_peer: usize,
    /// Hard cap on concurrent inbound streams per peer.
    pub max_inbound_streams_per_peer: usize,
    /// Outbound stream-establishment deadline in milliseconds.
    pub send_timeout_ms: u64,
    /// Whether unsigned messages are accepted.
    pub allow_unsigned: bool,
}

impl Default for GossipsubConfig {
    fn default() -> Self {
        Self {
            d: 6,
            d_low: 4,
            d_high: 12,
            d_lazy: 6,
            heartbeat_interval_ms: 1_000,
            mcache_len: 5,
            mcache_gossip: 3,
            max_mcache_messages: 512,
            fanout_ttl_ms: 60_000,
            prune_backoff_ms: 60_000,
            unsubscribe_backoff_ms: 10_000,
            max_backoff_ms: 3_600_000,
            max_ihave_length: 5_000,
            max_ihave_messages_per_heartbeat: 10,
            max_iwant_ids_per_heartbeat: 5_000,
            max_iwant_serves_per_heartbeat: 32,
            seen_ttl_ms: 120_000,
            max_seen_messages: 4_096,
            max_pending_per_peer: 32,
            max_topics_per_peer: 256,
            max_inbound_streams_per_peer: 4,
            send_timeout_ms: 10_000,
            allow_unsigned: false,
        }
    }
}

impl GossipsubConfig {
    /// Validates relationships and non-zero bounds without normalizing.
    pub fn validate(&self) -> Result<(), PubsubConfigError> {
        if self.d_low == 0 || self.d_low > self.d {
            return invalid("d_low", "must be in 1..=d");
        }
        if self.d > self.d_high {
            return invalid("d_high", "must be greater than or equal to d");
        }
        if self.mcache_gossip == 0 || self.mcache_gossip > self.mcache_len {
            return invalid("mcache_gossip", "must be in 1..=mcache_len");
        }
        nonzero(self.heartbeat_interval_ms, "heartbeat_interval_ms")?;
        nonzero(self.max_mcache_messages, "max_mcache_messages")?;
        nonzero(self.max_ihave_length, "max_ihave_length")?;
        nonzero(
            self.max_ihave_messages_per_heartbeat,
            "max_ihave_messages_per_heartbeat",
        )?;
        nonzero(
            self.max_iwant_ids_per_heartbeat,
            "max_iwant_ids_per_heartbeat",
        )?;
        nonzero(
            self.max_iwant_serves_per_heartbeat,
            "max_iwant_serves_per_heartbeat",
        )?;
        nonzero(self.seen_ttl_ms, "seen_ttl_ms")?;
        nonzero(self.max_seen_messages, "max_seen_messages")?;
        nonzero(self.max_pending_per_peer, "max_pending_per_peer")?;
        nonzero(self.max_topics_per_peer, "max_topics_per_peer")?;
        nonzero(
            self.max_inbound_streams_per_peer,
            "max_inbound_streams_per_peer",
        )?;
        nonzero(self.send_timeout_ms, "send_timeout_ms")?;
        nonzero(self.prune_backoff_ms, "prune_backoff_ms")?;
        if self.max_backoff_ms < self.prune_backoff_ms {
            return invalid("max_backoff_ms", "must be at least prune_backoff_ms");
        }
        if self.max_backoff_ms < self.unsubscribe_backoff_ms {
            return invalid("max_backoff_ms", "must be at least unsubscribe_backoff_ms");
        }
        Ok(())
    }
}

fn nonzero<T>(value: T, field: &'static str) -> Result<(), PubsubConfigError>
where
    T: Default + PartialEq,
{
    if value == T::default() {
        invalid(field, "must be non-zero")
    } else {
        Ok(())
    }
}

fn invalid<T>(field: &'static str, reason: &'static str) -> Result<T, PubsubConfigError> {
    Err(PubsubConfigError { field, reason })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate() {
        GossipsubConfig::default().validate().unwrap();
    }

    #[test]
    fn invalid_relationships_name_the_field() {
        let mut config = GossipsubConfig::default();
        config.d_low = config.d + 1;
        assert_eq!(config.validate().unwrap_err().field, "d_low");

        let mut config = GossipsubConfig::default();
        config.mcache_gossip = config.mcache_len + 1;
        assert_eq!(config.validate().unwrap_err().field, "mcache_gossip");

        let config = GossipsubConfig {
            heartbeat_interval_ms: 0,
            ..GossipsubConfig::default()
        };
        assert_eq!(
            config.validate().unwrap_err().field,
            "heartbeat_interval_ms"
        );
    }
}
