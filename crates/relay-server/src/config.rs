/// A token bucket replenishing one token per interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimit {
    /// Maximum tokens held by the bucket.
    pub capacity: u32,
    /// Milliseconds between one-token refills.
    pub refill_interval_ms: u64,
}

/// Deterministic relay service limits and admission policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayServerConfig {
    /// Maximum committed reservations; zero denies new reservations.
    pub max_reservations: usize,
    /// Monotonic reservation lifetime in seconds; must be positive.
    pub reservation_duration_secs: u64,
    /// Maximum pending plus committed circuits; zero denies CONNECT.
    pub max_circuits: usize,
    /// Maximum circuits involving one peer, counting a self-circuit once.
    pub max_circuits_per_peer: usize,
    /// Committed circuit lifetime in seconds; zero is unlimited.
    pub max_circuit_duration_secs: u64,
    /// Accepted application bytes allowed per direction; zero is unlimited.
    pub max_circuit_bytes: u64,
    /// Post-negotiation inbound HOP workers allowed per connection.
    pub max_pending_hop_requests_per_connection: usize,
    /// Post-negotiation outbound STOP workers allowed per connection.
    pub max_pending_stop_requests_per_connection: usize,
    /// End-to-end HOP/STOP control timeout in milliseconds.
    pub control_stream_timeout_ms: u64,
    /// Optional reservation-attempt bucket keyed by peer.
    pub reservation_rate_limit_per_peer: Option<RateLimit>,
    /// Optional reservation-attempt bucket keyed by the first remote IP.
    pub reservation_rate_limit_per_ip: Option<RateLimit>,
    /// Optional CONNECT-attempt bucket keyed by source peer.
    pub circuit_rate_limit_per_peer: Option<RateLimit>,
    /// Optional CONNECT-attempt bucket keyed by the source's first remote IP.
    pub circuit_rate_limit_per_ip: Option<RateLimit>,
}

impl Default for RelayServerConfig {
    fn default() -> Self {
        let per_peer = Some(RateLimit {
            capacity: 30,
            refill_interval_ms: 120_000,
        });
        let per_ip = Some(RateLimit {
            capacity: 60,
            refill_interval_ms: 60_000,
        });
        Self {
            max_reservations: 128,
            reservation_duration_secs: 3_600,
            max_circuits: 16,
            max_circuits_per_peer: 4,
            max_circuit_duration_secs: 120,
            max_circuit_bytes: 131_072,
            max_pending_hop_requests_per_connection: 10,
            max_pending_stop_requests_per_connection: 10,
            control_stream_timeout_ms: 60_000,
            reservation_rate_limit_per_peer: per_peer,
            reservation_rate_limit_per_ip: per_ip,
            circuit_rate_limit_per_peer: per_peer,
            circuit_rate_limit_per_ip: per_ip,
        }
    }
}

/// Machine-readable reason a relay configuration is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayServerConfigErrorKind {
    /// A field whose contract requires a positive value was zero.
    MustBeNonZero,
    /// A duration cannot be represented by the relay wire's `u32` seconds.
    ExceedsWireU32,
}

/// An invalid relay configuration field.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid relay server configuration `{field}`: {reason}")]
pub struct RelayServerConfigError {
    /// Stable field path identifying the rejected value.
    pub field: &'static str,
    /// Machine-readable rejection reason.
    pub reason: RelayServerConfigErrorKind,
}

impl core::fmt::Display for RelayServerConfigErrorKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MustBeNonZero => f.write_str("must be non-zero"),
            Self::ExceedsWireU32 => f.write_str("exceeds the wire u32 seconds bound"),
        }
    }
}

impl RelayServerConfig {
    /// Validates values whose meaning cannot be enforced by their Rust types.
    pub fn validate(&self) -> Result<(), RelayServerConfigError> {
        if self.reservation_duration_secs == 0 {
            return Err(invalid(
                "reservation_duration_secs",
                RelayServerConfigErrorKind::MustBeNonZero,
            ));
        }
        if self.max_circuit_duration_secs > u32::MAX as u64 {
            return Err(invalid(
                "max_circuit_duration_secs",
                RelayServerConfigErrorKind::ExceedsWireU32,
            ));
        }
        if self.control_stream_timeout_ms == 0 {
            return Err(invalid(
                "control_stream_timeout_ms",
                RelayServerConfigErrorKind::MustBeNonZero,
            ));
        }
        validate_rate_limit(
            "reservation_rate_limit_per_peer",
            self.reservation_rate_limit_per_peer,
        )?;
        validate_rate_limit(
            "reservation_rate_limit_per_ip",
            self.reservation_rate_limit_per_ip,
        )?;
        validate_rate_limit(
            "circuit_rate_limit_per_peer",
            self.circuit_rate_limit_per_peer,
        )?;
        validate_rate_limit("circuit_rate_limit_per_ip", self.circuit_rate_limit_per_ip)?;
        Ok(())
    }
}

const fn invalid(
    field: &'static str,
    reason: RelayServerConfigErrorKind,
) -> RelayServerConfigError {
    RelayServerConfigError { field, reason }
}

fn validate_rate_limit(
    name: &'static str,
    limit: Option<RateLimit>,
) -> Result<(), RelayServerConfigError> {
    let Some(limit) = limit else {
        return Ok(());
    };
    if limit.capacity == 0 {
        let field = match name {
            "reservation_rate_limit_per_peer" => "reservation_rate_limit_per_peer.capacity",
            "reservation_rate_limit_per_ip" => "reservation_rate_limit_per_ip.capacity",
            "circuit_rate_limit_per_peer" => "circuit_rate_limit_per_peer.capacity",
            _ => "circuit_rate_limit_per_ip.capacity",
        };
        return Err(invalid(field, RelayServerConfigErrorKind::MustBeNonZero));
    }
    if limit.refill_interval_ms == 0 {
        let field = match name {
            "reservation_rate_limit_per_peer" => {
                "reservation_rate_limit_per_peer.refill_interval_ms"
            }
            "reservation_rate_limit_per_ip" => "reservation_rate_limit_per_ip.refill_interval_ms",
            "circuit_rate_limit_per_peer" => "circuit_rate_limit_per_peer.refill_interval_ms",
            _ => "circuit_rate_limit_per_ip.refill_interval_ms",
        };
        return Err(invalid(field, RelayServerConfigErrorKind::MustBeNonZero));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_canonical_contract() {
        let config = RelayServerConfig::default();
        assert_eq!(config.max_reservations, 128);
        assert_eq!(config.reservation_duration_secs, 3_600);
        assert_eq!(config.max_circuits, 16);
        assert_eq!(config.max_circuits_per_peer, 4);
        assert_eq!(config.max_circuit_duration_secs, 120);
        assert_eq!(config.max_circuit_bytes, 131_072);
        assert_eq!(config.max_pending_hop_requests_per_connection, 10);
        assert_eq!(config.max_pending_stop_requests_per_connection, 10);
        assert_eq!(config.control_stream_timeout_ms, 60_000);
        assert_eq!(
            config.reservation_rate_limit_per_peer,
            Some(RateLimit {
                capacity: 30,
                refill_interval_ms: 120_000,
            })
        );
        assert_eq!(
            config.reservation_rate_limit_per_ip,
            Some(RateLimit {
                capacity: 60,
                refill_interval_ms: 60_000,
            })
        );
        assert_eq!(
            config.circuit_rate_limit_per_peer,
            config.reservation_rate_limit_per_peer
        );
        assert_eq!(
            config.circuit_rate_limit_per_ip,
            config.reservation_rate_limit_per_ip
        );
        config.validate().expect("defaults are valid");
    }

    #[test]
    fn invalid_configuration_reports_the_exact_field_and_reason() {
        let mut config = RelayServerConfig {
            reservation_duration_secs: 0,
            ..RelayServerConfig::default()
        };
        assert_eq!(
            config.validate(),
            Err(RelayServerConfigError {
                field: "reservation_duration_secs",
                reason: RelayServerConfigErrorKind::MustBeNonZero,
            })
        );

        config.reservation_duration_secs = 1;
        config.max_circuit_duration_secs = u32::MAX as u64 + 1;
        assert_eq!(
            config.validate().unwrap_err().reason,
            RelayServerConfigErrorKind::ExceedsWireU32
        );

        config.max_circuit_duration_secs = 0;
        config.control_stream_timeout_ms = 0;
        assert_eq!(
            config.validate().unwrap_err().field,
            "control_stream_timeout_ms"
        );
    }

    #[test]
    fn disabled_limiters_and_zero_resource_capacities_are_valid() {
        let config = RelayServerConfig {
            max_reservations: 0,
            max_circuits: 0,
            max_circuits_per_peer: 0,
            max_circuit_duration_secs: 0,
            max_circuit_bytes: 0,
            max_pending_hop_requests_per_connection: 0,
            max_pending_stop_requests_per_connection: 0,
            reservation_rate_limit_per_peer: None,
            reservation_rate_limit_per_ip: None,
            circuit_rate_limit_per_peer: None,
            circuit_rate_limit_per_ip: None,
            ..RelayServerConfig::default()
        };
        config
            .validate()
            .expect("zero capacities deny work or disable limits");
    }

    #[test]
    fn enabled_limiters_reject_zero_capacity_and_refill_interval() {
        let mut config = RelayServerConfig {
            circuit_rate_limit_per_peer: Some(RateLimit {
                capacity: 0,
                refill_interval_ms: 1,
            }),
            ..RelayServerConfig::default()
        };
        assert_eq!(
            config.validate().unwrap_err(),
            RelayServerConfigError {
                field: "circuit_rate_limit_per_peer.capacity",
                reason: RelayServerConfigErrorKind::MustBeNonZero,
            }
        );
        config.circuit_rate_limit_per_peer = Some(RateLimit {
            capacity: 1,
            refill_interval_ms: 0,
        });
        assert_eq!(
            config.validate().unwrap_err().field,
            "circuit_rate_limit_per_peer.refill_interval_ms"
        );
    }
}
