//! mDNS wire, schedule, and adapter configuration.

/// Caller-controlled mDNS behavior.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MdnsConfig {
    /// Whether IPv6 interfaces and advertisements are enabled.
    pub enable_ipv6: bool,
    /// Positive record lifetime advertised on the wire, in milliseconds.
    pub ttl_ms: u64,
    /// Steady-state query interval after exponential startup probing.
    pub query_interval_ms: u64,
    /// Maximum DNS/UDP payload emitted by the encoder.
    pub max_packet_bytes: usize,
    /// Maximum local addresses announced in one response burst.
    pub max_announced_addrs: usize,
    /// Interface re-enumeration interval used by the `std` adapter.
    pub interface_refresh_ms: u64,
    /// Maximum blocking wait before the facade polls mDNS sockets again.
    pub socket_poll_interval_ms: u64,
}

impl Default for MdnsConfig {
    fn default() -> Self {
        Self {
            enable_ipv6: false,
            ttl_ms: 120_000,
            query_interval_ms: 300_000,
            max_packet_bytes: 1_400,
            max_announced_addrs: 16,
            interface_refresh_ms: 10_000,
            socket_poll_interval_ms: 100,
        }
    }
}

impl MdnsConfig {
    /// Validates limits required by the encoder and caller-driven timers.
    pub fn validate(&self) -> Result<(), MdnsConfigError> {
        if self.ttl_ms == 0 {
            return Err(MdnsConfigError::ZeroTtl);
        }
        if self.query_interval_ms == 0 {
            return Err(MdnsConfigError::ZeroQueryInterval);
        }
        if !(256..=4_096).contains(&self.max_packet_bytes) {
            return Err(MdnsConfigError::InvalidMaxPacketBytes);
        }
        if self.max_announced_addrs == 0 {
            return Err(MdnsConfigError::ZeroMaxAnnouncedAddrs);
        }
        if self.interface_refresh_ms == 0 {
            return Err(MdnsConfigError::ZeroInterfaceRefresh);
        }
        if self.socket_poll_interval_ms == 0 {
            return Err(MdnsConfigError::ZeroSocketPollInterval);
        }
        Ok(())
    }
}

/// Why an mDNS component cannot be constructed from its configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MdnsConfigError {
    /// Positive records need a non-zero lifetime.
    #[error("mDNS TTL must be non-zero")]
    ZeroTtl,
    /// A zero query interval would livelock the caller's driver loop.
    #[error("mDNS query interval must be non-zero")]
    ZeroQueryInterval,
    /// Interoperable DNS payloads must be between 256 and 4096 bytes.
    #[error("mDNS maximum packet size must be between 256 and 4096 bytes")]
    InvalidMaxPacketBytes,
    /// At least one local address must be eligible for announcement.
    #[error("mDNS maximum announced addresses must be non-zero")]
    ZeroMaxAnnouncedAddrs,
    /// Interface polling must use a non-zero interval.
    #[error("mDNS interface refresh interval must be non-zero")]
    ZeroInterfaceRefresh,
    /// Socket polling must use a non-zero interval.
    #[error("mDNS socket poll interval must be non-zero")]
    ZeroSocketPollInterval,
}
