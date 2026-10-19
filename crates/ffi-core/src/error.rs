//! Errors exposed to binding shells.

/// An error returned by a synchronous FFI operation.
#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum FfiError {
    /// The endpoint's background driver was already started.
    #[error("endpoint driver already started")]
    AlreadyStarted,
    /// The endpoint has stopped and cannot be restarted.
    #[error("endpoint is stopped")]
    Stopped,
    /// Endpoint configuration was invalid; `capability` names the part of
    /// it that was.
    #[error("invalid {capability} configuration: {detail}")]
    InvalidConfig {
        /// The part of the configuration that failed.
        capability: ConfigCapability,
        /// Human-readable validation detail.
        detail: String,
    },
    /// Secret key material was not exactly 32 bytes.
    #[error("invalid secret key: {detail}")]
    InvalidKey {
        /// Human-readable validation detail.
        detail: String,
    },
    /// A peer ID could not be parsed.
    #[error("invalid peer id: {detail}")]
    InvalidPeerId {
        /// Human-readable parse detail.
        detail: String,
    },
    /// A multiaddress or peer address could not be parsed.
    #[error("invalid address: {detail}")]
    InvalidAddress {
        /// Human-readable parse detail.
        detail: String,
    },
    /// A pubsub topic failed validation.
    #[error("invalid topic: {detail}")]
    InvalidTopic {
        /// Human-readable validation detail.
        detail: String,
    },
    /// The operation is valid but reserved by another endpoint subsystem.
    #[error("operation not permitted: {detail}")]
    NotPermitted {
        /// Human-readable refusal detail.
        detail: String,
    },
    /// A bounded outbound queue is full.
    #[error("outbound backpressure")]
    Backpressure,
    /// A pubsub message exceeds the protocol limit.
    #[error("message too large")]
    MessageTooLarge,
    /// A synchronous transport operation failed, or the platform refused a
    /// socket the endpoint needed (a port in use, say).
    #[error("transport error: {detail}")]
    Transport {
        /// Human-readable transport detail.
        detail: String,
    },
    /// The operation is unavailable in the endpoint's current lifecycle state.
    #[error("invalid endpoint state: {detail}")]
    InvalidState {
        /// Human-readable state detail.
        detail: String,
    },
    /// An internal invariant or unexpected construction path failed.
    #[error("internal error: {detail}")]
    Internal {
        /// Human-readable failure detail.
        detail: String,
    },
}

impl FfiError {
    /// The variant name: the stable `code` a JavaScript shell tags its
    /// thrown error with, which the TypeScript SDK maps to typed errors.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::AlreadyStarted => "AlreadyStarted",
            Self::Stopped => "Stopped",
            Self::InvalidConfig { .. } => "InvalidConfig",
            Self::InvalidKey { .. } => "InvalidKey",
            Self::InvalidPeerId { .. } => "InvalidPeerId",
            Self::InvalidAddress { .. } => "InvalidAddress",
            Self::InvalidTopic { .. } => "InvalidTopic",
            Self::NotPermitted { .. } => "NotPermitted",
            Self::Backpressure => "Backpressure",
            Self::MessageTooLarge => "MessageTooLarge",
            Self::Transport { .. } => "Transport",
            Self::InvalidState { .. } => "InvalidState",
            Self::Internal { .. } => "Internal",
        }
    }

    /// The variant's detail field, when it has one.
    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::AlreadyStarted | Self::Stopped | Self::Backpressure | Self::MessageTooLarge => {
                None
            }
            Self::InvalidConfig { detail, .. }
            | Self::InvalidKey { detail }
            | Self::InvalidPeerId { detail }
            | Self::InvalidAddress { detail }
            | Self::InvalidTopic { detail }
            | Self::NotPermitted { detail }
            | Self::Transport { detail }
            | Self::InvalidState { detail }
            | Self::Internal { detail } => Some(detail),
        }
    }

    /// The capability an [`FfiError::InvalidConfig`] names.
    pub const fn capability(&self) -> Option<ConfigCapability> {
        match self {
            Self::InvalidConfig { capability, .. } => Some(*capability),
            _ => None,
        }
    }
}

/// The part of an endpoint's configuration an [`FfiError::InvalidConfig`]
/// names.
///
/// A configuration mistake is fixed by changing that part; an environment
/// failure (a socket the platform refused) is [`FfiError::Transport`]
/// instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum ConfigCapability {
    /// Gossipsub settings.
    Gossipsub,
    /// mDNS settings.
    Mdns,
    /// Signed discovery or peer-book settings.
    Discovery,
    /// QUIC or TCP transport settings (limits, TLS, the TCP namespace).
    Transport,
    /// The endpoint's own options: listen addresses, protocols, NAT and
    /// relay policy, auto-dial.
    Options,
}

impl ConfigCapability {
    /// The variant name, the stable tag the bindings expose.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gossipsub => "Gossipsub",
            Self::Mdns => "Mdns",
            Self::Discovery => "Discovery",
            Self::Transport => "Transport",
            Self::Options => "Options",
        }
    }
}

impl core::fmt::Display for ConfigCapability {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Maps a runtime endpoint failure: transport failures to
/// [`FfiError::Transport`], anything else to [`FfiError::Internal`].
pub fn map_driver_error(error: minip2p::DriverError) -> FfiError {
    match error {
        minip2p::DriverError::Transport(_) => FfiError::Transport {
            detail: error.to_string(),
        },
        _ => FfiError::Internal {
            detail: error.to_string(),
        },
    }
}

/// Maps a Gossipsub refusal: reserved topics to [`FfiError::NotPermitted`],
/// publish limits to their own variants, topic mistakes to
/// [`FfiError::InvalidTopic`].
pub fn map_gossipsub_error(error: minip2p::GossipsubError) -> FfiError {
    match error {
        minip2p::GossipsubError::DiscoveryTopicReserved => FfiError::NotPermitted {
            detail: error.to_string(),
        },
        minip2p::GossipsubError::Publish(minip2p::PublishError::TooLarge) => {
            FfiError::MessageTooLarge
        }
        minip2p::GossipsubError::Publish(minip2p::PublishError::Backpressure) => {
            FfiError::Backpressure
        }
        minip2p::GossipsubError::Publish(minip2p::PublishError::Topic(error))
        | minip2p::GossipsubError::Topic(error) => map_topic_error(error),
        minip2p::GossipsubError::Driver(error) => map_driver_error(error),
        minip2p::GossipsubError::NotEnabled => FfiError::Internal {
            detail: error.to_string(),
        },
    }
}

/// Maps an invalid pubsub topic.
pub fn map_topic_error(error: minip2p::TopicError) -> FfiError {
    FfiError::InvalidTopic {
        detail: error.to_string(),
    }
}
