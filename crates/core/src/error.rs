use alloc::string::String;

use minip2p_identity::{PeerIdError, VarintError};
use thiserror::Error;

/// Errors from parsing a multiaddr (string or binary).
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MultiaddrError {
    #[error("multiaddr input is empty")]
    EmptyInput,
    #[error("multiaddr must start with '/' (example: /ip4/127.0.0.1/udp/4001/quic-v1)")]
    MissingLeadingSlash,
    #[error("empty protocol segment in multiaddr")]
    EmptyProtocol,
    #[error("missing value for protocol '{protocol}'")]
    MissingValue { protocol: String },
    #[error("unknown protocol '{protocol}'")]
    UnknownProtocol { protocol: String },
    #[error("invalid ip4 value '{value}'")]
    InvalidIp4 { value: String },
    #[error("invalid ip6 value '{value}'")]
    InvalidIp6 { value: String },
    #[error("invalid udp port '{value}'")]
    InvalidPort { value: String },
    #[error("invalid dns value '{value}'")]
    InvalidDnsName { value: String },
    #[error("invalid peer id '{value}': {source}")]
    InvalidPeerId {
        value: String,
        #[source]
        source: PeerIdError,
    },
    /// The binary decoder encountered a multicodec code it does not know.
    #[error("unknown multicodec protocol code {code:#x}")]
    UnknownProtocolCode { code: u64 },
    /// The binary decoder ran out of bytes partway through a protocol's
    /// fixed- or variable-length value.
    #[error("truncated binary value for protocol '{protocol}'")]
    TruncatedBinaryValue { protocol: &'static str },
    /// A binary protocol value failed validation (e.g. malformed
    /// multihash for `/p2p/`, non-UTF-8 DNS name).
    #[error("invalid binary value for protocol '{protocol}': {reason}")]
    InvalidBinaryValue {
        protocol: &'static str,
        reason: String,
    },
    /// A varint in the binary encoding was malformed.
    #[error("invalid varint in binary multiaddr: {0}")]
    Varint(#[from] VarintError),
}

/// Errors from parsing or constructing a peer address.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PeerAddrError {
    #[error("multiaddr parse error: {0}")]
    Multiaddr(#[from] MultiaddrError),
    #[error("peer address must end with /p2p/<peer-id>")]
    MissingPeerId,
    #[error("peer id protocol must be terminal")]
    NonTerminalPeerId,
    #[error("transport address must not already contain /p2p")]
    TransportContainsPeerId,
    #[error("transport address must contain at least one protocol before /p2p/<peer-id>")]
    EmptyTransport,
}
