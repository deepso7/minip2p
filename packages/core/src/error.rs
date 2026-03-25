use alloc::string::String;

use minip2p_identity::PeerIdError;
use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MultiaddrError {
    #[error("multiaddr input is empty")]
    EmptyInput,
    #[error("multiaddr must start with '/' (example: /ip4/127.0.0.1/udp/4001/quic-v1)")]
    MissingLeadingSlash,
    #[error("empty protocol segment at index {segment}")]
    EmptyProtocol { segment: usize },
    #[error("missing value for protocol '{protocol}' at segment {segment}")]
    MissingValue { protocol: String, segment: usize },
    #[error("unknown protocol '{protocol}' at segment {segment}")]
    UnknownProtocol { protocol: String, segment: usize },
    #[error("invalid ip4 value '{value}' at segment {segment}")]
    InvalidIp4 { value: String, segment: usize },
    #[error("invalid ip6 value '{value}' at segment {segment}")]
    InvalidIp6 { value: String, segment: usize },
    #[error("invalid udp port '{value}' at segment {segment}")]
    InvalidPort { value: String, segment: usize },
    #[error("invalid dns value '{value}' at segment {segment}")]
    InvalidDnsName { value: String, segment: usize },
    #[error("invalid peer id '{value}' at segment {segment}: {source}")]
    InvalidPeerId {
        value: String,
        segment: usize,
        #[source]
        source: PeerIdError,
    },
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PeerAddrError {
    #[error("multiaddr parse error: {0}")]
    Multiaddr(#[from] MultiaddrError),
    #[error("peer address must end with /p2p/<peer-id>")]
    MissingPeerId,
    #[error("peer id protocol must be terminal (found at segment {segment})")]
    NonTerminalPeerId { segment: usize },
    #[error("transport address must not already contain /p2p")]
    TransportContainsPeerId,
    #[error(
        "transport must be one host protocol + /udp/<port>/quic-v1 (host is ip4/ip6/dns/dns4/dns6)"
    )]
    InvalidTransportShape,
}
