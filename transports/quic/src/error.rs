//! Why a QUIC transport could not be built.

use std::net::SocketAddr;

use minip2p_core::Multiaddr;
use minip2p_platform::IoErrorKind;

/// A failure building a [`QuicTransport`](crate::QuicTransport).
///
/// Configuration mistakes ([`InvalidLimit`](Self::InvalidLimit),
/// [`InvalidAddress`](Self::InvalidAddress),
/// [`AddressFamilies`](Self::AddressFamilies)) are caught before any socket
/// is bound; [`Socket`](Self::Socket) is the platform refusing one.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum QuicBindError {
    /// A [`QuicLimits`](crate::QuicLimits) field is out of range.
    #[error("QuicLimits::{field} {requirement}")]
    InvalidLimit {
        /// The field, as named on `QuicLimits`.
        field: &'static str,
        /// What the field must satisfy.
        requirement: &'static str,
    },
    /// A bind address is not a numeric `/ip4|ip6/udp/<port>/quic-v1`
    /// address.
    #[error("`{addr}` is not a QUIC bind address: {reason}")]
    InvalidAddress {
        /// The address as given.
        addr: Multiaddr,
        /// What is wrong with it.
        reason: String,
    },
    /// QUIC binds one `/ip4` address, one `/ip6` address, or one of each.
    #[error(
        "QUIC binds one /ip4 address, one /ip6 address, or one of each; got {count} address(es)"
    )]
    AddressFamilies {
        /// How many addresses were given.
        count: usize,
    },
    /// The libp2p TLS identity or configuration could not be built.
    #[error("QUIC TLS setup failed: {detail}")]
    Tls {
        /// What TLS reported.
        detail: String,
    },
    /// The platform refused a UDP socket.
    #[error("QUIC socket {addr}: {operation} failed ({kind}): {detail}")]
    Socket {
        /// The address the socket was bound, or asked, to.
        addr: SocketAddr,
        /// What was being done to it.
        operation: &'static str,
        /// What kind of failure the platform reported.
        kind: IoErrorKind,
        /// The platform's own description, for diagnostics.
        detail: String,
    },
}

impl QuicBindError {
    pub(crate) fn socket(
        addr: SocketAddr,
        operation: &'static str,
        error: &std::io::Error,
    ) -> Self {
        Self::Socket {
            addr,
            operation,
            kind: error.kind().into(),
            detail: error.to_string(),
        }
    }
}
