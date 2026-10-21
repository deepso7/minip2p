//! Why a QUIC transport could not be built.

use std::net::SocketAddr;

use minip2p_core::Multiaddr;
use minip2p_core::platform::IoErrorKind;

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
    /// The libp2p TLS certificate for this identity could not be generated.
    #[error("QUIC TLS certificate: {0}")]
    Certificate(minip2p_tls::TlsError),
    /// A [`WebTransportCertificates::Provided`](crate::WebTransportCertificates::Provided)
    /// certificate can't be served: the chain is empty or unparseable, the
    /// key doesn't match the leaf, or the leaf has expired.
    #[error("WebTransport certificate: {0}")]
    WebTransportCertificate(String),
    /// A TLS setup step failed in the crypto provider.
    #[error("QUIC TLS setup failed while {stage}: {detail}")]
    Tls {
        /// Which step failed.
        stage: QuicTlsStage,
        /// What the crypto provider reported.
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

/// The TLS setup step a [`QuicBindError::Tls`] failed in.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum QuicTlsStage {
    /// Loading the generated private key.
    LoadKey,
    /// Loading the generated certificate with its key.
    LoadCertificate,
    /// Building the listener's TLS 1.3 configuration.
    ServerConfig,
    /// Turning that configuration into QUIC's (it needs a QUIC cipher suite).
    QuicCipherSuites,
}

impl core::fmt::Display for QuicTlsStage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::LoadKey => "loading the private key",
            Self::LoadCertificate => "loading the certificate",
            Self::ServerConfig => "building the server configuration",
            Self::QuicCipherSuites => "selecting QUIC cipher suites",
        })
    }
}

impl QuicBindError {
    pub(crate) fn tls(stage: QuicTlsStage, error: impl core::fmt::Display) -> Self {
        Self::Tls {
            stage,
            detail: error.to_string(),
        }
    }

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
