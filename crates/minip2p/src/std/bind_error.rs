//! Why an [`EndpointBuilder`](super::EndpointBuilder) could not become an
//! [`Endpoint`](super::Endpoint).
//!
//! A bind error describes a failure before any event is polled, and names
//! what failed: a transport, a capability, or the options themselves. What
//! fails later is a runtime [`Error`](super::Error) or a capability failure
//! event, never one of these.

use minip2p_core::platform::IoErrorKind;
use minip2p_core::{Multiaddr, MultiaddrError};
#[cfg(feature = "tcp")]
use minip2p_transport::ConnectionNamespace;
use minip2p_transport::{InvalidLimit, TransportError, TransportSetError};

#[cfg(feature = "pubsub")]
use crate::GossipsubConfigError;
use crate::SwarmError;
#[cfg(feature = "mdns")]
use crate::{MdnsConfigError, MdnsError};
#[cfg(feature = "relay-server")]
use crate::{RelayServerAddressError, RelayServerConfigError};
#[cfg(feature = "quic")]
use minip2p_quic::QuicBindError;

/// An IP address family.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IpFamily {
    /// IPv4.
    Ipv4,
    /// IPv6.
    Ipv6,
}

impl core::fmt::Display for IpFamily {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
        })
    }
}

/// A mistake in the Endpoint's own options: its listen addresses, the
/// transports they select, and what those transports present.
///
/// The listen setters ([`listen_on`](super::EndpointBuilder::listen_on) and
/// friends) return this as soon as an address is added;
/// [`bind`](super::EndpointBuilder::bind) wraps it in [`BindError::Options`]
/// for mistakes only the whole set of options reveals.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum EndpointOptionsError {
    /// A listen address is not a multiaddr at all.
    #[error("`{addr}` is not a multiaddr: {error}")]
    InvalidListenAddress {
        /// The address as given.
        addr: String,
        /// Why it does not parse.
        error: MultiaddrError,
    },
    /// A listen address is a multiaddr, but not one the Endpoint can listen
    /// on.
    #[error("`{addr}` is not a supported listen address; expected {expected}")]
    UnsupportedListenShape {
        /// The rejected address.
        addr: Multiaddr,
        /// What a listen address must look like instead.
        expected: &'static str,
    },
    /// No listen address selects a transport, so the endpoint could neither
    /// dial nor be reached.
    #[error(
        "an endpoint needs at least one transport to bind; add a listen address with \
         EndpointBuilder::listen_on or listen_default"
    )]
    NoTransport,
    /// A QUIC listen address for a family whose socket is already named: QUIC
    /// binds one socket per family, serving at most one `/quic-v1` and one
    /// `/quic-v1/webtransport` address on the same host and port.
    #[error(
        "QUIC listens on one socket per IP family (one /quic-v1 and one /quic-v1/webtransport \
         address on the same host and port); `{addr}` repeats {family}"
    )]
    DuplicateQuicFamily {
        /// The rejected address.
        addr: Multiaddr,
        /// The family it repeats.
        family: IpFamily,
    },
    /// [`TcpConfig::namespace`](crate::TcpConfig) is not a TCP namespace, so
    /// TCP connection ids would route to the wrong transport.
    #[cfg(feature = "tcp")]
    #[error(
        "a TCP transport must allocate in a TCP namespace, not {namespace}; see TcpConfig::namespace"
    )]
    TcpNamespace {
        /// The configured namespace.
        namespace: ConnectionNamespace,
    },
    /// The selected transports conflict with each other in the transport
    /// set (two claiming one connection namespace, say).
    #[error("the endpoint's transports conflict: {0}")]
    TransportConflict(TransportSetError),
    /// A TCP or circuit limit cannot work: see
    /// [`TcpConfig::validate`](crate::TcpConfig) and
    /// [`CircuitLimits::validate`](crate::CircuitLimits).
    #[error(transparent)]
    InvalidLimit(InvalidLimit),
    /// The PEM given to
    /// [`webtransport_certificate_pem`](super::EndpointBuilder::webtransport_certificate_pem)
    /// is unusable: no certificate, no private key, more than one key, or a
    /// malformed section.
    #[cfg(feature = "quic")]
    #[error("WebTransport certificate PEM: {problem}")]
    WebTransportCertificatePem {
        /// What is wrong with it.
        problem: String,
    },
    /// A WebTransport certificate was configured, but no listen address
    /// would serve it.
    #[cfg(feature = "quic")]
    #[error(
        "a WebTransport certificate was configured, but no listen address is \
         `/ip4|ip6/udp/<port>/quic-v1/webtransport`; add one with EndpointBuilder::listen_on"
    )]
    WebTransportCertificateWithoutListener,
    /// Relay-server announce addresses were configured without enabling the
    /// relay server.
    #[cfg(feature = "relay-server")]
    #[error(
        "relay-server announce addresses were configured, but the relay server is not \
         enabled; call EndpointBuilder::relay_server or relay_server_config"
    )]
    RelayAnnounceWithoutServer,
}

/// A failure turning [`EndpointBuilder`](super::EndpointBuilder) options into
/// a running [`Endpoint`](super::Endpoint).
///
/// Each variant names what failed and carries that part's own typed error,
/// so a caller can tell a configuration mistake (fix the options) from an
/// environment failure (a port in use, say).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BindError {
    /// The Endpoint's own options are inconsistent.
    #[error(transparent)]
    Options(#[from] EndpointOptionsError),
    /// The swarm refused the configuration (a reserved protocol id, say).
    #[error("swarm configuration: {0}")]
    Swarm(#[from] SwarmError),
    /// The relay server's configuration is invalid.
    #[cfg(feature = "relay-server")]
    #[error("relay-server configuration: {0}")]
    RelayServer(RelayServerConfigError),
    /// A relay-server announce address does not fit this endpoint's
    /// identity, or its `/certhash` does not fit the WebTransport
    /// certificate mode.
    #[cfg(feature = "relay-server")]
    #[error("relay-server announce address: {0}")]
    RelayServerAnnounce(Box<RelayServerAddressError>),
    /// The Gossipsub configuration is invalid.
    #[cfg(feature = "pubsub")]
    #[error("gossipsub configuration: {0}")]
    Gossipsub(GossipsubConfigError),
    /// The mDNS configuration is invalid.
    #[cfg(feature = "mdns")]
    #[error("mDNS configuration: {0}")]
    Mdns(MdnsConfigError),
    /// The mDNS sockets could not be set up.
    #[cfg(feature = "mdns")]
    #[error("mDNS sockets: {0}")]
    MdnsSocket(MdnsError),
    /// The QUIC transport could not be built.
    #[cfg(feature = "quic")]
    #[error("QUIC transport: {0}")]
    Quic(QuicBindError),
    /// A transport could not start listening (a TCP listener's port in use,
    /// say).
    #[error("listen: {0}")]
    Listen(TransportError),
    /// The platform refused the readiness poll the endpoint waits on.
    #[error("{operation} failed ({kind}): {detail}")]
    ReadinessPoll {
        /// What the endpoint was doing.
        operation: &'static str,
        /// What kind of failure the platform reported.
        kind: IoErrorKind,
        /// The platform's own description, for diagnostics.
        detail: String,
    },
    /// An internal construction invariant failed: a configuration that was
    /// already validated was rejected. A bug, not a caller mistake.
    #[error("endpoint construction invariant violated: {reason}")]
    Invariant {
        /// Which invariant.
        reason: &'static str,
    },
}

impl BindError {
    pub(crate) fn readiness_poll(operation: &'static str, error: &std::io::Error) -> Self {
        Self::ReadinessPoll {
            operation,
            kind: error.kind().into(),
            detail: error.to_string(),
        }
    }
}
