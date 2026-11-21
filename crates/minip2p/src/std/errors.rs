//! Errors of the std endpoint's runtime controls.

#[cfg(feature = "relay-server")]
use crate::{RelayServerAddressError, RelayServerConfigError};

/// Relay announce-address validation failure while building an endpoint.
#[cfg(feature = "relay-server")]
#[derive(Debug)]
pub enum RelayServerAnnounceError {
    /// The temporary validator could not be constructed from its configuration.
    Config(RelayServerConfigError),
    /// An announce address is invalid for the relay identity.
    Address(RelayServerAddressError),
}

#[cfg(feature = "relay-server")]
impl From<RelayServerConfigError> for RelayServerAnnounceError {
    fn from(error: RelayServerConfigError) -> Self {
        Self::Config(error)
    }
}

#[cfg(feature = "relay-server")]
impl From<RelayServerAddressError> for RelayServerAnnounceError {
    fn from(error: RelayServerAddressError) -> Self {
        Self::Address(error)
    }
}

#[cfg(feature = "relay-server")]
impl core::fmt::Display for RelayServerAnnounceError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Config(error) => error.fmt(formatter),
            Self::Address(error) => error.fmt(formatter),
        }
    }
}

#[cfg(feature = "relay-server")]
impl std::error::Error for RelayServerAnnounceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::Address(error) => Some(error),
        }
    }
}

/// Why [`Endpoint::set_webtransport_certificate_pem`](crate::Endpoint::set_webtransport_certificate_pem) kept the current
/// certificate.
#[cfg(feature = "quic")]
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum SetWebTransportCertificateError {
    /// The endpoint serves no CA-signed WebTransport certificate to replace.
    #[error(
        "this endpoint serves no CA-signed WebTransport certificate; bind it with \
         EndpointBuilder::webtransport_certificate_pem and a /quic-v1/webtransport listen address"
    )]
    NotConfigured,
    /// The PEM is unusable: no certificate, no private key, more than one
    /// key, or a malformed section.
    #[error("WebTransport certificate PEM: {problem}")]
    Pem {
        /// What is wrong with it.
        problem: String,
    },
    /// The certificate can't be served: the key does not match the leaf, or
    /// the leaf has expired by the host clock.
    #[error("WebTransport certificate: {reason}")]
    Invalid {
        /// Why, as bind would report it.
        reason: String,
    },
}
