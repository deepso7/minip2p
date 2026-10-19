use alloc::vec::Vec;

use minip2p_core::{Multiaddr, PeerId, Protocol};

/// Host-refreshed address source whose rejection is reported by
/// [`RelayServerEvent::AddrsRejected`](crate::RelayServerEvent::AddrsRejected).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayServerAddrSource {
    /// Concrete bound listeners, from
    /// [`RelayServerAgent::set_listener_addrs`](crate::RelayServerAgent::set_listener_addrs).
    Listener,
    /// AutoNAT-confirmed direct addresses, from
    /// [`RelayServerAgent::set_confirmed_addrs`](crate::RelayServerAgent::set_confirmed_addrs).
    Confirmed,
}

/// Why a relay announce address cannot be advertised.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayServerAddressErrorKind {
    /// The host is unspecified and therefore not remotely dialable.
    Wildcard,
    /// Relay circuit addresses cannot describe a relay's direct listener.
    Circuit,
    /// A trailing peer id names a different relay.
    ConflictingPeerId {
        /// Local relay identity required on the address.
        expected: PeerId,
        /// Different identity found on the address.
        found: PeerId,
    },
    /// The protocol sequence is not a supported direct TCP, QUIC-v1, or
    /// WebTransport (with `/certhash`) address.
    UnsupportedShape,
}

impl core::fmt::Display for RelayServerAddressErrorKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Wildcard => f.write_str("wildcard hosts are not dialable"),
            Self::Circuit => f.write_str("relay circuit addresses cannot be announced"),
            Self::ConflictingPeerId { expected, found } => {
                write!(f, "peer id {found} does not match local peer {expected}")
            }
            Self::UnsupportedShape => f.write_str(
                "expected a direct TCP, QUIC-v1, or WebTransport address with a /certhash",
            ),
        }
    }
}

/// Indexed, actionable validation failure for an announce address.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid relay announce address at index {index} (`{address}`): {reason}")]
pub struct RelayServerAddressError {
    /// Zero-based index in the replacement input.
    pub index: usize,
    /// Exact rejected input address.
    pub address: Multiaddr,
    /// Machine-readable rejection reason.
    pub reason: RelayServerAddressErrorKind,
}

#[expect(
    clippy::result_large_err,
    reason = "The error owns the rejected address so callers can report the exact invalid input."
)]
pub(crate) fn normalize_addrs(
    local_peer_id: &PeerId,
    addrs: Vec<Multiaddr>,
) -> Result<Vec<Multiaddr>, RelayServerAddressError> {
    let mut normalized = Vec::with_capacity(addrs.len());
    for (index, address) in addrs.into_iter().enumerate() {
        let value = normalize_addr(local_peer_id, address.clone()).map_err(|reason| {
            RelayServerAddressError {
                index,
                address,
                reason,
            }
        })?;
        if !normalized.iter().any(|existing| existing == &value) {
            normalized.push(value);
        }
    }
    Ok(normalized)
}

#[expect(
    clippy::result_large_err,
    reason = "Address validation keeps the rejected input and its actionable reason together."
)]
fn normalize_addr(
    local_peer_id: &PeerId,
    address: Multiaddr,
) -> Result<Multiaddr, RelayServerAddressErrorKind> {
    let mut protocols = address.protocols().to_vec();
    if protocols
        .iter()
        .any(|protocol| matches!(protocol, Protocol::P2pCircuit))
    {
        return Err(RelayServerAddressErrorKind::Circuit);
    }
    if let Some(Protocol::P2p(found)) = protocols.last() {
        if found != local_peer_id {
            return Err(RelayServerAddressErrorKind::ConflictingPeerId {
                expected: local_peer_id.clone(),
                found: found.clone(),
            });
        }
        protocols.pop();
    }

    let Some(host) = protocols.first() else {
        return Err(RelayServerAddressErrorKind::UnsupportedShape);
    };
    if matches!(host, Protocol::Ip4(bytes) if *bytes == [0; 4])
        || matches!(host, Protocol::Ip6(bytes) if *bytes == [0; 16])
    {
        return Err(RelayServerAddressErrorKind::Wildcard);
    }
    if !matches!(
        host,
        Protocol::Ip4(_)
            | Protocol::Ip6(_)
            | Protocol::Dns(_)
            | Protocol::Dns4(_)
            | Protocol::Dns6(_)
    ) {
        return Err(RelayServerAddressErrorKind::UnsupportedShape);
    }
    let supported = matches!(protocols.as_slice(), [_, Protocol::Tcp(port)] if *port != 0)
        || matches!(
            protocols.as_slice(),
            [_, Protocol::Udp(port), Protocol::QuicV1] if *port != 0
        )
        // A browser dials only what its certificate hash pins.
        || matches!(
            protocols.as_slice(),
            [_, Protocol::Udp(port), Protocol::QuicV1, Protocol::WebTransport, hashes @ ..]
                if *port != 0
                    && !hashes.is_empty()
                    && hashes.iter().all(|hash| matches!(hash, Protocol::Certhash(_)))
        );
    if !supported {
        return Err(RelayServerAddressErrorKind::UnsupportedShape);
    }
    Ok(Multiaddr::from_protocols(protocols))
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use minip2p_core::{Multiaddr, PeerId, Protocol};

    use super::*;

    fn peer(seed: &[u8]) -> PeerId {
        PeerId::from_public_key_protobuf(seed)
    }

    fn addr(value: &str) -> Multiaddr {
        Multiaddr::from_str(value).unwrap()
    }

    #[test]
    fn supported_addresses_are_normalized_and_deduplicated_first_wins() {
        let local = peer(b"relay-local");
        let tcp = addr("/dns4/relay.example/tcp/4001");
        let quic = addr("/ip6/2001:db8::1/udp/4002/quic-v1");
        let webtransport = addr(
            "/ip4/192.0.2.1/udp/4002/quic-v1/webtransport/certhash/uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g",
        );
        let mut tcp_with_peer = tcp.clone();
        tcp_with_peer.push(Protocol::P2p(local.clone()));

        assert_eq!(
            normalize_addrs(
                &local,
                vec![
                    tcp_with_peer,
                    tcp.clone(),
                    quic.clone(),
                    webtransport.clone()
                ]
            )
            .unwrap(),
            vec![tcp, quic, webtransport]
        );
    }

    #[test]
    fn invalid_address_reports_index_address_and_typed_reason() {
        let local = peer(b"relay-local");
        let wildcard = addr("/ip4/0.0.0.0/tcp/4001");
        assert_eq!(
            normalize_addrs(&local, vec![addr("/ip4/192.0.2.1/tcp/1"), wildcard.clone()]),
            Err(RelayServerAddressError {
                index: 1,
                address: wildcard,
                reason: RelayServerAddressErrorKind::Wildcard,
            })
        );

        let mut conflicting = addr("/ip4/192.0.2.1/tcp/4001");
        let found = peer(b"other-peer");
        conflicting.push(Protocol::P2p(found.clone()));
        assert_eq!(
            normalize_addrs(&local, vec![conflicting.clone()])
                .unwrap_err()
                .reason,
            RelayServerAddressErrorKind::ConflictingPeerId {
                expected: local,
                found,
            }
        );
    }

    #[test]
    fn circuit_and_unsupported_shapes_are_rejected() {
        let local = peer(b"relay-local");
        for (address, reason) in [
            (
                addr("/ip4/192.0.2.1/tcp/4001/p2p-circuit"),
                RelayServerAddressErrorKind::Circuit,
            ),
            (
                addr("/ip4/192.0.2.1/udp/4001"),
                RelayServerAddressErrorKind::UnsupportedShape,
            ),
            // No browser can dial a WebTransport address without a certhash.
            (
                addr("/ip4/192.0.2.1/udp/4001/quic-v1/webtransport"),
                RelayServerAddressErrorKind::UnsupportedShape,
            ),
        ] {
            assert_eq!(
                normalize_addrs(&local, vec![address]).unwrap_err().reason,
                reason
            );
        }
    }
}
