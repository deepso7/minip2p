//! One Connection-target shape shared by every binding shell.

use crate::endpoint::parse_peer_id;
use crate::{FfiError, parse_direct_peer_addr};

/// What a foreign runtime supplies to start one Connection attempt.
///
/// Validation for every form lives here, once; binding shells only adapt
/// the shape to their toolchain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectTarget {
    /// Peer ID only: the endpoint applies its discovery-book and relay
    /// policy.
    Peer {
        /// Base58 peer ID.
        peer_id: String,
    },
    /// One or more complete direct peer addresses that all name the same
    /// peer. One address is the single-address form.
    Addresses {
        /// Complete `/quic-v1` or `/tcp` peer addresses.
        addresses: Vec<String>,
    },
}

/// Validates a foreign `target` into the upstream Connection target.
pub(crate) fn parse_connect_target(
    target: ConnectTarget,
) -> Result<minip2p::ConnectTarget, FfiError> {
    match target {
        ConnectTarget::Peer { peer_id } => {
            Ok(minip2p::ConnectTarget::from(parse_peer_id(&peer_id)?))
        }
        ConnectTarget::Addresses { addresses } => {
            let addresses = addresses
                .iter()
                .map(|address| parse_direct_peer_addr(address))
                .collect::<Result<Vec<_>, _>>()?;
            minip2p::ConnectTarget::try_from(addresses).map_err(|error| FfiError::InvalidAddress {
                detail: error.to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FfiError;

    fn peer(seed: u8) -> minip2p::PeerId {
        minip2p::Ed25519Keypair::from_secret_key_bytes([seed; 32]).peer_id()
    }

    #[test]
    fn peer_target_parses_a_peer_id_and_rejects_garbage() {
        let target_peer = peer(7);

        let target = parse_connect_target(ConnectTarget::Peer {
            peer_id: target_peer.to_base58(),
        })
        .expect("peer target");
        assert_eq!(target.peer_id(), &target_peer);
        assert!(target.candidates().is_empty());

        assert!(matches!(
            parse_connect_target(ConnectTarget::Peer {
                peer_id: "nope".into()
            }),
            Err(FfiError::InvalidPeerId { .. })
        ));
    }

    #[test]
    fn address_targets_require_at_least_one_complete_same_peer_address() {
        let target_peer = peer(7);
        let other = peer(8);
        let quic = format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{target_peer}");
        let tcp = format!("/ip4/127.0.0.1/tcp/4001/p2p/{target_peer}");

        assert!(matches!(
            parse_connect_target(ConnectTarget::Addresses {
                addresses: Vec::new()
            }),
            Err(FfiError::InvalidAddress { .. })
        ));

        let Err(FfiError::InvalidAddress { detail }) =
            parse_connect_target(ConnectTarget::Addresses {
                addresses: vec![
                    quic.clone(),
                    format!("/ip4/127.0.0.1/udp/4002/quic-v1/p2p/{other}"),
                ],
            })
        else {
            panic!("addresses naming different peers must fail");
        };
        assert!(detail.contains("different peers"), "{detail}");

        let relay = peer(9);
        assert!(matches!(
            parse_connect_target(ConnectTarget::Addresses {
                addresses: vec![format!(
                    "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{relay}/p2p-circuit/p2p/{target_peer}"
                )],
            }),
            Err(FfiError::InvalidAddress { .. })
        ));

        let target = parse_connect_target(ConnectTarget::Addresses {
            addresses: vec![quic, tcp],
        })
        .expect("same-peer addresses");
        assert_eq!(target.candidates().len(), 2);
        assert_eq!(target.peer_id(), &target_peer);
    }
}
