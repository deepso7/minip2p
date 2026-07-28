//! Foreign-facing endpoint object and construction.

use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use minip2p::{
    BeaconConfig, Endpoint, GossipsubConfig, Multiaddr, NatConfig, PeerDiscoveryConfig,
    TransportError,
};

use crate::{EndpointConfig, FfiError, keypair_from_bytes, parse_direct_quic_peer_addr};

/// A minip2p endpoint owned by a foreign runtime.
#[derive(uniffi::Object)]
pub struct P2pEndpoint {
    endpoint: Mutex<Option<Endpoint>>,
    peer_id: String,
    listen_addrs: Vec<String>,
}

#[uniffi::export]
impl P2pEndpoint {
    /// Validates the secret key and `config`, binds QUIC, and creates a stopped endpoint.
    #[uniffi::constructor]
    pub fn new(secret_key: Vec<u8>, config: EndpointConfig) -> Result<Arc<Self>, FfiError> {
        let keypair = keypair_from_bytes(secret_key)?;
        let relays = config
            .relays
            .iter()
            .map(|address| parse_direct_quic_peer_addr(address))
            .collect::<Result<Vec<_>, _>>()?;
        if config.force_relay && relays.is_empty() {
            return Err(FfiError::InvalidConfig {
                detail: "force_relay requires at least one relay".into(),
            });
        }

        let pubsub = GossipsubConfig {
            allow_unsigned: config.allow_unsigned,
            ..GossipsubConfig::default()
        };
        pubsub.validate().map_err(invalid_config)?;

        let mut builder = Endpoint::builder()
            .identity(keypair)
            .agent_version(
                config
                    .agent_version
                    .unwrap_or_else(|| format!("minip2p-rn/{}", env!("CARGO_PKG_VERSION"))),
            )
            .pubsub_config(pubsub);

        if !relays.is_empty() || config.force_relay {
            builder = builder.nat_config(NatConfig {
                relays,
                force_relay: config.force_relay,
                ..NatConfig::default()
            });
        }

        if let Some(discovery) = config.discovery {
            let beacon = BeaconConfig {
                topic: discovery.topic,
                beacon_interval_ms: discovery.beacon_interval_ms,
                ..BeaconConfig::default()
            };
            beacon.validate().map_err(invalid_config)?;
            let peer_discovery = PeerDiscoveryConfig {
                beacon_peer_ttl_ms: discovery.peer_ttl_ms,
                auto_dial: discovery.auto_dial,
                ..PeerDiscoveryConfig::default()
            };
            peer_discovery.validate().map_err(invalid_config)?;
            builder = builder
                .discovery_config(beacon)
                .map_err(invalid_config)?
                .peer_discovery_config(peer_discovery)
                .map_err(invalid_config)?;
        }

        let mut endpoint = match config.listen_addr {
            Some(address) => {
                let address =
                    Multiaddr::from_str(&address).map_err(|error| FfiError::InvalidAddress {
                        detail: error.to_string(),
                    })?;
                builder
                    .bind_quic_multiaddr(&address)
                    .map_err(map_constructor_error)?
            }
            None => builder
                .bind_quic_dual_stack()
                .map_err(map_constructor_error)?,
        };
        let listen_addrs = endpoint
            .listen_all()
            .map_err(map_constructor_error)?
            .into_iter()
            .map(|address| address.to_string())
            .collect();
        let peer_id = endpoint.peer_id().to_base58();

        Ok(Arc::new(Self {
            endpoint: Mutex::new(Some(endpoint)),
            peer_id,
            listen_addrs,
        }))
    }

    /// Returns the local peer ID as legacy base58 text.
    pub fn peer_id(&self) -> String {
        self.peer_id.clone()
    }

    /// Returns the bound QUIC peer addresses.
    pub fn listen_addrs(&self) -> Vec<String> {
        self.listen_addrs.clone()
    }

    /// Returns peers with an established QUIC or circuit connection.
    pub fn connected_peers(&self) -> Result<Vec<String>, FfiError> {
        self.lock_endpoint()
            .as_ref()
            .map(|endpoint| {
                endpoint
                    .connected_peers()
                    .into_iter()
                    .map(|peer| peer.to_base58())
                    .collect()
            })
            .ok_or_else(|| FfiError::InvalidState {
                detail: "endpoint is stopped".into(),
            })
    }
}

impl P2pEndpoint {
    fn lock_endpoint(&self) -> MutexGuard<'_, Option<Endpoint>> {
        self.endpoint.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn invalid_config(error: impl std::fmt::Display) -> FfiError {
    FfiError::InvalidConfig {
        detail: error.to_string(),
    }
}

fn map_constructor_error(error: minip2p::Error) -> FfiError {
    match error {
        minip2p::Error::Transport(TransportError::InvalidAddress { .. }) => {
            FfiError::InvalidAddress {
                detail: error.to_string(),
            }
        }
        minip2p::Error::Transport(TransportError::InvalidConfig { .. }) => invalid_config(error),
        _ => FfiError::Internal {
            detail: error.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> EndpointConfig {
        EndpointConfig {
            agent_version: None,
            relays: Vec::new(),
            listen_addr: Some("/ip4/127.0.0.1/udp/0/quic-v1".into()),
            force_relay: false,
            allow_unsigned: false,
            discovery: None,
        }
    }

    fn endpoint(config: EndpointConfig) -> Result<Arc<P2pEndpoint>, FfiError> {
        P2pEndpoint::new(vec![9; 32], config)
    }

    #[test]
    fn constructs_a_real_loopback_endpoint() {
        let endpoint = endpoint(config()).expect("endpoint");

        assert!(!endpoint.peer_id().is_empty());
        assert_eq!(endpoint.listen_addrs().len(), 1);
    }

    #[test]
    fn force_relay_requires_a_relay_before_binding() {
        let mut config = config();
        config.force_relay = true;

        assert!(matches!(
            endpoint(config),
            Err(FfiError::InvalidConfig { .. })
        ));
    }

    #[test]
    fn constructor_rejects_bad_key_relay_and_listen_address() {
        let bad_key = config();
        let mut bad_secret = vec![9; 32];
        bad_secret.pop();
        assert!(matches!(
            P2pEndpoint::new(bad_secret, bad_key),
            Err(FfiError::InvalidKey { .. })
        ));

        let mut bad_relay = config();
        bad_relay.relays.push("not-a-peer-address".into());
        assert!(matches!(
            endpoint(bad_relay),
            Err(FfiError::InvalidAddress { .. })
        ));

        let mut bad_listen = config();
        bad_listen.listen_addr = Some("not-a-multiaddr".into());
        assert!(matches!(
            endpoint(bad_listen),
            Err(FfiError::InvalidAddress { .. })
        ));
    }

    #[test]
    fn constructor_validates_discovery_before_binding() {
        let mut invalid_topic = config();
        invalid_topic.discovery = Some(crate::DiscoveryOptions {
            topic: String::new(),
            beacon_interval_ms: 10_000,
            peer_ttl_ms: 35_000,
            auto_dial: true,
        });
        assert!(matches!(
            endpoint(invalid_topic),
            Err(FfiError::InvalidConfig { .. })
        ));

        let mut invalid_ttl = config();
        invalid_ttl.discovery = Some(crate::DiscoveryOptions {
            topic: "room".into(),
            beacon_interval_ms: 10_000,
            peer_ttl_ms: 0,
            auto_dial: true,
        });
        assert!(matches!(
            endpoint(invalid_ttl),
            Err(FfiError::InvalidConfig { .. })
        ));
    }

    #[test]
    fn immutable_queries_reflect_the_constructed_endpoint() {
        let expected_peer = minip2p::Ed25519Keypair::from_secret_key_bytes([9; 32])
            .peer_id()
            .to_base58();
        let endpoint = endpoint(config()).expect("endpoint");

        assert_eq!(endpoint.peer_id(), expected_peer);
        assert!(endpoint.listen_addrs()[0].starts_with("/ip4/127.0.0.1/udp/"));
        assert!(
            endpoint
                .connected_peers()
                .expect("running endpoint")
                .is_empty()
        );
    }

    #[test]
    fn endpoint_config_contains_no_secret_material() {
        let debug = format!("{:?}", config());

        assert!(!debug.contains("9, 9, 9"));
    }

    #[test]
    fn poisoned_endpoint_lock_recovers() {
        let endpoint = endpoint(config()).expect("endpoint");
        let endpoint_for_panic = Arc::clone(&endpoint);
        let _ = std::thread::spawn(move || {
            let _guard = endpoint_for_panic.endpoint.lock().expect("lock");
            panic!("poison endpoint lock");
        })
        .join();

        assert!(endpoint.lock_endpoint().is_some());
    }

    #[test]
    fn constructor_accepts_default_dual_stack_binding() {
        let mut config = config();
        config.listen_addr = None;

        let endpoint = endpoint(config).expect("dual-stack endpoint");

        assert!(!endpoint.listen_addrs().is_empty());
    }

    #[test]
    fn constructor_accepts_valid_discovery_configuration() {
        let mut config = config();
        config.discovery = Some(crate::DiscoveryOptions {
            topic: "room".into(),
            beacon_interval_ms: 10_000,
            peer_ttl_ms: 35_000,
            auto_dial: true,
        });

        endpoint(config).expect("discovery endpoint");
    }

    #[test]
    fn constructor_rejects_non_quic_and_circuit_relays() {
        let relay = minip2p::Ed25519Keypair::from_secret_key_bytes([8; 32]).peer_id();

        for address in [
            format!("/ip4/127.0.0.1/udp/4001/p2p/{relay}"),
            format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p-circuit/p2p/{relay}"),
        ] {
            let mut config = config();
            config.relays.push(address);
            assert!(matches!(
                endpoint(config),
                Err(FfiError::InvalidAddress { .. })
            ));
        }
    }

    #[test]
    fn connected_peers_reports_a_stopped_endpoint() {
        let endpoint = endpoint(config()).expect("endpoint");
        *endpoint.lock_endpoint() = None;

        assert!(matches!(
            endpoint.connected_peers(),
            Err(FfiError::InvalidState { .. })
        ));
    }

    #[test]
    fn runtime_constructor_failures_are_internal() {
        for error in [
            TransportError::ListenFailed {
                reason: "socket unavailable".into(),
            },
            TransportError::ResourceExhausted { resource: "socket" },
        ] {
            assert!(matches!(
                map_constructor_error(error.into()),
                FfiError::Internal { .. }
            ));
        }
    }
}
