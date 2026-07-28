//! Foreign-facing endpoint object and construction.

use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use minip2p::{
    BeaconConfig, Endpoint, GossipsubConfig, Multiaddr, NatConfig, PeerDiscoveryConfig,
    QuicWaitHandle, TransportError,
};

use crate::{EndpointConfig, FfiError, keypair_from_bytes, parse_direct_quic_peer_addr};

/// A minip2p endpoint owned by a foreign runtime.
#[derive(uniffi::Object)]
pub struct P2pEndpoint {
    shared: Arc<Shared>,
    peer_id: String,
    listen_addrs: Vec<String>,
}

struct Shared {
    state: Mutex<EndpointState>,
    stopped_cv: Condvar,
    wait_handle: QuicWaitHandle,
    pending_commands: AtomicUsize,
}

struct EndpointState {
    lifecycle: Lifecycle,
    endpoint: Option<Endpoint>,
    active: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Lifecycle {
    Created,
    Running,
    Stopped,
}

#[uniffi::export]
impl P2pEndpoint {
    /// Validates the secret key and `config`, binds QUIC, and creates an endpoint.
    ///
    /// The endpoint begins in the created state and owns its bound sockets,
    /// but does not run a background driver until explicitly started.
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
        let wait_handle = endpoint.wait_handle();

        Ok(Arc::new(Self {
            shared: Arc::new(Shared {
                state: Mutex::new(EndpointState {
                    lifecycle: Lifecycle::Created,
                    endpoint: Some(endpoint),
                    active: false,
                }),
                stopped_cv: Condvar::new(),
                wait_handle,
                pending_commands: AtomicUsize::new(0),
            }),
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
        self.shared
            .lock_state()
            .endpoint
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

    /// Selects active or idle driver polling without changing delivery semantics.
    pub fn set_active(&self, active: bool) {
        let _pending = PendingCommand::new(&self.shared);
        self.shared.lock_state().active = active;
    }

    /// Returns whether the background driver is currently running.
    pub fn is_running(&self) -> bool {
        self.shared.lock_state().lifecycle == Lifecycle::Running
    }

    /// Requests shutdown without waiting for an in-flight callback.
    pub fn stop(&self) {
        let _pending = PendingCommand::new(&self.shared);
        let endpoint = {
            let mut state = self.shared.lock_state();
            match state.lifecycle {
                Lifecycle::Created | Lifecycle::Running => {
                    state.lifecycle = Lifecycle::Stopped;
                    state.endpoint.take()
                }
                Lifecycle::Stopped => None,
            }
        };
        drop(endpoint);

        let stopped = self.shared.lock_state().lifecycle == Lifecycle::Stopped;
        if stopped {
            self.shared.stopped_cv.notify_all();
        }
    }

    /// Waits up to `timeout_ms` for the endpoint to reach the stopped state.
    ///
    /// A newly created endpoint still owns bound sockets, so this returns
    /// `false` until either a driver exits or [`P2pEndpoint::stop`] is called.
    pub fn wait_stopped(&self, timeout_ms: u64) -> bool {
        let timeout = Duration::from_millis(timeout_ms);
        let started = Instant::now();
        let mut state = self.shared.lock_state();
        loop {
            if state.lifecycle == Lifecycle::Stopped {
                return true;
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return false;
            }
            let (next, result) = self
                .shared
                .stopped_cv
                .wait_timeout(state, remaining)
                .unwrap_or_else(PoisonError::into_inner);
            state = next;
            if result.timed_out() && state.lifecycle != Lifecycle::Stopped {
                return false;
            }
        }
    }
}

impl Drop for P2pEndpoint {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Shared {
    fn lock_state(&self) -> MutexGuard<'_, EndpointState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

struct PendingCommand<'a> {
    shared: &'a Shared,
}

impl<'a> PendingCommand<'a> {
    fn new(shared: &'a Shared) -> Self {
        shared.pending_commands.fetch_add(1, Ordering::AcqRel);
        shared.wait_handle.interrupt();
        Self { shared }
    }
}

impl Drop for PendingCommand<'_> {
    fn drop(&mut self) {
        self.shared.pending_commands.fetch_sub(1, Ordering::AcqRel);
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
            let _guard = endpoint_for_panic.shared.state.lock().expect("lock");
            panic!("poison endpoint lock");
        })
        .join();

        assert!(endpoint.shared.lock_state().endpoint.is_some());
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
        endpoint.stop();

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

    #[test]
    fn created_endpoint_requires_stop_before_wait_stopped() {
        let endpoint = endpoint(config()).expect("endpoint");

        assert!(!endpoint.is_running());
        assert!(!endpoint.wait_stopped(0));
        endpoint.stop();
        assert!(endpoint.wait_stopped(100));
        assert!(!endpoint.is_running());
    }

    #[test]
    fn stop_and_set_active_are_idempotent_in_created_and_stopped_states() {
        let endpoint = endpoint(config()).expect("endpoint");

        endpoint.set_active(true);
        assert!(endpoint.shared.lock_state().active);
        endpoint.stop();
        endpoint.stop();
        endpoint.set_active(false);

        let state = endpoint.shared.lock_state();
        assert_eq!(state.lifecycle, Lifecycle::Stopped);
        assert!(!state.active);
        assert!(state.endpoint.is_none());
    }

    #[test]
    fn stop_finishes_a_synthetic_running_state() {
        let endpoint = endpoint(config()).expect("endpoint");
        endpoint.shared.lock_state().lifecycle = Lifecycle::Running;

        endpoint.stop();

        let state = endpoint.shared.lock_state();
        assert_eq!(state.lifecycle, Lifecycle::Stopped);
        assert!(state.endpoint.is_none());
        drop(state);
        assert!(endpoint.wait_stopped(0));
    }

    #[test]
    fn pending_command_interrupts_a_waiter_and_balances_the_counter() {
        let endpoint = endpoint(config()).expect("endpoint");
        let shared = Arc::clone(&endpoint.shared);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let mut state = shared.lock_state();
            entered_tx.send(()).expect("signal waiter");
            let wake = state
                .endpoint
                .as_mut()
                .expect("endpoint")
                .next_wake(Duration::from_secs(5))
                .expect("wait");
            assert!(matches!(wake, minip2p::EndpointWake::Interrupted));
        });
        entered_rx.recv().expect("waiter entered");
        std::thread::sleep(Duration::from_millis(20));

        {
            let _pending = PendingCommand::new(&endpoint.shared);
            assert_eq!(endpoint.shared.pending_commands.load(Ordering::Acquire), 1);
        }
        waiter.join().expect("waiter exits after interrupt");
        assert_eq!(endpoint.shared.pending_commands.load(Ordering::Acquire), 0);
    }
}
