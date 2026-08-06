//! Foreign-facing endpoint object and construction.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use minip2p::{
    BeaconConfig, Endpoint, EndpointBuilder, FloodsubConfig, GossipsubConfig, MdnsConfig,
    Multiaddr, NatConfig, PeerDiscoveryConfig, PeerId, PublishError, PubsubConfig, PubsubError,
    StreamId, TopicError, TransportError, WaitHandle,
};

use crate::{
    DriverStats, EndpointConfig, FfiError, IdentifyInfo, KnownPeerInfo, P2pEventListener,
    PubsubRouter, RelayReservationInfo, TransportOptions, keypair_from_bytes,
    parse_direct_peer_addr,
};

fn configure_transports(
    mut builder: EndpointBuilder,
    quic: Option<TransportOptions>,
    tcp: Option<TransportOptions>,
) -> Result<EndpointBuilder, FfiError> {
    if quic.is_none() && tcp.is_none() {
        return Err(FfiError::InvalidConfig {
            detail: "at least one transport must be enabled".into(),
        });
    }

    if let Some(options) = quic {
        match options.listen_addrs {
            None => builder = builder.quic_dual_stack(),
            Some(addresses) => {
                if addresses.is_empty() {
                    return Err(empty_transport_list("QUIC"));
                }
                for address in addresses {
                    let address = parse_listen_addr(&address, "QUIC")?;
                    if !address.is_quic_transport() {
                        return Err(wrong_transport("QUIC", &address));
                    }
                    builder = builder.quic_multiaddr(&address);
                }
            }
        }
    }

    if let Some(options) = tcp {
        let addresses = options
            .listen_addrs
            .unwrap_or_else(|| vec!["/ip4/0.0.0.0/tcp/0".into(), "/ip6/::/tcp/0".into()]);
        if addresses.is_empty() {
            return Err(empty_transport_list("TCP"));
        }
        for address in addresses {
            let address = parse_listen_addr(&address, "TCP")?;
            if !address.is_tcp_transport() {
                return Err(wrong_transport("TCP", &address));
            }
            builder = builder.tcp_multiaddr(&address);
        }
    }

    Ok(builder)
}

fn parse_listen_addr(address: &str, transport: &str) -> Result<Multiaddr, FfiError> {
    Multiaddr::from_str(address).map_err(|error| FfiError::InvalidAddress {
        detail: format!("invalid {transport} listen address `{address}`: {error}"),
    })
}

fn empty_transport_list(transport: &str) -> FfiError {
    FfiError::InvalidConfig {
        detail: format!(
            "{transport} listen cannot be empty; omit listen to use dual-stack defaults, or omit the {} transport configuration to disable it",
            transport.to_ascii_lowercase()
        ),
    }
}

fn wrong_transport(transport: &str, address: &Multiaddr) -> FfiError {
    FfiError::InvalidConfig {
        detail: format!("{transport} listen address `{address}` does not use {transport}"),
    }
}

/// A minip2p endpoint owned by a foreign runtime.
#[derive(uniffi::Object)]
pub struct P2pEndpoint {
    shared: Arc<Shared>,
    peer_id: String,
    listen_addrs: Vec<String>,
}

pub(crate) struct Shared {
    state: Mutex<EndpointState>,
    pub(crate) stopped_cv: Condvar,
    wait_handle: WaitHandle,
    pub(crate) pending_commands: AtomicUsize,
    pub(crate) driver_running: AtomicBool,
}

pub(crate) struct EndpointState {
    pub(crate) lifecycle: Lifecycle,
    pub(crate) endpoint: Option<Endpoint>,
    pub(crate) active: bool,
    pub(crate) driver_thread_id: Option<std::thread::ThreadId>,
    connect_ids: BTreeMap<u64, minip2p::ConnectId>,
    pub(crate) cancelled_connect_ids: BTreeSet<u64>,
    pub(crate) stats: DriverStats,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Lifecycle {
    Created,
    Running,
    Stopping,
    Stopped,
}

#[uniffi::export]
impl P2pEndpoint {
    /// Validates the secret key and `config`, binds its transports, and creates
    /// an endpoint.
    ///
    /// The endpoint begins in the created state and owns its bound sockets,
    /// but does not run a background driver until explicitly started.
    #[uniffi::constructor]
    pub fn new(secret_key: Vec<u8>, config: EndpointConfig) -> Result<Arc<Self>, FfiError> {
        let keypair = keypair_from_bytes(secret_key)?;
        let relays = config
            .relays
            .iter()
            .map(|address| parse_direct_peer_addr(address))
            .collect::<Result<Vec<_>, _>>()?;
        let autonat_servers = config
            .autonat_servers
            .iter()
            .map(|address| parse_direct_peer_addr(address))
            .collect::<Result<Vec<_>, _>>()?;
        if config.force_relay && relays.is_empty() {
            return Err(FfiError::InvalidConfig {
                detail: "force_relay requires at least one relay".into(),
            });
        }

        let pubsub = match config.pubsub_router {
            PubsubRouter::Gossipsub => PubsubConfig::Gossipsub(GossipsubConfig {
                allow_unsigned: config.allow_unsigned,
                ..GossipsubConfig::default()
            }),
            PubsubRouter::Floodsub => PubsubConfig::Floodsub(FloodsubConfig {
                allow_unsigned: config.allow_unsigned,
                ..FloodsubConfig::default()
            }),
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
        for protocol in config.protocols {
            builder = builder.protocol(protocol);
        }

        builder = builder.nat_config(NatConfig {
            relays,
            autonat_servers,
            force_relay: config.force_relay,
            ..NatConfig::default()
        });

        let signed_auto_dial = config.discovery.as_ref().map(|options| options.auto_dial);
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
        if let Some(mdns) = config.mdns {
            if signed_auto_dial.is_some_and(|auto_dial| auto_dial != mdns.auto_dial) {
                return Err(FfiError::InvalidConfig {
                    detail: "signed discovery and mDNS must use the same auto_dial policy".into(),
                });
            }
            let mdns_config = MdnsConfig {
                enable_ipv6: mdns.enable_ipv6,
                ttl_ms: mdns.ttl_ms,
                query_interval_ms: mdns.query_interval_ms,
                max_packet_bytes: mdns.max_packet_bytes as usize,
                max_announced_addrs: mdns.max_announced_addrs as usize,
                interface_refresh_ms: mdns.interface_refresh_ms,
                socket_poll_interval_ms: mdns.socket_poll_interval_ms,
            };
            mdns_config.validate().map_err(invalid_config)?;
            builder = builder.mdns_config(mdns_config).map_err(invalid_config)?;
            if signed_auto_dial.is_none() {
                builder = builder
                    .peer_discovery_config(PeerDiscoveryConfig {
                        auto_dial: mdns.auto_dial,
                        ..PeerDiscoveryConfig::default()
                    })
                    .map_err(invalid_config)?;
            }
        }

        builder = configure_transports(builder, config.quic, config.tcp)?;
        let mut endpoint = builder.bind().map_err(map_constructor_error)?;
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
                    driver_thread_id: None,
                    connect_ids: BTreeMap::new(),
                    cancelled_connect_ids: BTreeSet::new(),
                    stats: DriverStats::default(),
                }),
                stopped_cv: Condvar::new(),
                wait_handle,
                pending_commands: AtomicUsize::new(0),
                driver_running: AtomicBool::new(false),
            }),
            peer_id,
            listen_addrs,
        }))
    }

    /// Returns the local peer ID as legacy base58 text.
    pub fn peer_id(&self) -> String {
        self.peer_id.clone()
    }

    /// Returns the bound TCP or QUIC peer addresses.
    pub fn listen_addrs(&self) -> Vec<String> {
        self.listen_addrs.clone()
    }

    /// Returns peers with an established TCP, QUIC, or circuit connection.
    pub fn connected_peers(&self) -> Result<Vec<String>, FfiError> {
        let _pending = PendingCommand::new(&self.shared);
        let state = self.shared.lock_state();
        if matches!(state.lifecycle, Lifecycle::Stopping | Lifecycle::Stopped) {
            return Err(FfiError::Stopped);
        }
        state
            .endpoint
            .as_ref()
            .map(|endpoint| {
                endpoint
                    .connected_peers()
                    .into_iter()
                    .map(|peer| peer.to_base58())
                    .collect()
            })
            .ok_or(FfiError::Stopped)
    }

    /// Returns whether Identify has completed for `peer_id`.
    pub fn is_peer_ready(&self, peer_id: String) -> Result<bool, FfiError> {
        let peer = parse_peer_id(&peer_id)?;
        self.with_endpoint(|endpoint| endpoint.is_peer_ready(&peer))
    }

    /// Returns the latest Identify snapshot for `peer_id`.
    pub fn peer_info(&self, peer_id: String) -> Result<Option<IdentifyInfo>, FfiError> {
        let peer = parse_peer_id(&peer_id)?;
        self.with_endpoint(|endpoint| {
            endpoint
                .peer_info(&peer)
                .map(crate::events::convert_identify)
        })
    }

    /// Selects active or idle driver polling without changing delivery semantics.
    pub fn set_active(&self, active: bool) {
        let _pending = PendingCommand::new(&self.shared);
        self.shared.lock_state().active = active;
    }

    /// Returns whether the background driver is accepting work.
    ///
    /// This becomes `false` when shutdown is requested. Use
    /// [`P2pEndpoint::wait_stopped`] to observe complete driver exit.
    pub fn is_running(&self) -> bool {
        let _pending = PendingCommand::new(&self.shared);
        self.shared.lock_state().lifecycle == Lifecycle::Running
    }

    /// Starts the detached background endpoint driver.
    pub fn start(&self, listener: Arc<dyn P2pEventListener>) -> Result<(), FfiError> {
        self.start_with(listener, |shared, listener| {
            std::thread::Builder::new()
                .name("minip2p-driver".into())
                .spawn(move || crate::driver::run(shared, listener))
                .map(drop)
        })
    }

    /// Requests shutdown without waiting for an in-flight callback.
    pub fn stop(&self) {
        let _pending = PendingCommand::new(&self.shared);
        let endpoint = {
            let mut state = self.shared.lock_state();
            match state.lifecycle {
                Lifecycle::Created => {
                    state.lifecycle = Lifecycle::Stopped;
                    state.endpoint.take()
                }
                Lifecycle::Running => {
                    state.lifecycle = Lifecycle::Stopping;
                    None
                }
                Lifecycle::Stopping | Lifecycle::Stopped => None,
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
    /// `false` until `stop` releases it. For a running endpoint, `stop` only
    /// requests shutdown and this waits for the driver exit cleanup.
    ///
    /// Calling this from a listener callback would wait on the callback's own
    /// driver thread, so that case returns `false` immediately.
    pub fn wait_stopped(&self, timeout_ms: u64) -> bool {
        let timeout = Duration::from_millis(timeout_ms);
        let started = Instant::now();
        let mut state = self.shared.lock_state();
        if state.lifecycle == Lifecycle::Stopped {
            return true;
        }
        if state.driver_thread_id == Some(std::thread::current().id()) {
            return false;
        }
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

    /// Subscribes to a pubsub topic.
    pub fn subscribe(&self, topic: String) -> Result<bool, FfiError> {
        self.with_endpoint_mut(|endpoint| endpoint.subscribe(&topic).map_err(map_pubsub_error))
    }

    /// Withdraws a pubsub subscription.
    pub fn unsubscribe(&self, topic: String) -> Result<bool, FfiError> {
        self.with_endpoint_mut(|endpoint| endpoint.unsubscribe(&topic).map_err(map_pubsub_error))
    }

    /// Publishes one application payload.
    pub fn publish(&self, topic: String, data: Vec<u8>) -> Result<(), FfiError> {
        if data.len() > minip2p_pubsub::MAX_RPC_SIZE {
            return Err(FfiError::MessageTooLarge);
        }
        self.with_endpoint_mut(|endpoint| endpoint.publish(&topic, data).map_err(map_pubsub_error))
    }

    /// Sends an explicit ping; completion arrives as a ping event.
    pub fn ping(&self, peer_id: String) -> Result<(), FfiError> {
        let peer = parse_peer_id(&peer_id)?;
        self.with_endpoint_mut(|endpoint| endpoint.ping(&peer).map_err(map_driver_error))
    }

    /// Registers an application protocol.
    pub fn add_protocol(&self, protocol_id: String) -> Result<(), FfiError> {
        self.with_endpoint_mut(|endpoint| {
            endpoint.add_protocol(protocol_id).map_err(map_driver_error)
        })
    }

    /// Opens a negotiated application stream and returns its opaque id.
    pub fn open_stream(
        &self,
        peer_id: String,
        protocol_id: String,
    ) -> Result<crate::OpenStreamResult, FfiError> {
        let peer = parse_peer_id(&peer_id)?;
        self.with_endpoint_mut(|endpoint| {
            endpoint
                .open_stream_with_connection(&peer, &protocol_id)
                .map(|(conn_id, stream_id)| crate::OpenStreamResult {
                    conn_id: conn_id.as_u64(),
                    stream_id: stream_id.as_u64(),
                })
                .map_err(map_driver_error)
        })
    }

    /// Sends one byte chunk on an application stream.
    pub fn send_stream(
        &self,
        peer_id: String,
        stream_id: u64,
        data: Vec<u8>,
    ) -> Result<(), FfiError> {
        let peer = parse_peer_id(&peer_id)?;
        self.with_endpoint_mut(|endpoint| {
            endpoint
                .send_stream(&peer, StreamId::new(stream_id), data)
                .map_err(map_driver_error)
        })
    }

    /// Half-closes the local write side of an application stream.
    pub fn close_stream_write(&self, peer_id: String, stream_id: u64) -> Result<(), FfiError> {
        let peer = parse_peer_id(&peer_id)?;
        self.with_endpoint_mut(|endpoint| {
            endpoint
                .close_stream_write(&peer, StreamId::new(stream_id))
                .map_err(map_driver_error)
        })
    }

    /// Resets an application stream while retaining later close events.
    pub fn reset_stream(&self, peer_id: String, stream_id: u64) -> Result<(), FfiError> {
        let peer = parse_peer_id(&peer_id)?;
        self.with_endpoint_mut(|endpoint| {
            endpoint
                .reset_stream(&peer, StreamId::new(stream_id))
                .map_err(map_driver_error)
        })
    }

    /// Resets and forgets an application stream.
    pub fn abandon_stream(&self, peer_id: String, stream_id: u64) -> Result<(), FfiError> {
        let peer = parse_peer_id(&peer_id)?;
        self.with_endpoint_mut(|endpoint| {
            endpoint
                .abandon_stream(&peer, StreamId::new(stream_id))
                .map_err(map_driver_error)
        })
    }

    /// Starts a connection attempt toward a peer without known direct addresses.
    pub fn connect(&self, peer_id: String) -> Result<u64, FfiError> {
        let peer = PeerId::from_str(&peer_id).map_err(|error| FfiError::InvalidPeerId {
            detail: error.to_string(),
        })?;
        let _pending = PendingCommand::new(&self.shared);
        let mut state = self.shared.lock_state();
        ensure_accepting_commands(&state)?;
        let id = state
            .endpoint
            .as_mut()
            .ok_or(FfiError::Stopped)?
            .connect(&peer)
            .map_err(map_driver_error)?;
        state.connect_ids.insert(id.as_u64(), id);
        Ok(id.as_u64())
    }

    /// Starts a NAT connection attempt using an explicit ordered address set.
    pub fn connect_with_addrs(
        &self,
        peer_id: String,
        addresses: Vec<String>,
    ) -> Result<u64, FfiError> {
        let peer = parse_peer_id(&peer_id)?;
        let addresses = addresses
            .iter()
            .map(|address| parse_direct_peer_addr(address))
            .collect::<Result<Vec<_>, _>>()?;
        if addresses.iter().any(|address| address.peer_id() != &peer) {
            return Err(FfiError::InvalidAddress {
                detail: "every connection address must end in the requested peer id".into(),
            });
        }
        let direct_addrs = addresses
            .into_iter()
            .map(|address| address.transport().clone())
            .collect();
        let _pending = PendingCommand::new(&self.shared);
        let mut state = self.shared.lock_state();
        ensure_accepting_commands(&state)?;
        let id = state
            .endpoint
            .as_mut()
            .ok_or(FfiError::Stopped)?
            .connect_with_addrs(peer, direct_addrs)
            .map_err(map_driver_error)?;
        state.connect_ids.insert(id.as_u64(), id);
        Ok(id.as_u64())
    }

    /// Starts a connection attempt toward a direct `/tcp` or `/quic-v1` peer
    /// address.
    pub fn connect_addr(&self, address: String) -> Result<u64, FfiError> {
        let address = parse_direct_peer_addr(&address)?;
        let _pending = PendingCommand::new(&self.shared);
        let mut state = self.shared.lock_state();
        ensure_accepting_commands(&state)?;
        let id = state
            .endpoint
            .as_mut()
            .ok_or(FfiError::Stopped)?
            .connect_addr(&address)
            .map_err(map_driver_error)?;
        state.connect_ids.insert(id.as_u64(), id);
        Ok(id.as_u64())
    }

    /// Dials a direct peer address on every applicable local address family.
    pub fn dial(&self, address: String) -> Result<Vec<u64>, FfiError> {
        let address = parse_direct_peer_addr(&address)?;
        self.with_endpoint_mut(|endpoint| {
            endpoint
                .dial(&address)
                .map(|ids| ids.into_iter().map(|id| id.as_u64()).collect())
                .map_err(map_driver_error)
        })
    }

    /// Dials a direct peer address using IPv4.
    pub fn dial_ip4(&self, address: String) -> Result<u64, FfiError> {
        let address = parse_direct_peer_addr(&address)?;
        self.with_endpoint_mut(|endpoint| {
            endpoint
                .dial_ip4(&address)
                .map(|id| id.as_u64())
                .map_err(map_driver_error)
        })
    }

    /// Dials a direct peer address using IPv6.
    pub fn dial_ip6(&self, address: String) -> Result<u64, FfiError> {
        let address = parse_direct_peer_addr(&address)?;
        self.with_endpoint_mut(|endpoint| {
            endpoint
                .dial_ip6(&address)
                .map(|id| id.as_u64())
                .map_err(map_driver_error)
        })
    }

    /// Cancels a known connection attempt; unknown ids are an idempotent no-op.
    ///
    /// Queued connection events are suppressed when possible. A listener
    /// callback that already won the dispatch race may still arrive.
    pub fn cancel_connect(&self, id: u64) -> Result<(), FfiError> {
        let _pending = PendingCommand::new(&self.shared);
        let mut state = self.shared.lock_state();
        ensure_accepting_commands(&state)?;
        let connect_id = state.connect_ids.get(&id).copied();
        let endpoint = state.endpoint.as_mut().ok_or(FfiError::Stopped)?;
        if let Some(connect_id) = connect_id {
            endpoint.cancel_connect(connect_id);
            state.cancelled_connect_ids.insert(id);
        }
        Ok(())
    }

    /// Closes the active connection to `peer_id`.
    ///
    /// Cancelling a connection attempt suppresses that attempt's progress
    /// events, but cannot retract a transport connection that has already
    /// completed. Call this method when cancellation must also close an
    /// established connection.
    pub fn disconnect(&self, peer_id: String) -> Result<(), FfiError> {
        let peer = PeerId::from_str(&peer_id).map_err(|error| FfiError::InvalidPeerId {
            detail: error.to_string(),
        })?;
        self.with_endpoint_mut(|endpoint| endpoint.disconnect(&peer).map_err(map_driver_error))
    }

    /// Returns the current usable NAT-orchestrated path to `peer_id`.
    pub fn path(&self, peer_id: String) -> Result<Option<crate::PathKind>, FfiError> {
        let peer = PeerId::from_str(&peer_id).map_err(|error| FfiError::InvalidPeerId {
            detail: error.to_string(),
        })?;
        self.with_endpoint(|endpoint| endpoint.path(&peer).map(crate::events::convert_path))
    }

    /// Returns the shared discovery address-book snapshot.
    pub fn known_peers(&self) -> Result<Vec<KnownPeerInfo>, FfiError> {
        self.with_endpoint(|endpoint| {
            let now = endpoint.discovery_now_ms();
            endpoint
                .known_peers()
                .into_iter()
                .map(|peer| KnownPeerInfo {
                    peer_id: peer.peer.to_base58(),
                    addrs: display_addrs(peer.addrs),
                    beacon_addrs: display_addrs(peer.beacon_addrs),
                    mdns_addrs: display_addrs(peer.mdns_addrs),
                    beacon_last_seen_age_ms: age(now, peer.beacon_last_seen_ms),
                    mdns_last_seen_age_ms: age(now, peer.mdns_last_seen_ms),
                    connected: peer.connected,
                })
                .collect()
        })
    }

    /// Returns the discovery driver's monotonic clock in milliseconds.
    pub fn discovery_now_ms(&self) -> Result<Option<u64>, FfiError> {
        self.with_endpoint(|endpoint| endpoint.discovery_now_ms())
    }

    /// Returns the current AutoNAT reachability verdict.
    pub fn reachability(&self) -> Result<crate::Reachability, FfiError> {
        self.with_endpoint(|endpoint| crate::events::convert_reachability(endpoint.reachability()))
    }

    /// Returns the active inbound relay reservation.
    pub fn active_reservation(&self) -> Result<Option<RelayReservationInfo>, FfiError> {
        self.with_endpoint(|endpoint| {
            endpoint
                .active_reservation()
                .map(|reservation| RelayReservationInfo {
                    relay_peer_id: reservation.relay.to_base58(),
                    expires_unix_secs: reservation.expires_unix_secs,
                })
        })
    }
}

impl P2pEndpoint {
    fn start_with(
        &self,
        listener: Arc<dyn P2pEventListener>,
        spawn: impl FnOnce(Arc<Shared>, Arc<dyn P2pEventListener>) -> std::io::Result<()>,
    ) -> Result<(), FfiError> {
        let mut state = self.shared.lock_state();
        match state.lifecycle {
            Lifecycle::Created => {}
            Lifecycle::Running => return Err(FfiError::AlreadyStarted),
            Lifecycle::Stopping | Lifecycle::Stopped => return Err(FfiError::Stopped),
        }

        let shared = Arc::clone(&self.shared);
        spawn(shared, listener).map_err(|error| {
            state.lifecycle = Lifecycle::Stopped;
            state.endpoint.take();
            self.shared.stopped_cv.notify_all();
            FfiError::Internal {
                detail: format!("failed to spawn endpoint driver: {error}"),
            }
        })?;
        state.lifecycle = Lifecycle::Running;
        self.shared.driver_running.store(true, Ordering::Release);
        Ok(())
    }
    /// Returns Rust-side background-driver diagnostics.
    ///
    /// This method is intentionally outside the UniFFI export block.
    pub fn driver_stats(&self) -> DriverStats {
        self.shared.lock_state().stats
    }

    fn with_endpoint<T>(&self, operation: impl FnOnce(&Endpoint) -> T) -> Result<T, FfiError> {
        let _pending = PendingCommand::new(&self.shared);
        let state = self.shared.lock_state();
        ensure_accepting_commands(&state)?;
        let endpoint = state.endpoint.as_ref().ok_or(FfiError::Stopped)?;
        Ok(operation(endpoint))
    }

    fn with_endpoint_mut<T>(
        &self,
        operation: impl FnOnce(&mut Endpoint) -> Result<T, FfiError>,
    ) -> Result<T, FfiError> {
        let _pending = PendingCommand::new(&self.shared);
        let mut state = self.shared.lock_state();
        ensure_accepting_commands(&state)?;
        operation(state.endpoint.as_mut().ok_or(FfiError::Stopped)?)
    }
}

impl Drop for P2pEndpoint {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Shared {
    pub(crate) fn lock_state(&self) -> MutexGuard<'_, EndpointState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

struct PendingCommand<'a> {
    shared: &'a Shared,
    engaged: bool,
}

impl<'a> PendingCommand<'a> {
    fn new(shared: &'a Shared) -> Self {
        let engaged = shared.driver_running.load(Ordering::Acquire);
        if engaged {
            shared.pending_commands.fetch_add(1, Ordering::AcqRel);
            shared.wait_handle.interrupt();
        }
        Self { shared, engaged }
    }
}

impl Drop for PendingCommand<'_> {
    fn drop(&mut self) {
        if self.engaged {
            self.shared.pending_commands.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

fn invalid_config(error: impl std::fmt::Display) -> FfiError {
    FfiError::InvalidConfig {
        detail: error.to_string(),
    }
}

fn parse_peer_id(peer_id: &str) -> Result<PeerId, FfiError> {
    PeerId::from_str(peer_id).map_err(|error| FfiError::InvalidPeerId {
        detail: error.to_string(),
    })
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

fn map_pubsub_error(error: PubsubError) -> FfiError {
    match error {
        PubsubError::DiscoveryTopicReserved => FfiError::NotPermitted {
            detail: error.to_string(),
        },
        PubsubError::Publish(PublishError::TooLarge) => FfiError::MessageTooLarge,
        PubsubError::Publish(PublishError::Backpressure) => FfiError::Backpressure,
        PubsubError::Publish(PublishError::Topic(error)) | PubsubError::Topic(error) => {
            map_topic_error(error)
        }
        PubsubError::Driver(error) => map_driver_error(error),
        PubsubError::NotEnabled => FfiError::Internal {
            detail: error.to_string(),
        },
    }
}

fn map_topic_error(error: TopicError) -> FfiError {
    FfiError::InvalidTopic {
        detail: error.to_string(),
    }
}

fn map_driver_error(error: minip2p::Error) -> FfiError {
    match error {
        minip2p::Error::Transport(_) => FfiError::Transport {
            detail: error.to_string(),
        },
        _ => FfiError::Internal {
            detail: error.to_string(),
        },
    }
}

fn display_addrs(addrs: Vec<Multiaddr>) -> Vec<String> {
    addrs
        .into_iter()
        .map(|address| address.to_string())
        .collect()
}

fn age(now: Option<u64>, last_seen: Option<u64>) -> Option<u64> {
    Some(now?.saturating_sub(last_seen?))
}

fn ensure_accepting_commands(state: &EndpointState) -> Result<(), FfiError> {
    match state.lifecycle {
        Lifecycle::Created | Lifecycle::Running => Ok(()),
        Lifecycle::Stopping | Lifecycle::Stopped => Err(FfiError::Stopped),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct NoopListener;

    impl P2pEventListener for NoopListener {
        fn on_event(&self, _event: crate::P2pEvent) {}
    }

    #[derive(Default)]
    struct RecordingListener {
        events: Mutex<Vec<crate::P2pEvent>>,
    }

    impl P2pEventListener for RecordingListener {
        fn on_event(&self, event: crate::P2pEvent) {
            self.events
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(event);
        }
    }

    struct DropTrackingListener {
        callbacks: Arc<AtomicUsize>,
        dropped: Arc<AtomicBool>,
    }

    impl P2pEventListener for DropTrackingListener {
        fn on_event(&self, _event: crate::P2pEvent) {
            self.callbacks.fetch_add(1, Ordering::AcqRel);
        }
    }

    impl Drop for DropTrackingListener {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    struct WaitingListener {
        endpoint: std::sync::Weak<P2pEndpoint>,
        result: Mutex<Option<bool>>,
    }

    impl P2pEventListener for WaitingListener {
        fn on_event(&self, _event: crate::P2pEvent) {
            let result = self
                .endpoint
                .upgrade()
                .expect("endpoint")
                .wait_stopped(60_000);
            *self.result.lock().unwrap_or_else(PoisonError::into_inner) = Some(result);
        }
    }

    fn config() -> EndpointConfig {
        EndpointConfig {
            agent_version: None,
            relays: Vec::new(),
            autonat_servers: Vec::new(),
            quic: Some(TransportOptions {
                listen_addrs: Some(vec!["/ip4/127.0.0.1/udp/0/quic-v1".into()]),
            }),
            tcp: None,
            force_relay: false,
            allow_unsigned: false,
            pubsub_router: PubsubRouter::Gossipsub,
            protocols: Vec::new(),
            discovery: None,
            mdns: None,
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
        bad_listen.quic = Some(TransportOptions {
            listen_addrs: Some(vec!["not-a-multiaddr".into()]),
        });
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
        config.quic = Some(TransportOptions { listen_addrs: None });

        let endpoint = endpoint(config).expect("dual-stack endpoint");

        assert!(!endpoint.listen_addrs().is_empty());
    }

    #[test]
    fn constructor_accepts_quic_and_tcp_together() {
        let mut config = config();
        config.tcp = Some(TransportOptions {
            listen_addrs: Some(vec!["/ip4/127.0.0.1/tcp/0".into()]),
        });

        let endpoint = endpoint(config).expect("QUIC + TCP endpoint");
        let addresses = endpoint.listen_addrs();
        assert!(addresses.iter().any(|address| address.contains("/quic-v1")));
        assert!(addresses.iter().any(|address| address.contains("/tcp/")));
    }

    #[test]
    fn constructor_rejects_disabled_empty_and_mismatched_transports() {
        let mut disabled = config();
        disabled.quic = None;
        assert!(matches!(
            endpoint(disabled),
            Err(FfiError::InvalidConfig { .. })
        ));

        let mut empty = config();
        empty.quic = Some(TransportOptions {
            listen_addrs: Some(Vec::new()),
        });
        assert!(matches!(
            endpoint(empty),
            Err(FfiError::InvalidConfig { .. })
        ));

        let mut mismatched = config();
        mismatched.quic = Some(TransportOptions {
            listen_addrs: Some(vec!["/ip4/127.0.0.1/tcp/0".into()]),
        });
        assert!(matches!(
            endpoint(mismatched),
            Err(FfiError::InvalidConfig { .. })
        ));
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
    fn constructor_accepts_mdns_and_floodsub_configuration() {
        let mut config = config();
        config.pubsub_router = PubsubRouter::Floodsub;
        config.mdns = Some(crate::MdnsOptions {
            enable_ipv6: false,
            ttl_ms: 120_000,
            query_interval_ms: 300_000,
            max_packet_bytes: 1_400,
            max_announced_addrs: 16,
            interface_refresh_ms: 10_000,
            socket_poll_interval_ms: 100,
            auto_dial: true,
        });

        endpoint(config).expect("mDNS + floodsub endpoint");
    }

    #[test]
    fn constructor_rejects_invalid_mdns_configuration() {
        let mut config = config();
        config.mdns = Some(crate::MdnsOptions {
            enable_ipv6: false,
            ttl_ms: 0,
            query_interval_ms: 300_000,
            max_packet_bytes: 1_400,
            max_announced_addrs: 16,
            interface_refresh_ms: 10_000,
            socket_poll_interval_ms: 100,
            auto_dial: true,
        });

        assert!(matches!(
            endpoint(config),
            Err(FfiError::InvalidConfig { .. })
        ));
    }

    #[test]
    fn constructor_rejects_non_quic_and_circuit_relays() {
        let relay = minip2p::Ed25519Keypair::from_secret_key_bytes([8; 32]).peer_id();

        for address in [
            format!("/ip4/127.0.0.1/udp/4001/p2p/{relay}"),
            format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p-circuit/p2p/{relay}"),
            format!("/ip4/0.0.0.0/udp/4001/quic-v1/p2p/{relay}"),
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

        assert!(matches!(endpoint.connected_peers(), Err(FfiError::Stopped)));
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
    fn stop_finishes_a_running_driver() {
        let endpoint = endpoint(config()).expect("endpoint");
        endpoint.start(Arc::new(NoopListener)).expect("start");
        assert!(endpoint.is_running());

        endpoint.stop();

        assert!(endpoint.wait_stopped(1_000));
        assert!(!endpoint.is_running());
        assert!(endpoint.shared.lock_state().endpoint.is_none());
    }

    #[test]
    fn start_rejects_double_start_and_restart_after_stop() {
        let endpoint = endpoint(config()).expect("endpoint");
        endpoint.start(Arc::new(NoopListener)).expect("start");

        assert!(matches!(
            endpoint.start(Arc::new(NoopListener)),
            Err(FfiError::AlreadyStarted)
        ));
        endpoint.stop();
        assert!(endpoint.wait_stopped(1_000));
        assert!(matches!(
            endpoint.start(Arc::new(NoopListener)),
            Err(FfiError::Stopped)
        ));
    }

    #[test]
    fn spawn_failure_stops_and_releases_endpoint() {
        let endpoint = endpoint(config()).expect("endpoint");

        let error = endpoint
            .start_with(Arc::new(NoopListener), |_, _| {
                Err(std::io::Error::other("injected spawn failure"))
            })
            .expect_err("spawn must fail");

        assert!(matches!(error, FfiError::Internal { .. }));
        assert!(endpoint.wait_stopped(0));
        let state = endpoint.shared.lock_state();
        assert_eq!(state.lifecycle, Lifecycle::Stopped);
        assert!(state.endpoint.is_none());
    }

    #[test]
    fn wait_stopped_releases_listener_before_returning() {
        let endpoint = endpoint(config()).expect("endpoint");
        let callbacks = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicBool::new(false));
        endpoint
            .start(Arc::new(DropTrackingListener {
                callbacks: Arc::clone(&callbacks),
                dropped: Arc::clone(&dropped),
            }))
            .expect("start");

        endpoint.stop();
        assert!(endpoint.wait_stopped(1_000));

        assert!(dropped.load(Ordering::Acquire));
    }

    #[test]
    fn drop_without_explicit_stop_releases_listener() {
        let endpoint = endpoint(config()).expect("endpoint");
        let callbacks = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicBool::new(false));
        endpoint
            .start(Arc::new(DropTrackingListener {
                callbacks,
                dropped: Arc::clone(&dropped),
            }))
            .expect("start");

        drop(endpoint);

        let deadline = Instant::now() + Duration::from_secs(1);
        while !dropped.load(Ordering::Acquire) && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(dropped.load(Ordering::Acquire));
    }

    #[test]
    fn concurrent_commands_queries_and_stop_complete() {
        let endpoint = endpoint(config()).expect("endpoint");
        endpoint.start(Arc::new(NoopListener)).expect("start");
        let mut workers = Vec::new();

        for worker in 0..4 {
            let endpoint = Arc::clone(&endpoint);
            workers.push(std::thread::spawn(move || {
                for index in 0..250 {
                    match worker {
                        0 => {
                            let _ = endpoint.connected_peers();
                        }
                        1 => endpoint.set_active(index % 2 == 0),
                        2 => {
                            let _ = endpoint.publish("room".into(), vec![index as u8]);
                        }
                        _ => {
                            let _ = endpoint.cancel_connect(u64::MAX);
                        }
                    }
                }
            }));
        }

        std::thread::yield_now();
        endpoint.stop();
        for worker in workers {
            worker.join().expect("worker must not panic");
        }

        assert!(endpoint.wait_stopped(5_000));
        assert!(!endpoint.is_running());
    }

    #[test]
    fn fatal_driver_panic_is_reported_before_stopped() {
        let endpoint = endpoint(config()).expect("endpoint");
        let listener = Arc::new(RecordingListener::default());
        {
            let mut state = endpoint.shared.lock_state();
            state.lifecycle = Lifecycle::Running;
            state.endpoint = None;
        }
        endpoint
            .shared
            .driver_running
            .store(true, Ordering::Release);

        crate::driver::run(
            Arc::clone(&endpoint.shared),
            Arc::clone(&listener) as Arc<dyn P2pEventListener>,
        );

        assert!(matches!(
            listener
                .events
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_slice(),
            [crate::P2pEvent::DriverFailed {
                kind: crate::DriverFailureKind::Panic,
                ..
            }]
        ));
        assert!(endpoint.wait_stopped(0));
    }

    #[test]
    fn wait_stopped_from_driver_callback_returns_immediately() {
        let endpoint = endpoint(config()).expect("endpoint");
        let listener = Arc::new(WaitingListener {
            endpoint: Arc::downgrade(&endpoint),
            result: Mutex::new(None),
        });
        {
            let mut state = endpoint.shared.lock_state();
            state.lifecycle = Lifecycle::Running;
            state.endpoint = None;
        }
        endpoint
            .shared
            .driver_running
            .store(true, Ordering::Release);

        let started = Instant::now();
        crate::driver::run(
            Arc::clone(&endpoint.shared),
            Arc::clone(&listener) as Arc<dyn P2pEventListener>,
        );

        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(
            *listener
                .result
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
            Some(false)
        );
    }

    #[test]
    fn pending_command_interrupts_a_waiter_and_balances_the_counter() {
        let endpoint = endpoint(config()).expect("endpoint");
        endpoint
            .shared
            .driver_running
            .store(true, Ordering::Release);
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
        endpoint
            .shared
            .driver_running
            .store(false, Ordering::Release);
    }

    #[test]
    fn pre_start_commands_and_queries_are_deterministic() {
        let endpoint = endpoint(config()).expect("endpoint");
        let remote = minip2p::Ed25519Keypair::from_secret_key_bytes([7; 32]).peer_id();

        assert!(endpoint.subscribe("room".into()).expect("subscribe"));
        assert!(!endpoint.subscribe("room".into()).expect("idempotent"));
        endpoint
            .publish("room".into(), b"hello".to_vec())
            .expect("publish");
        assert!(endpoint.unsubscribe("room".into()).expect("unsubscribe"));
        assert!(endpoint.connected_peers().expect("peers").is_empty());
        assert!(endpoint.known_peers().expect("known peers").is_empty());
        assert_eq!(
            endpoint.reachability().expect("reachability"),
            crate::Reachability::Unknown
        );
        assert!(
            endpoint
                .active_reservation()
                .expect("reservation")
                .is_none()
        );
        let connect_id = endpoint
            .connect(remote.to_base58())
            .expect("connection attempt");
        {
            let state = endpoint.shared.lock_state();
            assert!(state.connect_ids.contains_key(&connect_id));
        }
        endpoint.cancel_connect(connect_id).expect("known cancel");
        assert!(
            endpoint
                .shared
                .lock_state()
                .cancelled_connect_ids
                .contains(&connect_id)
        );
        endpoint.cancel_connect(u64::MAX).expect("unknown cancel");
    }

    #[test]
    fn disconnect_validates_the_peer_id() {
        let endpoint = endpoint(config()).expect("endpoint");

        assert!(matches!(
            endpoint.disconnect("not-a-peer-id".into()),
            Err(FfiError::InvalidPeerId { .. })
        ));
    }

    #[test]
    fn command_inputs_and_stopped_state_are_typed() {
        let endpoint = endpoint(config()).expect("endpoint");

        assert!(matches!(
            endpoint.subscribe(String::new()),
            Err(FfiError::InvalidTopic { .. })
        ));
        assert!(matches!(
            endpoint.connect("not-a-peer".into()),
            Err(FfiError::InvalidPeerId { .. })
        ));
        assert!(matches!(
            endpoint.connect_addr("not-an-address".into()),
            Err(FfiError::InvalidAddress { .. })
        ));

        endpoint.stop();
        assert!(matches!(
            endpoint.publish("room".into(), Vec::new()),
            Err(FfiError::Stopped)
        ));
        assert!(matches!(endpoint.known_peers(), Err(FfiError::Stopped)));
    }

    #[test]
    fn source_age_uses_saturating_discovery_clock_math() {
        assert_eq!(age(Some(100), Some(40)), Some(60));
        assert_eq!(age(Some(40), Some(100)), Some(0));
        assert_eq!(age(None, Some(10)), None);
        assert_eq!(age(Some(10), None), None);
    }

    #[test]
    fn commands_reject_stopping_and_oversized_payloads() {
        let endpoint = endpoint(config()).expect("endpoint");
        assert!(matches!(
            endpoint.publish("room".into(), vec![0; minip2p_pubsub::MAX_RPC_SIZE + 1]),
            Err(FfiError::MessageTooLarge)
        ));

        endpoint.shared.lock_state().lifecycle = Lifecycle::Stopping;
        assert!(matches!(
            endpoint.subscribe("room".into()),
            Err(FfiError::Stopped)
        ));
        assert!(matches!(
            endpoint.publish("room".into(), Vec::new()),
            Err(FfiError::Stopped)
        ));
        assert!(matches!(endpoint.cancel_connect(0), Err(FfiError::Stopped)));
    }

    #[test]
    fn pubsub_and_transport_errors_map_by_context() {
        let mut discovery = config();
        discovery.discovery = Some(crate::DiscoveryOptions {
            topic: "presence".into(),
            beacon_interval_ms: 10_000,
            peer_ttl_ms: 35_000,
            auto_dial: false,
        });
        let endpoint = endpoint(discovery).expect("endpoint");
        assert!(matches!(
            endpoint.unsubscribe("presence".into()),
            Err(FfiError::NotPermitted { .. })
        ));

        assert!(matches!(
            map_pubsub_error(PubsubError::Publish(PublishError::TooLarge)),
            FfiError::MessageTooLarge
        ));
        assert!(matches!(
            map_pubsub_error(PubsubError::Publish(PublishError::Backpressure)),
            FfiError::Backpressure
        ));
        assert!(matches!(
            map_driver_error(
                TransportError::PollError {
                    reason: "test".into()
                }
                .into()
            ),
            FfiError::Transport { .. }
        ));
    }
}
