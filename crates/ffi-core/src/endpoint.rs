//! Binding-agnostic endpoint object and construction.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use minip2p::{
    BeaconConfig, ConnectionId, Endpoint, EndpointBuilder, GossipsubConfig, GossipsubError,
    MdnsConfig, Multiaddr, NatConfig, PeerDiscoveryConfig, PeerId, PublishError, StreamId,
    TopicError, TransportError, WaitHandle,
};

use crate::{
    DriverStats, EndpointConfig, EventDoorbell, FfiError, IdentifyInfo, KnownPeerInfo, P2pEvent,
    RelayReservationInfo, keypair_from_bytes, parse_direct_peer_addr,
};

/// Adds address-shaped listeners, or the QUIC dual-stack defaults when
/// `listen` is absent. Transport is inferred from each address's shape.
fn configure_listen(
    builder: EndpointBuilder,
    listen: Option<Vec<String>>,
) -> Result<EndpointBuilder, FfiError> {
    let Some(addresses) = listen else {
        return builder.listen_default().map_err(map_listen_error);
    };
    if addresses.is_empty() {
        return Err(FfiError::InvalidConfig {
            detail: "listen cannot be empty; omit listen for the QUIC dual-stack defaults, or pass complete multiaddresses".into(),
        });
    }
    addresses.iter().try_fold(builder, |builder, address| {
        let parsed = Multiaddr::from_str(address).map_err(|error| FfiError::InvalidAddress {
            detail: format!("invalid listen address `{address}`: {error}"),
        })?;
        builder
            .listen_on_multiaddr(&parsed)
            .map_err(map_listen_error)
    })
}

fn map_listen_error(error: minip2p::Error) -> FfiError {
    FfiError::InvalidConfig {
        detail: error.to_string(),
    }
}

/// A minip2p endpoint owned by a foreign runtime.
pub struct P2pEndpoint {
    shared: Arc<Shared>,
    peer_id: String,
    listen_addrs: Vec<String>,
}

/// How long an interrupted driver stays off `state` after the last command.
/// This and [`MAX_COMMAND_LINGER`] were tuned on Linux x64; sleep granularity
/// is coarser on macOS, Windows and mobile, so lingers run longer there.
const COMMAND_LINGER: Duration = Duration::from_micros(50);
/// Longest an interrupted driver lingers in total, so a steady stream of
/// calls cannot starve it: past this it retakes `state` once commands clear.
const MAX_COMMAND_LINGER: Duration = Duration::from_millis(1);

pub(crate) struct Shared {
    state: Mutex<EndpointState>,
    /// Converted events awaiting `drain_events`. Locked apart from `state`,
    /// which the driver holds across its wait, so draining neither waits for
    /// nor interrupts the driver. Lock order: `state`, then `events`.
    events: Mutex<crate::driver::EventState>,
    /// Latched once the lifecycle reaches `Stopped`. `wait_stopped` sleeps on
    /// this rather than on `state`, which the driver holds for as long as the
    /// endpoint has nothing due.
    stopped: Mutex<bool>,
    stopped_cv: Condvar,
    wait_handle: WaitHandle,
    pub(crate) pending_commands: AtomicUsize,
    /// Commands ever started; the lingering driver watches it for a burst.
    commands_started: AtomicUsize,
    /// Set while an interrupted driver waits on `commands_idle_cv` for
    /// `pending_commands` to reach zero, so only then do commands notify.
    driver_waiting: AtomicBool,
    /// Guards `commands_idle_cv`, and holds when the driver last resumed
    /// from `wait_for_commands`.
    commands_idle: Mutex<Option<Instant>>,
    commands_idle_cv: Condvar,
    pub(crate) driver_running: AtomicBool,
    doorbell_running: AtomicBool,
}

pub(crate) struct EndpointState {
    pub(crate) lifecycle: Lifecycle,
    pub(crate) endpoint: Option<Endpoint>,
    pub(crate) driver_thread_id: Option<std::thread::ThreadId>,
    doorbell_thread_id: Option<std::thread::ThreadId>,
    /// Unsent tails of the bindings' stream writes.
    pub(crate) writes: crate::writes::PendingWrites,
}

impl EndpointState {
    /// Releases the Endpoint together with the tails held for it, which can
    /// be large and are owed to streams that no longer exist.
    pub(crate) fn release_endpoint(&mut self) -> Option<Endpoint> {
        self.writes = crate::writes::PendingWrites::default();
        self.endpoint.take()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Lifecycle {
    Created,
    Running,
    Stopping,
    Stopped,
}

struct DoorbellSender(SyncSender<()>);

impl EventDoorbell for DoorbellSender {
    fn on_events_ready(&self) {
        match self.0.try_send(()) {
            Ok(()) | Err(TrySendError::Full(())) | Err(TrySendError::Disconnected(())) => {}
        }
    }
}

impl P2pEndpoint {
    /// Validates the secret key and `config`, binds its transports, and creates
    /// an endpoint.
    ///
    /// The endpoint begins in the created state and owns its bound sockets,
    /// but does not run a background driver until explicitly started.
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

        let gossipsub = GossipsubConfig {
            allow_unsigned: config.allow_unsigned,
            ..GossipsubConfig::default()
        };

        let mut builder = Endpoint::builder()
            .identity(keypair)
            .agent_version(
                config
                    .agent_version
                    .unwrap_or_else(|| format!("minip2p/{}", env!("CARGO_PKG_VERSION"))),
            )
            .gossipsub_config(gossipsub);
        // The binding acknowledges stream data as its reader consumes it
        // (`stream_consumed`), not as this driver pulls the event.
        for protocol in config.protocols {
            builder = builder.manual_ack_protocol(protocol);
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

        builder = configure_listen(builder, config.listen)?;
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
                    driver_thread_id: None,
                    doorbell_thread_id: None,
                    writes: crate::writes::PendingWrites::default(),
                }),
                events: Mutex::default(),
                stopped: Mutex::new(false),
                stopped_cv: Condvar::new(),
                wait_handle,
                pending_commands: AtomicUsize::new(0),
                commands_started: AtomicUsize::new(0),
                driver_waiting: AtomicBool::new(false),
                commands_idle: Mutex::new(None),
                commands_idle_cv: Condvar::new(),
                driver_running: AtomicBool::new(false),
                doorbell_running: AtomicBool::new(false),
            }),
            peer_id,
            listen_addrs,
        }))
    }

    /// Returns the local peer ID as legacy base58 text.
    pub fn peer_id(&self) -> String {
        self.peer_id.clone()
    }

    /// Returns the bound QUIC or TCP peer addresses.
    pub fn listen_addrs(&self) -> Vec<String> {
        self.listen_addrs.clone()
    }

    /// Returns peers with an established QUIC, TCP, or circuit connection.
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

    /// Accepted for compatibility and ignored.
    ///
    /// The driver used to poll on a faster cadence while active. It now
    /// sleeps until the endpoint's next deadline in either state, so there is
    /// no cadence left to select.
    pub fn set_active(&self, _active: bool) {}

    /// Returns whether the background driver is accepting work.
    ///
    /// This becomes `false` when shutdown is requested. Use
    /// [`P2pEndpoint::wait_stopped`] to observe complete driver exit.
    pub fn is_running(&self) -> bool {
        let _pending = PendingCommand::new(&self.shared);
        self.shared.lock_state().lifecycle == Lifecycle::Running
    }

    /// Starts the detached background endpoint driver.
    pub fn start(&self, doorbell: Arc<dyn EventDoorbell>) -> Result<(), FfiError> {
        self.start_with(doorbell, |shared, doorbell| {
            let (doorbell, doorbell_thread_id) =
                Self::spawn_doorbell(Arc::clone(&shared), doorbell)?;
            std::thread::Builder::new()
                .name("minip2p-driver".into())
                .spawn(move || crate::driver::run(shared, doorbell))
                .map(|_| doorbell_thread_id)
        })
    }

    /// Drains at most `limit` queued events in source order.
    pub fn drain_events(&self, limit: u32) -> Vec<P2pEvent> {
        if limit == 0 {
            return Vec::new();
        }
        let mut events = self.shared.lock_events();
        let crate::driver::EventState {
            carry,
            overflow,
            stats,
        } = &mut *events;
        let mut delivery = crate::driver::take_delivery(carry, overflow, stats, limit as usize);
        stats.dispatch_attempted = stats
            .dispatch_attempted
            .saturating_add(delivery.batch.len() as u64);
        let mut events =
            Vec::with_capacity(delivery.batch.len() + usize::from(delivery.diagnostic.is_some()));
        if let Some(diagnostic) = delivery.diagnostic.take() {
            events.push(diagnostic);
        }
        events.extend(delivery.batch);
        events
    }

    /// Requests shutdown without waiting for an in-flight callback.
    ///
    /// Unsettled Connection attempts emit no terminal after this: shells must
    /// settle their pending waits on stop (and on `DriverFailed`) themselves.
    pub fn stop(&self) {
        let _pending = PendingCommand::new(&self.shared);
        let endpoint = {
            let mut state = self.shared.lock_state();
            match state.lifecycle {
                Lifecycle::Created => {
                    state.lifecycle = Lifecycle::Stopped;
                    state.release_endpoint()
                }
                Lifecycle::Running => {
                    state.lifecycle = Lifecycle::Stopping;
                    None
                }
                Lifecycle::Stopping | Lifecycle::Stopped => None,
            }
        };
        // Only a stop from `Created` releases the endpoint here; a running
        // driver releases it on exit.
        let released = endpoint.is_some();
        drop(endpoint);
        if released {
            self.shared.latch_stopped();
        }
    }

    /// Waits up to `timeout_ms` for the endpoint to reach the stopped state.
    ///
    /// A newly created endpoint still owns bound sockets, so this returns
    /// `false` until `stop` releases it. For a running endpoint, `stop` only
    /// requests shutdown and this waits for the driver exit cleanup.
    ///
    /// Calling this from a doorbell callback would wait on the callback's own
    /// driver thread, so that case returns `false` immediately.
    pub fn wait_stopped(&self, timeout_ms: u64) -> bool {
        let timeout = Duration::from_millis(timeout_ms);
        let started = Instant::now();
        let is_stopped =
            |latched: bool| latched && !self.shared.doorbell_running.load(Ordering::Acquire);
        if is_stopped(*self.shared.lock_stopped()) {
            return true;
        }
        // A zero timeout is a pure poll: skip the thread-identity check, which
        // interrupts the driver and takes `state`, since there's nothing to wait on.
        if timeout.is_zero() {
            return false;
        }
        {
            let _pending = PendingCommand::new(&self.shared);
            let state = self.shared.lock_state();
            if state.driver_thread_id == Some(std::thread::current().id())
                || state.doorbell_thread_id == Some(std::thread::current().id())
            {
                return false;
            }
        }
        // Sleeps on the stopped latch rather than on `state`: an idle driver
        // holds `state` until something is due, which could be never.
        let mut stopped = self.shared.lock_stopped();
        loop {
            if is_stopped(*stopped) {
                return true;
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return false;
            }
            stopped = self
                .shared
                .stopped_cv
                .wait_timeout(stopped, remaining)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// Subscribes to a pubsub topic.
    pub fn subscribe(&self, topic: String) -> Result<bool, FfiError> {
        self.with_endpoint_mut(|endpoint| endpoint.subscribe(&topic).map_err(map_gossipsub_error))
    }

    /// Withdraws a pubsub subscription.
    pub fn unsubscribe(&self, topic: String) -> Result<bool, FfiError> {
        self.with_endpoint_mut(|endpoint| endpoint.unsubscribe(&topic).map_err(map_gossipsub_error))
    }

    /// Publishes one application payload.
    pub fn publish(&self, topic: String, data: Vec<u8>) -> Result<(), FfiError> {
        if data.len() > minip2p_pubsub::MAX_RPC_SIZE {
            return Err(FfiError::MessageTooLarge);
        }
        self.with_endpoint_mut(|endpoint| {
            endpoint.publish(&topic, data).map_err(map_gossipsub_error)
        })
    }

    /// Sends an explicit ping; completion arrives as a ping event.
    pub fn ping(&self, peer_id: String) -> Result<(), FfiError> {
        let peer = parse_peer_id(&peer_id)?;
        self.with_endpoint_mut(|endpoint| endpoint.ping(&peer).map_err(map_driver_error))
    }

    /// Registers an application protocol.
    ///
    /// Like every protocol registered through this crate, its stream data is
    /// acknowledged by the binding with [`Self::stream_consumed`].
    pub fn add_protocol(&self, protocol_id: String) -> Result<(), FfiError> {
        self.with_endpoint_mut(|endpoint| {
            endpoint
                .add_manual_ack_protocol(protocol_id)
                .map_err(map_driver_error)
        })
    }

    /// Acknowledges `bytes` of a stream's delivered `StreamData` as
    /// consumed, replenishing its receive budget (ADR 0012).
    ///
    /// Every protocol registered through this crate is acknowledged this
    /// way: a stream delivers at most one receive window that the binding
    /// has not acknowledged, so a reader that stops consuming stalls its
    /// sender instead of buffering without bound. More than the stream's
    /// unacknowledged bytes fails with [`FfiError::Transport`], naming the
    /// stream and both counts. A closed stream releases its bytes (and its
    /// stream slot once none are left); a settled or unknown stream or
    /// connection is a no-op.
    pub fn stream_consumed(
        &self,
        conn_id: u64,
        stream_id: u64,
        bytes: u64,
    ) -> Result<(), FfiError> {
        let bytes = usize::try_from(bytes).unwrap_or(usize::MAX);
        self.with_endpoint_mut(|endpoint| {
            endpoint
                .stream_consumed(ConnectionId::new(conn_id), StreamId::new(stream_id), bytes)
                .map_err(map_driver_error)
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
                .open_stream(&peer, &protocol_id)
                .map(|(conn_id, stream_id)| crate::OpenStreamResult {
                    conn_id: conn_id.as_u64(),
                    stream_id: stream_id.as_u64(),
                })
                .map_err(map_driver_error)
        })
    }

    /// Sends one byte chunk on an application stream.
    ///
    /// Returns `true` when the stream accepted every byte. Returns `false`
    /// when it accepted only part: ffi-core holds the rest, resends it as the
    /// stream drains, and emits [`P2pEvent::StreamWriteAccepted`] once all of
    /// it has been accepted. Until then the stream takes no other write
    /// ([`FfiError::Backpressure`]); a `StreamWriteStopped`, `StreamClosed`,
    /// or connection end instead means the held bytes were dropped.
    ///
    /// Like the other stream operations, the stream is named by connection
    /// as well as id; an operation for a connection the peer no longer uses
    /// fails instead of reaching a same-numbered stream on its replacement.
    pub fn send_stream(
        &self,
        peer_id: String,
        conn_id: u64,
        stream_id: u64,
        data: Vec<u8>,
    ) -> Result<bool, FfiError> {
        let peer = parse_peer_id(&peer_id)?;
        self.with_state_mut(|endpoint, writes| {
            writes.send(
                endpoint,
                peer,
                ConnectionId::new(conn_id),
                StreamId::new(stream_id),
                data,
            )
        })
    }

    /// Half-closes the local write side of an application stream.
    ///
    /// The FIN follows a pending write's held bytes, and later writes are
    /// refused.
    pub fn close_stream_write(
        &self,
        peer_id: String,
        conn_id: u64,
        stream_id: u64,
    ) -> Result<(), FfiError> {
        let peer = parse_peer_id(&peer_id)?;
        self.with_state_mut(|endpoint, writes| {
            writes.close_write(
                endpoint,
                &peer,
                ConnectionId::new(conn_id),
                StreamId::new(stream_id),
            )
        })
    }

    /// Resets an application stream while retaining later close events.
    pub fn reset_stream(
        &self,
        peer_id: String,
        conn_id: u64,
        stream_id: u64,
    ) -> Result<(), FfiError> {
        let peer = parse_peer_id(&peer_id)?;
        let (conn_id, stream_id) = (ConnectionId::new(conn_id), StreamId::new(stream_id));
        // Forget the tail only once the Endpoint accepted the request, so a
        // rejected call (another peer's ids) cannot lose a pending write.
        self.with_state_mut(|endpoint, writes| {
            endpoint
                .reset_stream(&peer, conn_id, stream_id)
                .map_err(map_driver_error)?;
            writes.forget(conn_id, stream_id);
            Ok(())
        })
    }

    /// Resets and forgets an application stream.
    pub fn abandon_stream(
        &self,
        peer_id: String,
        conn_id: u64,
        stream_id: u64,
    ) -> Result<(), FfiError> {
        let peer = parse_peer_id(&peer_id)?;
        let (conn_id, stream_id) = (ConnectionId::new(conn_id), StreamId::new(stream_id));
        // Forget the tail only once the Endpoint accepted the request, so a
        // rejected call (another peer's ids) cannot lose a pending write.
        self.with_state_mut(|endpoint, writes| {
            endpoint
                .abandon_stream(&peer, conn_id, stream_id)
                .map_err(map_driver_error)?;
            writes.forget(conn_id, stream_id);
            Ok(())
        })
    }

    /// Starts one Connection attempt toward `target` and returns its Connect
    /// ID.
    ///
    /// The whole attempt — every candidate dial, relay fallback, and path
    /// upgrade — settles under that one Connect ID with exactly one terminal
    /// event: [`P2pEvent::PathEstablished`], [`P2pEvent::ConnectFailed`], or
    /// [`P2pEvent::ConnectCancelled`] after [`Self::cancel_connect`].
    /// Synchronous errors cover malformed targets only.
    pub fn connect(&self, target: crate::ConnectTarget) -> Result<u64, FfiError> {
        let target = crate::connect::parse_connect_target(target)?;
        let _pending = PendingCommand::new(&self.shared);
        let mut state = self.shared.lock_state();
        ensure_accepting_commands(&state)?;
        let id = state
            .endpoint
            .as_mut()
            .ok_or(FfiError::Stopped)?
            .connect(target)
            .map_err(|error| FfiError::InvalidAddress {
                detail: error.to_string(),
            })?;
        Ok(id.as_u64())
    }

    /// Cancels a connection attempt by Connect ID.
    ///
    /// Idempotent. An unsettled attempt emits exactly one
    /// [`P2pEvent::ConnectCancelled`] terminal; settled or unknown ids are a
    /// no-op and their terminal is still delivered once. Never disconnects
    /// an established connection — use [`Self::disconnect`].
    pub fn cancel_connect(&self, id: u64) -> Result<(), FfiError> {
        self.with_endpoint_mut(|endpoint| {
            endpoint.cancel_connect(minip2p::ConnectId::from_u64(id));
            Ok(())
        })
    }

    /// Closes the active connection to `peer_id`.
    ///
    /// Cancelling a connection attempt ends it with a `ConnectCancelled`
    /// terminal, but cannot retract a transport connection that has already
    /// completed. Call this method when cancellation must also close an
    /// established connection.
    pub fn disconnect(&self, peer_id: String) -> Result<(), FfiError> {
        let peer = PeerId::from_str(&peer_id).map_err(|error| FfiError::InvalidPeerId {
            detail: error.to_string(),
        })?;
        self.with_endpoint_mut(|endpoint| endpoint.disconnect(&peer).map_err(map_driver_error))
    }

    /// Returns the current usable NAT-orchestrated path to `peer_id`.
    ///
    /// `None` once the connection the path describes closes (the last relay
    /// circuit for a relayed path, the last direct connection for a direct
    /// one), even while the peer stays connected over the other kind.
    pub fn path(&self, peer_id: String) -> Result<Option<crate::PathKind>, FfiError> {
        let peer = PeerId::from_str(&peer_id).map_err(|error| FfiError::InvalidPeerId {
            detail: error.to_string(),
        })?;
        self.with_endpoint(|endpoint| endpoint.path(&peer).map(crate::events::convert_path))
    }

    /// Returns the transport connection selected for `peer_id`, when
    /// connected.
    pub fn connection_info(
        &self,
        peer_id: String,
    ) -> Result<Option<crate::ConnectionInfo>, FfiError> {
        let peer = parse_peer_id(&peer_id)?;
        self.with_endpoint(|endpoint| {
            let ready = endpoint.peer_readiness(&peer);
            endpoint
                .connection_id(&peer)
                .map(|id| crate::ConnectionInfo {
                    conn_id: id.as_u64(),
                    remote_addr: endpoint.connection_remote_addr(id).map(ToString::to_string),
                    ready_protocols: ready
                        .filter(|(ready_id, _)| *ready_id == id)
                        .map(|(_, info)| info.protocols.clone()),
                })
        })
    }

    /// Returns the shared discovery address-book snapshot.
    pub fn known_peers(&self) -> Result<Vec<KnownPeerInfo>, FfiError> {
        self.with_endpoint_mut(|endpoint| {
            let now = endpoint.discovery_now_ms();
            Ok(endpoint
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
                .collect())
        })
    }

    /// Returns the discovery driver's monotonic clock in milliseconds.
    pub fn discovery_now_ms(&self) -> Result<Option<u64>, FfiError> {
        self.with_endpoint_mut(|endpoint| Ok(endpoint.discovery_now_ms()))
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
    fn spawn_doorbell(
        shared: Arc<Shared>,
        doorbell: Arc<dyn EventDoorbell>,
    ) -> std::io::Result<(Arc<dyn EventDoorbell>, std::thread::ThreadId)> {
        let (sender, receiver) = sync_channel(1);
        shared.doorbell_running.store(true, Ordering::Release);
        let thread_shared = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("minip2p-doorbell".into())
            .spawn(move || {
                while receiver.recv().is_ok() {
                    for _ in 0..2 {
                        if catch_unwind(AssertUnwindSafe(|| doorbell.on_events_ready())).is_ok() {
                            break;
                        }
                    }
                }
                drop(doorbell);
                thread_shared.lock_state().doorbell_thread_id = None;
                thread_shared
                    .doorbell_running
                    .store(false, Ordering::Release);
                thread_shared.wake_stop_waiters();
            })
            .inspect_err(|_| {
                shared.doorbell_running.store(false, Ordering::Release);
            })?;
        let thread_id = thread.thread().id();
        drop(thread);
        Ok((Arc::new(DoorbellSender(sender)), thread_id))
    }

    fn start_with(
        &self,
        doorbell: Arc<dyn EventDoorbell>,
        spawn: impl FnOnce(
            Arc<Shared>,
            Arc<dyn EventDoorbell>,
        ) -> std::io::Result<std::thread::ThreadId>,
    ) -> Result<(), FfiError> {
        // A second `start` finds the driver parked on the lock.
        let _pending = PendingCommand::new(&self.shared);
        let mut state = self.shared.lock_state();
        match state.lifecycle {
            Lifecycle::Created => {}
            Lifecycle::Running => return Err(FfiError::AlreadyStarted),
            Lifecycle::Stopping | Lifecycle::Stopped => return Err(FfiError::Stopped),
        }

        let shared = Arc::clone(&self.shared);
        state.lifecycle = Lifecycle::Running;
        self.shared.driver_running.store(true, Ordering::Release);
        let doorbell_thread_id = spawn(shared, doorbell).map_err(|error| {
            state.lifecycle = Lifecycle::Stopped;
            state.release_endpoint();
            self.shared.driver_running.store(false, Ordering::Release);
            self.shared.latch_stopped();
            FfiError::Internal {
                detail: format!("failed to spawn endpoint driver: {error}"),
            }
        })?;
        state.doorbell_thread_id = Some(doorbell_thread_id);
        Ok(())
    }
    /// Returns Rust-side background-driver diagnostics.
    ///
    /// This method is intentionally outside the UniFFI export block.
    pub fn driver_stats(&self) -> DriverStats {
        self.shared.lock_events().stats
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
        self.with_state_mut(|endpoint, _| operation(endpoint))
    }

    /// Like [`Self::with_endpoint_mut`], with the pending stream writes.
    fn with_state_mut<T>(
        &self,
        operation: impl FnOnce(&mut Endpoint, &mut crate::writes::PendingWrites) -> Result<T, FfiError>,
    ) -> Result<T, FfiError> {
        let _pending = PendingCommand::new(&self.shared);
        let mut state = self.shared.lock_state();
        ensure_accepting_commands(&state)?;
        let EndpointState {
            endpoint, writes, ..
        } = &mut *state;
        operation(endpoint.as_mut().ok_or(FfiError::Stopped)?, writes)
    }
}

impl Drop for P2pEndpoint {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Shared {
    /// Locks the endpoint state. The driver holds this across its blocking
    /// wait, so another thread takes a `PendingCommand` first to interrupt it.
    pub(crate) fn lock_state(&self) -> MutexGuard<'_, EndpointState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn lock_events(&self) -> MutexGuard<'_, crate::driver::EventState> {
        self.events.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Holds an interrupted driver back until no caller is waiting for
    /// `state`. Without it the driver could retake `state` first and park
    /// again in a wait whose interrupt was already spent.
    ///
    /// Once pending commands clear, it returns at once unless a command
    /// started since it last looked, or the driver was interrupted within
    /// [`COMMAND_LINGER`] of last resuming, which marks a burst. Otherwise it
    /// lingers another [`COMMAND_LINGER`] and checks again, up to
    /// [`MAX_COMMAND_LINGER`] in all. An isolated command thus costs the
    /// driver no sleep, and a burst of synchronous calls runs without the
    /// driver retaking `state` between each. Measured with the Node FFI
    /// benches, this beats a fixed 1 ms sleep, which stalls the driver after
    /// every write or read acknowledgement, and waking per command, which
    /// contends with bursts.
    pub(crate) fn wait_for_commands(&self) {
        let entered = Instant::now();
        let linger_until = entered + MAX_COMMAND_LINGER;
        let mut started = self.commands_started.load(Ordering::Acquire);
        let mut idle = self
            .commands_idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut burst =
            idle.is_some_and(|resumed| entered.saturating_duration_since(resumed) < COMMAND_LINGER);
        loop {
            self.driver_waiting.store(true, Ordering::SeqCst);
            while self.pending_commands.load(Ordering::SeqCst) != 0 {
                idle = self
                    .commands_idle_cv
                    .wait(idle)
                    .unwrap_or_else(PoisonError::into_inner);
            }
            self.driver_waiting.store(false, Ordering::SeqCst);
            let now_started = self.commands_started.load(Ordering::Acquire);
            if (now_started == started && !burst) || Instant::now() >= linger_until {
                *idle = Some(Instant::now());
                return;
            }
            burst = false;
            started = now_started;
            drop(idle);
            std::thread::sleep(COMMAND_LINGER);
            idle = self
                .commands_idle
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn lock_stopped(&self) -> MutexGuard<'_, bool> {
        self.stopped.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records that the lifecycle reached `Stopped` and wakes `wait_stopped`.
    pub(crate) fn latch_stopped(&self) {
        *self.lock_stopped() = true;
        self.stopped_cv.notify_all();
    }

    /// Wakes `wait_stopped` to re-check the doorbell thread.
    fn wake_stop_waiters(&self) {
        let _latch = self.lock_stopped();
        self.stopped_cv.notify_all();
    }
}

/// Marks a caller about to take the state lock and interrupts the driver so
/// it lets go.
///
/// Engaged unconditionally: a caller that skipped it on seeing no driver
/// could race a concurrent `start` and then wait on a driver parked with no
/// deadline. An interrupt with no wait to end is latched for the next one,
/// which costs the driver one extra pass.
struct PendingCommand<'a> {
    shared: &'a Shared,
}

impl<'a> PendingCommand<'a> {
    fn new(shared: &'a Shared) -> Self {
        shared.commands_started.fetch_add(1, Ordering::AcqRel);
        shared.pending_commands.fetch_add(1, Ordering::SeqCst);
        shared.wait_handle.interrupt();
        Self { shared }
    }
}

impl Drop for PendingCommand<'_> {
    fn drop(&mut self) {
        // SeqCst pairs with `wait_for_commands`: either the driver sees this
        // decrement before waiting, or this sees it waiting and notifies.
        if self.shared.pending_commands.fetch_sub(1, Ordering::SeqCst) == 1
            && self.shared.driver_waiting.load(Ordering::SeqCst)
        {
            // Taken so the notify cannot fall between the driver's check
            // and its wait.
            let _idle = self
                .shared
                .commands_idle
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            self.shared.commands_idle_cv.notify_all();
        }
    }
}

fn invalid_config(error: impl std::fmt::Display) -> FfiError {
    FfiError::InvalidConfig {
        detail: error.to_string(),
    }
}

pub(crate) fn parse_peer_id(peer_id: &str) -> Result<PeerId, FfiError> {
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

fn map_gossipsub_error(error: GossipsubError) -> FfiError {
    match error {
        GossipsubError::DiscoveryTopicReserved => FfiError::NotPermitted {
            detail: error.to_string(),
        },
        GossipsubError::Publish(PublishError::TooLarge) => FfiError::MessageTooLarge,
        GossipsubError::Publish(PublishError::Backpressure) => FfiError::Backpressure,
        GossipsubError::Publish(PublishError::Topic(error)) | GossipsubError::Topic(error) => {
            map_topic_error(error)
        }
        GossipsubError::Driver(error) => map_driver_error(error),
        GossipsubError::NotEnabled => FfiError::Internal {
            detail: error.to_string(),
        },
    }
}

fn map_topic_error(error: TopicError) -> FfiError {
    FfiError::InvalidTopic {
        detail: error.to_string(),
    }
}

pub(crate) fn map_driver_error(error: minip2p::Error) -> FfiError {
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

    struct NoopDoorbell;

    impl EventDoorbell for NoopDoorbell {
        fn on_events_ready(&self) {}
    }

    #[derive(Default)]
    struct RecordingDoorbell {
        rings: AtomicUsize,
    }

    impl EventDoorbell for RecordingDoorbell {
        fn on_events_ready(&self) {
            self.rings.fetch_add(1, Ordering::AcqRel);
        }
    }

    struct DropTrackingDoorbell {
        callbacks: Arc<AtomicUsize>,
        dropped: Arc<AtomicBool>,
    }

    impl EventDoorbell for DropTrackingDoorbell {
        fn on_events_ready(&self) {
            self.callbacks.fetch_add(1, Ordering::AcqRel);
        }
    }

    impl Drop for DropTrackingDoorbell {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    struct WaitingDoorbell {
        endpoint: std::sync::Weak<P2pEndpoint>,
        result: Mutex<Option<bool>>,
    }

    struct DropThreadDoorbell(SyncSender<std::thread::ThreadId>);

    impl EventDoorbell for DropThreadDoorbell {
        fn on_events_ready(&self) {}
    }

    impl Drop for DropThreadDoorbell {
        fn drop(&mut self) {
            // The receiver may already be gone while the test tears down.
            match self.0.send(std::thread::current().id()) {
                Ok(()) | Err(_) => {}
            }
        }
    }

    struct PanickingDoorbell(Arc<AtomicUsize>);

    impl EventDoorbell for PanickingDoorbell {
        fn on_events_ready(&self) {
            self.0.fetch_add(1, Ordering::AcqRel);
            panic!("injected doorbell panic");
        }
    }

    impl EventDoorbell for WaitingDoorbell {
        fn on_events_ready(&self) {
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
            listen: Some(vec!["/ip4/127.0.0.1/udp/0/quic-v1".into()]),
            force_relay: false,
            allow_unsigned: false,
            protocols: Vec::new(),
            discovery: None,
            mdns: None,
        }
    }

    #[test]
    fn drain_is_bounded_and_preserves_order() {
        let endpoint = endpoint(config()).expect("endpoint");
        {
            let mut events = endpoint.shared.lock_events();
            events.carry.push(P2pEvent::PingTimeout {
                peer_id: "a".into(),
            });
            events.carry.push(P2pEvent::PingTimeout {
                peer_id: "b".into(),
            });
        }

        assert_eq!(
            endpoint.drain_events(1),
            vec![P2pEvent::PingTimeout {
                peer_id: "a".into()
            }]
        );
        assert_eq!(
            endpoint.drain_events(1),
            vec![P2pEvent::PingTimeout {
                peer_id: "b".into()
            }]
        );
        assert!(endpoint.drain_events(1).is_empty());
        assert!(endpoint.drain_events(u32::MAX).is_empty());
    }

    #[test]
    fn an_interrupted_driver_resumes_once_commands_end() {
        let endpoint = endpoint(config()).expect("endpoint");
        let pending = PendingCommand::new(&endpoint.shared);
        let shared = Arc::clone(&endpoint.shared);
        let (resumed_tx, resumed_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            shared.wait_for_commands();
            resumed_tx.send(()).expect("signal resume");
        });
        assert!(
            resumed_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "held back while a command is pending"
        );
        drop(pending);
        resumed_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("resumes after the last command ends");
    }

    #[test]
    fn draining_neither_waits_for_nor_interrupts_the_driver() {
        let endpoint = endpoint(config()).expect("endpoint");
        let ping = P2pEvent::PingTimeout {
            peer_id: "a".into(),
        };
        endpoint.shared.lock_events().carry.push(ping.clone());
        // A driver parked in `wait` holds the state lock.
        let mut parked = endpoint.shared.lock_state();
        let (drained_tx, drained_rx) = std::sync::mpsc::channel();
        let drainer = Arc::clone(&endpoint);
        std::thread::spawn(move || drained_tx.send(drainer.drain_events(8)));
        assert_eq!(
            drained_rx.recv_timeout(Duration::from_secs(5)),
            Ok(vec![ping]),
            "drain completes while the driver holds the state lock"
        );
        let outcome = parked
            .endpoint
            .as_mut()
            .expect("endpoint")
            .wait(Duration::from_millis(20))
            .expect("wait");
        assert!(
            !matches!(outcome, minip2p::EndpointWaitOutcome::Interrupted),
            "drain latched no interrupt"
        );
    }

    #[test]
    fn cancelling_an_unsettled_attempt_emits_exactly_one_connect_cancelled() {
        let a = endpoint(config()).expect("endpoint a");
        a.start(Arc::new(NoopDoorbell)).expect("start a");

        let black_hole_peer = minip2p::Ed25519Keypair::from_secret_key_bytes([8; 32])
            .peer_id()
            .to_base58();
        let connect_id = a
            .connect(crate::ConnectTarget::Addresses {
                addresses: vec![format!(
                    "/ip4/127.0.0.1/udp/1/quic-v1/p2p/{black_hole_peer}"
                )],
            })
            .expect("connect");
        a.cancel_connect(connect_id).expect("cancel");

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut drained = Vec::new();
        while Instant::now() < deadline {
            drained.extend(a.drain_events(4_096));
            if drained
                .iter()
                .any(|event| crate::driver::terminal_connect_id(event) == Some(connect_id))
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        let terminals: Vec<&P2pEvent> = drained
            .iter()
            .filter(|event| crate::driver::terminal_connect_id(event) == Some(connect_id))
            .collect();
        assert_eq!(
            terminals,
            [&P2pEvent::ConnectCancelled {
                connect_id,
                peer_id: black_hole_peer,
            }]
            .as_slice(),
            "exactly one ConnectCancelled terminal: {drained:#?}"
        );

        a.cancel_connect(connect_id).expect("idempotent cancel");
        let quiet = Instant::now() + Duration::from_millis(200);
        while Instant::now() < quiet {
            drained.extend(a.drain_events(4_096));
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            drained
                .iter()
                .filter(|event| crate::driver::terminal_connect_id(event) == Some(connect_id))
                .count(),
            1,
            "no further terminal after the first cancel: {drained:#?}"
        );

        a.stop();
        assert!(a.wait_stopped(5_000));
    }

    #[test]
    fn cancelling_a_settled_attempt_is_a_no_op_and_the_terminal_is_delivered_once() {
        let a = endpoint(config()).expect("endpoint a");
        let b = endpoint(config()).expect("endpoint b");
        a.start(Arc::new(NoopDoorbell)).expect("start a");
        b.start(Arc::new(NoopDoorbell)).expect("start b");

        let connect_id = a
            .connect(crate::ConnectTarget::Addresses {
                addresses: vec![b.listen_addrs()[0].clone()],
            })
            .expect("connect");
        let deadline = Instant::now() + Duration::from_secs(5);
        while a.path(b.peer_id()).expect("path").is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(a.path(b.peer_id()).expect("path").is_some());

        a.cancel_connect(connect_id).expect("cancel after settle");

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut drained = Vec::new();
        while Instant::now() < deadline {
            drained.extend(a.drain_events(4_096));
            if drained
                .iter()
                .any(|event| crate::driver::terminal_connect_id(event) == Some(connect_id))
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // Let the driver run a little longer so a duplicate terminal could
        // not still be in flight.
        let quiet = Instant::now() + Duration::from_millis(200);
        while Instant::now() < quiet {
            drained.extend(a.drain_events(4_096));
            std::thread::sleep(Duration::from_millis(10));
        }

        let terminals: Vec<&P2pEvent> = drained
            .iter()
            .filter(|event| crate::driver::terminal_connect_id(event) == Some(connect_id))
            .collect();
        assert_eq!(
            terminals.len(),
            1,
            "exactly one terminal event for connect id {connect_id}: {drained:#?}"
        );
        assert!(
            matches!(terminals[0], P2pEvent::PathEstablished { .. }),
            "settled attempt keeps its PathEstablished terminal: {terminals:#?}"
        );

        a.stop();
        b.stop();
        assert!(a.wait_stopped(5_000));
        assert!(b.wait_stopped(5_000));
    }

    #[test]
    fn connect_admits_addresses_and_settles_once() {
        let a = endpoint(config()).expect("endpoint a");
        let b = endpoint(config()).expect("endpoint b");
        a.start(Arc::new(NoopDoorbell)).expect("start a");
        b.start(Arc::new(NoopDoorbell)).expect("start b");

        let connect_id = a
            .connect(crate::ConnectTarget::Addresses {
                addresses: vec![b.listen_addrs()[0].clone()],
            })
            .expect("connect");
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut drained = Vec::new();
        while Instant::now() < deadline {
            drained.extend(a.drain_events(4_096));
            if drained.iter().any(|event| {
                matches!(event, P2pEvent::PathEstablished { connect_id: id, .. } if *id == connect_id)
            }) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        let terminals: Vec<&P2pEvent> = drained
            .iter()
            .filter(|event| crate::driver::terminal_connect_id(event) == Some(connect_id))
            .collect();
        assert_eq!(
            terminals.len(),
            1,
            "exactly one terminal event for connect id {connect_id}: {drained:#?}"
        );
        let P2pEvent::PathEstablished { conn_id, .. } = terminals[0] else {
            panic!("terminal must be PathEstablished: {terminals:#?}");
        };

        let info = a
            .connection_info(b.peer_id())
            .expect("connection info")
            .expect("connected peer has a transport connection");
        assert_eq!(info.conn_id, *conn_id);
        assert!(
            info.remote_addr
                .as_deref()
                .is_some_and(|addr| addr.contains("/quic-v1")),
            "remote addr records the transport: {info:?}"
        );
        assert!(matches!(
            a.connection_info("not-a-peer-id".into()),
            Err(FfiError::InvalidPeerId { .. })
        ));
        let stranger = minip2p::Ed25519Keypair::from_secret_key_bytes([7; 32])
            .peer_id()
            .to_base58();
        assert_eq!(a.connection_info(stranger).expect("connection info"), None);

        a.stop();
        b.stop();
        assert!(a.wait_stopped(5_000));
        assert!(b.wait_stopped(5_000));
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
        bad_listen.listen = Some(vec!["not-a-multiaddr".into()]);
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
        let result = std::thread::spawn(move || {
            let _guard = endpoint_for_panic.shared.state.lock().expect("lock");
            panic!("poison endpoint lock");
        })
        .join();
        assert!(result.is_err(), "the lock-poisoning worker must panic");

        assert!(endpoint.shared.lock_state().endpoint.is_some());
    }

    #[test]
    fn constructor_uses_quic_dual_stack_defaults_without_listen() {
        let mut config = config();
        config.listen = None;

        let endpoint = endpoint(config).expect("default endpoint");

        assert!(!endpoint.listen_addrs().is_empty());
        assert!(
            endpoint
                .listen_addrs()
                .iter()
                .all(|address| address.contains("/quic-v1"))
        );
    }

    #[test]
    fn constructor_infers_each_transport_from_the_listen_address() {
        let mut config = config();
        config.listen = Some(vec![
            "/ip4/127.0.0.1/udp/0/quic-v1".into(),
            "/ip6/::1/udp/0/quic-v1".into(),
            "/ip4/127.0.0.1/tcp/0".into(),
        ]);

        let endpoint = endpoint(config).expect("address-shaped listen");
        let addresses = endpoint.listen_addrs();
        assert_eq!(addresses.len(), 3);
        assert!(
            addresses
                .iter()
                .any(|address| address.starts_with("/ip6/::1/") && address.contains("/quic-v1"))
        );
        assert!(addresses.iter().any(|address| address.contains("/tcp/")));
    }

    #[test]
    fn constructor_rejects_empty_and_duplicate_family_listen() {
        let mut empty = config();
        empty.listen = Some(Vec::new());
        let Err(FfiError::InvalidConfig { detail }) = endpoint(empty) else {
            panic!("an explicit empty listen list must fail");
        };
        assert!(detail.contains("omit listen"), "{detail}");

        let mut duplicate_quic_family = config();
        duplicate_quic_family.listen = Some(vec![
            "/ip4/127.0.0.1/udp/0/quic-v1".into(),
            "/ip4/0.0.0.0/udp/0/quic-v1".into(),
        ]);
        assert!(matches!(
            endpoint(duplicate_quic_family),
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
    fn constructor_accepts_mdns_configuration() {
        let mut config = config();
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

        endpoint(config).expect("mDNS endpoint");
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
    fn stop_is_idempotent_in_created_and_stopped_states() {
        let endpoint = endpoint(config()).expect("endpoint");

        endpoint.stop();
        endpoint.stop();

        assert!(endpoint.wait_stopped(0));
        let state = endpoint.shared.lock_state();
        assert_eq!(state.lifecycle, Lifecycle::Stopped);
        assert!(state.endpoint.is_none());
    }

    #[test]
    fn stop_finishes_a_running_driver() {
        let endpoint = endpoint(config()).expect("endpoint");
        endpoint.start(Arc::new(NoopDoorbell)).expect("start");
        assert!(endpoint.is_running());

        endpoint.stop();

        assert!(endpoint.wait_stopped(1_000));
        assert!(!endpoint.is_running());
        assert!(endpoint.shared.lock_state().endpoint.is_none());
    }

    #[test]
    fn an_idle_driver_sleeps_until_a_caller_wakes_it() {
        let endpoint = endpoint(config()).expect("endpoint");
        endpoint.start(Arc::new(NoopDoorbell)).expect("start");
        // Long enough for any fixed polling cadence to show.
        std::thread::sleep(Duration::from_millis(600));
        assert_eq!(
            endpoint.driver_stats().iterations,
            0,
            "an endpoint with nothing due must not cycle its driver"
        );

        // The parked driver holds the endpoint lock with no deadline, so each
        // of these would block forever if it failed to wake it.
        let (done, finished) = std::sync::mpsc::channel();
        let caller = Arc::clone(&endpoint);
        std::thread::spawn(move || {
            assert!(!caller.wait_stopped(20), "nothing has stopped it yet");
            assert!(matches!(
                caller.start(Arc::new(NoopDoorbell)),
                Err(FfiError::AlreadyStarted)
            ));
            assert_eq!(
                caller.driver_stats().iterations,
                0,
                "an interrupt alone is no cycle"
            );
            assert!(caller.subscribe("room".into()).expect("subscribe"));
            caller.stop();
            done.send(caller.wait_stopped(60_000)).expect("report");
        });
        assert_eq!(
            finished.recv_timeout(Duration::from_secs(30)),
            Ok(true),
            "queries, commands and stop must each wake an idle driver"
        );
    }

    #[test]
    fn start_rejects_double_start_and_restart_after_stop() {
        let endpoint = endpoint(config()).expect("endpoint");
        endpoint.start(Arc::new(NoopDoorbell)).expect("start");

        assert!(matches!(
            endpoint.start(Arc::new(NoopDoorbell)),
            Err(FfiError::AlreadyStarted)
        ));
        endpoint.stop();
        assert!(endpoint.wait_stopped(1_000));
        assert!(matches!(
            endpoint.start(Arc::new(NoopDoorbell)),
            Err(FfiError::Stopped)
        ));
    }

    #[test]
    fn rejected_start_does_not_spawn_an_orphan_doorbell() {
        let endpoint = endpoint(config()).expect("endpoint");
        endpoint.start(Arc::new(NoopDoorbell)).expect("start");
        let caller = std::thread::current().id();
        let (dropped, received) = sync_channel(1);
        assert!(matches!(
            endpoint.start(Arc::new(DropThreadDoorbell(dropped))),
            Err(FfiError::AlreadyStarted)
        ));
        assert_eq!(received.recv_timeout(Duration::from_secs(1)), Ok(caller));
        endpoint.stop();
        assert!(endpoint.wait_stopped(1_000));
    }

    #[test]
    fn repeated_doorbell_panics_do_not_block_shutdown() {
        let a = endpoint(config()).expect("endpoint a");
        let b = endpoint(config()).expect("endpoint b");
        let callbacks = Arc::new(AtomicUsize::new(0));
        a.start(Arc::new(PanickingDoorbell(Arc::clone(&callbacks))))
            .expect("start a");
        b.start(Arc::new(NoopDoorbell)).expect("start b");
        a.connect(crate::ConnectTarget::Addresses {
            addresses: vec![b.listen_addrs()[0].clone()],
        })
        .expect("connect");

        let deadline = Instant::now() + Duration::from_secs(5);
        while callbacks.load(Ordering::Acquire) == 0 && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(callbacks.load(Ordering::Acquire) > 0);

        a.stop();
        assert!(a.wait_stopped(1_000));
        b.stop();
        assert!(b.wait_stopped(1_000));
    }

    #[test]
    fn spawn_failure_stops_and_releases_endpoint() {
        let endpoint = endpoint(config()).expect("endpoint");

        let error = endpoint
            .start_with(Arc::new(NoopDoorbell), |_, _| {
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
    fn wait_stopped_releases_doorbell_before_returning() {
        let endpoint = endpoint(config()).expect("endpoint");
        let callbacks = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicBool::new(false));
        endpoint
            .start(Arc::new(DropTrackingDoorbell {
                callbacks: Arc::clone(&callbacks),
                dropped: Arc::clone(&dropped),
            }))
            .expect("start");

        endpoint.stop();
        assert!(endpoint.wait_stopped(1_000));

        assert!(dropped.load(Ordering::Acquire));
    }

    #[test]
    fn drop_without_explicit_stop_releases_doorbell() {
        let endpoint = endpoint(config()).expect("endpoint");
        let callbacks = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicBool::new(false));
        endpoint
            .start(Arc::new(DropTrackingDoorbell {
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
        endpoint.start(Arc::new(NoopDoorbell)).expect("start");
        let mut workers = Vec::new();

        for worker in 0..4 {
            let endpoint = Arc::clone(&endpoint);
            workers.push(std::thread::spawn(move || {
                for index in 0_u8..250 {
                    match worker {
                        0 => {
                            drop(endpoint.connected_peers());
                        }
                        1 => endpoint.set_active(index % 2 == 0),
                        2 => {
                            drop(endpoint.publish("room".into(), vec![index]));
                        }
                        _ => {
                            drop(endpoint.cancel_connect(u64::MAX));
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
        let listener = Arc::new(RecordingDoorbell::default());
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
            Arc::clone(&listener) as Arc<dyn EventDoorbell>,
        );

        assert!(matches!(
            endpoint.drain_events(10).as_slice(),
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
        let listener = Arc::new(WaitingDoorbell {
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
            Arc::clone(&listener) as Arc<dyn EventDoorbell>,
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
            let outcome = state
                .endpoint
                .as_mut()
                .expect("endpoint")
                .wait(Duration::from_secs(5))
                .expect("wait");
            assert!(matches!(outcome, minip2p::EndpointWaitOutcome::Interrupted));
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
            .connect(crate::ConnectTarget::Peer {
                peer_id: remote.to_base58(),
            })
            .expect("connection attempt");
        endpoint.cancel_connect(connect_id).expect("known cancel");
        endpoint
            .cancel_connect(connect_id)
            .expect("settled cancel is a no-op");
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
            endpoint.connect(crate::ConnectTarget::Peer {
                peer_id: "not-a-peer".into()
            }),
            Err(FfiError::InvalidPeerId { .. })
        ));
        assert!(matches!(
            endpoint.connect(crate::ConnectTarget::Addresses {
                addresses: vec!["not-an-address".into()]
            }),
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
    fn gossipsub_and_transport_errors_map_by_context() {
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
            map_gossipsub_error(GossipsubError::Publish(PublishError::TooLarge)),
            FfiError::MessageTooLarge
        ));
        assert!(matches!(
            map_gossipsub_error(GossipsubError::Publish(PublishError::Backpressure)),
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
