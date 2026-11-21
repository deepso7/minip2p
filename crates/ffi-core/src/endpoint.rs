//! Binding-agnostic endpoint object and construction.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use minip2p::{
    BeaconConfig, BindError, Endpoint, EndpointBuilder, EndpointOptionsError, GossipsubConfig,
    MdnsConfig, Multiaddr, NatConfig, PeerDiscoveryConfig, PeerId, QuicBindError,
    ReservationPolicy, TransportError, WaitHandle,
};

use crate::limits::{Bound, resolve_limits};
use crate::{
    ConfigCapability, DriverStats, EndpointConfig, EventCarry, EventDoorbell, FfiError,
    IdentifyInfo, KnownPeerInfo, P2pEvent, RelayReservationInfo, keypair_from_bytes,
    map_driver_error, map_gossipsub_error, parse_direct_peer_addr, parse_peer_id, stream_key,
};

/// Parses the listen addresses; `None` keeps the QUIC dual-stack defaults.
fn parse_listen(listen: Option<Vec<String>>) -> Result<Option<Vec<Multiaddr>>, FfiError> {
    let Some(addresses) = listen else {
        return Ok(None);
    };
    if addresses.is_empty() {
        return Err(FfiError::InvalidConfig {
            capability: ConfigCapability::Options,
            detail: "listen cannot be empty; omit listen for the QUIC dual-stack defaults, or pass complete multiaddresses".into(),
        });
    }
    addresses
        .iter()
        .map(|address| {
            Multiaddr::from_str(address).map_err(|error| FfiError::InvalidAddress {
                detail: format!("invalid listen address `{address}`: {error}"),
            })
        })
        .collect::<Result<_, _>>()
        .map(Some)
}

/// The transports `listen` binds, classified the way the endpoint does.
fn bound_transports(listen: Option<&[Multiaddr]>) -> Bound {
    listen.map_or(
        Bound {
            quic: true,
            tcp: false,
        },
        |addresses| Bound {
            quic: addresses
                .iter()
                .any(|address| address.is_quic_transport() || address.is_webtransport()),
            tcp: addresses.iter().any(Multiaddr::is_tcp_transport),
        },
    )
}

/// Adds address-shaped listeners, or the QUIC dual-stack defaults when
/// `listen` is absent. Transport is inferred from each address's shape.
fn configure_listen(
    builder: EndpointBuilder,
    listen: Option<Vec<Multiaddr>>,
) -> Result<EndpointBuilder, FfiError> {
    let Some(addresses) = listen else {
        return builder.listen_default().map_err(map_options_error);
    };
    addresses.iter().try_fold(builder, |builder, address| {
        builder
            .listen_on_multiaddr(address)
            .map_err(map_options_error)
    })
}

/// A minip2p endpoint owned by a foreign runtime.
pub struct P2pEndpoint {
    shared: Arc<Shared>,
    peer_id: String,
}

/// The close drain a dropped [`P2pEndpoint`] grants, in milliseconds:
/// [`minip2p::DEFAULT_CLOSE_TIMEOUT`], as [`minip2p::Endpoint::close`] uses.
pub const DEFAULT_STOP_TIMEOUT_MS: u64 = minip2p::DEFAULT_CLOSE_TIMEOUT.as_millis() as u64;

/// How long an interrupted driver sleeps, once pending commands clear, before
/// checking for further commands. See [`Shared::wait_for_commands`].
const COMMAND_LINGER: Duration = Duration::from_micros(50);
/// Lingering budget for an interrupted driver, counted from entering
/// [`Shared::wait_for_commands`], so a steady stream of calls cannot starve
/// it: once spent, it retakes `state` as soon as pending commands clear.
const MAX_COMMAND_LINGER: Duration = Duration::from_millis(1);

pub(crate) struct Shared {
    state: Mutex<EndpointState>,
    /// Converted events awaiting `drain_events`. Locked apart from `state`,
    /// which the driver holds across its wait, so draining neither waits for
    /// nor interrupts the driver. Lock order: `state`, then `events`.
    events: Mutex<EventState>,
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
    commands_idle: Mutex<()>,
    commands_idle_cv: Condvar,
    doorbell_running: AtomicBool,
}

/// The carry and what the driver publishes beside it, behind the endpoint's
/// event lock.
#[derive(Default)]
pub(crate) struct EventState {
    pub(crate) carry: EventCarry,
    /// What `connected_peers` returns, published from the endpoint's peer
    /// table by the driver (see `Shared::publish_peers`), so the
    /// query neither interrupts nor waits for the driver.
    pub(crate) connected_peers: Vec<String>,
    /// What `listen_addrs` returns: the bound listen set at build, then
    /// each [`P2pEvent::ListenAddressesChanged`] the driver ingests.
    pub(crate) listen_addrs: Vec<String>,
    /// Set with the lifecycle once it reaches `Stopping` or `Stopped`.
    pub(crate) stopped: bool,
}

impl EventState {
    /// Takes the driver's converted events into the carry, following the
    /// listen set they announce; returns whether to ring the doorbell
    /// (see [`EventCarry::ingest`]).
    pub(crate) fn ingest(&mut self, converted: Vec<P2pEvent>) -> bool {
        for event in &converted {
            if let P2pEvent::ListenAddressesChanged { addrs } = event {
                self.listen_addrs.clone_from(addrs);
            }
        }
        self.carry.ingest(converted)
    }
}

pub(crate) struct EndpointState {
    pub(crate) lifecycle: Lifecycle,
    pub(crate) driver_thread_id: Option<std::thread::ThreadId>,
    doorbell_thread_id: Option<std::thread::ThreadId>,
    /// The peer table last published to `connected_peers`.
    pub(crate) published_peers: Vec<PeerId>,
}

pub(crate) enum Lifecycle {
    /// Bound and accepting commands; no driver yet.
    Created(Endpoint),
    /// The driver is running.
    Running(Endpoint),
    /// Shutdown has begun. The driver holds `live` until it leaves its loop,
    /// then takes it to close within `close_timeout` (at once after a failure).
    Stopping {
        live: Option<Endpoint>,
        close_timeout: Duration,
    },
    /// The endpoint is released.
    Stopped,
}

impl Lifecycle {
    /// The live endpoint while it accepts commands: created or running.
    fn accepting(&mut self) -> Result<&mut Endpoint, FfiError> {
        match self {
            Self::Created(live) | Self::Running(live) => Ok(live),
            Self::Stopping { .. } | Self::Stopped => Err(FfiError::Stopped),
        }
    }
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
        let inbound_stream_limits = config.resolve_inbound_stream_limits()?;
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

        let listen = parse_listen(config.listen)?;
        let limits = resolve_limits(config.limits, bound_transports(listen.as_deref()))?;

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
            .gossipsub_config(gossipsub)
            .timeouts(config.timeouts.map(Into::into).unwrap_or_default())
            .quic_limits(limits.quic)
            .tcp_config(limits.tcp)
            .circuit_limits(limits.circuit)
            .write_budget(crate::BINDING_WRITE_BUDGET);
        for protocol in config.protocols {
            builder = builder.manual_ack_protocol(protocol);
        }
        for (protocol, limit) in inbound_stream_limits {
            builder = builder
                .protocol_with_inbound_limit(&protocol, limit)
                .manual_ack_protocol(protocol);
        }

        let custom_circuits = limits.max_circuits != NatConfig::default().max_circuits;
        if config.force_relay || (custom_circuits && !relays.is_empty()) {
            let reservation_policy = if relays.is_empty() {
                ReservationPolicy::Never
            } else {
                ReservationPolicy::default()
            };
            builder = builder.nat_config(NatConfig {
                force_relay: config.force_relay,
                max_circuits: limits.max_circuits,
                reservation_policy,
                ..NatConfig::default()
            });
        }
        for relay in relays {
            builder = builder.relay(relay);
        }
        for server in autonat_servers {
            builder = builder.autonat_server(server);
        }

        let signed_auto_dial = config.discovery.as_ref().map(|options| options.auto_dial);
        if let Some(discovery) = config.discovery {
            let beacon = BeaconConfig {
                topic: discovery.topic,
                beacon_interval_ms: discovery.beacon_interval_ms,
                ..BeaconConfig::default()
            };
            let peer_discovery = PeerDiscoveryConfig {
                beacon_peer_ttl_ms: discovery.peer_ttl_ms,
                auto_dial: discovery.auto_dial,
                ..PeerDiscoveryConfig::default()
            };
            builder = builder
                .discovery_config(beacon)
                .peer_discovery_config(peer_discovery);
        }
        if let Some(mdns) = config.mdns {
            if signed_auto_dial.is_some_and(|auto_dial| auto_dial != mdns.auto_dial) {
                return Err(FfiError::InvalidConfig {
                    capability: ConfigCapability::Options,
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
            };
            builder = builder.mdns_config(mdns_config);
            if signed_auto_dial.is_none() {
                builder = builder.peer_discovery_config(PeerDiscoveryConfig {
                    auto_dial: mdns.auto_dial,
                    ..PeerDiscoveryConfig::default()
                });
            }
        }

        builder = configure_listen(builder, listen)?;
        let mut endpoint = builder.bind().map_err(map_bind_error)?;
        let listen_addrs = endpoint
            .listen_all()
            .map_err(map_driver_error)?
            .into_iter()
            .map(|address| address.to_string())
            .collect();
        let peer_id = endpoint.peer_id().to_base58();
        let wait_handle = endpoint.wait_handle();

        Ok(Arc::new(Self {
            shared: Arc::new(Shared {
                state: Mutex::new(EndpointState {
                    lifecycle: Lifecycle::Created(endpoint),
                    driver_thread_id: None,
                    doorbell_thread_id: None,
                    published_peers: Vec::new(),
                }),
                events: Mutex::new(EventState {
                    listen_addrs,
                    ..EventState::default()
                }),
                stopped: Mutex::new(false),
                stopped_cv: Condvar::new(),
                wait_handle,
                pending_commands: AtomicUsize::new(0),
                commands_started: AtomicUsize::new(0),
                driver_waiting: AtomicBool::new(false),
                commands_idle: Mutex::new(()),
                commands_idle_cv: Condvar::new(),
                doorbell_running: AtomicBool::new(false),
            }),
            peer_id,
        }))
    }

    /// Returns the local peer ID as legacy base58 text.
    pub fn peer_id(&self) -> String {
        self.peer_id.clone()
    }

    /// Returns the bound QUIC or TCP peer addresses, as of the last
    /// [`P2pEvent::ListenAddressesChanged`] the driver carried (a
    /// WebTransport certificate rotation changes them).
    pub fn listen_addrs(&self) -> Vec<String> {
        self.shared.lock_events().listen_addrs.clone()
    }

    /// Returns peers with an established QUIC, TCP, or circuit connection.
    ///
    /// Served from a snapshot the driver publishes, so it neither
    /// interrupts nor waits for the driver. Like the endpoint's peer table,
    /// it can run ahead of the event stream: it may list a peer whose events
    /// are not drained yet, or a reconnected peer while an older close is
    /// still queued.
    pub fn connected_peers(&self) -> Result<Vec<String>, FfiError> {
        let events = self.shared.lock_events();
        if events.stopped {
            return Err(FfiError::Stopped);
        }
        Ok(events.connected_peers.clone())
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

    /// Tells the endpoint its app is back in the foreground; see
    /// [`Endpoint::resume`].
    pub fn resume(&self) -> Result<(), FfiError> {
        self.with_endpoint_mut(|endpoint| {
            endpoint.resume();
            Ok(())
        })
    }

    /// Returns whether the background driver is accepting work.
    ///
    /// This becomes `false` when shutdown is requested. Use
    /// [`P2pEndpoint::wait_stopped`] to observe complete driver exit.
    pub fn is_running(&self) -> bool {
        let _pending = PendingCommand::new(&self.shared);
        matches!(self.shared.lock_state().lifecycle, Lifecycle::Running(_))
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
        self.shared
            .lock_events()
            .carry
            .take_delivery(limit as usize)
    }

    /// Requests shutdown without waiting for an in-flight callback.
    ///
    /// A running driver then closes the endpoint, draining for up to
    /// `timeout_ms` (`0` tears down at once, best effort), and reports how
    /// that went as its last event, [`P2pEvent::EndpointClosed`](crate::P2pEvent::EndpointClosed);
    /// [`P2pEndpoint::wait_stopped`] returns once it has. The drain flushes
    /// accepted writes and FINs first, within the same deadline; what is
    /// still unsent when it passes is lost. Only the first `stop`
    /// sets the deadline. A never-started endpoint is released at once, with
    /// no event.
    ///
    /// An attempt that settles during the close drain reports its terminal
    /// ahead of `EndpointClosed`; one still unsettled when the endpoint closes
    /// emits none, so shells settle their remaining waits on stop (and on
    /// `DriverFailed`) themselves.
    pub fn stop(&self, timeout_ms: u64) {
        let _pending = PendingCommand::new(&self.shared);
        let mut state = self.shared.lock_state();
        match state.lifecycle {
            Lifecycle::Created(_) => self.shared.finish_stop(state),
            Lifecycle::Running(_) => self
                .shared
                .begin_stop(&mut state, Duration::from_millis(timeout_ms)),
            Lifecycle::Stopping { .. } | Lifecycle::Stopped => {}
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
                .map(drop)
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
    /// stream slot once none are left), also after its connection closed:
    /// the ended connection holds its slot until every stream settles, so a
    /// binding must keep acknowledging (or abandon) what it read across a
    /// close. A settled or unknown stream or connection is a no-op.
    pub fn stream_consumed(
        &self,
        conn_id: u64,
        stream_id: u64,
        bytes: u64,
    ) -> Result<(), FfiError> {
        let bytes = usize::try_from(bytes).unwrap_or(usize::MAX);
        self.with_endpoint_mut(|endpoint| {
            endpoint
                .stream_consumed(stream_key(conn_id, stream_id), bytes)
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
            let stream = endpoint
                .open_stream(&peer, &protocol_id)
                .map_err(map_driver_error)?;
            self.shared
                .lock_events()
                .carry
                .mark_connection_seen(stream.conn_id().as_u64());
            Ok(stream.into())
        })
    }

    /// Sends one byte chunk on an application stream, named by its
    /// connection and stream ids.
    ///
    /// Returns `true` when the stream accepted every byte. Returns `false`
    /// when it accepted only part: the endpoint holds the rest, resends it as
    /// the stream drains, and emits [`P2pEvent::StreamWriteAccepted`] once all of
    /// it has been accepted. Until then the stream takes no other write
    /// ([`FfiError::Backpressure`]); a `StreamWriteStopped`, `StreamClosed`,
    /// or connection end instead means the held bytes were dropped.
    ///
    /// Like the other stream operations, the stream is named by connection
    /// as well as id, and the connection must still be the one holding it:
    /// an id from a closed or replaced connection fails instead of reaching a
    /// same-numbered stream on its replacement.
    pub fn send_stream(
        &self,
        conn_id: u64,
        stream_id: u64,
        data: Vec<u8>,
    ) -> Result<bool, FfiError> {
        self.with_endpoint_mut(|endpoint| {
            crate::send_whole(endpoint, stream_key(conn_id, stream_id), data)
        })
    }

    /// Half-closes the local write side of an application stream.
    ///
    /// The FIN follows a pending write's held bytes, and later writes are
    /// refused.
    pub fn close_stream_write(&self, conn_id: u64, stream_id: u64) -> Result<(), FfiError> {
        self.with_endpoint_mut(|endpoint| {
            endpoint
                .close_stream_write(stream_key(conn_id, stream_id))
                .map_err(map_driver_error)
        })
    }

    /// Resets an application stream while retaining later close events.
    ///
    /// A held tail is dropped only once the Endpoint accepts the reset, so a
    /// rejected call (a stale connection id) cannot lose a pending write.
    pub fn reset_stream(&self, conn_id: u64, stream_id: u64) -> Result<(), FfiError> {
        self.with_endpoint_mut(|endpoint| {
            endpoint
                .reset_stream(stream_key(conn_id, stream_id))
                .map_err(map_driver_error)
        })
    }

    /// Resets and forgets an application stream, dropping its events still
    /// in the carry.
    ///
    /// Abandoning works top-down (ADR 0012): the carry and the Endpoint drop
    /// what they hold for the stream, and the transport resets it, or settles
    /// it outright once its connection has ended, giving up the bytes it
    /// delivered. A stream the peer closed on a live connection is abandoned
    /// only while its `StreamClosed` is undrained, here or in the Endpoint.
    pub fn abandon_stream(&self, conn_id: u64, stream_id: u64) -> Result<(), FfiError> {
        let (raw_conn, raw_stream) = (conn_id, stream_id);
        let stream = stream_key(conn_id, stream_id);
        self.with_endpoint_mut(|endpoint| {
            let abandoned = endpoint.abandon_stream(stream);
            let dropped = self.shared.lock_events().carry.abandon_stream(
                raw_conn,
                raw_stream,
                abandoned.is_ok(),
            );
            let Some(dropped_data) = dropped else {
                return abandoned.map_err(map_driver_error);
            };
            if dropped_data > 0 {
                match endpoint.stream_consumed(stream, dropped_data) {
                    Ok(()) | Err(_) => {}
                }
            }
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
    ///
    /// A peer that is already connected keeps its connection: the attempt
    /// settles on it and the addresses passed are not dialed.
    pub fn connect(&self, target: crate::ConnectTarget) -> Result<u64, FfiError> {
        let target = crate::connect::parse_connect_target(target)?;
        self.with_endpoint_mut(|endpoint| {
            endpoint
                .connect(target)
                .map(|id| id.as_u64())
                .map_err(|error| FfiError::InvalidAddress {
                    detail: error.to_string(),
                })
        })
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

    /// Returns the path of `peer_id`'s established connection; `None` only
    /// while the peer is not connected. See `minip2p::Endpoint::path`.
    pub fn path(&self, peer_id: String) -> Result<Option<crate::PathKind>, FfiError> {
        let peer = PeerId::from_str(&peer_id).map_err(|error| FfiError::InvalidPeerId {
            detail: error.to_string(),
        })?;
        self.with_endpoint(|endpoint| endpoint.path(&peer).map(crate::events::convert_path))
    }

    /// Returns a snapshot of `peer_id`'s established connection; `None`
    /// while the peer is not connected. A by-peer convenience over
    /// `minip2p::Endpoint::connection_info`.
    pub fn connection_info(
        &self,
        peer_id: String,
    ) -> Result<Option<crate::ConnectionInfo>, FfiError> {
        let peer = parse_peer_id(&peer_id)?;
        self.with_endpoint(|endpoint| {
            let info = endpoint.connection_info(endpoint.connection_id(&peer)?)?;
            Some(crate::ConnectionInfo {
                peer_id: info.peer_id.to_base58(),
                conn_id: info.conn_id.as_u64(),
                remote_addr: info.remote_addr.to_string(),
                path: crate::events::convert_path(info.path),
                ready_protocols: info.ready_protocols,
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
        let _pending = PendingCommand::new(&self.shared);
        let mut state = self.shared.lock_state();
        state.lifecycle = match std::mem::replace(&mut state.lifecycle, Lifecycle::Stopped) {
            Lifecycle::Created(live) => Lifecycle::Running(live),
            other => {
                let error = match other {
                    Lifecycle::Running(_) => FfiError::AlreadyStarted,
                    _ => FfiError::Stopped,
                };
                state.lifecycle = other;
                return Err(error);
            }
        };

        match spawn(Arc::clone(&self.shared), doorbell) {
            Ok(doorbell_thread_id) => {
                state.doorbell_thread_id = Some(doorbell_thread_id);
                Ok(())
            }
            Err(error) => {
                self.shared.finish_stop(state);
                Err(FfiError::Internal {
                    detail: format!("failed to spawn endpoint driver: {error}"),
                })
            }
        }
    }
    /// Returns Rust-side background-driver diagnostics.
    ///
    /// This method is intentionally outside the UniFFI export block.
    pub fn driver_stats(&self) -> DriverStats {
        self.shared.lock_events().carry.stats()
    }

    fn with_endpoint<T>(&self, operation: impl FnOnce(&Endpoint) -> T) -> Result<T, FfiError> {
        let _pending = PendingCommand::new(&self.shared);
        let mut state = self.shared.lock_state();
        Ok(operation(state.lifecycle.accepting()?))
    }

    fn with_endpoint_mut<T>(
        &self,
        operation: impl FnOnce(&mut Endpoint) -> Result<T, FfiError>,
    ) -> Result<T, FfiError> {
        let _pending = PendingCommand::new(&self.shared);
        let mut state = self.shared.lock_state();
        operation(state.lifecycle.accepting()?)
    }
}

impl Drop for P2pEndpoint {
    fn drop(&mut self) {
        self.stop(DEFAULT_STOP_TIMEOUT_MS);
    }
}

impl Shared {
    /// Locks the endpoint state. The driver holds this across its blocking
    /// wait, so another thread takes a `PendingCommand` first to interrupt it.
    pub(crate) fn lock_state(&self) -> MutexGuard<'_, EndpointState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn lock_events(&self) -> MutexGuard<'_, EventState> {
        self.events.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Moves a running endpoint to `Stopping`, for the driver to close
    /// within `close_timeout`, and `connected_peers` to `Stopped` with it.
    /// Any other lifecycle is left as is.
    pub(crate) fn begin_stop(&self, state: &mut EndpointState, close_timeout: Duration) {
        state.lifecycle = match std::mem::replace(&mut state.lifecycle, Lifecycle::Stopped) {
            Lifecycle::Running(live) => Lifecycle::Stopping {
                live: Some(live),
                close_timeout,
            },
            other => {
                state.lifecycle = other;
                return;
            }
        };
        self.lock_events().stopped = true;
    }

    /// Moves `state` to `Stopped`, and `connected_peers` with it; then,
    /// outside the lock, releases whatever endpoint it still held and wakes
    /// `wait_stopped`.
    pub(crate) fn finish_stop(&self, mut state: MutexGuard<'_, EndpointState>) {
        let released = std::mem::replace(&mut state.lifecycle, Lifecycle::Stopped);
        self.lock_events().stopped = true;
        drop(state);
        drop(released);
        self.latch_stopped();
    }

    /// Publishes `endpoint`'s peer table to `connected_peers` when it differs
    /// from `published`, the last one published. Called by the driver while
    /// it holds `state`: membership only changes as the endpoint processes
    /// transport events in `wait`, so commands (even `disconnect`, which
    /// queues the close) never need to publish.
    pub(crate) fn publish_peers(&self, endpoint: &Endpoint, published: &mut Vec<PeerId>) {
        let peers = endpoint.connected_peers();
        if peers == *published {
            return;
        }
        self.lock_events().connected_peers = peers.iter().map(PeerId::to_base58).collect();
        *published = peers;
    }

    /// Holds an interrupted driver back until no caller is waiting for
    /// `state`. Without it the driver could retake `state` first and park
    /// again in a wait whose interrupt was already spent.
    ///
    /// After pending commands clear it sleeps for [`COMMAND_LINGER`] before
    /// checking for further commands, unless the [`MAX_COMMAND_LINGER`]
    /// budget has already elapsed, and repeats while commands keep starting:
    /// a burst of synchronous calls then runs without the driver retaking
    /// `state` between each. The budget starts on entry; pending-command
    /// waits and sleep granularity can exceed it. Measured with the Node FFI
    /// benches, this beats a fixed 1 ms sleep, which stalls the driver after
    /// every write or read acknowledgement, waking per command, which
    /// contends with bursts, and skipping the sleep after an isolated
    /// command, which on slow hosts lets the driver retake `state` between
    /// every synchronous call.
    pub(crate) fn wait_for_commands(&self) {
        let linger_until = Instant::now() + MAX_COMMAND_LINGER;
        loop {
            {
                let mut idle = self
                    .commands_idle
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                self.driver_waiting.store(true, Ordering::SeqCst);
                while self.pending_commands.load(Ordering::SeqCst) != 0 {
                    idle = self
                        .commands_idle_cv
                        .wait(idle)
                        .unwrap_or_else(PoisonError::into_inner);
                }
                self.driver_waiting.store(false, Ordering::SeqCst);
            }
            if Instant::now() >= linger_until {
                return;
            }
            let started = self.commands_started.load(Ordering::Acquire);
            std::thread::sleep(COMMAND_LINGER);
            if self.commands_started.load(Ordering::Acquire) == started
                && self.pending_commands.load(Ordering::SeqCst) == 0
            {
                return;
            }
        }
    }

    fn lock_stopped(&self) -> MutexGuard<'_, bool> {
        self.stopped.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records that the lifecycle reached `Stopped` and wakes `wait_stopped`.
    fn latch_stopped(&self) {
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
        if self.shared.pending_commands.fetch_sub(1, Ordering::SeqCst) == 1
            && self.shared.driver_waiting.load(Ordering::SeqCst)
        {
            let _idle = self
                .shared
                .commands_idle
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            self.shared.commands_idle_cv.notify_all();
        }
    }
}

/// Maps a failure to build the endpoint: configuration mistakes to
/// `InvalidConfig` naming their capability, malformed listen input to
/// `InvalidAddress`, refused sockets to `Transport`, and broken invariants to
/// `Internal`. Runtime failures go through [`map_driver_error`] instead.
fn map_bind_error(error: BindError) -> FfiError {
    let detail = error.to_string();
    let config = |capability| FfiError::InvalidConfig {
        capability,
        detail: detail.clone(),
    };
    match &error {
        BindError::Options(error) => map_options_error(error.clone()),
        BindError::Swarm(_) => config(ConfigCapability::Options),
        BindError::Gossipsub(_) => config(ConfigCapability::Gossipsub),
        BindError::Mdns(_) => config(ConfigCapability::Mdns),
        BindError::Discovery(_) => config(ConfigCapability::Discovery),
        BindError::NatConfig(_) => config(ConfigCapability::Options),
        BindError::Quic(
            QuicBindError::InvalidLimit { .. }
            | QuicBindError::Tls { .. }
            | QuicBindError::Certificate(_)
            | QuicBindError::AddressFamilies { .. },
        ) => config(ConfigCapability::Transport),
        BindError::Quic(QuicBindError::InvalidAddress { .. })
        | BindError::Listen(TransportError::InvalidAddress { .. }) => {
            FfiError::InvalidAddress { detail }
        }
        BindError::Quic(QuicBindError::Socket { .. })
        | BindError::Listen(_)
        | BindError::MdnsSocket(_)
        | BindError::ReadinessPoll { .. } => FfiError::Transport { detail },
        BindError::Invariant { .. } => FfiError::Internal { detail },
        _ => FfiError::Internal { detail },
    }
}

/// Maps a mistake in the endpoint's own options.
fn map_options_error(error: EndpointOptionsError) -> FfiError {
    let detail = error.to_string();
    match error {
        EndpointOptionsError::InvalidListenAddress { .. }
        | EndpointOptionsError::UnsupportedListenShape { .. } => {
            FfiError::InvalidAddress { detail }
        }
        EndpointOptionsError::TcpNamespace { .. } | EndpointOptionsError::InvalidLimit(_) => {
            FfiError::InvalidConfig {
                capability: ConfigCapability::Transport,
                detail,
            }
        }
        EndpointOptionsError::NoTransport
        | EndpointOptionsError::DuplicateQuicFamily { .. }
        | EndpointOptionsError::TransportConflict(_) => FfiError::InvalidConfig {
            capability: ConfigCapability::Options,
            detail,
        },
        _ => FfiError::InvalidConfig {
            capability: ConfigCapability::Options,
            detail,
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

#[cfg(test)]
#[path = "endpoint_tests.rs"]
mod tests;
