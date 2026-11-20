//! The browser host: one [`PortableEndpoint`] driven by a single-threaded
//! pump, feeding ffi-core's [`EventCarry`].
//!
//! It is the thread-free counterpart of ffi-core's `P2pEndpoint`, with the
//! same commands, errors and event stream. The transport is always wrapped in
//! a [`CircuitTransport`], so with relays configured the browser holds a
//! reservation (it is dialable at its `/p2p-circuit` address) and races
//! direct dials against a relay leg; it never hole punches (`dcutr = false`). Nothing here touches wasm or the
//! browser: the caller samples time, schedules [`Host::pump`], and rings the
//! doorbell [`Pumped::ring`] asks for, so the host runs over any transport
//! and is tested natively.

use minip2p::{
    CircuitTransport, ConnectId, ConnectionId, Deadline, DriverError, Ed25519Keypair, ManualClock,
    NatConfig, Now, PeerId, PortableBuildError, PortableEndpoint, PortableEndpointBuilder,
    ReservationPolicy, Transport,
};
#[cfg(feature = "pubsub")]
use minip2p_ffi_core::map_gossipsub_error;
use minip2p_ffi_core::{
    BINDING_WRITE_BUDGET, CloseOutcome, ConfigCapability, ConnectTarget, ConnectionInfo,
    EndpointConfig, EventCarry, FfiError, IdentifyInfo, KnownPeerInfo, OpenStreamResult, P2pEvent,
    PUMP_DRAIN_LIMIT, PathKind, Reachability, RelayReservationInfo, UnfinishedConnection,
    convert_endpoint_event, convert_identify, convert_path, convert_reachability,
    driver_failure_kind, keypair_from_bytes, map_driver_error, parse_connect_target,
    parse_direct_peer_addr, parse_peer_id, send_whole, stream_key,
};

use crate::WebEntropy;

/// What one [`Host::pump`] asks of its caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pumped {
    /// The carry went from empty to non-empty: ring the doorbell.
    pub ring: bool,
    /// When to pump next: [`Deadline::IMMEDIATE`] while work is queued,
    /// `None` once nothing is scheduled (or the host stopped).
    pub next_deadline: Option<Deadline>,
}

/// The endpoint a [`Host`] drives: `T` behind a circuit transport.
type HostEndpoint<T> = PortableEndpoint<CircuitTransport<T, WebEntropy>, WebEntropy, ManualClock>;

enum Lifecycle<T: Transport> {
    /// Commands work; [`Host::pump`] does nothing yet.
    Created(HostEndpoint<T>),
    Running(HostEndpoint<T>),
    /// Closed or failed: the endpoint is released.
    Stopped,
}

impl<T: Transport> Lifecycle<T> {
    /// The endpoint while it accepts commands: created or running.
    fn live(&mut self) -> Result<&mut HostEndpoint<T>, FfiError> {
        match self {
            Self::Created(live) | Self::Running(live) => Ok(live),
            Self::Stopped => Err(FfiError::Stopped),
        }
    }
}

/// A browser endpoint: the portable endpoint and the carry its events wait
/// in until the binding drains them.
pub struct Host<T: Transport> {
    peer_id: String,
    lifecycle: Lifecycle<T>,
    carry: EventCarry,
    /// The listen set, followed from `ListenAddressesChanged`; a browser
    /// never listens, so it stays empty (a reservation is reported as
    /// `RelayReserved`, not as a listen address).
    listen_addrs: Vec<String>,
}

impl<T: Transport> Host<T> {
    /// Validates `config` for a browser, then builds the endpoint over the
    /// transport `transport` makes for the node's identity. Like
    /// `P2pEndpoint`, it starts in the created state: commands work, but
    /// nothing is driven until [`Self::start`].
    pub fn new(
        secret_key: Vec<u8>,
        config: EndpointConfig,
        transport: impl FnOnce(&Ed25519Keypair) -> T,
    ) -> Result<Self, FfiError> {
        let keypair = keypair_from_bytes(secret_key)?;
        validate_browser_config(&config)?;
        let relays = config
            .relays
            .iter()
            .map(|address| parse_direct_peer_addr(address))
            .collect::<Result<Vec<_>, _>>()?;
        let mut builder =
            PortableEndpointBuilder::new(&keypair, WebEntropy, ManualClock::default())
                .agent_version(
                    config
                        .agent_version
                        .unwrap_or_else(|| format!("minip2p-web/{}", env!("CARGO_PKG_VERSION"))),
                )
                .timeouts(config.timeouts.map(Into::into).unwrap_or_default())
                .write_budget(BINDING_WRITE_BUDGET);
        #[cfg(feature = "pubsub")]
        {
            builder = builder.gossipsub_config(minip2p::GossipsubConfig {
                allow_unsigned: config.allow_unsigned,
                ..minip2p::GossipsubConfig::default()
            });
        }
        // `force_relay` without a relay still submits the config, so the
        // endpoint's validation refuses it rather than dropping the flag.
        if !relays.is_empty() || config.force_relay {
            // A browser is never publicly reachable and cannot hole punch:
            // it always reserves, and its relayed paths never upgrade.
            builder = builder.nat_config(NatConfig {
                force_relay: config.force_relay,
                dcutr: false,
                reservation_policy: ReservationPolicy::Always,
                ..NatConfig::default()
            });
        }
        for relay in relays {
            builder = builder.relay(relay);
        }
        // The binding acknowledges stream data as its reader consumes it
        // (`stream_consumed`), not as the pump pulls the event.
        for protocol in config.protocols {
            builder = builder.manual_ack_protocol(protocol);
        }
        let circuits = CircuitTransport::new(transport(&keypair), keypair.clone(), WebEntropy);
        let endpoint = builder
            .build_with_circuits(circuits)
            .map_err(map_build_error)?;
        Ok(Self {
            peer_id: keypair.peer_id().to_base58(),
            lifecycle: Lifecycle::Created(endpoint),
            carry: EventCarry::default(),
            listen_addrs: Vec::new(),
        })
    }

    /// Starts driving: [`Self::pump`] does nothing before this.
    pub fn start(&mut self) -> Result<(), FfiError> {
        match core::mem::replace(&mut self.lifecycle, Lifecycle::Stopped) {
            Lifecycle::Created(live) => {
                self.lifecycle = Lifecycle::Running(live);
                Ok(())
            }
            Lifecycle::Running(live) => {
                self.lifecycle = Lifecycle::Running(live);
                Err(FfiError::AlreadyStarted)
            }
            Lifecycle::Stopped => Err(FfiError::Stopped),
        }
    }

    /// Polls the endpoint once at `now` and carries what it returned.
    ///
    /// A failed poll fails the host: `DriverFailed`, the close's events and
    /// `EndpointClosed` are carried, and every later command is
    /// [`FfiError::Stopped`].
    pub fn pump(&mut self, now: Now) -> Pumped {
        let Lifecycle::Running(endpoint) = &mut self.lifecycle else {
            return Pumped {
                ring: false,
                next_deadline: None,
            };
        };
        match endpoint.at(now).poll() {
            Ok(events) => {
                let mut ring = false;
                let mut events = events.into_iter().peekable();
                // Each ingest takes a bounded batch, as the carry expects.
                while events.peek().is_some() {
                    let batch: Vec<_> = events.by_ref().take(PUMP_DRAIN_LIMIT).collect();
                    let converted = batch.into_iter().filter_map(convert_endpoint_event);
                    ring |= self.ingest(converted.collect());
                }
                let next_deadline = match &mut self.lifecycle {
                    Lifecycle::Running(endpoint) => endpoint.at(now).next_deadline(),
                    Lifecycle::Created(_) | Lifecycle::Stopped => None,
                };
                Pumped {
                    ring,
                    next_deadline,
                }
            }
            Err(error) => {
                let failure = P2pEvent::DriverFailed {
                    kind: driver_failure_kind(&error),
                    detail: error.to_string(),
                };
                Pumped {
                    ring: self.shut_down(now, Some(failure)),
                    next_deadline: None,
                }
            }
        }
    }

    /// Closes the endpoint: its connections close at once (a WebTransport
    /// session sends its close capsule as it goes), the close's events are
    /// carried, then `EndpointClosed` as the last event. Returns whether to
    /// ring the doorbell. A never-started host is released with no event;
    /// a second close does nothing.
    pub fn close(&mut self, now: Now) -> bool {
        match self.lifecycle {
            Lifecycle::Created(_) => {
                self.lifecycle = Lifecycle::Stopped;
                false
            }
            Lifecycle::Running(_) => self.shut_down(now, None),
            Lifecycle::Stopped => false,
        }
    }

    /// Takes at most `limit` carried events in source order.
    pub fn drain_events(&mut self, limit: usize) -> Vec<P2pEvent> {
        self.carry.take_delivery(limit)
    }

    /// The local peer ID as base58 text.
    pub fn peer_id(&self) -> String {
        self.peer_id.clone()
    }

    /// The current listen set (see `P2pEndpoint::listen_addrs`).
    pub fn listen_addrs(&self) -> Vec<String> {
        self.listen_addrs.clone()
    }

    /// Whether the host is started and not yet closed.
    pub fn is_running(&self) -> bool {
        matches!(self.lifecycle, Lifecycle::Running(_))
    }

    /// Peers with an established connection.
    pub fn connected_peers(&mut self) -> Result<Vec<String>, FfiError> {
        Ok(self
            .endpoint()?
            .connected_peers()
            .iter()
            .map(PeerId::to_base58)
            .collect())
    }

    /// Whether Identify completed for `peer_id`.
    pub fn is_peer_ready(&mut self, peer_id: String) -> Result<bool, FfiError> {
        let peer = parse_peer_id(&peer_id)?;
        Ok(self.endpoint()?.is_peer_ready(&peer))
    }

    /// The latest Identify snapshot for `peer_id`.
    pub fn peer_info(&mut self, peer_id: String) -> Result<Option<IdentifyInfo>, FfiError> {
        let peer = parse_peer_id(&peer_id)?;
        Ok(self.endpoint()?.peer_info(&peer).map(convert_identify))
    }

    /// Subscribes to a pubsub topic.
    #[cfg(feature = "pubsub")]
    pub fn subscribe(&mut self, topic: String, now: Now) -> Result<bool, FfiError> {
        self.endpoint()?
            .at(now)
            .subscribe(&topic)
            .map_err(map_gossipsub_error)
    }

    /// Withdraws a pubsub subscription.
    #[cfg(feature = "pubsub")]
    pub fn unsubscribe(&mut self, topic: String, now: Now) -> Result<bool, FfiError> {
        self.endpoint()?
            .at(now)
            .unsubscribe(&topic)
            .map_err(map_gossipsub_error)
    }

    /// Publishes one pubsub payload.
    #[cfg(feature = "pubsub")]
    pub fn publish(&mut self, topic: String, data: Vec<u8>, now: Now) -> Result<(), FfiError> {
        if data.len() > minip2p_pubsub::MAX_RPC_SIZE {
            return Err(FfiError::MessageTooLarge);
        }
        self.endpoint()?
            .at(now)
            .publish(&topic, data)
            .map_err(map_gossipsub_error)
    }

    /// Refuses: this build has no pubsub. The pubsub commands stay so the
    /// JavaScript surface is the same with or without the feature.
    #[cfg(not(feature = "pubsub"))]
    pub fn subscribe(&mut self, _topic: String, _now: Now) -> Result<bool, FfiError> {
        self.endpoint()?;
        Err(pubsub_not_built())
    }

    /// Refuses: this build has no pubsub.
    #[cfg(not(feature = "pubsub"))]
    pub fn unsubscribe(&mut self, _topic: String, _now: Now) -> Result<bool, FfiError> {
        self.endpoint()?;
        Err(pubsub_not_built())
    }

    /// Refuses: this build has no pubsub.
    #[cfg(not(feature = "pubsub"))]
    pub fn publish(&mut self, _topic: String, _data: Vec<u8>, _now: Now) -> Result<(), FfiError> {
        self.endpoint()?;
        Err(pubsub_not_built())
    }

    /// Sends an explicit ping; its result arrives as an event.
    pub fn ping(&mut self, peer_id: String, now: Now) -> Result<(), FfiError> {
        let peer = parse_peer_id(&peer_id)?;
        self.endpoint()?
            .at(now)
            .ping(&peer)
            .map_err(map_driver_error)
    }

    /// Registers an application protocol, acknowledged by the binding with
    /// [`Self::stream_consumed`].
    pub fn add_protocol(&mut self, protocol_id: String) -> Result<(), FfiError> {
        self.endpoint()?
            .add_manual_ack_protocol(protocol_id)
            .map(drop)
            .map_err(map_driver_error)
    }

    /// Acknowledges `bytes` of a stream's delivered data as consumed (see
    /// `P2pEndpoint::stream_consumed`).
    pub fn stream_consumed(
        &mut self,
        conn_id: u64,
        stream_id: u64,
        bytes: u64,
        _now: Now,
    ) -> Result<(), FfiError> {
        let bytes = usize::try_from(bytes).unwrap_or(usize::MAX);
        self.endpoint()?
            .stream_consumed(stream_key(conn_id, stream_id), bytes)
            .map_err(map_driver_error)
    }

    /// Opens a negotiated application stream.
    pub fn open_stream(
        &mut self,
        peer_id: String,
        protocol_id: String,
        now: Now,
    ) -> Result<OpenStreamResult, FfiError> {
        let peer = parse_peer_id(&peer_id)?;
        let stream = self
            .endpoint()?
            .at(now)
            .open_stream(&peer, &protocol_id)
            .map_err(map_driver_error)?;
        // The binding knows this connection now, so the carry must not
        // elide its events, its end above all.
        self.carry.mark_connection_seen(stream.conn_id().as_u64());
        Ok(stream.into())
    }

    /// Sends one payload (see `P2pEndpoint::send_stream`): `true` once every
    /// byte is accepted, `false` while the tail is held.
    pub fn send_stream(
        &mut self,
        conn_id: u64,
        stream_id: u64,
        data: Vec<u8>,
        now: Now,
    ) -> Result<bool, FfiError> {
        send_whole(
            self.endpoint()?.at(now),
            stream_key(conn_id, stream_id),
            data,
        )
    }

    /// Half-closes a stream's write side, after any held tail.
    pub fn close_stream_write(
        &mut self,
        conn_id: u64,
        stream_id: u64,
        now: Now,
    ) -> Result<(), FfiError> {
        self.endpoint()?
            .at(now)
            .close_stream_write(stream_key(conn_id, stream_id))
            .map_err(map_driver_error)
    }

    /// Resets a stream, dropping its held tail once the reset is accepted.
    pub fn reset_stream(&mut self, conn_id: u64, stream_id: u64, now: Now) -> Result<(), FfiError> {
        self.endpoint()?
            .at(now)
            .reset_stream(stream_key(conn_id, stream_id))
            .map_err(map_driver_error)
    }

    /// Resets and forgets a stream, dropping its events still carried (see
    /// `P2pEndpoint::abandon_stream`, whose order this follows).
    pub fn abandon_stream(
        &mut self,
        conn_id: u64,
        stream_id: u64,
        now: Now,
    ) -> Result<(), FfiError> {
        let (raw_conn, raw_stream) = (conn_id, stream_id);
        let stream = stream_key(conn_id, stream_id);
        let endpoint = self.lifecycle.live()?;
        let abandoned = endpoint.at(now).abandon_stream(stream);
        if abandoned.is_err() && !self.carry.holds_stream_close(raw_conn, raw_stream) {
            return abandoned.map_err(map_driver_error);
        }
        let dropped_data = self.carry.remove_stream(raw_conn, raw_stream);
        // Never drained, so never acknowledged: after a reset this is moot,
        // and a stream closed on a live connection is released by it.
        if dropped_data > 0 {
            match endpoint.stream_consumed(stream, dropped_data) {
                Ok(()) | Err(_) => {}
            }
        }
        Ok(())
    }

    /// Starts one Connection attempt and returns its Connect ID.
    pub fn connect(&mut self, target: ConnectTarget, now: Now) -> Result<u64, FfiError> {
        let target = parse_connect_target(target)?;
        self.endpoint()?
            .at(now)
            .connect(target)
            .map(|id| id.as_u64())
            .map_err(|error| FfiError::InvalidAddress {
                detail: error.to_string(),
            })
    }

    /// Cancels a Connection attempt; idempotent.
    pub fn cancel_connect(&mut self, id: u64, now: Now) -> Result<(), FfiError> {
        self.endpoint()?
            .at(now)
            .cancel_connect(ConnectId::from_u64(id));
        Ok(())
    }

    /// Closes the connection to `peer_id`.
    pub fn disconnect(&mut self, peer_id: String, now: Now) -> Result<(), FfiError> {
        let peer = parse_peer_id(&peer_id)?;
        self.endpoint()?
            .at(now)
            .disconnect(&peer)
            .map_err(map_driver_error)
    }

    /// The path of `peer_id`'s established connection.
    pub fn path(&mut self, peer_id: String) -> Result<Option<PathKind>, FfiError> {
        let peer = parse_peer_id(&peer_id)?;
        Ok(self.endpoint()?.path(&peer).map(convert_path))
    }

    /// A snapshot of `peer_id`'s established connection.
    pub fn connection_info(&mut self, peer_id: String) -> Result<Option<ConnectionInfo>, FfiError> {
        let peer = parse_peer_id(&peer_id)?;
        let endpoint = self.endpoint()?;
        Ok(endpoint
            .connection_id(&peer)
            .and_then(|conn_id| endpoint.connection_info(conn_id))
            .map(|info| ConnectionInfo {
                peer_id: info.peer_id.to_base58(),
                conn_id: info.conn_id.as_u64(),
                remote_addr: info.remote_addr.to_string(),
                path: convert_path(info.path),
                ready_protocols: info.ready_protocols,
            }))
    }

    /// The discovery book: always empty, browsers run no discovery.
    pub fn known_peers(&mut self) -> Result<Vec<KnownPeerInfo>, FfiError> {
        self.endpoint().map(|_| Vec::new())
    }

    /// The discovery clock: `None`, browsers run no discovery.
    pub fn discovery_now_ms(&mut self) -> Result<Option<u64>, FfiError> {
        self.endpoint().map(|_| None)
    }

    /// Reachability: browsers run no AutoNAT, so it stays `Unknown`.
    pub fn reachability(&mut self) -> Result<Reachability, FfiError> {
        Ok(convert_reachability(self.endpoint()?.reachability()))
    }

    /// The relay reservation currently held, if any.
    pub fn active_reservation(&mut self) -> Result<Option<RelayReservationInfo>, FfiError> {
        Ok(self
            .endpoint()?
            .active_reservation()
            .map(|reservation| RelayReservationInfo {
                relay_peer_id: reservation.relay.to_base58(),
                expires_unix_secs: reservation.expires_unix_secs,
            }))
    }

    fn endpoint(&mut self) -> Result<&mut HostEndpoint<T>, FfiError> {
        self.lifecycle.live()
    }

    /// Ingests one batch, following the listen set, and returns whether to
    /// ring.
    fn ingest(&mut self, events: Vec<P2pEvent>) -> bool {
        for event in &events {
            if let P2pEvent::ListenAddressesChanged { addrs } = event {
                self.listen_addrs.clone_from(addrs);
            }
        }
        self.carry.ingest(events)
    }

    /// Stops the host after `failure` (or a requested close): shuts the
    /// endpoint down and carries the failure, the shutdown's events and
    /// `EndpointClosed`.
    fn shut_down(&mut self, now: Now, failure: Option<P2pEvent>) -> bool {
        let endpoint = match core::mem::replace(&mut self.lifecycle, Lifecycle::Stopped) {
            Lifecycle::Created(endpoint) | Lifecycle::Running(endpoint) => Some(endpoint),
            Lifecycle::Stopped => None,
        };
        let failed = failure.is_some();
        let report = endpoint.map(|mut endpoint| {
            endpoint.at(now);
            endpoint.close()
        });
        let mut events: Vec<P2pEvent> = failure.into_iter().collect();
        let closed = match report {
            Some(report) => {
                events.extend(report.events.into_iter().filter_map(convert_endpoint_event));
                closed_event(failed, &report.errors, report.unfinished)
            }
            None => P2pEvent::EndpointClosed {
                outcome: CloseOutcome::Failed,
                unfinished: Vec::new(),
            },
        };
        events.push(closed);
        self.ingest(events)
    }
}

/// The `EndpointClosed` a finished shutdown ends with, listing the
/// connections it abandoned: `Failed` after a host failure or any shutdown
/// error, else `DeadlineExpired` if any connection was still tracked (the one
/// pass portable shutdown makes is a zero deadline, as with std
/// `close_within(Duration::ZERO)`), else `Drained`.
fn closed_event(
    failed: bool,
    errors: &[DriverError],
    unfinished: Vec<(ConnectionId, Option<PeerId>)>,
) -> P2pEvent {
    P2pEvent::EndpointClosed {
        outcome: if failed || !errors.is_empty() {
            CloseOutcome::Failed
        } else if !unfinished.is_empty() {
            CloseOutcome::DeadlineExpired
        } else {
            CloseOutcome::Drained
        },
        unfinished: unfinished
            .into_iter()
            .map(|(conn_id, peer)| UnfinishedConnection {
                conn_id: conn_id.as_u64(),
                peer_id: peer.as_ref().map(PeerId::to_base58),
            })
            .collect(),
    }
}

/// The refusal pubsub commands get from a build without the `pubsub` feature.
#[cfg(not(feature = "pubsub"))]
fn pubsub_not_built() -> FfiError {
    FfiError::NotPermitted {
        detail: "this build of minip2p-web has no pubsub; build it with the `pubsub` feature"
            .into(),
    }
}

/// Rejects configuration a browser cannot run, each with the reason.
fn validate_browser_config(config: &EndpointConfig) -> Result<(), FfiError> {
    let reject = |capability, detail: &str| {
        Err(FfiError::InvalidConfig {
            capability,
            detail: detail.into(),
        })
    };
    if config.listen.is_some() {
        return reject(
            ConfigCapability::Options,
            "browsers cannot listen; omit listen and configure relays (a browser is reached at its /p2p-circuit address through a relay reservation)",
        );
    }
    #[cfg(not(feature = "pubsub"))]
    if config.allow_unsigned {
        return reject(
            ConfigCapability::Gossipsub,
            "this build of minip2p-web has no pubsub; omit allowUnsigned, or build it with the `pubsub` feature",
        );
    }
    if config.mdns.is_some() {
        return reject(
            ConfigCapability::Mdns,
            "browsers have no multicast sockets, so mDNS cannot run; omit mdns",
        );
    }
    if config.discovery.is_some() {
        return reject(
            ConfigCapability::Discovery,
            "signed discovery is not available in the browser build; omit discovery",
        );
    }
    if config.limits.is_some() {
        return reject(
            ConfigCapability::Transport,
            "transport limits are not configurable in the browser build; omit limits",
        );
    }
    if !config.autonat_servers.is_empty() {
        return reject(
            ConfigCapability::Options,
            "browsers cannot be dialed back, so AutoNAT does not apply; omit autonatServers",
        );
    }
    Ok(())
}

fn map_build_error(error: PortableBuildError) -> FfiError {
    let detail = error.to_string();
    match error {
        PortableBuildError::Swarm(_) | PortableBuildError::NatConfig(_) => {
            FfiError::InvalidConfig {
                capability: ConfigCapability::Options,
                detail,
            }
        }
        #[cfg(feature = "pubsub")]
        PortableBuildError::Gossipsub(_) | PortableBuildError::Topic(_) => {
            FfiError::InvalidConfig {
                capability: ConfigCapability::Gossipsub,
                detail,
            }
        }
        _ => FfiError::Internal { detail },
    }
}
