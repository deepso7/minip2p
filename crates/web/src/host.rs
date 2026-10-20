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
    CircuitTransport, ConnectId, ConnectionId, Deadline, Ed25519Keypair, EndpointEvent,
    GossipsubConfig, NatConfig, Now, PeerId, PortableBuildError, PortableEndpoint,
    PortableEndpointBuilder, ReservationPolicy, StreamId, Transport, WriteProgress,
};
use minip2p_ffi_core::{
    CloseOutcome, ConfigCapability, ConnectTarget, ConnectionInfo, EndpointConfig, EventCarry,
    FfiError, IdentifyInfo, KnownPeerInfo, OpenStreamResult, P2pEvent, PUMP_DRAIN_LIMIT, PathKind,
    Reachability, RelayReservationInfo, convert_endpoint_event, convert_identify, convert_path,
    convert_reachability, driver_failure_kind, keypair_from_bytes, map_driver_error,
    map_gossipsub_error, map_write_error, parse_connect_target, parse_direct_peer_addr,
    parse_peer_id, stream_writer, write_accepted_event,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Lifecycle {
    Created,
    Running,
    Stopped,
}

/// The endpoint a [`Host`] drives: `T` behind a circuit transport.
type HostEndpoint<T> = PortableEndpoint<CircuitTransport<T, WebEntropy>, WebEntropy>;

/// A browser endpoint: the portable endpoint, its pending stream writes, and
/// the carry its events wait in until the binding drains them.
pub struct Host<T: Transport> {
    peer_id: String,
    lifecycle: Lifecycle,
    endpoint: Option<HostEndpoint<T>>,
    writes: minip2p::StreamWriter,
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
        let mut builder = PortableEndpointBuilder::new(&keypair, WebEntropy)
            .agent_version(
                config
                    .agent_version
                    .unwrap_or_else(|| format!("minip2p-web/{}", env!("CARGO_PKG_VERSION"))),
            )
            .gossipsub_config(GossipsubConfig {
                allow_unsigned: config.allow_unsigned,
                ..GossipsubConfig::default()
            });
        if !relays.is_empty() {
            // A browser is never publicly reachable and cannot hole punch:
            // it always reserves, and its relayed paths never upgrade.
            builder = builder.nat_config(NatConfig {
                relays,
                force_relay: config.force_relay,
                dcutr: false,
                reservation_policy: ReservationPolicy::Always,
                ..NatConfig::default()
            });
        }
        let circuits = CircuitTransport::new(transport(&keypair), keypair.clone(), WebEntropy);
        let mut endpoint = builder
            .build_with_circuits(circuits)
            .map_err(map_build_error)?;
        // The binding acknowledges stream data as its reader consumes it
        // (`stream_consumed`), not as the pump pulls the event.
        for protocol in config.protocols {
            endpoint
                .add_manual_ack_protocol(protocol)
                .map_err(|error| FfiError::InvalidConfig {
                    capability: ConfigCapability::Options,
                    detail: error.to_string(),
                })?;
        }
        Ok(Self {
            peer_id: keypair.peer_id().to_base58(),
            lifecycle: Lifecycle::Created,
            endpoint: Some(endpoint),
            writes: stream_writer(),
            carry: EventCarry::default(),
            listen_addrs: Vec::new(),
        })
    }

    /// Starts driving: [`Self::pump`] does nothing before this.
    pub fn start(&mut self) -> Result<(), FfiError> {
        match self.lifecycle {
            Lifecycle::Created => {
                self.lifecycle = Lifecycle::Running;
                Ok(())
            }
            Lifecycle::Running => Err(FfiError::AlreadyStarted),
            Lifecycle::Stopped => Err(FfiError::Stopped),
        }
    }

    /// Polls the endpoint once at `now` and carries what it returned.
    ///
    /// A failed poll fails the host: `DriverFailed`, the close's events and
    /// `EndpointClosed` are carried, and every later command is
    /// [`FfiError::Stopped`].
    pub fn pump(&mut self, now: Now) -> Pumped {
        let Some(endpoint) = self.running_endpoint() else {
            return Pumped {
                ring: false,
                next_deadline: None,
            };
        };
        match endpoint.poll(now) {
            Ok(events) => {
                let mut ring = false;
                let mut events = events.into_iter().peekable();
                // Each ingest takes a bounded batch, as the carry expects.
                while events.peek().is_some() {
                    let batch: Vec<_> = events.by_ref().take(PUMP_DRAIN_LIMIT).collect();
                    let converted = self.convert(batch, now);
                    ring |= self.ingest(converted);
                }
                let next_deadline = self
                    .endpoint
                    .as_ref()
                    .and_then(|endpoint| endpoint.next_deadline(now));
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
            Lifecycle::Created => {
                self.lifecycle = Lifecycle::Stopped;
                self.endpoint = None;
                false
            }
            Lifecycle::Running => self.shut_down(now, None),
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
        self.lifecycle == Lifecycle::Running
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
    pub fn subscribe(&mut self, topic: String, now: Now) -> Result<bool, FfiError> {
        self.endpoint()?
            .subscribe(&topic, now)
            .map_err(map_gossipsub_error)
    }

    /// Withdraws a pubsub subscription.
    pub fn unsubscribe(&mut self, topic: String, now: Now) -> Result<bool, FfiError> {
        self.endpoint()?
            .unsubscribe(&topic, now)
            .map_err(map_gossipsub_error)
    }

    /// Publishes one pubsub payload.
    pub fn publish(&mut self, topic: String, data: Vec<u8>, now: Now) -> Result<(), FfiError> {
        if data.len() > minip2p_pubsub::MAX_RPC_SIZE {
            return Err(FfiError::MessageTooLarge);
        }
        self.endpoint()?
            .publish(&topic, data, now)
            .map_err(map_gossipsub_error)
    }

    /// Sends an explicit ping; its result arrives as an event.
    pub fn ping(&mut self, peer_id: String, now: Now) -> Result<(), FfiError> {
        let peer = parse_peer_id(&peer_id)?;
        self.endpoint()?.ping(&peer, now).map_err(map_driver_error)
    }

    /// Registers an application protocol, acknowledged by the binding with
    /// [`Self::stream_consumed`].
    pub fn add_protocol(&mut self, protocol_id: String) -> Result<(), FfiError> {
        self.endpoint()?
            .add_manual_ack_protocol(protocol_id)
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
            .stream_consumed(ConnectionId::new(conn_id), StreamId::new(stream_id), bytes)
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
        let (conn_id, stream_id) = self
            .endpoint()?
            .open_stream(&peer, &protocol_id, now)
            .map_err(map_driver_error)?;
        // The binding knows this connection now, so the carry must not
        // elide its events, its end above all.
        self.carry.mark_connection_seen(conn_id.as_u64());
        Ok(OpenStreamResult {
            conn_id: conn_id.as_u64(),
            stream_id: stream_id.as_u64(),
        })
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
        let endpoint = endpoint_mut(&mut self.endpoint, self.lifecycle)?;
        self.writes
            .write_at(
                endpoint,
                ConnectionId::new(conn_id),
                StreamId::new(stream_id),
                data,
                now,
            )
            .map(|progress| progress == WriteProgress::Accepted)
            .map_err(map_write_error)
    }

    /// Half-closes a stream's write side, after any held tail.
    pub fn close_stream_write(
        &mut self,
        conn_id: u64,
        stream_id: u64,
        now: Now,
    ) -> Result<(), FfiError> {
        let endpoint = endpoint_mut(&mut self.endpoint, self.lifecycle)?;
        self.writes
            .close_write_at(
                endpoint,
                ConnectionId::new(conn_id),
                StreamId::new(stream_id),
                now,
            )
            .map_err(map_write_error)
    }

    /// Resets a stream, forgetting its held tail once accepted.
    pub fn reset_stream(&mut self, conn_id: u64, stream_id: u64, now: Now) -> Result<(), FfiError> {
        let (conn_id, stream_id) = (ConnectionId::new(conn_id), StreamId::new(stream_id));
        self.endpoint()?
            .reset_stream(conn_id, stream_id, now)
            .map_err(map_driver_error)?;
        self.writes.forget(conn_id, stream_id);
        Ok(())
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
        let (conn_id, stream_id) = (ConnectionId::new(conn_id), StreamId::new(stream_id));
        let endpoint = endpoint_mut(&mut self.endpoint, self.lifecycle)?;
        let abandoned = endpoint.abandon_stream(conn_id, stream_id, now);
        if abandoned.is_err() && !self.carry.holds_stream_close(raw_conn, raw_stream) {
            return abandoned.map_err(map_driver_error);
        }
        let dropped_data = self.carry.remove_stream(raw_conn, raw_stream);
        // Never drained, so never acknowledged: after a reset this is moot,
        // and a stream closed on a live connection is released by it.
        if dropped_data > 0 {
            match endpoint.stream_consumed(conn_id, stream_id, dropped_data) {
                Ok(()) | Err(_) => {}
            }
        }
        self.writes.forget(conn_id, stream_id);
        Ok(())
    }

    /// Starts one Connection attempt and returns its Connect ID.
    pub fn connect(&mut self, target: ConnectTarget, now: Now) -> Result<u64, FfiError> {
        let target = parse_connect_target(target)?;
        self.endpoint()?
            .connect(target, now)
            .map(|id| id.as_u64())
            .map_err(|error| FfiError::InvalidAddress {
                detail: error.to_string(),
            })
    }

    /// Cancels a Connection attempt; idempotent.
    pub fn cancel_connect(&mut self, id: u64, now: Now) -> Result<(), FfiError> {
        self.endpoint()?
            .cancel_connect(ConnectId::from_u64(id), now);
        Ok(())
    }

    /// Closes the connection to `peer_id`.
    pub fn disconnect(&mut self, peer_id: String, now: Now) -> Result<(), FfiError> {
        let peer = parse_peer_id(&peer_id)?;
        self.endpoint()?
            .disconnect(&peer, now)
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
        endpoint_mut(&mut self.endpoint, self.lifecycle)
    }

    fn running_endpoint(&mut self) -> Option<&mut HostEndpoint<T>> {
        if self.lifecycle == Lifecycle::Running {
            self.endpoint.as_mut()
        } else {
            None
        }
    }

    /// Converts one batch: each event's held write is followed first, so a
    /// Writable that settles a write reports it right after the event.
    fn convert(&mut self, batch: Vec<EndpointEvent>, now: Now) -> Vec<P2pEvent> {
        let Some(endpoint) = self.endpoint.as_mut() else {
            return Vec::new();
        };
        let mut converted = Vec::with_capacity(batch.len());
        for event in batch {
            let settled = self
                .writes
                .observe_at(endpoint, &event, now)
                .map(write_accepted_event);
            converted.extend(convert_endpoint_event(event));
            converted.extend(settled);
        }
        converted
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
        self.lifecycle = Lifecycle::Stopped;
        self.writes = stream_writer();
        let outcome_if_ok = if failure.is_some() {
            CloseOutcome::Failed
        } else {
            CloseOutcome::Drained
        };
        let (drained, outcome) = match self.endpoint.take().map(|endpoint| endpoint.shutdown(now)) {
            Some(Ok(events)) => (events, outcome_if_ok),
            Some(Err(_)) | None => (Vec::new(), CloseOutcome::Failed),
        };
        let mut events: Vec<P2pEvent> = failure.into_iter().collect();
        events.extend(drained.into_iter().filter_map(convert_endpoint_event));
        events.push(P2pEvent::EndpointClosed {
            outcome,
            unfinished: Vec::new(),
        });
        self.ingest(events)
    }
}

fn endpoint_mut<T: Transport>(
    endpoint: &mut Option<HostEndpoint<T>>,
    lifecycle: Lifecycle,
) -> Result<&mut HostEndpoint<T>, FfiError> {
    match lifecycle {
        Lifecycle::Created | Lifecycle::Running => endpoint.as_mut().ok_or(FfiError::Stopped),
        Lifecycle::Stopped => Err(FfiError::Stopped),
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
    if config.force_relay && config.relays.is_empty() {
        return reject(
            ConfigCapability::Options,
            "forceRelay requires at least one relay",
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
        PortableBuildError::Gossipsub(_) | PortableBuildError::Topic(_) => {
            FfiError::InvalidConfig {
                capability: ConfigCapability::Gossipsub,
                detail,
            }
        }
        _ => FfiError::Internal { detail },
    }
}
