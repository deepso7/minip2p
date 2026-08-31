//! Portable action pump driving [`SwarmCore`] against a [`Transport`].
//!
//! `no_std + alloc`: no clock, no entropy source, no executor. The caller
//! samples time and passes it in, which is what lets the same pump run on an
//! embedded board and under the `std` [`Swarm`](crate::Swarm) wrapper.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::{Multiaddr, PeerAddr, PeerId};
use minip2p_identify::{IdentifyConfig, IdentifyMessage};
use minip2p_ping::{PING_PAYLOAD_LEN, PingConfig};
use minip2p_platform::{Deadline, EntropySource, Now};
use minip2p_transport::{ConnectionId, StreamId, Transport, TransportError};

use crate::core::SwarmCore;
use crate::events::{
    SwarmAction, SwarmError, SwarmErrorKind, SwarmEvent, SwarmInput, SwarmOutput, SwarmRuntimeError,
};

/// Errors returned synchronously by the std swarm driver.
///
/// Protocol-state rejections remain distinguishable from transport failures;
/// callers no longer need to recover their meaning from a flattened string.
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    /// The underlying transport rejected the operation.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The Sans-I/O swarm core rejected the operation.
    #[error(transparent)]
    Swarm(#[from] SwarmError),
    /// The driver and core violated their internal action contract.
    #[error("swarm driver invariant violated: {reason}")]
    Invariant { reason: &'static str },
    /// The std-only `Swarm::run_until` set aside its maximum number of
    /// non-matching events without finding a match.
    ///
    /// The skipped events were restored to the event buffer in their
    /// original order; drain them with `Swarm::poll_next` before waiting
    /// again, or use a predicate that matches (and thereby consumes) the
    /// high-volume events.
    #[error(
        "run_until skipped {limit} events without a match; drain the event buffer with poll_next"
    )]
    EventBacklogExceeded { limit: usize },
    /// The operating system's entropy source failed.
    #[error("system entropy source failed")]
    Entropy,
}

/// Portable action pump driving [`SwarmCore`] against a concrete
/// [`Transport`].
///
/// `no_std + alloc`: it owns no clock, no entropy source of its own, and no
/// executor. The caller samples time and passes it in, which is what lets the
/// same pump run on an embedded board and under the `Swarm` std wrapper.
///
/// Applications on `std` usually want `Swarm`, which adds a clock and
/// blocking drive loops on top of this.
pub struct SwarmRuntime<T: Transport, E: EntropySource> {
    transport: T,
    pub(crate) core: SwarmCore,

    /// Our own `PeerId`. Cached from the [`crate::SwarmBuilder`]'s keypair
    /// so applications don't have to drill into the transport to get it.
    local_peer_id: PeerId,

    /// Buffer of events yielded by [`SwarmRuntime::poll`] that haven't yet
    /// been consumed. Each `poll()` returns a batch; the std
    /// [`Swarm`](crate::Swarm) wrapper hands them out one at a time and calls
    /// `poll()` again when the buffer drains, which is why this is visible to
    /// the rest of the crate.
    pub(crate) event_buffer: VecDeque<SwarmEvent>,

    /// Transport actions ordered after application events by the Sans-I/O
    /// core. They are dispatched only after the buffered events have been
    /// returned to the application. In particular, supersession must expose
    /// `ConnectionClosed` before closing the old transport connection.
    after_event_actions: VecDeque<SwarmAction>,

    /// Externally validated addresses advertised through Identify in
    /// addition to the transport's bound set. See
    /// [`SwarmRuntime::set_external_addresses`].
    external_addresses: Vec<Multiaddr>,
    external_addresses_revision: u64,

    /// Randomness for ping nonces. Injected so the pump stays deterministic
    /// and testable, and so `no_std` hosts can supply their own source.
    entropy: E,
}

impl<T: Transport, E: EntropySource> SwarmRuntime<T, E> {
    /// Creates a swarm driver around the given transport, identify config,
    /// and ping config.
    ///
    /// Most callers should construct via `crate::SwarmBuilder` instead,
    /// which derives `local_peer_id` from the keypair automatically.
    pub fn new(
        transport: T,
        identify_config: IdentifyConfig,
        ping_config: PingConfig,
        local_peer_id: PeerId,
        entropy: E,
    ) -> Self {
        Self {
            transport,
            core: SwarmCore::new(identify_config, ping_config),
            local_peer_id,
            event_buffer: VecDeque::new(),
            after_event_actions: VecDeque::new(),
            external_addresses: Vec::new(),
            external_addresses_revision: 0,
            entropy,
        }
    }

    /// Sets externally validated addresses (e.g. AutoNAT-confirmed public
    /// addresses or relay circuit addresses) to advertise through Identify
    /// alongside the transport's bound addresses.
    ///
    /// Replaces the previous external set; pass an empty vector to stop
    /// advertising extras. Duplicates of transport-bound addresses are
    /// dropped.
    pub fn set_external_addresses(&mut self, addrs: Vec<Multiaddr>) {
        self.external_addresses = addrs;
        self.external_addresses_revision = self.external_addresses_revision.wrapping_add(1);
    }

    /// Returns the externally validated addresses currently contributed to
    /// Identify, excluding transport-bound addresses.
    pub fn external_addresses(&self) -> &[Multiaddr] {
        &self.external_addresses
    }

    /// Returns the wrapping revision of the external-address replacement.
    ///
    /// The revision advances even when a replacement contains the same values,
    /// allowing composed hosts to distinguish address ownership changes.
    pub fn external_addresses_revision(&self) -> u64 {
        self.external_addresses_revision
    }

    /// Returns a reference to the underlying transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Returns a mutable reference to the underlying transport.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Returns a reference to the Sans-I/O core (for advanced introspection).
    pub fn core(&self) -> &SwarmCore {
        &self.core
    }

    /// Crate-internal mutable access to the Sans-I/O core.
    ///
    /// Used by [`crate::SwarmBuilder`] to register user protocols during
    /// `build()`. Not public: mutating the core without flushing its
    /// actions would desynchronize the driver.
    /// Mutable core access for [`SwarmBuilder`](crate::SwarmBuilder), which
    /// registers protocols before the runtime is handed to the application
    /// and wants the core's own error type rather than [`DriverError`].
    pub(crate) fn core_mut(&mut self) -> &mut SwarmCore {
        &mut self.core
    }

    /// Returns peers currently surfaced through `ConnectionEstablished` and not yet closed.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.core.connected_peers()
    }

    /// Returns the latest Identify information received for `peer_id`.
    pub fn peer_info(&self, peer_id: &PeerId) -> Option<&IdentifyMessage> {
        self.core.peer_info(peer_id)
    }

    /// Returns whether `peer_id` has emitted `PeerReady`.
    pub fn is_peer_ready(&self, peer_id: &PeerId) -> bool {
        self.core.is_peer_ready(peer_id)
    }

    /// Returns this node's own `PeerId`.
    ///
    /// This accessor is infallible because the [`crate::SwarmBuilder`] requires
    /// a keypair at construction time.
    pub fn local_peer_id(&self) -> &PeerId {
        &self.local_peer_id
    }

    /// Registers an application protocol id for inbound acceptance and
    /// outbound opens.
    ///
    /// Built-in ids ([`crate::RESERVED_PROTOCOL_IDS`]) are rejected with
    /// [`SwarmError::ReservedProtocol`]; the swarm's own handlers already
    /// own them.
    pub fn add_protocol(&mut self, protocol_id: impl Into<String>) -> Result<(), DriverError> {
        self.core.add_protocol(protocol_id)?;
        Ok(())
    }

    /// Registers a protocol only for inbound negotiation by a composed service.
    pub fn add_inbound_protocol(
        &mut self,
        protocol_id: impl Into<String>,
    ) -> Result<(), DriverError> {
        self.core.add_inbound_protocol(protocol_id)?;
        Ok(())
    }

    /// Registers a protocol only for outbound opens by a composed service.
    pub fn add_outbound_protocol(
        &mut self,
        protocol_id: impl Into<String>,
    ) -> Result<(), DriverError> {
        self.core.add_outbound_protocol(protocol_id)?;
        Ok(())
    }

    /// Adds a protocol only to future Identify responses.
    pub fn add_advertised_protocol(
        &mut self,
        protocol_id: impl Into<String>,
    ) -> Result<(), DriverError> {
        self.core.add_advertised_protocol(protocol_id)?;
        Ok(())
    }

    /// Returns the remote transport address recorded for an exact connection.
    pub fn connection_remote_addr(&self, conn_id: ConnectionId) -> Option<&Multiaddr> {
        self.core.connection_remote_addr(conn_id)
    }

    /// Start listening on the given multiaddr and return the resolved local address.
    pub fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, DriverError> {
        Ok(self.transport.listen(addr)?)
    }

    /// Start listening on the transport's already-bound local addresses.
    ///
    /// Transports that know their bound addresses expose them via
    /// `Transport::local_addresses()`. Multi-socket transports such as a
    /// dual-stack QUIC endpoint can therefore advertise every bound address
    /// without forcing callers to pick one.
    pub fn listen_on_bound_addrs(&mut self) -> Result<Vec<PeerAddr>, DriverError> {
        let addrs = self.transport.local_addresses();
        if addrs.is_empty() {
            return Err(TransportError::InvalidConfig {
                reason: "transport does not expose a bound local address".into(),
            }
            .into());
        }

        let mut resolved = Vec::with_capacity(addrs.len());
        for addr in addrs {
            let addr = self.transport.listen(&addr)?;
            let peer_addr = PeerAddr::new(addr, self.local_peer_id.clone()).map_err(|e| {
                TransportError::InvalidConfig {
                    reason: format!("failed to build local PeerAddr: {e}"),
                }
            })?;
            resolved.push(peer_addr);
        }
        Ok(resolved)
    }

    /// Start listening on the transport's first already-bound local address.
    ///
    /// Prefer [`SwarmRuntime::listen_on_bound_addrs`] for transports that may bind
    /// more than one socket.
    pub fn listen_on_bound_addr(&mut self) -> Result<PeerAddr, DriverError> {
        let addr = self
            .transport
            .local_addresses()
            .into_iter()
            .next()
            .ok_or_else(|| TransportError::InvalidConfig {
                reason: "transport does not expose a bound local address".into(),
            })?;
        let addr = self.transport.listen(&addr)?;
        Ok(
            PeerAddr::new(addr, self.local_peer_id.clone()).map_err(|e| {
                TransportError::InvalidConfig {
                    reason: format!("failed to build local PeerAddr: {e}"),
                }
            })?,
        )
    }

    /// Dial a remote peer. The transport allocates the connection id.
    pub fn dial(&mut self, addr: &PeerAddr) -> Result<ConnectionId, DriverError> {
        Ok(self.transport.dial(addr)?)
    }

    /// Pings a peer, sending a random 32-byte payload and measuring RTT.
    ///
    /// If a ping stream isn't yet negotiated the payload is queued and
    /// fires when the stream becomes ready. The resulting RTT is delivered
    /// via [`SwarmEvent::PingRttMeasured`] on the next `poll()`.
    ///
    /// A failed entropy draw refuses the ping with [`DriverError::Entropy`].
    /// There is no fallback: a predictable nonce lets a remote pre-compute the
    /// reply, so a ping that cannot be random must not be sent at all.
    pub fn ping(&mut self, peer_id: &PeerId, now_ms: u64) -> Result<(), DriverError> {
        let mut payload = [0u8; PING_PAYLOAD_LEN];
        #[expect(
            clippy::map_err_ignore,
            reason = "DriverError intentionally keeps entropy backend failures opaque."
        )]
        self.entropy
            .fill_bytes(&mut payload)
            .map_err(|_| DriverError::Entropy)?;
        self.core.ping(peer_id, payload, now_ms)?;
        self.flush_actions(now_ms);
        Ok(())
    }

    /// Close the connection to a peer.
    pub fn disconnect(&mut self, peer_id: &PeerId, now_ms: u64) -> Result<(), DriverError> {
        self.core.disconnect(peer_id)?;
        self.flush_actions(now_ms);
        Ok(())
    }

    /// Opens a new outbound stream and negotiates `protocol_id` via
    /// multistream-select.
    ///
    /// The protocol must have been registered via
    /// [`SwarmRuntime::add_protocol`] first. When negotiation completes the
    /// [`SwarmEvent::StreamReady`] event fires with the allocated
    /// stream id; subsequent stream data arrives as
    /// [`SwarmEvent::StreamData`].
    pub fn open_stream(
        &mut self,
        peer_id: &PeerId,
        protocol_id: &str,
        now_ms: u64,
    ) -> Result<StreamId, DriverError> {
        self.open_stream_with_connection(peer_id, protocol_id, now_ms)
            .map(|(_, stream_id)| stream_id)
    }

    /// Opens an application stream and returns its full transport identity.
    pub fn open_stream_with_connection(
        &mut self,
        peer_id: &PeerId,
        protocol_id: &str,
        now_ms: u64,
    ) -> Result<(ConnectionId, StreamId), DriverError> {
        // Flush anything already queued first, so the capture window below
        // contains only this call's own action cascade. A failure from an
        // unrelated, previously queued open must surface asynchronously as
        // SwarmEvent::Error -- not as this caller's synchronous error.
        self.flush_actions(now_ms);

        // The core emits a Pending OpenStream action; we drain it now so
        // the transport.open_stream call happens synchronously and we can
        // return the allocated StreamId to the caller.
        self.core.open_stream(peer_id, protocol_id)?;
        let conn_id = self
            .core
            .connection_id(peer_id)
            .ok_or_else(|| SwarmError::NotConnected {
                peer_id: peer_id.clone(),
            })?;

        // Flush all actions, capturing the stream id allocated for this
        // user-protocol open. We inspect actions as we execute them.
        // `window_start` marks where this call's events begin in the buffer
        // so a synchronously reported failure can suppress its duplicate
        // buffered event below.
        let window_start = self.event_buffer.len();
        let mut allocated_stream: Option<StreamId> = None;
        let mut open_error: Option<TransportError> = None;
        while let Some(output) = self.core.poll_output() {
            match output {
                SwarmOutput::Action(action) => {
                    self.dispatch_action(
                        action,
                        now_ms,
                        &mut allocated_stream,
                        &mut open_error,
                        &mut None,
                    );
                }
                SwarmOutput::Event(event) => self.event_buffer.push_back(event),
            }
        }

        // Any cascade from dispatch_action (e.g. MSS header SendStream) is
        // already in the core's action queue. Drain those too.
        self.flush_actions(now_ms);

        if let Some(error) = open_error {
            // The failure is reported synchronously through Err, so drop the
            // OpenStreamFailed event this call buffered -- applications must
            // not observe the same failure twice. Failures outside a
            // synchronous call keep flowing as SwarmEvent::Error.
            if let Some(index) = (window_start..self.event_buffer.len()).find(|&i| {
                matches!(
                    self.event_buffer.get(i),
                    Some(SwarmEvent::Error(e)) if e.kind == SwarmErrorKind::OpenStreamFailed
                )
            }) {
                self.event_buffer.remove(index);
            }
            return Err(DriverError::Transport(error));
        }
        allocated_stream
            .map(|stream_id| (conn_id, stream_id))
            .ok_or(DriverError::Invariant {
                reason: "core did not allocate a stream id for open_stream",
            })
    }

    /// Sends raw bytes on a negotiated user stream.
    pub fn send_stream(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
        data: Vec<u8>,
        now_ms: u64,
    ) -> Result<(), DriverError> {
        // Flush anything already queued first, so the capture window below
        // contains only this call's own action cascade (same discipline as
        // `Swarm::open_stream`).
        self.flush_actions(now_ms);

        self.core.send_stream(peer_id, stream_id, data)?;

        // Dispatch this call's own actions synchronously, capturing a
        // transport rejection. Callers that commit state once a stream
        // closes (e.g. the pubsub one-shot sender) must learn that the
        // write was never accepted -- a buffered error event carries no
        // stream correlation to recover that from.
        let window_start = self.event_buffer.len();
        let mut send_error: Option<TransportError> = None;
        while let Some(output) = self.core.poll_output() {
            match output {
                SwarmOutput::Action(action) => {
                    self.dispatch_action(action, now_ms, &mut None, &mut None, &mut send_error);
                }
                SwarmOutput::Event(event) => self.event_buffer.push_back(event),
            }
        }
        self.flush_actions(now_ms);

        if let Some(error) = send_error {
            // Reported synchronously through Err: drop the duplicate
            // buffered runtime-error event this call produced.
            if let Some(index) = (window_start..self.event_buffer.len()).find(|&i| {
                matches!(
                    self.event_buffer.get(i),
                    Some(SwarmEvent::Error(e)) if e.kind == SwarmErrorKind::Transport
                )
            }) {
                self.event_buffer.remove(index);
            }
            return Err(DriverError::Transport(error));
        }
        Ok(())
    }

    /// Half-closes the write side of a user stream.
    pub fn close_stream_write(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
        now_ms: u64,
    ) -> Result<(), DriverError> {
        self.core.close_stream_write(peer_id, stream_id)?;
        self.flush_actions(now_ms);
        Ok(())
    }

    /// Resets (abruptly closes) a user stream.
    pub fn reset_stream(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
        now_ms: u64,
    ) -> Result<(), DriverError> {
        self.core.reset_stream(peer_id, stream_id)?;
        self.flush_actions(now_ms);
        Ok(())
    }

    /// Forgets swarm bookkeeping for a stream without touching the transport.
    ///
    /// This is used when ownership of a negotiated stream moves to another
    /// protocol layer. Already-buffered events are intentionally preserved.
    pub fn forget_stream(&mut self, conn_id: ConnectionId, stream_id: StreamId) {
        self.core.forget_stream(conn_id, stream_id);
    }

    /// Resets and forgets a stream whose consumer will never read it again.
    ///
    /// This is idempotent with a previously queued reset and removes matching
    /// events already buffered by both the Sans-I/O core and this driver.
    pub fn abandon_stream(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
        now_ms: u64,
    ) -> Result<(), DriverError> {
        let result = self.core.abandon_stream(peer_id, stream_id);
        self.event_buffer
            .retain(|event| !event.matches_stream(peer_id, stream_id));
        result?;
        self.flush_actions(now_ms);
        Ok(())
    }

    /// Drive the swarm: poll transport, feed events to core, dispatch
    /// actions, return application-visible events. Must be called repeatedly.
    ///
    /// Std event-loop code can instead use `Swarm::poll_next` or
    /// `Swarm::run_until`, which call this in a sleep/poll loop and return one
    /// event at a time.
    pub fn poll(&mut self, now: Now) -> Result<Vec<SwarmEvent>, DriverError> {
        let now_ms = now.monotonic_ms;

        // Actions deferred by the previous poll are now safe to dispatch if
        // every event that preceded them has been returned to the caller.
        // Do this before reading more transport input so superseded
        // connections cannot produce another batch ahead of their close.
        self.flush_actions(now_ms);

        // 0. Refresh the core's snapshot of our listening addresses so
        //    Identify advertises the current bound set plus any validated
        //    external addresses. Cheap -- a handful of multiaddrs at most.
        let mut local_addresses = self.transport.local_addresses();
        for addr in &self.external_addresses {
            if !local_addresses.contains(addr) {
                local_addresses.push(addr.clone());
            }
        }
        self.core.set_local_addresses(local_addresses);

        // 1. Feed transport events to the core.
        let events = self.transport.poll(now)?;
        for event in events {
            self.core
                .handle_input(SwarmInput::Transport { event, now_ms });
            // Preserve the core driver's event/action boundary within a
            // transport batch. A later event must not observe core state that
            // assumes an earlier event's transport actions have already run.
            self.flush_actions(now_ms);
        }

        // 2. Advance timers.
        self.core.handle_input(SwarmInput::Tick { now_ms });

        // 3. Execute all queued actions (may cascade -- see flush_actions).
        self.flush_actions(now_ms);

        // 4. Return the application's events. `flush_actions` fully drained
        //    the core; any action ordered after these events is held in the
        //    driver's `after_event_actions` queue until a later call.
        Ok(self.event_buffer.drain(..).collect())
    }

    /// Returns when this runtime next needs polling, if it has a timer.
    ///
    /// Folds the transport's deadline together with the core's protocol
    /// timers, both on the timeline of the samples passed to
    /// [`poll`](Self::poll). Hosts idle until this deadline rather than
    /// polling on a fixed cadence.
    pub fn next_deadline(&self, now: Now) -> Option<Deadline> {
        // Work already queued needs another drive iteration whatever the
        // timers say. `poll` defers actions ordered after an event until the
        // application has seen that event, so a supersession's
        // `CloseConnection` can be sitting here with no timer to wake it.
        if !self.after_event_actions.is_empty() || !self.event_buffer.is_empty() {
            return Some(Deadline::IMMEDIATE);
        }

        fold_deadlines(
            now,
            self.transport.next_deadline(),
            self.core.next_timeout(now.monotonic_ms),
        )
    }
}

impl<T: Transport, E: EntropySource> SwarmRuntime<T, E> {
    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    /// Drains all actions from the core and dispatches each to the
    /// transport, repeating until the core has nothing left. This handles
    /// cascades where executing an action causes the core to emit more
    /// (e.g. `OpenStream` leading to `SendStream` once the stream id is
    /// reported back).
    ///
    /// `now_ms` is the caller's time sample, threaded through so a single
    /// drive iteration reports one instant to the core no matter how many
    /// actions cascade.
    fn flush_actions(&mut self, now_ms: u64) {
        let mut allocated: Option<StreamId> = None;

        // A buffered event has not yet been delivered by `poll_next`, so its
        // dependent actions must remain deferred. `poll()` drains this buffer
        // into its return value; the next driver call may then dispatch them.
        if self.event_buffer.is_empty() {
            while let Some(action) = self.after_event_actions.pop_front() {
                self.dispatch_action(action, now_ms, &mut allocated, &mut None, &mut None);
            }
        }

        // Only events drained in this pass gate the actions that follow them.
        // Pre-existing buffered events may be unrelated (for example, a
        // failed reset's error before a synchronous retry), so they must not
        // defer new caller-initiated work.
        let mut saw_event = false;
        while let Some(output) = self.core.poll_output() {
            match output {
                SwarmOutput::Action(action) if saw_event => {
                    self.after_event_actions.push_back(action);
                }
                SwarmOutput::Action(action) => {
                    self.dispatch_action(action, now_ms, &mut allocated, &mut None, &mut None)
                }
                SwarmOutput::Event(event) => {
                    saw_event = true;
                    self.event_buffer.push_back(event);
                }
            }
        }
    }

    /// Executes a single action against the transport and feeds any result
    /// back into the core.
    ///
    /// `captured_stream_id` is used by [`SwarmRuntime::open_stream`] to
    /// synchronously recover the stream id for the caller. The driver
    /// remembers the **last** stream id allocated during the flush, which
    /// is accurate because `open_stream` triggers exactly one
    /// `OpenStream` action per call.
    fn dispatch_action(
        &mut self,
        action: SwarmAction,
        now_ms: u64,
        captured_stream_id: &mut Option<StreamId>,
        captured_open_error: &mut Option<TransportError>,
        captured_send_error: &mut Option<TransportError>,
    ) {
        match action {
            SwarmAction::OpenStream { conn_id, token } => match self.transport.open_stream(conn_id)
            {
                Ok(stream_id) => {
                    *captured_stream_id = Some(stream_id);
                    self.core.handle_input(SwarmInput::StreamOpened {
                        conn_id,
                        stream_id,
                        token,
                        now_ms,
                    });
                }
                Err(e) => {
                    let reason = format!("{e}");
                    *captured_open_error = Some(e);
                    self.core.handle_input(SwarmInput::OpenStreamFailed {
                        token,
                        reason,
                        now_ms,
                    });
                }
            },
            SwarmAction::SendStream {
                conn_id,
                stream_id,
                data,
            } => {
                if let Err(e) = self.transport.send_stream(conn_id, stream_id, data) {
                    let reason = format!(
                        "send_stream to connection {conn_id} stream {stream_id} failed: {e}"
                    );
                    *captured_send_error = Some(e);
                    self.core
                        .handle_input(SwarmInput::RuntimeError(runtime_error(
                            SwarmErrorKind::Transport,
                            Some(conn_id),
                            Some(stream_id),
                            reason,
                        )));
                }
            }
            SwarmAction::CloseStreamWrite { conn_id, stream_id } => {
                if let Err(e) = self.transport.close_stream_write(conn_id, stream_id) {
                    self.core.handle_input(SwarmInput::RuntimeError(runtime_error(
                        SwarmErrorKind::Transport,
                        Some(conn_id),
                        Some(stream_id),
                        format!(
                            "close_stream_write on connection {conn_id} stream {stream_id} failed: {e}"
                        ),
                    )));
                }
            }
            SwarmAction::ResetStream { conn_id, stream_id } => {
                if let Err(e) = self.transport.reset_stream(conn_id, stream_id) {
                    self.core.reset_stream_failed(conn_id, stream_id);
                    self.core.handle_input(SwarmInput::RuntimeError(runtime_error(
                        SwarmErrorKind::Transport,
                        Some(conn_id),
                        Some(stream_id),
                        format!(
                            "reset_stream on connection {conn_id} stream {stream_id} failed: {e}"
                        ),
                    )));
                }
            }
            SwarmAction::CloseConnection { conn_id } => match self.transport.close(conn_id) {
                Ok(()) | Err(TransportError::ConnectionNotFound { .. }) => {}
                Err(e) => {
                    self.core
                        .handle_input(SwarmInput::RuntimeError(runtime_error(
                            SwarmErrorKind::Transport,
                            Some(conn_id),
                            None,
                            format!("close on connection {conn_id} failed: {e}"),
                        )));
                }
            },
        }
    }
}

fn runtime_error(
    kind: SwarmErrorKind,
    conn_id: Option<ConnectionId>,
    stream_id: Option<StreamId>,
    detail: String,
) -> SwarmRuntimeError {
    SwarmRuntimeError {
        kind,
        peer_id: None,
        conn_id,
        stream_id,
        detail,
    }
}

/// Folds a transport deadline together with the core's next protocol timer.
///
/// [`SwarmCore::next_timeout`] reports milliseconds *remaining*, while
/// [`Deadline`] is an absolute point on the host's timeline, so the core's
/// value has to be anchored to `now` rather than used directly. Getting that
/// wrong makes timers read as long expired once uptime exceeds the timeout,
/// which busy-spins a blocking driver and can hang a host that sleeps for
/// `millis_until`.
///
/// Split out so the unit conversion is testable without arming a real timer.
fn fold_deadlines(
    now: Now,
    transport: Option<Deadline>,
    core_remaining_ms: Option<u64>,
) -> Option<Deadline> {
    let core = core_remaining_ms.map(|remaining| now.deadline_after(remaining));
    Deadline::earliest_opt(transport, core)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::string::ToString;
    use alloc::vec;

    use minip2p_core::SansIoProtocol;
    use minip2p_identify::IDENTIFY_PROTOCOL_ID;
    use minip2p_identity::Ed25519Keypair;
    use minip2p_multistream_select::{MultistreamInput, MultistreamOutput, MultistreamSelect};
    use minip2p_ping::PING_PROTOCOL_ID;
    use minip2p_platform::EntropyError;
    use minip2p_transport::{ConnectionEndpoint, TransportEvent};

    /// Counter-based entropy: no OS, no `getrandom`, fully deterministic.
    struct SeqEntropy(u8);

    impl EntropySource for SeqEntropy {
        fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), minip2p_platform::EntropyError> {
            for byte in output.iter_mut() {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    /// Entropy source with nothing to give -- an embedded target with no RNG,
    /// or a hardware RNG that failed its health check.
    struct BrokenEntropy;

    impl EntropySource for BrokenEntropy {
        fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
            // Partially written and then failed: per the `EntropySource`
            // contract the buffer holds no entropy, so this is exactly the
            // payload a driver that ignored the error would put on the wire.
            output.fill(0);
            Err(EntropyError::unavailable("no RNG in this test"))
        }
    }

    /// Transport that replays a scripted batch and records opened streams.
    #[derive(Default)]
    struct ScriptedTransport {
        initial: Vec<TransportEvent>,
        next_stream_id: u64,
        opened: usize,
        deadline: Option<Deadline>,
        /// When set, every locally opened stream gets a multistream-select
        /// listener that answers the dialer, so identify and ping streams
        /// actually reach the negotiated state and carry payloads.
        negotiate: bool,
        /// Listeners for streams still negotiating, keyed by stream id.
        negotiators: BTreeMap<StreamId, MultistreamSelect>,
        /// Protocol frames written after negotiation completed. This is the
        /// wire as the remote peer would see it.
        sent: Vec<(StreamId, Vec<u8>)>,
        close_count: usize,
        /// Second `close` returns `ConnectionNotFound` (TCP after map removal).
        fail_second_close: bool,
    }

    impl ScriptedTransport {
        /// Frames the size of a ping payload that reached the wire.
        fn ping_frames(&self) -> Vec<&[u8]> {
            self.sent
                .iter()
                .map(|(_, data)| data.as_slice())
                .filter(|data| data.len() == PING_PAYLOAD_LEN)
                .collect()
        }
    }

    impl Transport for ScriptedTransport {
        fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
            Err(TransportError::Unsupported { operation: "dial" })
        }

        fn listen(&mut self, _: &Multiaddr) -> Result<Multiaddr, TransportError> {
            Err(TransportError::Unsupported {
                operation: "listen",
            })
        }

        fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
            self.next_stream_id += 1;
            self.opened += 1;
            let stream_id = StreamId::new(self.next_stream_id);
            if self.negotiate {
                let mut listener = MultistreamSelect::listener(vec![
                    IDENTIFY_PROTOCOL_ID.to_string(),
                    PING_PROTOCOL_ID.to_string(),
                ]);
                listener
                    .handle_input(MultistreamInput::Start)
                    .map_err(|error| TransportError::PollError {
                        reason: alloc::format!("listener start failed: {error}"),
                    })?;
                self.negotiators.insert(stream_id, listener);
            }
            Ok(stream_id)
        }

        fn send_stream(
            &mut self,
            id: ConnectionId,
            stream_id: StreamId,
            data: Vec<u8>,
        ) -> Result<(), TransportError> {
            let Some(negotiator) = self.negotiators.get_mut(&stream_id) else {
                // Negotiation is done (or was never scripted): this is
                // protocol payload, which is what tests assert on.
                self.sent.push((stream_id, data));
                return Ok(());
            };

            negotiator
                .handle_input(MultistreamInput::Data(data))
                .map_err(|error| TransportError::PollError {
                    reason: alloc::format!("listener negotiation input failed: {error}"),
                })?;
            let mut negotiated = false;
            let mut outbound = Vec::new();
            while let Some(output) = negotiator.poll_output() {
                match output {
                    MultistreamOutput::OutboundData(bytes) => outbound.push(bytes),
                    MultistreamOutput::Negotiated { .. } => negotiated = true,
                    other => {
                        return Err(TransportError::PollError {
                            reason: alloc::format!("unexpected multistream output: {other:?}"),
                        });
                    }
                }
            }
            if negotiated {
                self.negotiators.remove(&stream_id);
            }
            // The dialer only learns the protocol was accepted on its next
            // poll, so hand the answer back as inbound stream data.
            for data in outbound {
                self.initial.push(TransportEvent::StreamData {
                    id,
                    stream_id,
                    data,
                });
            }
            Ok(())
        }

        fn close_stream_write(
            &mut self,
            _: ConnectionId,
            _: StreamId,
        ) -> Result<(), TransportError> {
            Ok(())
        }

        fn reset_stream(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
            Ok(())
        }

        fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
            self.close_count += 1;
            if self.fail_second_close && self.close_count > 1 {
                return Err(TransportError::ConnectionNotFound { id });
            }
            Ok(())
        }

        fn poll(&mut self, _now: Now) -> Result<Vec<TransportEvent>, TransportError> {
            Ok(core::mem::take(&mut self.initial))
        }

        fn next_deadline(&self) -> Option<Deadline> {
            self.deadline
        }
    }

    fn runtime(initial: Vec<TransportEvent>) -> SwarmRuntime<ScriptedTransport, SeqEntropy> {
        runtime_with(
            ScriptedTransport {
                initial,
                ..ScriptedTransport::default()
            },
            SeqEntropy(1),
        )
    }

    /// Same runtime, with the transport and entropy source chosen by the test.
    fn runtime_with<E: EntropySource>(
        transport: ScriptedTransport,
        entropy: E,
    ) -> SwarmRuntime<ScriptedTransport, E> {
        let keypair = Ed25519Keypair::generate();
        let identify = IdentifyConfig {
            protocol_version: "test/1".into(),
            agent_version: "test/1".into(),
            protocols: Vec::new(),
            public_key: keypair.public_key().encode_protobuf(),
        };
        SwarmRuntime::new(
            transport,
            identify,
            PingConfig::default(),
            keypair.peer_id(),
            entropy,
        )
    }

    /// A transport already holding a connection to `peer`, whose
    /// multistream-select listener answers so protocol streams negotiate.
    fn negotiating_transport(peer: &PeerId) -> ScriptedTransport {
        ScriptedTransport {
            initial: vec![TransportEvent::Connected {
                id: ConnectionId::new(1),
                endpoint: ConnectionEndpoint::with_peer_id(
                    "/ip4/198.51.100.7/udp/4001/quic-v1"
                        .parse()
                        .expect("endpoint"),
                    peer.clone(),
                ),
            }],
            negotiate: true,
            ..ScriptedTransport::default()
        }
    }

    /// Drives the runtime far enough for a queued ping to finish negotiating
    /// its stream and reach the transport.
    fn settle<E: EntropySource>(runtime: &mut SwarmRuntime<ScriptedTransport, E>, from_ms: u64) {
        for step in 0..8 {
            runtime
                .poll(Now::from_millis(from_ms + step))
                .expect("poll");
        }
    }

    /// The whole point of the extraction: this drives a connection open and
    /// close with no clock, no OS entropy, and no `std` wrapper -- the same
    /// path an embedded host takes.
    #[test]
    fn runtime_drives_without_a_clock_or_os_entropy() {
        let peer = Ed25519Keypair::generate().peer_id();
        let mut runtime = runtime(vec![TransportEvent::Connected {
            id: ConnectionId::new(1),
            endpoint: ConnectionEndpoint::with_peer_id(
                "/ip4/198.51.100.7/udp/4001/quic-v1"
                    .parse()
                    .expect("endpoint"),
                peer.clone(),
            ),
        }]);

        let events = runtime.poll(Now::from_millis(5_000)).expect("poll");
        assert!(
            events.iter().any(|event| matches!(
                event,
                SwarmEvent::ConnectionEstablished { peer_id, .. } if *peer_id == peer
            )),
            "expected the connection to surface: {events:?}"
        );
        // Identify started, so an action really was dispatched to the
        // transport during that poll.
        assert!(runtime.transport().opened > 0);
        assert!(runtime.connected_peers().contains(&peer));
        assert!(runtime.core().is_idle(), "core must settle after the open");

        // ...and the close half of the lifecycle, on the same timeline.
        runtime.transport_mut().initial = vec![TransportEvent::Closed {
            id: ConnectionId::new(1),
        }];
        let events = runtime.poll(Now::from_millis(6_000)).expect("poll");
        assert!(
            events.iter().any(|event| matches!(
                event,
                SwarmEvent::ConnectionClosed { peer_id, .. } if *peer_id == peer
            )),
            "expected the close to surface: {events:?}"
        );
        assert!(runtime.connected_peers().is_empty());
    }

    #[test]
    fn actions_from_one_batched_event_run_before_the_next_event() {
        let peer = Ed25519Keypair::generate().peer_id();
        let id = ConnectionId::new(1);
        let mut runtime = runtime(vec![
            TransportEvent::Connected {
                id,
                endpoint: ConnectionEndpoint::with_peer_id(
                    "/ip4/198.51.100.7/udp/4001/quic-v1"
                        .parse()
                        .expect("endpoint"),
                    peer,
                ),
            },
            TransportEvent::Closed { id },
        ]);

        runtime.poll(Now::from_millis(5_000)).expect("poll");
        assert!(
            runtime.transport().opened > 0,
            "the Connected event's protocol opens must run before Closed mutates core state"
        );
    }

    #[test]
    fn core_timers_are_anchored_to_now_not_used_as_absolute() {
        // `SwarmCore::next_timeout` reports remaining milliseconds. Using it
        // as an absolute deadline reads as long expired once uptime exceeds
        // the timeout, so pin the conversion at a realistic uptime where the
        // two interpretations differ wildly.
        let now = Now::from_millis(3_600_000);

        assert_eq!(
            fold_deadlines(now, None, Some(500)),
            Some(Deadline::from_millis(3_600_500)),
            "core timers must be anchored to now"
        );
        assert_eq!(
            fold_deadlines(now, None, Some(500))
                .expect("armed")
                .millis_until(now),
            500,
            "a timer 500ms out must not read as already due"
        );

        // A past-due core timer reports zero remaining, which really is due.
        assert_eq!(fold_deadlines(now, None, Some(0)), Some(now.as_deadline()));
    }

    #[test]
    fn next_deadline_folds_transport_and_core_timers() {
        let now = Now::from_millis(1_000);
        let transport = Deadline::from_millis(1_400);

        // Whichever needs attention first wins.
        assert_eq!(fold_deadlines(now, Some(transport), None), Some(transport));
        assert_eq!(
            fold_deadlines(now, Some(transport), Some(100)),
            Some(Deadline::from_millis(1_100)),
            "the nearer core timer must win"
        );
        assert_eq!(
            fold_deadlines(now, Some(transport), Some(900)),
            Some(transport),
            "the nearer transport timer must win"
        );
        assert_eq!(fold_deadlines(now, None, None), None);

        // And the runtime reports its transport's deadline through the fold.
        let mut runtime = runtime(Vec::new());
        runtime.poll(now).expect("poll");
        assert_eq!(runtime.next_deadline(now), None);
        runtime.transport_mut().deadline = Some(transport);
        assert_eq!(runtime.next_deadline(now), Some(transport));
    }

    #[test]
    fn queued_work_is_reported_as_immediately_due() {
        let now = Now::from_millis(1_000);
        let mut runtime = runtime(Vec::new());
        runtime.poll(now).expect("poll");
        assert_eq!(runtime.next_deadline(now), None);

        // A deferred action has no timer of its own; without this a host
        // would idle until unrelated I/O happened to wake it.
        runtime
            .after_event_actions
            .push_back(SwarmAction::CloseConnection {
                conn_id: ConnectionId::new(1),
            });
        assert_eq!(runtime.next_deadline(now), Some(Deadline::IMMEDIATE));

        runtime.after_event_actions.clear();
        runtime
            .event_buffer
            .push_back(SwarmEvent::ConnectionClosed {
                peer_id: Ed25519Keypair::generate().peer_id(),
                conn_id: ConnectionId::new(1),
                cause: crate::ConnectionCloseCause::Transport,
            });
        assert_eq!(runtime.next_deadline(now), Some(Deadline::IMMEDIATE));
    }

    #[test]
    fn ping_draws_from_the_injected_entropy_source() {
        let peer = Ed25519Keypair::generate().peer_id();
        let mut runtime = runtime(vec![TransportEvent::Connected {
            id: ConnectionId::new(1),
            endpoint: ConnectionEndpoint::with_peer_id(
                "/ip4/198.51.100.7/udp/4001/quic-v1"
                    .parse()
                    .expect("endpoint"),
                peer.clone(),
            ),
        }]);
        runtime.poll(Now::from_millis(0)).expect("poll");

        let before = runtime.entropy.0;
        // Reaches the core rather than failing for want of an OS RNG.
        runtime.ping(&peer, 1_000).expect("ping queues");

        // The nonce came from the injected source, not `getrandom`: the
        // counter advanced by exactly one payload.
        assert_eq!(
            runtime.entropy.0,
            before.wrapping_add(PING_PAYLOAD_LEN as u8),
            "ping must consume PING_PAYLOAD_LEN bytes of injected entropy"
        );
    }

    /// A ping nonce that an attacker can predict lets them pre-compute the
    /// reply, so a failed draw must refuse the ping outright -- never fall
    /// back to whatever the buffer happened to contain.
    #[test]
    fn ping_is_refused_when_the_entropy_source_fails() {
        let peer = Ed25519Keypair::generate().peer_id();
        let mut runtime = runtime_with(negotiating_transport(&peer), BrokenEntropy);
        runtime.poll(Now::from_millis(0)).expect("poll");
        assert!(
            runtime.connected_peers().contains(&peer),
            "the peer must be connected, so the ping fails for entropy alone"
        );

        let error = runtime
            .ping(&peer, 1_000)
            .expect_err("a ping must not be sent with a payload the RNG never produced");
        assert!(
            matches!(error, DriverError::Entropy),
            "expected DriverError::Entropy, got {error:?}"
        );

        // And nothing weak escaped: driving the runtime on cannot flush a
        // payload the caller was told was never generated.
        settle(&mut runtime, 2_000);
        assert!(
            runtime.transport().ping_frames().is_empty(),
            "no ping payload may reach the wire: {:?}",
            runtime.transport().ping_frames()
        );
    }

    /// The positive direction, observed on the wire rather than through the
    /// helper: the bytes the source produced are the bytes that get sent.
    #[test]
    fn ping_sends_the_payload_the_entropy_source_produced() {
        let peer = Ed25519Keypair::generate().peer_id();
        let mut runtime = runtime_with(negotiating_transport(&peer), SeqEntropy(0xA0));
        runtime.poll(Now::from_millis(0)).expect("poll");

        runtime.ping(&peer, 1_000).expect("ping queues");
        settle(&mut runtime, 2_000);

        // SeqEntropy(0xA0) hands out 0xA0, 0xA1, ... one byte at a time.
        let expected: [u8; PING_PAYLOAD_LEN] =
            core::array::from_fn(|i| 0xA0u8.wrapping_add(i as u8));
        assert_eq!(
            runtime.transport().ping_frames(),
            vec![expected.as_slice()],
            "the ping payload on the wire must be exactly the drawn bytes"
        );
    }

    #[test]
    fn a_second_close_of_the_same_connection_is_not_a_runtime_error() {
        let peer = Ed25519Keypair::generate().peer_id();
        let conn = ConnectionId::new(1);
        let address = "/ip4/198.51.100.7/udp/4001/quic-v1"
            .parse()
            .expect("endpoint");
        let mut runtime = runtime_with(
            ScriptedTransport {
                initial: vec![TransportEvent::Connected {
                    id: conn,
                    endpoint: ConnectionEndpoint::with_peer_id(address, peer.clone()),
                }],
                fail_second_close: true,
                ..ScriptedTransport::default()
            },
            SeqEntropy(1),
        );
        runtime.poll(Now::from_millis(0)).expect("connect");
        runtime.disconnect(&peer, 1).expect("first close");
        runtime.disconnect(&peer, 2).expect("second close");
        let events = runtime.poll(Now::from_millis(3)).expect("poll");
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, SwarmEvent::Error(_))),
            "already-gone close must not surface as Error: {events:?}"
        );
    }
}
