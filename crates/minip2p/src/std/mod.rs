//! Application-facing `Endpoint` API for minip2p.
//!
//! This is the ergonomic std entrypoint. It composes the lower-level crates
//! without hiding them: protocol crates and `SwarmCore` remain the Sans-I/O /
//! `no_std + alloc` surface, while [`Endpoint`] gives applications a small
//! batteries-included API for identity, transports, listen/dial, ping, and
//! event polling. It is [`Endpoint`] on the [`StdPlatform`]: the same
//! endpoint, engine and methods as the portable one, plus what only an
//! operating system has: a clock, socket binding, Name resolution, and a
//! blocking [`Endpoint::wait`] (ADR 0029).
//!
//! # Transports
//!
//! Prefer address-shaped listening: pass complete multiaddresses to
//! [`EndpointBuilder::listen_on`] (or [`EndpointBuilder::listen_default`] for
//! dual-stack QUIC) and call [`EndpointBuilder::bind`]. The builder infers
//! QUIC vs TCP from each address and groups compatible IPv4/IPv6 listeners
//! onto one transport per shape.
//!
//! Dial routing is address-shaped too: a `/udp/…/quic-v1` candidate is
//! reached over QUIC and a `/tcp` one over TCP.
//!
//! With the `pubsub` feature, `EndpointBuilder::gossipsub` enables gossipsub
//! and `EndpointBuilder::gossipsub_config` tunes it with a `GossipsubConfig`.
//!
//! The `autonat` feature exposes AutoNAT probing, and `relay` (which
//! includes `autonat`) adds relay paths, reservations, and, with QUIC,
//! DCUtR coordination. The `discovery` feature includes `pubsub`, adding
//! signed presence beacons plus a bounded peer book. The `mdns` feature adds
//! caller-driven local-link multicast discovery over the same book. Enable
//! both discovery sources to feed one shared peer book and automatic-dial
//! state; with `autonat` or `relay` built too, discovered peers are dialed
//! through the NAT connect race. Cargo features expose these APIs; the
//! corresponding builder methods activate their drivers.
//!
//! The `relay-server` feature enables the three-line
//! `Endpoint::builder().relay_server().listen_on(…)?.bind()` hosting path.
//!
//! Capabilities are validated, registered and installed by the same
//! Endpoint setup as the portable endpoint's; this module adds only OS
//! resources around it: the clock, the readiness poll, the mDNS sockets,
//! Name resolution, and WebTransport certificates. A capability's protocols
//! are advertised through Identify only when its configuration uses them:
//! relay-only endpoints advertise inbound HOP, a relay client advertises

mod bind_error;
mod builder;
mod dial;
mod errors;
#[cfg(all(test, feature = "relay", feature = "quic"))]
mod nat_tests;
#[cfg(all(test, feature = "relay", feature = "quic"))]
mod punch_batch_tests;
#[cfg(all(test, feature = "quic"))]
mod tests;

pub use bind_error::{BindError, EndpointOptionsError, IpFamily};
pub use builder::EndpointBuilder;
#[cfg(feature = "relay-server")]
use builder::check_webtransport_announce;
#[cfg(feature = "quic")]
use builder::parse_certificate_pem;
#[cfg(feature = "relay-server")]
pub use errors::RelayServerAnnounceError;
#[cfg(feature = "quic")]
pub use errors::SetWebTransportCertificateError;

use std::time::Duration;

#[cfg(feature = "relay-server")]
use crate::RelayServerControlError;
use crate::endpoint::{CloseOutcome, CloseReport};
use crate::names::Expander;
use crate::platform::sealed::Sealed;
use crate::setup::PlatformCaps;
use crate::{Endpoint, EndpointEvent, Platform};
#[cfg(feature = "relay-server")]
use minip2p_core::Multiaddr;
use minip2p_core::PeerAddr;
use minip2p_core::platform::{Clock, Now, StdClock, StdEntropy};
pub use minip2p_identity::Ed25519Keypair;
#[cfg(feature = "quic")]
pub use minip2p_quic::{CongestionController, QuicBindError, QuicLimits};
pub use minip2p_swarm::{
    DriverError as Error, PollNext, RESERVED_PROTOCOL_IDS, Swarm, SwarmError, WaitDeadline,
};
use minip2p_transport::SharedPoll;
pub use minip2p_transport::{TransportError, TransportSet, WaitHandle};

/// Cap on one readiness wait when the caller has no deadline; re-arming it
/// occasionally keeps unbounded durations out of OS interfaces.
const MAX_IDLE_WAIT: Duration = Duration::from_secs(60);

/// Why one blocking [`Endpoint::wait`] returned.
///
/// Deadline and interruption are control outcomes, not additional event
/// sources. Enabled capabilities deliver their output as [`EndpointEvent`]
/// variants inside [`Self::Event`](EndpointWaitOutcome::Event).
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "EndpointEvent ownership avoids a heap allocation on the ready path."
)]
#[must_use = "handle the wait outcome; an EndpointEvent has been removed from the endpoint"]
// Non-exhaustive, so a later outcome is not a breaking change: match
// `Event` and `Deadline`, and treat the rest (today, `Interrupted`) with `_`.
#[non_exhaustive]
pub enum EndpointWaitOutcome {
    /// An application event from the Endpoint event stream.
    ///
    /// The event has been removed from the endpoint and belongs to the caller.
    Event(EndpointEvent),
    /// The caller's deadline elapsed without an application event.
    Deadline,
    /// The transport wait was interrupted by an external wait handle.
    Interrupted,
}

pub(crate) const DEFAULT_AGENT_VERSION: &str = concat!("minip2p/", env!("CARGO_PKG_VERSION"));

/// Transport used by [`Endpoint`]. With relays built, relay bridges are
/// promoted into ordinary Noise/Yamux connections by `CircuitTransport`.
///
/// The endpoint always holds a [`TransportSet`], even with one member in it:
/// what an address is dialed over is then a routing decision the set makes
/// from the address itself, and adding a second transport changes nothing
/// above this line.
#[cfg(feature = "relay")]
pub(crate) type EndpointTransport =
    minip2p_circuit::CircuitTransport<TransportSet, minip2p_core::platform::StdEntropy>;

/// Transport used by [`Endpoint`] when relays are not compiled in.
#[cfg(not(feature = "relay"))]
pub(crate) type EndpointTransport = TransportSet;

/// The std endpoint's mDNS carrier: OS multicast sockets, which are `Send`
/// (the ffi-core detached driver needs that).
#[cfg(feature = "mdns")]
pub(crate) type StdCarrier = minip2p_mdns::MdnsSockets;
#[cfg(not(feature = "mdns"))]
pub(crate) type StdCarrier = ();

/// What the std endpoint offers its capabilities: DCUtR with QUIC, circuit
/// operations whenever relays are built (the transport set is wrapped in a
/// `CircuitTransport`), and OS mDNS sockets apart from the transport.
pub(crate) const STD_PLATFORM: PlatformCaps = PlatformCaps {
    runs_dcutr: cfg!(feature = "quic"),
    has_circuits: cfg!(feature = "relay"),
    mdns_shares_transport: false,
};

/// How long [`Endpoint::close`] waits for connections to finish their
/// teardown. Bindings default their stop and close drains to it too.
pub const DEFAULT_CLOSE_TIMEOUT: Duration = Duration::from_millis(500);

/// The std platform, and the default `P` of [`Endpoint`]: the transports
/// [`EndpointBuilder::bind`] bound (QUIC, TCP, or both, behind one
/// [`TransportSet`]), the OS clock and entropy, Name resolution off the
/// driver thread, and the one readiness poll the blocking
/// [`Endpoint::wait`] sleeps on.
///
/// Nothing constructs it but [`EndpointBuilder::bind`].
pub struct StdPlatform {
    clock: StdClock,
    /// Name resolution for `/dns*` candidates and NAT dials, off the driver
    /// thread; the engine routes its answers.
    resolver: dial::Resolver,
    /// Whether WebTransport presents a CA-signed certificate, which decides
    /// whether a WebTransport announce address must carry a `/certhash`.
    #[cfg(feature = "relay-server")]
    ca_webtransport_certificate: bool,
    /// Replaces the CA-signed WebTransport certificate; `None` unless one
    /// was configured and a WebTransport listener serves it.
    #[cfg(feature = "quic")]
    webtransport_certificate: Option<minip2p_quic::WebTransportCertificateHandle>,
    /// The one readiness poll the transport and mDNS sockets are registered
    /// with (ADR 0013). Its `Waker` carries caller interrupts and the
    /// endpoint's own wakeups (a finished name lookup) apart.
    poll: SharedPoll,
    /// Swarm events a test's raw poll read but has not handed out yet.
    #[cfg(all(test, feature = "quic"))]
    raw_events: std::collections::VecDeque<crate::SwarmEvent>,
}

impl Sealed for StdPlatform {
    type Transport = EndpointTransport;
    type Entropy = StdEntropy;
    type Carrier = StdCarrier;

    fn now(&mut self) -> Now {
        self.clock.now()
    }

    fn names(&mut self) -> &mut dyn Expander {
        &mut self.resolver
    }

    /// Collects readiness without blocking: every drive path harvests
    /// first, since an edge-triggered transport reads only what was
    /// dispatched.
    fn harvest(&mut self, transport: &mut EndpointTransport) -> Result<(), Error> {
        harvest(&mut self.poll, transport, Duration::ZERO)
    }

    /// [`close_within`](Endpoint::close_within) with
    /// [`DEFAULT_CLOSE_TIMEOUT`] (500 ms).
    fn close(endpoint: Endpoint) -> CloseReport {
        endpoint.close_within(DEFAULT_CLOSE_TIMEOUT)
    }
}

impl Platform for StdPlatform {}

/// Collects one bounded batch of readiness, blocking up to `timeout`, and
/// dispatches the transport's share.
fn harvest(
    poll: &mut SharedPoll,
    transport: &mut EndpointTransport,
    timeout: Duration,
) -> Result<(), Error> {
    poll.harvest(transport, timeout)
        .map(drop)
        .map_err(|error| TransportError::io("waiting for readiness", &error).into())
}

// The ffi-core detached driver moves the endpoint onto its own thread.
const _: () = {
    const fn assert_send<T: Send>() {}
    assert_send::<Endpoint>();
};

/// What only the std platform has: binding, the blocking wait and its
/// interrupt handle, a draining close, and the OS-held WebTransport and
/// relay-mesh resources.
///
/// QUIC, TCP, or both, chosen by the addresses passed to
/// [`EndpointBuilder::listen_on`]. They live behind one [`TransportSet`],
/// which routes each address to the transport that serves its shape, so
/// nothing here or above changes with the second one:
/// [`connect`](Endpoint::connect) takes the same complete peer addresses,
/// [`listen`](Endpoint::listen) arms every bound address, and the events
/// are the same events.
///
/// With the `relay` cargo feature and a relay configuration
/// (`EndpointBuilder::relay` / `EndpointBuilder::nat_config`), `connect`
/// races direct candidates against a relay leg. Path transitions arrive as
/// `EndpointEvent::Nat`; the attempt's outcome is its
/// [`EndpointEvent::ConnectSettled`].
impl Endpoint {
    /// Starts building an endpoint.
    pub fn builder() -> EndpointBuilder {
        EndpointBuilder::default()
    }

    /// Returns a cloneable handle that can interrupt a blocking endpoint wait
    /// from another thread.
    ///
    /// The interrupt handle of the one readiness poll every transport and
    /// mDNS socket is registered with. Its interrupts surface as
    /// [`EndpointWaitOutcome::Interrupted`]; interrupts sent before one is
    /// reported coalesce into one. The endpoint's own wakeups (a finished
    /// name lookup, mDNS input) use the poll's wake-only handle and never do.
    pub fn wait_handle(&self) -> WaitHandle {
        self.platform.poll.wait_handle()
    }

    /// Returns the first listen address.
    ///
    /// [`EndpointBuilder::bind`] already listens on every bound address, so
    /// this only reports; calling it again is harmless. Use
    /// [`listen_all`](Self::listen_all) to see them all.
    pub fn listen(&mut self) -> Result<PeerAddr, Error> {
        let mut addrs = self.listen_all()?;
        // `listen_all` fails rather than return nothing, so there is one here.
        addrs.drain(..).next().ok_or(Error::Invariant {
            reason: "a successful listen reported no address",
        })
    }

    /// Returns the relay-mesh backbone's listen addresses, with this node's
    /// backbone peer id: what the other members list for it. Empty unless
    /// built with [`EndpointBuilder::relay_mesh`].
    #[cfg(all(feature = "relay-server", feature = "quic"))]
    pub fn relay_mesh_addresses(&self) -> Vec<PeerAddr> {
        self.engine
            .relay_server
            .as_ref()
            .and_then(|relay_server| relay_server.backbone.as_ref())
            .map(|backbone| backbone.listen_addrs())
            .unwrap_or_default()
    }

    /// Drives the endpoint until an Endpoint event, the caller's deadline, or
    /// an interruption.
    ///
    /// This is the single Endpoint blocking wait. It runs one drive batch
    /// whenever its queue is empty and hands the batch's events out one per
    /// call, in the order documented on [`EndpointEvent`]. Deadline and
    /// interruption stay visible so a loop can service its own timers and
    /// commands (a [`WaitHandle`] from another thread interrupts it). A
    /// deadline that has already passed -- a stale [`std::time::Instant`] or
    /// [`std::time::Duration::ZERO`] alike -- never sleeps, but still returns
    /// a queued event or drives the endpoint once, so a stale timer cannot
    /// stall it. The deadline bounds blocking, not delivery: a caller with a
    /// strict operation timeout checks its own clock before each `wait`, as
    /// below. Enabled capabilities deliver their output here as
    /// [`EndpointEvent`] variants, so one `wait` loop sees every event
    /// exactly once. Each call drives only this endpoint.
    ///
    /// # Examples
    ///
    /// The canonical event loop: wait for one correlated outcome while still
    /// dispatching every unrelated event.
    ///
    /// ```no_run
    /// use std::time::{Duration, Instant};
    ///
    /// use minip2p::{ConnectOutcome, Endpoint, EndpointEvent, EndpointWaitOutcome, PeerAddr};
    ///
    /// fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let mut node = Endpoint::builder().listen_default()?.bind()?;
    ///     // A complete peer address, copied from the remote's `listen()` output.
    ///     let target: PeerAddr = "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
    ///         .parse()?;
    ///     let connect_id = node.connect(target)?;
    ///     let deadline = Instant::now() + Duration::from_secs(10);
    ///     loop {
    ///         // `wait` still serves events once the deadline has passed, so
    ///         // enforce the timeout here. Giving up locally does not cancel
    ///         // the attempt; do that explicitly.
    ///         if Instant::now() >= deadline {
    ///             node.cancel_connect(connect_id);
    ///             return Err("connect did not settle before the deadline".into());
    ///         }
    ///         match node.wait(deadline)? {
    ///             EndpointWaitOutcome::Event(EndpointEvent::ConnectSettled {
    ///                 connect_id: settled,
    ///                 outcome,
    ///                 ..
    ///             }) if settled == connect_id => match outcome {
    ///                 ConnectOutcome::Connected { conn_id, .. } => {
    ///                     println!("connected on {conn_id:?}");
    ///                     return Ok(());
    ///                 }
    ///                 other => return Err(format!("connect failed: {other:?}").into()),
    ///             },
    ///             // Unrelated events keep flowing: dispatch them as usual.
    ///             EndpointWaitOutcome::Event(event) => println!("{event:?}"),
    ///             // The clock check above gives up.
    ///             EndpointWaitOutcome::Deadline => {}
    ///             // `Interrupted`: another thread woke us; service its
    ///             // commands, then wait again.
    ///             _ => {}
    ///         }
    ///     }
    /// }
    /// ```
    pub fn wait(
        &mut self,
        deadline: impl Into<WaitDeadline>,
    ) -> Result<EndpointWaitOutcome, Error> {
        let deadline = deadline.into();
        // A passed deadline still drives the endpoint once, which is what
        // lets a stale timer make progress. Only once, so a continuous event
        // stream cannot keep this wait running past its deadline.
        let mut drove_past_deadline = false;
        // A blocking harvest already collected this batch's readiness; a
        // zero-timeout one right behind it would only cost a syscall.
        let mut harvested = false;
        // A taken host wake owes one more batch, which is what reads the
        // edge-triggered mDNS sockets; a passed deadline must not skip it.
        let mut woken = false;
        // Past the deadline only one such batch runs: a steady stream of
        // wakes (packets mDNS reads and drops) must not hold the caller.
        // Newer wakes stay pending for the next call.
        let mut woke_past_deadline = false;
        loop {
            if let Some(event) = self.engine.pop_event() {
                return Ok(EndpointWaitOutcome::Event(event));
            }
            if drove_past_deadline && deadline.has_passed() && !woken {
                return Ok(EndpointWaitOutcome::Deadline);
            }
            if !harvested {
                self.harvest(Duration::ZERO)?;
            }
            // The batch applies finished lookups (a lookup thread is what
            // woke the last sleep, unless the caller did) and starts the
            // lookups it parks before this can sleep.
            let now = self.now();
            drove_past_deadline |= deadline.has_passed();
            woke_past_deadline |= woken && deadline.has_passed();
            woken = false;
            self.drive(now)?;
            if !self.engine.events.is_empty() {
                harvested = false;
                continue;
            }
            // A pending interrupt outranks an expired deadline, so a host's
            // non-blocking pump still notices it. Checked before sleeping
            // even when its `Waker` event was already harvested.
            if self.platform.poll.take_interrupt() {
                return Ok(EndpointWaitOutcome::Interrupted);
            }
            if !(woke_past_deadline && deadline.has_passed()) && self.platform.poll.take_wake() {
                (harvested, woken) = (false, true);
                continue;
            }
            if deadline.has_passed() {
                return Ok(EndpointWaitOutcome::Deadline);
            }
            harvested = self.block(deadline)?;
        }
    }

    /// Drives the endpoint until nothing accepted is pending
    /// ([`Endpoint::has_pending_writes`] is `false`), or `deadline` passes,
    /// and returns which: `true` when drained.
    ///
    /// Drained means every byte and FIN the endpoint accepted has been
    /// handed to the transport, and every FIN on a direct QUIC or TCP stream
    /// has been sent (over QUIC, acknowledged by the peer, so the peer must
    /// be driving its endpoint for the flush to finish). Bytes on a stream
    /// left open are best effort: handed to QUIC, which may still hold them
    /// for congestion control. Over a relayed connection the FIN is handed
    /// to the relay, without waiting for its acknowledgement. To deliver
    /// everything, close the write side before flushing: `send_stream`,
    /// `close_stream_write`, `flush`, then `close`. Returns
    /// `true` at once when nothing is pending; a passed deadline still
    /// drives once. Events the drive produces stay queued for the next
    /// [`wait`](Self::wait) or [`poll`](Endpoint::poll), and an interrupt
    /// from a [`WaitHandle`] does not end the flush (the next `wait`
    /// reports it). `close_within` flushes first, within its own timeout.
    pub fn flush(&mut self, deadline: impl Into<WaitDeadline>) -> Result<bool, Error> {
        let deadline = deadline.into();
        while self.has_pending_writes() {
            self.harvest(Duration::ZERO)?;
            let now = self.now();
            self.drive(now)?;
            if !self.has_pending_writes() {
                break;
            }
            if deadline.has_passed() {
                return Ok(false);
            }
            self.block(deadline)?;
        }
        Ok(true)
    }

    /// Runs one engine batch, with Name resolution as candidate expansion.
    fn drive(&mut self, now: Now) -> Result<(), Error> {
        self.engine.drive(now, &mut self.platform.resolver)
    }

    /// Sleeps until input on any registered source, a `Waker` wake, the
    /// caller's deadline, or the engine's next timer, and dispatches the
    /// transport's share of the readiness. Returns whether it harvested.
    ///
    /// The engine's own timers (attempt deadlines, capability drivers) are
    /// floored at 1 ms, so a driver reporting "due now" without new input
    /// cannot spin the thread; the swarm's own due work is not.
    fn block(&mut self, deadline: WaitDeadline) -> Result<bool, Error> {
        let now = self.now();
        let mut budget = deadline.remaining().unwrap_or(MAX_IDLE_WAIT);
        if let Some(next) = self.engine.swarm_deadline(now) {
            budget = budget.min(Duration::from_millis(next.millis_until(now)));
        }
        if let Some(next) = self.engine.driver_deadline(now) {
            budget = budget.min(Duration::from_millis(next.millis_until(now).max(1)));
        }
        if budget.is_zero() {
            return Ok(false);
        }
        self.harvest(budget)?;
        Ok(true)
    }

    /// Collects one bounded batch of readiness, blocking up to `timeout`,
    /// and dispatches the transport's share. Every drive path harvests
    /// first: an edge-triggered transport reads only what was dispatched.
    fn harvest(&mut self, timeout: Duration) -> Result<(), Error> {
        harvest(
            &mut self.platform.poll,
            self.engine.core.transport_mut(),
            timeout,
        )
    }

    /// Replaces the CA-signed WebTransport certificate, for example after a
    /// renewal, without a restart or dropping a connection.
    ///
    /// Takes the same PEM as
    /// [`EndpointBuilder::webtransport_certificate_pem`] and makes bind's
    /// checks. New WebTransport handshakes present the new certificate; live
    /// connections keep theirs. The listen addresses carry no `/certhash`, so
    /// they and the announced addresses stay as they are.
    ///
    /// On any error the current certificate stays in service; see
    /// [`SetWebTransportCertificateError`] for each case.
    #[cfg(feature = "quic")]
    pub fn set_webtransport_certificate_pem(
        &mut self,
        chain_pem: impl AsRef<[u8]>,
        key_pem: impl AsRef<[u8]>,
    ) -> Result<(), SetWebTransportCertificateError> {
        let handle = self
            .platform
            .webtransport_certificate
            .as_ref()
            .ok_or(SetWebTransportCertificateError::NotConfigured)?;
        let (chain, key) = parse_certificate_pem(chain_pem.as_ref(), key_pem.as_ref())
            .map_err(|problem| SetWebTransportCertificateError::Pem { problem })?;
        handle.replace(chain, key).map_err(|error| match error {
            minip2p_quic::WebTransportCertificateError::Invalid(reason) => {
                SetWebTransportCertificateError::Invalid { reason }
            }
            other => SetWebTransportCertificateError::Invalid {
                reason: other.to_string(),
            },
        })
    }

    /// Atomically replaces the relay server's explicit announce-address override.
    ///
    /// Each address must be a concrete direct TCP, QUIC or WebTransport
    /// address for this endpoint's peer id. A WebTransport address carries a
    /// `/certhash` with the derived self-signed certificates and none with a
    /// CA-signed one (`EndpointBuilder::webtransport_certificate_pem`).
    /// [`RelayServerControlError::InvalidAddress`] retains the rejected
    /// input's index and reason; on error, the previous override remains
    /// active. An empty replacement clears the override, restoring the
    /// confirmed-NAT-then-concrete-listener fallback order.
    #[cfg(feature = "relay-server")]
    #[expect(
        clippy::result_large_err,
        reason = "The error retains the rejected address for actionable host diagnostics."
    )]
    pub fn set_relay_server_announce_addrs(
        &mut self,
        addrs: Vec<Multiaddr>,
    ) -> Result<(), RelayServerControlError> {
        let relay_server = self
            .engine
            .relay_server
            .as_mut()
            .ok_or(RelayServerControlError::NotConfigured)?;
        check_webtransport_announce(&addrs, self.platform.ca_webtransport_certificate)
            .map_err(RelayServerControlError::InvalidAddress)?;
        relay_server
            .agent
            .replace_announce_addrs(addrs)
            .map_err(RelayServerControlError::InvalidAddress)?;
        self.engine.addresses_changed();
        Ok(())
    }

    /// Flushes accepted writes, disconnects established peers, waits up to
    /// `timeout` until no connection is tracked, and consumes the endpoint.
    /// A dial still pending is tracked: the drain waits for it to fail, or
    /// to establish and then be disconnected.
    ///
    /// First it [`flush`](Self::flush)es, within the same `timeout`, so
    /// bytes and FINs the endpoint accepted go out before the connections
    /// close; what is still pending when the deadline passes is lost (QUIC
    /// discards it and TCP may abort). With [`Duration::ZERO`] this is an
    /// immediate best-effort teardown: one pass flushes once, disconnects,
    /// and hands over what is already queued. Running out
    /// the deadline is [`CloseOutcome::DeadlineExpired`], not an error, and
    /// [`CloseReport::unfinished`] lists what was still tracked.
    ///
    /// Dropping without closing still disconnects (errors ignored). Neither
    /// notifies a peer after `kill -9` or a hard partition. A replacement
    /// that lands while draining is disconnected too, including a handshake
    /// still pending when the replaced connection closes.
    ///
    /// Close never stops at the first failure: the [`CloseReport`] carries
    /// every event collected, starting with those already queued, and every
    /// transport or swarm error hit. A failed drain ends the drain early
    /// ([`CloseOutcome::Failed`]). mDNS goodbyes are best effort: one that
    /// could not be sent is an [`EndpointEvent::MdnsFailed`] in the report's
    /// events, not an error.
    pub fn close_within(mut self, timeout: Duration) -> CloseReport {
        let mut report = CloseReport {
            outcome: CloseOutcome::Drained,
            unfinished: Vec::new(),
            events: Vec::new(),
            errors: Vec::new(),
        };
        report.events.extend(self.engine.events.drain(..));
        // The failure is queued as an event too, and drained below.
        #[cfg(feature = "mdns")]
        drop(self.shutdown_mdns());
        let drain_by = std::time::Instant::now() + timeout;
        // Accepted writes go out before the connections close. A failed
        // flush is the drain's failure; teardown still runs.
        if let Err(error) = self.flush(drain_by) {
            report.errors.push(error);
            report.outcome = CloseOutcome::Failed;
        }
        loop {
            let now = self.now();
            report.errors.extend(self.disconnect_established(now));
            #[cfg(all(feature = "relay-server", feature = "quic"))]
            {
                let now = self.now();
                self.engine.shutdown_backbone(now);
            }
            // Out of time or failed: hand over what the swarm already queued
            // (a disconnect's close failure, say) without polling again.
            let (polled, mut last, now) = if std::time::Instant::now() >= drain_by {
                (self.engine.core.take_buffered_events(), true, self.now())
            } else {
                let harvested = if self.close_drain_busy() {
                    // Interrupts only end this sleep early.
                    self.block(WaitDeadline::from(drain_by))
                } else {
                    Ok(false)
                };
                let harvested = match harvested {
                    Ok(true) => Ok(()),
                    Ok(false) => self.harvest(Duration::ZERO),
                    Err(error) => Err(error),
                };
                let now = self.now();
                match harvested.and_then(|()| self.engine.core.poll(now)) {
                    Ok(polled) => (polled, false, now),
                    Err(error) => {
                        report.errors.push(error);
                        report.outcome = CloseOutcome::Failed;
                        (self.engine.core.take_buffered_events(), true, now)
                    }
                }
            };
            let quiet = polled.is_empty();
            // No agent tick or discovery sweep runs while closing, so only
            // connection, attempt and capability events (a relay
            // reservation closing, say) are returned.
            for event in polled {
                self.engine.ingest(event, now);
            }
            // A relay mesh's backbone closes alongside, and its timers are
            // in the drain's sleep budget, so it is polled here too.
            // A failure there ends the drain, as a public swarm's does.
            if let Err(error) = self.engine.drive_backbone(now) {
                report.errors.push(error);
                report.outcome = CloseOutcome::Failed;
                last = true;
            }
            self.engine.settle(now);
            report.events.extend(self.engine.events.drain(..));
            if last
                || (quiet && (!self.close_drain_busy() || std::time::Instant::now() >= drain_by))
            {
                break;
            }
        }
        // The last pass's own work (a driver's reset the transport refused,
        // say) can queue more swarm events: hand them over without polling.
        let now = self.now();
        for event in self.engine.core.take_buffered_events() {
            self.engine.ingest(event, now);
        }
        self.engine.settle(now);
        // Queued writes the transport has not ended yet die with the endpoint.
        let aborted = self.engine.writes.abort_all();
        self.engine.events.extend(aborted);
        report.events.extend(self.engine.events.drain(..));
        report.unfinished = self.tracked_connections();
        #[cfg(all(feature = "relay-server", feature = "quic"))]
        report.unfinished.extend(self.engine.backbone_connections());
        if report.outcome == CloseOutcome::Drained && !report.unfinished.is_empty() {
            report.outcome = CloseOutcome::DeadlineExpired;
        }
        report
    }

    fn close_drain_busy(&self) -> bool {
        let busy = !self.engine.core.connected_peers().is_empty()
            || self.engine.core.has_tracked_connections();
        #[cfg(all(feature = "relay-server", feature = "quic"))]
        let busy = busy || !self.engine.backbone_connections().is_empty();
        busy
    }
}

/// Raw swarm access for the crate's own tests, bypassing the engine.
#[cfg(all(test, feature = "quic"))]
impl Endpoint {
    pub(crate) fn core(&self) -> &minip2p_swarm::SwarmCore<EndpointTransport, StdEntropy> {
        &self.engine.core
    }

    #[cfg(any(feature = "relay", feature = "tcp"))]
    pub(crate) fn core_mut(
        &mut self,
    ) -> &mut minip2p_swarm::SwarmCore<EndpointTransport, StdEntropy> {
        &mut self.engine.core
    }

    /// One swarm poll whose events skip the engine.
    pub(crate) fn raw_poll(&mut self) -> Result<Vec<crate::SwarmEvent>, Error> {
        self.harvest(Duration::ZERO)?;
        let now = self.now();
        self.engine.core.poll(now)
    }

    /// The next swarm event within `timeout`, skipping the engine. A poll's
    /// other events are kept for the next call.
    pub(crate) fn raw_poll_next(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<crate::SwarmEvent>, Error> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(event) = self.platform.raw_events.pop_front() {
                return Ok(Some(event));
            }
            let polled = self.raw_poll()?;
            self.platform.raw_events.extend(polled);
            if self.platform.raw_events.is_empty() {
                let now = std::time::Instant::now();
                if now >= deadline {
                    return Ok(None);
                }
                let budget = (deadline - now).min(Duration::from_millis(10));
                self.harvest(budget)?;
            }
        }
    }
}

/// Test-only convenience over [`Endpoint::wait`]: the next event, or `None`
/// once the deadline passes. Interruptions are retried.
#[cfg(all(test, feature = "quic"))]
pub(crate) trait NextEvent {
    fn next_event(
        &mut self,
        deadline: impl Into<WaitDeadline>,
    ) -> Result<Option<EndpointEvent>, Error>;
}

#[cfg(all(test, feature = "quic"))]
impl NextEvent for Endpoint {
    fn next_event(
        &mut self,
        deadline: impl Into<WaitDeadline>,
    ) -> Result<Option<EndpointEvent>, Error> {
        let deadline = deadline.into();
        loop {
            match self.wait(deadline)? {
                EndpointWaitOutcome::Event(event) => return Ok(Some(event)),
                EndpointWaitOutcome::Deadline => return Ok(None),
                EndpointWaitOutcome::Interrupted => {}
            }
        }
    }
}
