//! Detached background endpoint driver and event delivery.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use minip2p::{EndpointWaitOutcome, Error, PeerId, WaitDeadline};

use crate::endpoint::{Lifecycle, Shared};
use crate::events::{CloseOutcome, UnfinishedConnection, convert_endpoint_event};
use crate::{DriverFailureKind, EventDoorbell, P2pEvent};

const MAX_CARRY_EVENTS: usize = 4096;
/// How many elided connection ids the carry remembers, so late path events
/// naming them are dropped too. The Endpoint reports those in the same batch
/// as the lifecycle events, and a batch is at most [`PUMP_DRAIN_LIMIT`].
const ELIDED_CONNECTION_MEMORY: usize = 4 * PUMP_DRAIN_LIMIT;
/// How many already-queued `wait` results one pump iteration will take
/// before yielding the lock. Further events stay queued for the next wait.
const PUMP_DRAIN_LIMIT: usize = 256;

/// Rust-side instrumentation for the background driver.
#[derive(Clone, Copy, Debug, Default)]
pub struct DriverStats {
    /// Largest bounded carry-buffer length observed.
    pub carry_high_water: usize,
    /// Source events returned by `drain_events`.
    pub dispatch_attempted: u64,
    /// Synthetic diagnostics returned by `drain_events`.
    pub dispatch_attempted_synthetic: u64,
    /// Source events discarded by overflow or shutdown.
    pub dropped: u64,
    /// Source events produced by conversion before batching.
    pub converted: u64,
    /// Completed driver-loop iterations.
    pub iterations: u64,
}

/// Drop accounting reported by the next delivery's `EventsDropped`.
///
/// `terminal_connect_ids` is deliberately uncapped so foreign runtimes can
/// correlate every lost terminal exactly. It stays bounded by application
/// work: only application-admitted Connection attempts reach this stream
/// (discovery-owned attempts settle internally), each emits one terminal,
/// and the list empties at every delivery — at most one `u64` per attempt
/// that settled while the foreign runtime was not draining.
#[derive(Default)]
pub(crate) struct OverflowDiagnostic {
    pending: u64,
    terminal_connect_ids: Vec<u64>,
    total: u64,
}

/// The carry with its drop accounting and stats, behind the endpoint's
/// event lock.
#[derive(Default)]
pub(crate) struct EventState {
    pub(crate) carry: Carry,
    pub(crate) overflow: OverflowDiagnostic,
    pub(crate) stats: DriverStats,
    /// What `connected_peers` returns, published from the endpoint's peer
    /// table by the driver (see `Shared::publish_peers`), so the
    /// query neither interrupts nor waits for the driver.
    pub(crate) connected_peers: Vec<String>,
    /// Set with the lifecycle once it reaches `Stopping` or `Stopped`.
    pub(crate) stopped: bool,
}

impl EventState {
    /// Ingests one driver batch, returning whether the carry went from empty
    /// to non-empty, which is when the doorbell rings.
    fn ingest(&mut self, events: impl IntoIterator<Item = P2pEvent>) -> bool {
        let was_empty = self.carry.is_empty();
        ingest(events, &mut self.carry, &mut self.overflow, &mut self.stats);
        self.stats.carry_high_water = self.stats.carry_high_water.max(self.carry.len());
        was_empty && !self.carry.is_empty()
    }
}

pub(crate) struct Delivery {
    pub(crate) diagnostic: Option<P2pEvent>,
    pub(crate) batch: Vec<P2pEvent>,
}

/// Converted events waiting for the binding to drain them, in order.
///
/// Stream events (ready, data, write settlement, stop, remote close, close,
/// and connection ends) are never dropped (ADR 0012): the receive budgets
/// bound their data, and adjacent data for one stream coalesces into one
/// event, so they do not count against the cap. Past
/// [`MAX_CARRY_EVENTS`] other events, the oldest gossipsub message is
/// dropped first, then the oldest other event.
///
/// A peer-opened stream that closes without carrying data before the binding
/// drained its `StreamReady` leaves the carry whole: the binding never saw
/// it, and nothing about it is left to settle. Without that, a peer opening
/// and closing streams could grow an undrained carry without bound, since
/// such a stream frees its transport slot at once.
///
/// Connections get the same rule (#356): one that ends without carrying data
/// before the binding took any of its events, whichever side dialed it,
/// leaves with every event naming it. One replaced instead folds into its
/// successor: its undrained `ConnectionEstablished` is rewritten to name the
/// successor and the `ConnectionReplaced` goes (when the cap already dropped
/// that `ConnectionEstablished`, the `ConnectionReplaced` goes too). A
/// connection the binding could know of otherwise -- a stream it opened or
/// wrote on, a ping result, an attempt terminal or path event naming it --
/// is kept. Path events the Endpoint reports after an elided connection's
/// lifecycle events (a relay circuit's) leave with it.
#[derive(Default)]
pub(crate) struct Carry {
    events: BTreeMap<u64, P2pEvent>,
    /// Droppable gossipsub messages, oldest first. May name removed events,
    /// but is rebuilt once those outnumber the held ones.
    message_ids: VecDeque<u64>,
    /// Other droppable events, oldest first, rebuilt like `message_ids`.
    other_ids: VecDeque<u64>,
    /// Droppable messages and other droppable events currently held.
    held_messages: usize,
    held_others: usize,
    dropped_terminal_connect_ids: BTreeSet<u64>,
    next_id: u64,
    /// Peer-opened streams whose `StreamReady` is still in the carry, by
    /// connection and stream id, with the ids of their events; `None` once
    /// one carried data.
    unseen_streams: BTreeMap<(u64, u64), Option<Vec<u64>>>,
    /// Connections whose `ConnectionEstablished` entered the carry and that
    /// neither the binding nor any kept event has seen yet.
    unseen_connections: BTreeSet<u64>,
    /// Live connections the binding learned of outside the carry, so a later
    /// replacement fold must not make them unseen; each leaves with its end.
    known_connections: BTreeSet<u64>,
    /// Recently elided or folded-away connections, oldest first, at most
    /// [`ELIDED_CONNECTION_MEMORY`]: a later event naming one is dropped, so
    /// the binding never meets an id whose lifecycle it never saw.
    elided_connections: VecDeque<u64>,
}

impl Carry {
    pub(crate) fn len(&self) -> usize {
        self.events.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Appends `event`, returning whether the cap dropped an event for it.
    pub(crate) fn push(&mut self, event: P2pEvent) -> bool {
        let event = match self.coalesce(event) {
            Some(event) => event,
            None => return false,
        };
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        if self.track_unseen(&event, id) || self.track_connection(&event) {
            return false;
        }
        match event {
            P2pEvent::Message { .. } => {
                self.message_ids.push_back(id);
                self.held_messages += 1;
            }
            _ if is_stream_event(&event) => {}
            _ => {
                self.other_ids.push_back(id);
                self.held_others += 1;
            }
        }
        self.events.insert(id, event);
        if self.held_messages + self.held_others <= MAX_CARRY_EVENTS {
            return false;
        }
        // Both queues together name every droppable event, so one is found.
        let dropped = self
            .pop_live(Queue::Messages)
            .or_else(|| self.pop_live(Queue::Others));
        // A lost stream terminal or write settlement can no longer happen,
        // so only Connection-attempt terminals need naming.
        if let Some(connect_id) = dropped.as_ref().and_then(terminal_connect_id) {
            self.dropped_terminal_connect_ids.insert(connect_id);
        }
        true
    }

    /// Appends `event`'s bytes to the newest event when both are data for
    /// the same stream; otherwise hands `event` back.
    fn coalesce(&mut self, event: P2pEvent) -> Option<P2pEvent> {
        let P2pEvent::StreamData {
            conn_id,
            stream_id,
            data,
            ..
        } = &event
        else {
            return Some(event);
        };
        match self
            .events
            .last_entry()
            .as_mut()
            .map(|entry| entry.get_mut())
        {
            Some(P2pEvent::StreamData {
                conn_id: last_conn,
                stream_id: last_stream,
                data: last_data,
                ..
            }) if last_conn == conn_id && last_stream == stream_id => {
                last_data.extend_from_slice(data);
                None
            }
            _ => Some(event),
        }
    }

    /// Records `event` (taking `id`) against an unseen peer stream. Returns
    /// whether it closed one that carried no data, which leaves the carry
    /// with all its events instead.
    fn track_unseen(&mut self, event: &P2pEvent, id: u64) -> bool {
        if let P2pEvent::StreamReady {
            conn_id,
            stream_id,
            initiated_locally: false,
            ..
        } = event
        {
            self.unseen_streams
                .insert((*conn_id, *stream_id), Some(vec![id]));
            return false;
        }
        let Some(key) = stream_key(event) else {
            return false;
        };
        let Some(ids) = self.unseen_streams.get_mut(&key) else {
            return false;
        };
        match (event, ids) {
            (P2pEvent::StreamData { .. }, ids) => *ids = None,
            (P2pEvent::StreamClosed { .. }, Some(_)) => {
                for id in self
                    .unseen_streams
                    .remove(&key)
                    .flatten()
                    .unwrap_or_default()
                {
                    self.remove(id);
                }
                return true;
            }
            (_, Some(ids)) => ids.push(id),
            (_, None) => {}
        }
        false
    }

    /// Records `event` against the unseen connections it names. Returns
    /// whether it ended (or replaced) one that carried no data, which leaves
    /// the carry with its events instead.
    fn track_connection(&mut self, event: &P2pEvent) -> bool {
        // Connection-attempt terminals answer the application's own connect,
        // so they are delivered even naming a connection it never saw.
        if terminal_connect_id(event).is_none()
            && connection_ids(event)
                .iter()
                .any(|conn_id| self.elided_connections.contains(conn_id))
        {
            return true;
        }
        match event {
            P2pEvent::ConnectionEstablished { conn_id, .. } => {
                if self.may_elide(*conn_id) {
                    self.unseen_connections.insert(*conn_id);
                }
            }
            P2pEvent::ConnectionClosed { conn_id, .. }
                if self.unseen_connections.remove(conn_id) =>
            {
                self.remove_connection_events(*conn_id);
                self.remember_elided(*conn_id);
                return true;
            }
            P2pEvent::ConnectionReplaced {
                old_conn_id,
                new_conn_id,
                ..
            } if self.unseen_connections.remove(old_conn_id) => {
                let opening = self.events.values_mut().find_map(|event| match event {
                    P2pEvent::ConnectionEstablished { conn_id, .. } if conn_id == old_conn_id => {
                        Some(conn_id)
                    }
                    _ => None,
                });
                if let Some(conn_id) = opening {
                    *conn_id = *new_conn_id;
                }
                self.remove_connection_events(*old_conn_id);
                self.remember_elided(*old_conn_id);
                if self.may_elide(*new_conn_id) {
                    self.unseen_connections.insert(*new_conn_id);
                }
                return true;
            }
            P2pEvent::ConnectionClosed { conn_id, .. } => {
                self.known_connections.remove(conn_id);
            }
            P2pEvent::ConnectionReplaced { old_conn_id, .. } => {
                self.known_connections.remove(old_conn_id);
            }
            // Only the events below leave a connection unseen: anything else
            // naming it is something the binding acts on or must hear about.
            P2pEvent::PeerReady { .. }
            | P2pEvent::IdentifyReceived { .. }
            | P2pEvent::EndpointError { .. }
            | P2pEvent::StreamReady {
                initiated_locally: false,
                ..
            }
            | P2pEvent::StreamRemoteWriteClosed { .. }
            | P2pEvent::StreamWriteStopped { .. }
            | P2pEvent::StreamClosed { .. } => {}
            _ => {
                for conn_id in connection_ids(event) {
                    self.unseen_connections.remove(&conn_id);
                }
            }
        }
        false
    }

    /// Whether `conn_id` may be tracked as unseen: not one the binding
    /// learned of otherwise.
    fn may_elide(&self, conn_id: u64) -> bool {
        !self.known_connections.contains(&conn_id)
    }

    /// Remembers an elided connection, so the path events the Endpoint
    /// reports after its lifecycle events (a relay circuit's, above all) go
    /// with it.
    fn remember_elided(&mut self, conn_id: u64) {
        if self.elided_connections.len() == ELIDED_CONNECTION_MEMORY {
            self.elided_connections.pop_front();
        }
        self.elided_connections.push_back(conn_id);
    }

    /// Removes every event naming `conn_id`, with its peer streams' records.
    fn remove_connection_events(&mut self, conn_id: u64) {
        let ids: Vec<u64> = self
            .events
            .iter()
            .filter(|(_, event)| connection_ids(event).contains(&conn_id))
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.remove(id);
        }
        self.unseen_streams.retain(|(conn, _), _| *conn != conn_id);
        self.compact_queues();
    }

    /// Whether the stream's `StreamClosed` waits in the carry.
    pub(crate) fn holds_stream_close(&self, conn_id: u64, stream_id: u64) -> bool {
        self.events.values().any(|event| {
            matches!(event, P2pEvent::StreamClosed { .. })
                && stream_key(event) == Some((conn_id, stream_id))
        })
    }

    /// Removes every event for one stream, returning the data bytes they
    /// carried and whether its `StreamClosed` was among them: what abandoning
    /// it drops from the carry (ADR 0012).
    pub(crate) fn remove_stream(&mut self, conn_id: u64, stream_id: u64) -> (usize, bool) {
        let ids: Vec<u64> = self
            .events
            .iter()
            .filter(|(_, event)| stream_key(event) == Some((conn_id, stream_id)))
            .map(|(id, _)| *id)
            .collect();
        let (mut data, mut closed) = (0, false);
        for id in ids {
            match self.remove(id) {
                Some(P2pEvent::StreamData { data: bytes, .. }) => data += bytes.len(),
                Some(P2pEvent::StreamClosed { .. }) => closed = true,
                _ => {}
            }
        }
        self.unseen_streams.remove(&(conn_id, stream_id));
        (data, closed)
    }

    /// Marks a connection the binding learned of outside the carry (it
    /// opened a stream on it), so its events are kept.
    pub(crate) fn mark_connection_seen(&mut self, conn_id: u64) {
        self.unseen_connections.remove(&conn_id);
        self.known_connections.insert(conn_id);
    }

    /// Removes one held event, keeping the droppable counts.
    fn remove(&mut self, id: u64) -> Option<P2pEvent> {
        let event = self.events.remove(&id)?;
        match event {
            P2pEvent::Message { .. } => self.held_messages -= 1,
            _ if is_stream_event(&event) => {}
            _ => self.held_others -= 1,
        }
        Some(event)
    }

    /// Rebuilds a droppable-id queue once its stale ids outnumber the held
    /// ones, so removing events out of order cannot grow it without bound.
    fn compact_queues(&mut self) {
        let events = &self.events;
        for (ids, held) in [
            (&mut self.message_ids, self.held_messages),
            (&mut self.other_ids, self.held_others),
        ] {
            if ids.len() > 2 * held {
                ids.retain(|id| events.contains_key(id));
            }
        }
    }

    /// Removes the oldest event still held from one droppable queue.
    fn pop_live(&mut self, queue: Queue) -> Option<P2pEvent> {
        loop {
            let ids = match queue {
                Queue::Messages => &mut self.message_ids,
                Queue::Others => &mut self.other_ids,
            };
            let id = ids.pop_front()?;
            if let Some(event) = self.remove(id) {
                return Some(event);
            }
        }
    }

    fn take(&mut self, limit: usize) -> Vec<P2pEvent> {
        let ids: Vec<_> = self.events.keys().take(limit).copied().collect();
        let mut batch = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(event) = self.remove(id) {
                if let P2pEvent::StreamReady {
                    conn_id, stream_id, ..
                } = &event
                {
                    self.unseen_streams.remove(&(*conn_id, *stream_id));
                }
                // The binding has now seen the connections it names.
                for conn_id in connection_ids(&event) {
                    self.unseen_connections.remove(&conn_id);
                }
                batch.push(event);
            }
        }
        // `take` removes the oldest events and the queues are in id order,
        // so the stale ids it leaves form a prefix: prune that.
        for ids in [&mut self.message_ids, &mut self.other_ids] {
            while ids.front().is_some_and(|id| !self.events.contains_key(id)) {
                ids.pop_front();
            }
        }
        self.compact_queues();
        batch
    }

    fn take_dropped_terminal_connect_ids(&mut self) -> BTreeSet<u64> {
        core::mem::take(&mut self.dropped_terminal_connect_ids)
    }
}

/// The connection and stream an event belongs to, for per-stream events.
fn stream_key(event: &P2pEvent) -> Option<(u64, u64)> {
    match event {
        P2pEvent::StreamReady {
            conn_id, stream_id, ..
        }
        | P2pEvent::StreamData {
            conn_id, stream_id, ..
        }
        | P2pEvent::StreamWriteAccepted {
            conn_id, stream_id, ..
        }
        | P2pEvent::StreamWriteStopped {
            conn_id, stream_id, ..
        }
        | P2pEvent::StreamRemoteWriteClosed {
            conn_id, stream_id, ..
        }
        | P2pEvent::StreamClosed {
            conn_id, stream_id, ..
        } => Some((*conn_id, *stream_id)),
        _ => None,
    }
}

/// Every connection `event` names.
fn connection_ids(event: &P2pEvent) -> Vec<u64> {
    match event {
        P2pEvent::ConnectionEstablished { conn_id, .. }
        | P2pEvent::ConnectionClosed { conn_id, .. }
        | P2pEvent::PeerReady { conn_id, .. }
        | P2pEvent::IdentifyReceived { conn_id, .. }
        | P2pEvent::PingRttMeasured { conn_id, .. }
        | P2pEvent::PingTimeout { conn_id, .. }
        | P2pEvent::StreamReady { conn_id, .. }
        | P2pEvent::StreamData { conn_id, .. }
        | P2pEvent::StreamWriteAccepted { conn_id, .. }
        | P2pEvent::StreamWriteStopped { conn_id, .. }
        | P2pEvent::StreamRemoteWriteClosed { conn_id, .. }
        | P2pEvent::StreamClosed { conn_id, .. }
        | P2pEvent::EndpointError {
            conn_id: Some(conn_id),
            ..
        }
        | P2pEvent::PathEstablished { conn_id, .. }
        | P2pEvent::InboundPathEstablished { conn_id, .. } => vec![*conn_id],
        P2pEvent::ConnectionReplaced {
            old_conn_id,
            new_conn_id,
            ..
        }
        | P2pEvent::PathUpgraded {
            old_conn_id,
            new_conn_id,
            ..
        }
        | P2pEvent::InboundDirectUpgrade {
            old_conn_id,
            new_conn_id,
            ..
        } => vec![*old_conn_id, *new_conn_id],
        _ => Vec::new(),
    }
}

#[derive(Clone, Copy)]
enum Queue {
    Messages,
    Others,
}

/// Events the carry never drops: everything a binding's stream and
/// connection state depends on (ADR 0012).
fn is_stream_event(event: &P2pEvent) -> bool {
    matches!(
        event,
        P2pEvent::StreamReady { .. }
            | P2pEvent::StreamData { .. }
            | P2pEvent::StreamWriteAccepted { .. }
            | P2pEvent::StreamWriteStopped { .. }
            | P2pEvent::StreamRemoteWriteClosed { .. }
            | P2pEvent::StreamClosed { .. }
            | P2pEvent::ConnectionClosed { .. }
            | P2pEvent::ConnectionReplaced { .. }
    )
}

struct ExitGuard {
    shared: Arc<Shared>,
    doorbell: Option<Arc<dyn EventDoorbell>>,
}

impl Drop for ExitGuard {
    fn drop(&mut self) {
        drop(self.doorbell.take());
        let mut state = self.shared.lock_state();
        state.release_endpoint();
        self.shared.set_lifecycle(&mut state, Lifecycle::Stopped);
        self.shared.driver_running.store(false, Ordering::Release);
        drop(state);
        self.shared.latch_stopped();
    }
}

/// Runs the driver until `stop` or a failure, then closes the endpoint
/// outside the state lock: within the stop's timeout, or at once after a
/// failure. The close's events, but for attempt terminals, are carried
/// ahead of the last event, `EndpointClosed`; the guard then latches
/// stopped. Only a panic leaves the endpoint to the guard's plain drop.
pub(crate) fn run(shared: Arc<Shared>, doorbell: Arc<dyn EventDoorbell>) {
    shared.lock_state().driver_thread_id = Some(std::thread::current().id());
    let mut guard = ExitGuard {
        shared,
        doorbell: Some(doorbell),
    };
    let result = catch_unwind(AssertUnwindSafe(|| pump(&mut guard)));
    let (failure, endpoint, timeout) = {
        let mut state = guard.shared.lock_state();
        let failed = matches!(&result, Err(_) | Ok(Err(_)));
        let panicked = result.is_err();
        let report_failure = state.lifecycle == Lifecycle::Running && failed;
        if report_failure {
            guard.shared.set_lifecycle(&mut state, Lifecycle::Stopping);
        }
        let failure = match result {
            Ok(Err(error)) if report_failure => Some(P2pEvent::DriverFailed {
                kind: failure_kind(&error),
                detail: error.to_string(),
            }),
            Err(_) if report_failure => Some(P2pEvent::DriverFailed {
                kind: DriverFailureKind::Panic,
                detail: "background endpoint driver panicked".into(),
            }),
            _ => None,
        };
        // A panic may have left the endpoint mid-update: the guard drops it.
        let endpoint = if panicked {
            None
        } else {
            state.release_endpoint()
        };
        let timeout = if failed {
            Duration::ZERO
        } else {
            state.close_timeout
        };
        (failure, endpoint, timeout)
    };
    // The drain's events (connection ends among them) go to the binding
    // ahead of `EndpointClosed`.
    let mut drained = Vec::new();
    let closed = match endpoint {
        Some(endpoint) => {
            let report = endpoint.close_within(timeout);
            drained.extend(
                report
                    .events
                    .into_iter()
                    .filter_map(crate::events::convert_detached_event),
            );
            P2pEvent::EndpointClosed {
                outcome: report.outcome.into(),
                unfinished: report
                    .unfinished
                    .into_iter()
                    .map(|(conn_id, peer)| UnfinishedConnection {
                        conn_id: conn_id.as_u64(),
                        peer_id: peer.as_ref().map(PeerId::to_base58),
                    })
                    .collect(),
            }
        }
        None => P2pEvent::EndpointClosed {
            outcome: CloseOutcome::Failed,
            unfinished: Vec::new(),
        },
    };
    if let Some(doorbell) = guard.doorbell.as_ref()
        && guard
            .shared
            .lock_events()
            .ingest(failure.into_iter().chain(drained).chain([closed]))
    {
        ring(doorbell);
    }
}

fn pump(guard: &mut ExitGuard) -> Result<(), Error> {
    loop {
        let mut state = guard.shared.lock_state();
        if state.lifecycle != Lifecycle::Running {
            return Ok(());
        }
        let crate::endpoint::EndpointState {
            endpoint,
            writes,
            published_peers,
            ..
        } = &mut *state;
        let endpoint = endpoint.as_mut().expect("running endpoint exists");
        // Only `Endpoint::wait`, so the carry stays in Endpoint emission
        // order. A follow-up `poll()` would open a second batch and finish
        // that batch on its own.
        //
        // No deadline of our own: the wait already wakes for every timer the
        // endpoint's transports, protocols and agents report, and for input
        // on any socket registered with its readiness poll (mDNS included).
        // Every command, query and `stop` interrupts it; interrupts sent
        // before one is reported coalesce into one, so a burst of commands
        // costs one wake and the queue is drained below. An idle driver
        // therefore sleeps until something is due.
        let mut batch = Vec::new();
        let mut interrupted = false;
        match endpoint.wait(WaitDeadline::NEVER)? {
            EndpointWaitOutcome::Interrupted => interrupted = true,
            EndpointWaitOutcome::Event(event) => batch.push(event),
            // Deadline, or an outcome this driver predates: nothing to carry.
            _ => {}
        }
        if !interrupted {
            for _ in 0..PUMP_DRAIN_LIMIT {
                match endpoint.wait(Duration::ZERO)? {
                    EndpointWaitOutcome::Event(event) => batch.push(event),
                    EndpointWaitOutcome::Interrupted => {
                        interrupted = true;
                        break;
                    }
                    // Deadline, or an outcome this driver predates.
                    _ => break,
                }
            }
        }
        if interrupted && batch.is_empty() {
            guard.shared.publish_peers(endpoint, published_peers);
            drop(state);
            guard.shared.wait_for_commands();
            continue;
        }
        // Pending writes follow each event first: a Writable resends a held
        // tail and, once it is all accepted, settles the binding's write
        // right after the event that caused it.
        let mut converted = Vec::with_capacity(batch.len());
        for event in batch {
            let settled = writes
                .observe(endpoint, &event)
                .map(crate::writes::accepted_event);
            converted.extend(convert_endpoint_event(endpoint, event));
            converted.extend(settled);
        }
        // Published and ingested before `state` is released, so no command
        // runs between the endpoint emitting these events and the carry
        // holding them, and the doorbell never rings ahead of the peers.
        guard.shared.publish_peers(endpoint, published_peers);
        let should_ring = {
            let mut events = guard.shared.lock_events();
            events.stats.iterations = events.stats.iterations.saturating_add(1);
            events.ingest(converted)
        };
        drop(state);
        if should_ring {
            ring(guard.doorbell.as_ref().expect("doorbell exists"));
        }
        if interrupted {
            guard.shared.wait_for_commands();
        }
    }
}

fn ingest(
    events: impl IntoIterator<Item = P2pEvent>,
    carry: &mut Carry,
    overflow: &mut OverflowDiagnostic,
    stats: &mut DriverStats,
) {
    let mut converted = 0_u64;
    let mut dropped = 0_u64;
    for event in events {
        converted = converted.saturating_add(1);
        dropped = dropped.saturating_add(u64::from(carry.push(event)));
    }
    stats.converted = stats.converted.saturating_add(converted);
    stats.dropped = stats.dropped.saturating_add(dropped);
    overflow.pending = overflow.pending.saturating_add(dropped);
    overflow.total = overflow.total.saturating_add(dropped);
    // Each Connect ID settles exactly one terminal, so the list cannot
    // contain duplicates.
    overflow
        .terminal_connect_ids
        .extend(carry.take_dropped_terminal_connect_ids());
}

pub(crate) fn take_delivery(
    carry: &mut Carry,
    overflow: &mut OverflowDiagnostic,
    stats: &mut DriverStats,
    limit: usize,
) -> Delivery {
    let diagnostic = (overflow.pending != 0).then(|| {
        let event = P2pEvent::EventsDropped {
            dropped: overflow.pending,
            terminal_connect_ids: core::mem::take(&mut overflow.terminal_connect_ids),
            total_dropped: overflow.total,
        };
        overflow.pending = 0;
        stats.dispatch_attempted_synthetic = stats.dispatch_attempted_synthetic.saturating_add(1);
        event
    });
    let batch = carry.take(limit.saturating_sub(usize::from(diagnostic.is_some())));
    Delivery { diagnostic, batch }
}

/// Returns the Connect ID `event` terminates, when it is one of the three
/// attempt terminals.
///
/// `PathUpgraded` carries a Connect ID but is not a terminal: it can follow
/// an attempt that settled on a provisional relayed path.
pub(crate) fn terminal_connect_id(event: &P2pEvent) -> Option<u64> {
    match event {
        P2pEvent::PathEstablished { connect_id, .. }
        | P2pEvent::ConnectFailed { connect_id, .. }
        | P2pEvent::ConnectCancelled { connect_id, .. } => Some(*connect_id),
        _ => None,
    }
}

fn ring(doorbell: &Arc<dyn EventDoorbell>) {
    // Foreign callbacks are advisory; an unwind must not stop event delivery.
    drop(catch_unwind(AssertUnwindSafe(|| {
        doorbell.on_events_ready()
    })));
}

fn failure_kind(error: &Error) -> DriverFailureKind {
    match error {
        Error::Transport(_) | Error::Full { .. } => DriverFailureKind::Transport,
        Error::Swarm(_) => DriverFailureKind::Swarm,
        // Includes failures this binding predates.
        _ => DriverFailureKind::Invariant,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn message(byte: u8) -> P2pEvent {
        P2pEvent::Message {
            from_peer_id: "peer".into(),
            topics: vec!["room".into()],
            data: vec![byte],
            seqno: vec![byte],
            signed: true,
        }
    }

    #[test]
    fn doorbell_rings_only_on_empty_to_non_empty_edges() {
        struct Bell(AtomicUsize);
        impl EventDoorbell for Bell {
            fn on_events_ready(&self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let bell = Arc::new(Bell(AtomicUsize::new(0)));
        let doorbell = Arc::clone(&bell) as Arc<dyn EventDoorbell>;
        let mut carry = Carry::default();
        let mut overflow = OverflowDiagnostic::default();
        let mut stats = DriverStats::default();

        let was_empty = carry.is_empty();
        ingest(
            [message(1), message(2)],
            &mut carry,
            &mut overflow,
            &mut stats,
        );
        if was_empty && !carry.is_empty() {
            ring(&doorbell);
        }
        ingest([message(3)], &mut carry, &mut overflow, &mut stats);
        assert_eq!(bell.0.load(Ordering::Relaxed), 1);
        assert_eq!(
            take_delivery(&mut carry, &mut overflow, &mut stats, 3)
                .batch
                .len(),
            3
        );

        let was_empty = carry.is_empty();
        ingest([message(4)], &mut carry, &mut overflow, &mut stats);
        if was_empty && !carry.is_empty() {
            ring(&doorbell);
        }
        assert_eq!(bell.0.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn terminal_attempt_events_are_identified_for_retirement() {
        assert_eq!(
            terminal_connect_id(&P2pEvent::PathEstablished {
                connect_id: 7,
                peer_id: "peer".into(),
                conn_id: 70,
                path: crate::PathKind::Direct,
            }),
            Some(7)
        );
        assert_eq!(
            terminal_connect_id(&P2pEvent::PathEstablished {
                connect_id: 8,
                peer_id: "peer".into(),
                conn_id: 80,
                path: crate::PathKind::Relayed {
                    relay_peer_id: "relay".into()
                },
            }),
            Some(8)
        );
        assert_eq!(
            terminal_connect_id(&P2pEvent::ConnectFailed {
                connect_id: 9,
                peer_id: "peer".into(),
                kind: crate::NatErrorKind::NoPathAvailable,
                detail: "failed".into(),
            }),
            Some(9)
        );
        assert_eq!(
            terminal_connect_id(&P2pEvent::ConnectCancelled {
                connect_id: 10,
                peer_id: "peer".into(),
            }),
            Some(10)
        );
        // Path progress carries a Connect ID but is not a terminal: it can
        // follow an attempt that settled on a provisional path.
        assert_eq!(
            terminal_connect_id(&P2pEvent::PathUpgraded {
                connect_id: 11,
                peer_id: "peer".into(),
                from: crate::PathKind::Relayed {
                    relay_peer_id: "relay".into()
                },
                to: crate::PathKind::Punched,
                old_conn_id: 1,
                new_conn_id: 2,
            }),
            None
        );
    }

    #[test]
    fn carry_cap_drops_oldest_messages_before_lifecycle_events() {
        let lifecycle = P2pEvent::PeerReady {
            peer_id: "peer".into(),
            conn_id: 1,
            protocols: Vec::new(),
        };
        let mut carry = Carry::default();
        assert!(!carry.push(lifecycle.clone()));
        let dropped = (0..=MAX_CARRY_EVENTS)
            .filter(|index| carry.push(message(*index as u8)))
            .count();

        assert_eq!(dropped, 2);
        assert_eq!(carry.len(), MAX_CARRY_EVENTS);
        let retained = carry.take(MAX_CARRY_EVENTS);
        assert_eq!(retained.first(), Some(&lifecycle));
        assert_eq!(retained.get(1), Some(&message(2)));
    }

    fn data(stream_id: u64, bytes: &[u8]) -> P2pEvent {
        P2pEvent::StreamData {
            peer_id: "peer".into(),
            conn_id: 1,
            stream_id,
            data: bytes.to_vec(),
        }
    }

    #[test]
    fn stream_events_are_never_dropped_and_only_messages_overflow() {
        let ready = P2pEvent::StreamReady {
            peer_id: "peer".into(),
            conn_id: 1,
            stream_id: 7,
            protocol_id: "/app/1".into(),
            initiated_locally: false,
        };
        let mut carry = Carry::default();
        let mut overflow = OverflowDiagnostic::default();
        let mut stats = DriverStats::default();
        // 5000 one-byte data events, each between two messages so none
        // coalesce, far past the cap.
        ingest(
            [ready.clone()].into_iter().chain(
                (0..5000_u32).flat_map(|index| [message(index as u8), data(7, &[index as u8])]),
            ),
            &mut carry,
            &mut overflow,
            &mut stats,
        );

        let mut events = Vec::new();
        while !carry.is_empty() {
            events.extend(take_delivery(&mut carry, &mut overflow, &mut stats, 512).batch);
        }
        assert_eq!(
            events.first(),
            Some(&ready),
            "StreamReady precedes its data"
        );
        let received: Vec<u8> = events
            .iter()
            .filter_map(|event| match event {
                P2pEvent::StreamData { data, .. } => Some(data[0]),
                _ => None,
            })
            .collect();
        assert_eq!(
            received,
            (0..5000_u32).map(|index| index as u8).collect::<Vec<_>>()
        );
        assert_eq!(
            stats.dropped,
            5000 - MAX_CARRY_EVENTS as u64,
            "only messages drop"
        );
    }

    fn lifecycle(stream_id: u64, initiated_locally: bool) -> [P2pEvent; 2] {
        [
            P2pEvent::StreamReady {
                peer_id: "peer".into(),
                conn_id: 1,
                stream_id,
                protocol_id: "/app/1".into(),
                initiated_locally,
            },
            P2pEvent::StreamClosed {
                peer_id: "peer".into(),
                conn_id: 1,
                stream_id,
            },
        ]
    }

    #[test]
    fn peer_stream_churn_without_data_does_not_grow_an_undrained_carry() {
        let mut carry = Carry::default();
        // A peer opens and closes streams without sending a byte while the
        // binding drains nothing: each stream it never saw leaves no trace.
        for stream_id in 0..10_000 {
            for event in lifecycle(stream_id, false) {
                assert!(!carry.push(event));
            }
        }
        assert!(carry.is_empty());

        // Streams the binding must hear about are kept: its own, one that
        // carried data, and one whose StreamReady it already drained.
        let [ready, closed] = lifecycle(1, true);
        carry.push(ready.clone());
        carry.push(closed.clone());
        let [peer_ready, peer_closed] = lifecycle(2, false);
        carry.push(peer_ready.clone());
        carry.push(data(2, b"x"));
        carry.push(peer_closed.clone());
        assert_eq!(
            carry.take(10),
            [ready, closed, peer_ready, data(2, b"x"), peer_closed]
        );
        let [drained, closed] = lifecycle(3, false);
        carry.push(drained.clone());
        assert_eq!(carry.take(10), [drained]);
        carry.push(closed.clone());
        assert_eq!(carry.take(10), [closed]);
    }

    fn established(conn_id: u64) -> P2pEvent {
        P2pEvent::ConnectionEstablished {
            peer_id: "peer".into(),
            conn_id,
        }
    }

    fn peer_ready(conn_id: u64) -> P2pEvent {
        P2pEvent::PeerReady {
            peer_id: "peer".into(),
            conn_id,
            protocols: Vec::new(),
        }
    }

    fn closed(conn_id: u64) -> P2pEvent {
        P2pEvent::ConnectionClosed {
            peer_id: "peer".into(),
            conn_id,
            reason: crate::ConnectionCloseReason::Local,
        }
    }

    fn replaced(old_conn_id: u64, new_conn_id: u64) -> P2pEvent {
        P2pEvent::ConnectionReplaced {
            peer_id: "peer".into(),
            old_conn_id,
            new_conn_id,
        }
    }

    fn stream_ready(conn_id: u64, stream_id: u64, initiated_locally: bool) -> P2pEvent {
        P2pEvent::StreamReady {
            peer_id: "peer".into(),
            conn_id,
            stream_id,
            protocol_id: "/app/1".into(),
            initiated_locally,
        }
    }

    fn data_on(conn_id: u64, stream_id: u64) -> P2pEvent {
        P2pEvent::StreamData {
            peer_id: "peer".into(),
            conn_id,
            stream_id,
            data: b"x".to_vec(),
        }
    }

    #[test]
    fn unseen_connections_that_end_without_data_leave_the_carry_whole() {
        // #356: a peer connecting and disconnecting while the binding drains
        // nothing leaves no trace, peer streams and all, whichever side
        // dialed: such a connection frees its transport slot at once.
        let mut carry = Carry::default();
        for conn_id in 0..10_000 {
            for event in [
                established(conn_id),
                peer_ready(conn_id),
                stream_ready(conn_id, 1, false),
                closed(conn_id),
            ] {
                assert!(!carry.push(event));
            }
        }
        assert!(carry.is_empty());
        // Elided events leave no stale ids behind for long.
        assert!(carry.other_ids.len() <= 2, "{}", carry.other_ids.len());

        // Kept: a connection that carried data, one the binding opened a
        // stream on, and one an attempt terminal names.
        let terminal = P2pEvent::PathEstablished {
            connect_id: 9,
            peer_id: "peer".into(),
            path: crate::PathKind::Direct,
            conn_id: 3,
        };
        let kept = [
            established(1),
            stream_ready(1, 1, false),
            data_on(1, 1),
            closed(1),
            established(2),
            stream_ready(2, 2, true),
            closed(2),
            established(3),
            terminal,
            closed(3),
        ];
        for event in kept.clone() {
            carry.push(event);
        }
        assert_eq!(carry.take(20), kept);
    }

    #[test]
    fn abandoning_drops_a_streams_events_and_reports_its_data() {
        let mut carry = Carry::default();
        let [_, close] = lifecycle(1, false);
        for event in [data_on(1, 1), data_on(1, 2), data_on(1, 1), close] {
            carry.push(event);
        }
        assert!(carry.holds_stream_close(1, 1));
        assert_eq!(carry.remove_stream(1, 1), (2, true));
        assert!(!carry.holds_stream_close(1, 1));
        assert_eq!(carry.take(10), [data_on(1, 2)]);
    }

    #[test]
    fn a_connection_the_binding_saw_is_kept_after_a_partial_drain() {
        let mut carry = Carry::default();
        carry.push(established(1));
        carry.push(peer_ready(1));
        assert_eq!(carry.take(1), [established(1)]);
        carry.push(closed(1));
        assert_eq!(carry.take(10), [peer_ready(1), closed(1)]);

        // So is one whose id the binding learned from a command.
        carry.push(established(2));
        carry.mark_connection_seen(2);
        carry.push(closed(2));
        assert_eq!(carry.take(10), [established(2), closed(2)]);

        // A ping the application waits on keeps its connection.
        carry.push(established(5));
        let ping = P2pEvent::PingTimeout {
            peer_id: "peer".into(),
            conn_id: 5,
        };
        carry.push(ping.clone());
        carry.push(closed(5));
        assert_eq!(carry.take(10), [established(5), ping, closed(5)]);

        // An elided circuit takes the path events reported after its end
        // with it, as does a folded-away one.
        let path = |conn_id| P2pEvent::InboundPathEstablished {
            peer_id: "peer".into(),
            conn_id,
            path: crate::PathKind::Direct,
        };
        carry.push(established(6));
        carry.push(closed(6));
        carry.push(path(6));
        carry.push(established(7));
        carry.push(replaced(7, 8));
        carry.push(P2pEvent::InboundDirectUpgrade {
            peer_id: "peer".into(),
            old_conn_id: 7,
            new_conn_id: 8,
        });
        assert_eq!(carry.take(10), [established(8)]);

        // An attempt terminal naming an elided connection is never elided:
        // a connection can establish and close before its connect settles.
        let settled = P2pEvent::PathEstablished {
            connect_id: 10,
            peer_id: "peer".into(),
            path: crate::PathKind::Direct,
            conn_id: 6,
        };
        carry.push(settled.clone());
        assert_eq!(carry.take(10), [settled]);

        // Even when an unseen predecessor folds into it afterwards.
        carry.push(established(3));
        carry.mark_connection_seen(4);
        carry.push(replaced(3, 4));
        carry.push(closed(4));
        assert_eq!(carry.take(10), [established(4), closed(4)]);
    }

    #[test]
    fn an_unseen_connection_replaced_folds_into_its_successor() {
        let mut carry = Carry::default();
        carry.push(established(1));
        carry.push(peer_ready(1));
        carry.push(replaced(1, 2));
        carry.push(peer_ready(2));
        carry.push(replaced(2, 3));
        // The chain reads as one connection; the old connections' readiness
        // is not attributed to the survivor.
        carry.push(peer_ready(3));
        assert_eq!(carry.take(10), [established(3), peer_ready(3)]);

        // A survivor that also ends unseen leaves nothing at all.
        carry.push(established(4));
        carry.push(replaced(4, 5));
        carry.push(closed(5));
        assert!(carry.is_empty());

        // A replaced connection the binding saw is reported as replaced.
        carry.push(established(6));
        let _ = carry.take(1);
        carry.push(replaced(6, 7));
        carry.push(closed(7));
        assert_eq!(carry.take(10), [replaced(6, 7), closed(7)]);
    }

    #[test]
    fn an_unseen_connection_whose_opening_event_the_cap_dropped_is_still_elided() {
        let mut carry = Carry::default();
        carry.push(established(1));
        carry.push(established(2));
        // Other droppable events push both openings out.
        for index in 0..MAX_CARRY_EVENTS - 1 {
            carry.push(P2pEvent::PingTimeout {
                peer_id: index.to_string(),
                conn_id: 100,
            });
        }
        assert!(carry.push(P2pEvent::PingTimeout {
            peer_id: "last".into(),
            conn_id: 100,
        }));
        carry.push(peer_ready(1));
        carry.push(closed(1));
        carry.push(replaced(2, 3));
        let events = carry.take(MAX_CARRY_EVENTS + 10);
        assert!(
            events
                .iter()
                .all(|event| matches!(event, P2pEvent::PingTimeout { conn_id: 100, .. })),
            "nothing about connections 1, 2 or 3 is left"
        );
    }

    #[test]
    fn adjacent_data_for_one_stream_coalesces() {
        let mut carry = Carry::default();
        for event in [data(1, b"ab"), data(1, b"c"), data(2, b"x"), data(1, b"d")] {
            assert!(!carry.push(event));
        }
        assert_eq!(
            carry.take(10),
            [data(1, b"abc"), data(2, b"x"), data(1, b"d")]
        );
    }

    #[test]
    fn carry_cap_falls_back_to_oldest_event_when_no_messages_exist() {
        let mut carry = Carry::default();
        let mut dropped = 0;
        for index in 0..=MAX_CARRY_EVENTS {
            dropped += usize::from(carry.push(P2pEvent::PingTimeout {
                peer_id: index.to_string(),
                conn_id: 1,
            }));
        }

        assert_eq!(dropped, 1);
        assert_eq!(carry.len(), MAX_CARRY_EVENTS);
        let retained = carry.take(MAX_CARRY_EVENTS);
        assert_eq!(
            retained.first(),
            Some(&P2pEvent::PingTimeout {
                peer_id: "1".into(),
                conn_id: 1,
            })
        );
    }

    #[test]
    fn overflow_diagnostic_batch_limit_and_stats_accounting_close() {
        let mut carry = Carry::default();
        let mut overflow = OverflowDiagnostic::default();
        let mut stats = DriverStats::default();
        ingest(
            (0..MAX_CARRY_EVENTS + 10).map(|index| message(index as u8)),
            &mut carry,
            &mut overflow,
            &mut stats,
        );

        let first = take_delivery(&mut carry, &mut overflow, &mut stats, 512);
        assert_eq!(first.batch.len(), 511);
        assert_eq!(
            first.diagnostic,
            Some(P2pEvent::EventsDropped {
                dropped: 10,
                terminal_connect_ids: Vec::new(),
                total_dropped: 10,
            })
        );
        assert_eq!(stats.dispatch_attempted_synthetic, 1);
        stats.dispatch_attempted += first.batch.len() as u64;

        while !carry.is_empty() {
            let delivery = take_delivery(&mut carry, &mut overflow, &mut stats, 512);
            assert!(delivery.batch.len() <= 512);
            assert!(delivery.diagnostic.is_none());
            stats.dispatch_attempted += delivery.batch.len() as u64;
        }

        assert_eq!(stats.converted, stats.dispatch_attempted + stats.dropped);
        assert_eq!(stats.converted, (MAX_CARRY_EVENTS + 10) as u64);
        assert_eq!(stats.dropped, 10);
    }

    #[test]
    fn dropped_terminal_connect_ids_travel_in_the_overflow_diagnostic() {
        let terminal = || P2pEvent::ConnectFailed {
            connect_id: 41,
            peer_id: "peer".into(),
            kind: crate::NatErrorKind::NoPathAvailable,
            detail: "no path".into(),
        };
        let ping = |index: usize| P2pEvent::PingTimeout {
            peer_id: index.to_string(),
            conn_id: 1,
        };

        // A full carry of non-payload events drops the oldest event — the
        // terminal — under the fallback rule.
        let mut carry = Carry::default();
        let mut overflow = OverflowDiagnostic::default();
        let mut stats = DriverStats::default();
        ingest(
            [terminal()]
                .into_iter()
                .chain((0..MAX_CARRY_EVENTS).map(ping)),
            &mut carry,
            &mut overflow,
            &mut stats,
        );

        let delivery = take_delivery(&mut carry, &mut overflow, &mut stats, 512);
        assert_eq!(
            delivery.diagnostic,
            Some(P2pEvent::EventsDropped {
                dropped: 1,
                terminal_connect_ids: vec![41],
                total_dropped: 1,
            })
        );
        assert!(
            take_delivery(&mut carry, &mut overflow, &mut stats, 512)
                .diagnostic
                .is_none()
        );

        // Payload events drop before lifecycle events, so the terminal is
        // retained and no Connect ID is reported.
        let mut carry = Carry::default();
        let mut overflow = OverflowDiagnostic::default();
        let mut stats = DriverStats::default();
        ingest(
            [terminal()]
                .into_iter()
                .chain((0..MAX_CARRY_EVENTS).map(|index| message(index as u8))),
            &mut carry,
            &mut overflow,
            &mut stats,
        );

        let delivery = take_delivery(&mut carry, &mut overflow, &mut stats, 512);
        assert_eq!(
            delivery.diagnostic,
            Some(P2pEvent::EventsDropped {
                dropped: 1,
                terminal_connect_ids: Vec::new(),
                total_dropped: 1,
            })
        );
        assert!(delivery.batch.contains(&terminal()));
    }

    #[test]
    fn every_dropped_terminal_id_is_named() {
        let terminal = |connect_id: u64| P2pEvent::ConnectFailed {
            connect_id,
            peer_id: "peer".into(),
            kind: crate::NatErrorKind::NoPathAvailable,
            detail: "no path".into(),
        };
        let ping = |index: usize| P2pEvent::PingTimeout {
            peer_id: index.to_string(),
            conn_id: 1,
        };
        let lost = MAX_CARRY_EVENTS as u64;

        // Terminals pushed first are the oldest events, so enough later
        // non-payload pushes drop every one of them — more than a single
        // carry's worth, across two ingests before one delivery.
        let mut carry = Carry::default();
        let mut overflow = OverflowDiagnostic::default();
        let mut stats = DriverStats::default();
        for ids in [1..=lost / 2, lost / 2 + 1..=lost] {
            ingest(
                ids.map(terminal).chain((0..MAX_CARRY_EVENTS).map(ping)),
                &mut carry,
                &mut overflow,
                &mut stats,
            );
        }

        let Some(P2pEvent::EventsDropped {
            terminal_connect_ids,
            ..
        }) = take_delivery(&mut carry, &mut overflow, &mut stats, 512).diagnostic
        else {
            panic!("overflow must report a diagnostic");
        };
        assert_eq!(terminal_connect_ids, (1..=lost).collect::<Vec<_>>());
    }
}
