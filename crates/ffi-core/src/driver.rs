//! Detached background endpoint driver and event delivery.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use minip2p::{Deadline, EndpointWaitOutcome, Error};

use crate::endpoint::{Lifecycle, Shared};
use crate::events::convert_endpoint_event;
use crate::{DriverFailureKind, EventDoorbell, P2pEvent};

const MAX_CARRY_EVENTS: usize = 4096;
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
#[derive(Default)]
pub(crate) struct Carry {
    events: BTreeMap<u64, P2pEvent>,
    /// Droppable gossipsub messages, oldest first. May name taken events.
    message_ids: VecDeque<u64>,
    /// Other droppable events, oldest first. May name taken events.
    other_ids: VecDeque<u64>,
    /// Droppable events currently held.
    droppable: usize,
    dropped_terminal_connect_ids: BTreeSet<u64>,
    next_id: u64,
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
        match event {
            P2pEvent::Message { .. } => self.message_ids.push_back(id),
            _ if is_stream_event(&event) => {}
            _ => self.other_ids.push_back(id),
        }
        if !is_stream_event(&event) {
            self.droppable += 1;
        }
        self.events.insert(id, event);
        if self.droppable <= MAX_CARRY_EVENTS {
            return false;
        }
        // Both queues together name every droppable event, so one is found.
        let dropped = self
            .pop_live(Queue::Messages)
            .or_else(|| self.pop_live(Queue::Others));
        self.droppable -= 1;
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

    /// Removes the oldest event still held from one droppable queue.
    fn pop_live(&mut self, queue: Queue) -> Option<P2pEvent> {
        let ids = match queue {
            Queue::Messages => &mut self.message_ids,
            Queue::Others => &mut self.other_ids,
        };
        while let Some(id) = ids.pop_front() {
            if let Some(event) = self.events.remove(&id) {
                return Some(event);
            }
        }
        None
    }

    fn take(&mut self, limit: usize) -> Vec<P2pEvent> {
        let ids: Vec<_> = self.events.keys().take(limit).copied().collect();
        let mut batch = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(event) = self.events.remove(&id) {
                if !is_stream_event(&event) {
                    self.droppable -= 1;
                }
                batch.push(event);
            }
        }
        self.message_ids.retain(|id| self.events.contains_key(id));
        self.other_ids.retain(|id| self.events.contains_key(id));
        batch
    }

    fn take_dropped_terminal_connect_ids(&mut self) -> BTreeSet<u64> {
        core::mem::take(&mut self.dropped_terminal_connect_ids)
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
        state.lifecycle = Lifecycle::Stopped;
        self.shared.driver_running.store(false, Ordering::Release);
        drop(state);
        self.shared.latch_stopped();
    }
}

pub(crate) fn run(shared: Arc<Shared>, doorbell: Arc<dyn EventDoorbell>) {
    shared.lock_state().driver_thread_id = Some(std::thread::current().id());
    let mut guard = ExitGuard {
        shared,
        doorbell: Some(doorbell),
    };
    let result = catch_unwind(AssertUnwindSafe(|| pump(&mut guard)));
    let report_failure = {
        let mut state = guard.shared.lock_state();
        if state.lifecycle == Lifecycle::Running && matches!(&result, Err(_) | Ok(Err(_))) {
            state.lifecycle = Lifecycle::Stopping;
            true
        } else {
            false
        }
    };
    if report_failure && let Some(doorbell) = guard.doorbell.as_ref() {
        let event = match result {
            Ok(Err(error)) => P2pEvent::DriverFailed {
                kind: failure_kind(&error),
                detail: error.to_string(),
            },
            Err(_) => P2pEvent::DriverFailed {
                kind: DriverFailureKind::Panic,
                detail: "background endpoint driver panicked".into(),
            },
            Ok(Ok(())) => return,
        };
        let should_ring = {
            let mut state = guard.shared.lock_state();
            let should_ring = state.carry.is_empty();
            let crate::endpoint::EndpointState {
                carry,
                overflow,
                stats,
                ..
            } = &mut *state;
            ingest([event], carry, overflow, stats);
            state.stats.carry_high_water = state.stats.carry_high_water.max(state.carry.len());
            should_ring
        };
        if should_ring {
            ring(doorbell);
        }
    }
}

fn pump(guard: &mut ExitGuard) -> Result<(), Error> {
    loop {
        let mut state = guard.shared.lock_state();
        if state.lifecycle != Lifecycle::Running {
            return Ok(());
        }
        let was_empty = state.carry.is_empty();
        let crate::endpoint::EndpointState {
            endpoint,
            carry,
            overflow,
            stats,
            writes,
            ..
        } = &mut *state;
        let endpoint = endpoint.as_mut().expect("running endpoint exists");
        // Only `Endpoint::wait`, so the carry stays in Endpoint emission
        // order. A follow-up `poll()` would open a second batch and finish
        // that batch on its own.
        //
        // No deadline of our own: the wait already wakes for every timer the
        // endpoint's transports, protocols and agents report (mDNS's socket
        // polling included), and every command, query and `stop` interrupts
        // it. An idle driver therefore sleeps until something is due.
        let mut batch = Vec::new();
        let mut interrupted = false;
        match endpoint.wait(Deadline::NEVER)? {
            EndpointWaitOutcome::Interrupted => interrupted = true,
            EndpointWaitOutcome::Event(event) => batch.push(event),
            EndpointWaitOutcome::Deadline => {}
        }
        if !interrupted {
            for _ in 0..PUMP_DRAIN_LIMIT {
                match endpoint.wait(Duration::ZERO)? {
                    EndpointWaitOutcome::Event(event) => batch.push(event),
                    EndpointWaitOutcome::Deadline => break,
                    EndpointWaitOutcome::Interrupted => {
                        interrupted = true;
                        break;
                    }
                }
            }
        }
        if interrupted && batch.is_empty() {
            drop(state);
            while guard.shared.pending_commands.load(Ordering::Acquire) != 0 {
                std::thread::sleep(Duration::from_millis(1));
            }
            continue;
        }
        // Pending writes follow each event first: a Writable resends a held
        // tail and, once it is all accepted, settles the binding's write
        // right after the event that caused it.
        let mut converted = Vec::with_capacity(batch.len());
        for event in batch {
            let settled = writes.observe(endpoint, &event);
            converted.extend(convert_endpoint_event(endpoint, event));
            converted.extend(settled);
        }
        ingest(converted, carry, overflow, stats);
        stats.carry_high_water = stats.carry_high_water.max(carry.len());
        stats.iterations = stats.iterations.saturating_add(1);
        let should_ring = was_empty && !carry.is_empty();
        drop(state);
        if should_ring {
            ring(guard.doorbell.as_ref().expect("doorbell exists"));
        }
        if interrupted {
            while guard.shared.pending_commands.load(Ordering::Acquire) != 0 {
                std::thread::sleep(Duration::from_millis(1));
            }
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
        Error::Invariant { .. } | Error::EventBacklogExceeded { .. } | Error::Entropy => {
            DriverFailureKind::Invariant
        }
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
                path: crate::PathKind::DirectDialed,
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
                to: crate::PathKind::DirectPunched,
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
            }));
        }

        assert_eq!(dropped, 1);
        assert_eq!(carry.len(), MAX_CARRY_EVENTS);
        let retained = carry.take(MAX_CARRY_EVENTS);
        assert_eq!(
            retained.first(),
            Some(&P2pEvent::PingTimeout {
                peer_id: "1".into()
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
