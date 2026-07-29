//! Detached background endpoint driver.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use minip2p::{EndpointWake, Error, NatEvent};

use crate::endpoint::{Lifecycle, Shared};
use crate::events::{convert_discovery, convert_nat, convert_pubsub, convert_swarm};
use crate::{DriverFailureKind, P2pEvent, P2pEventListener};

const DRIVER_POLL: Duration = Duration::from_millis(25);
const DRIVER_IDLE_POLL: Duration = Duration::from_millis(500);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const MAX_BATCH_PER_ITER: usize = 512;
const MAX_CARRY_EVENTS: usize = 4096;

/// Rust-side instrumentation for the background driver.
#[derive(Clone, Copy, Debug, Default)]
pub struct DriverStats {
    /// Largest bounded carry-buffer length observed.
    pub carry_high_water: usize,
    /// Source events for which a listener callback was attempted.
    pub dispatch_attempted: u64,
    /// Synthetic diagnostics for which a listener callback was attempted.
    pub dispatch_attempted_synthetic: u64,
    /// Source events discarded by overflow or shutdown.
    pub dropped: u64,
    /// Source events produced by conversion before batching.
    pub converted: u64,
    /// Completed driver-loop iterations.
    pub iterations: u64,
}

#[derive(Default)]
struct OverflowDiagnostic {
    pending: u64,
    total: u64,
}

struct Delivery {
    diagnostic: Option<P2pEvent>,
    batch: Vec<P2pEvent>,
}

#[derive(Default)]
struct Carry {
    events: BTreeMap<u64, P2pEvent>,
    message_ids: VecDeque<u64>,
    next_id: u64,
}

impl Carry {
    fn len(&self) -> usize {
        self.events.len()
    }

    fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    fn push(&mut self, event: P2pEvent) -> bool {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        if matches!(event, P2pEvent::Message { .. }) {
            self.message_ids.push_back(id);
        }
        self.events.insert(id, event);
        if self.events.len() <= MAX_CARRY_EVENTS {
            return false;
        }
        if let Some(message_id) = self.message_ids.pop_front() {
            self.events.remove(&message_id);
        } else {
            self.events.pop_first();
        }
        true
    }

    fn take(&mut self, limit: usize) -> Vec<P2pEvent> {
        let ids: Vec<_> = self.events.keys().take(limit).copied().collect();
        let mut batch = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(event) = self.events.remove(&id) {
                batch.push(event);
            }
        }
        self.prune_message_ids();
        batch
    }

    fn suppress_cancelled(&mut self, cancelled: &BTreeSet<u64>) -> usize {
        let before = self.events.len();
        self.events
            .retain(|_, event| p2p_connect_id(event).is_none_or(|id| !cancelled.contains(&id)));
        self.prune_message_ids();
        before - self.events.len()
    }

    fn prune_message_ids(&mut self) {
        self.message_ids.retain(|id| self.events.contains_key(id));
    }
}

struct ExitGuard {
    shared: Arc<Shared>,
    listener: Option<Arc<dyn P2pEventListener>>,
}

impl Drop for ExitGuard {
    fn drop(&mut self) {
        drop(self.listener.take());
        let mut state = self.shared.lock_state();
        state.endpoint.take();
        state.lifecycle = Lifecycle::Stopped;
        self.shared.driver_running.store(false, Ordering::Release);
        drop(state);
        self.shared.stopped_cv.notify_all();
    }
}

pub(crate) fn run(shared: Arc<Shared>, listener: Arc<dyn P2pEventListener>) {
    shared.lock_state().driver_thread_id = Some(std::thread::current().id());
    let mut guard = ExitGuard {
        shared,
        listener: Some(listener),
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
    if report_failure && let Some(listener) = guard.listener.as_ref() {
        {
            let mut state = guard.shared.lock_state();
            state.stats.dispatch_attempted_synthetic =
                state.stats.dispatch_attempted_synthetic.saturating_add(1);
        }
        match result {
            Ok(Err(error)) => dispatch(
                listener,
                P2pEvent::DriverFailed {
                    kind: failure_kind(&error),
                    detail: error.to_string(),
                },
            ),
            Err(_) => dispatch(
                listener,
                P2pEvent::DriverFailed {
                    kind: DriverFailureKind::Panic,
                    detail: "background endpoint driver panicked".into(),
                },
            ),
            Ok(Ok(())) => {}
        }
    }
}

fn pump(guard: &mut ExitGuard) -> Result<(), Error> {
    let mut carry = Carry::default();
    let mut overflow = OverflowDiagnostic::default();
    let mut next_keepalive_at = Instant::now() + KEEPALIVE_INTERVAL;
    loop {
        service_keepalive(&guard.shared, &mut next_keepalive_at);
        let mut state = guard.shared.lock_state();
        if state.lifecycle != Lifecycle::Running {
            state.stats.dropped = state.stats.dropped.saturating_add(carry.len() as u64);
            return Ok(());
        }
        if !carry.is_empty() || overflow.pending != 0 {
            let cancelled = carry.suppress_cancelled(&state.cancelled_connect_ids);
            state.stats.dropped = state.stats.dropped.saturating_add(cancelled as u64);
            let delivery = take_delivery(&mut carry, &mut overflow, &mut state.stats);
            state.stats.iterations = state.stats.iterations.saturating_add(1);
            drop(state);
            let listener = guard.listener.as_ref().expect("listener exists");
            if let Some(event) = delivery.diagnostic {
                dispatch(listener, event);
            }
            for event in delivery.batch {
                service_keepalive(&guard.shared, &mut next_keepalive_at);
                let should_dispatch = {
                    let mut state = guard.shared.lock_state();
                    let cancelled = p2p_connect_id(&event)
                        .is_some_and(|id| state.cancelled_connect_ids.contains(&id));
                    record_source_dispatch(cancelled, &mut state.stats)
                };
                if should_dispatch {
                    dispatch(listener, event);
                }
            }
            continue;
        }
        let deadline = if state.active {
            DRIVER_POLL
        } else {
            DRIVER_IDLE_POLL
        };
        let crate::endpoint::EndpointState {
            endpoint,
            cancelled_connect_ids,
            stats,
            ..
        } = &mut *state;
        let endpoint = endpoint.as_mut().expect("running endpoint exists");
        let wake = endpoint.next_wake(deadline)?;
        if matches!(wake, EndpointWake::Interrupted) {
            drop(state);
            while guard.shared.pending_commands.load(Ordering::Acquire) != 0 {
                std::thread::sleep(Duration::from_millis(1));
            }
            continue;
        }

        if let EndpointWake::Event(event) = wake {
            ingest(convert_swarm(event), &mut carry, &mut overflow, stats);
        }
        ingest(
            endpoint.poll()?.into_iter().filter_map(convert_swarm),
            &mut carry,
            &mut overflow,
            stats,
        );
        let nat_events = endpoint.take_nat_events();
        ingest(
            nat_events
                .into_iter()
                .filter(|event| {
                    nat_connect_id(event).is_none_or(|id| !cancelled_connect_ids.contains(&id))
                })
                .map(convert_nat),
            &mut carry,
            &mut overflow,
            stats,
        );
        ingest(
            endpoint
                .take_pubsub_events()
                .into_iter()
                .map(convert_pubsub),
            &mut carry,
            &mut overflow,
            stats,
        );
        ingest(
            endpoint
                .take_discovery_events()
                .into_iter()
                .map(convert_discovery),
            &mut carry,
            &mut overflow,
            stats,
        );
        stats.carry_high_water = stats.carry_high_water.max(carry.len());
        stats.iterations = stats.iterations.saturating_add(1);
    }
}

fn service_keepalive(shared: &Shared, next_at: &mut Instant) {
    let now = Instant::now();
    if now < *next_at {
        return;
    }
    advance_keepalive_deadline(next_at, now);
    let peers = {
        let state = shared.lock_state();
        if state.lifecycle != Lifecycle::Running {
            return;
        }
        let Some(endpoint) = state.endpoint.as_ref() else {
            return;
        };
        endpoint.connected_peers()
    };
    for peer in keepalive_targets(&peers) {
        let mut state = shared.lock_state();
        if state.lifecycle != Lifecycle::Running {
            return;
        }
        let Some(endpoint) = state.endpoint.as_mut() else {
            return;
        };
        // A peer may disconnect between the snapshot and ping. Its
        // close/timeout event is the authoritative signal.
        let _ = endpoint.ping(peer);
    }
}

fn advance_keepalive_deadline(deadline: &mut Instant, now: Instant) {
    while *deadline <= now {
        *deadline += KEEPALIVE_INTERVAL;
    }
}

fn keepalive_targets<T>(peers: &[T]) -> &[T] {
    peers
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
}

fn take_delivery(
    carry: &mut Carry,
    overflow: &mut OverflowDiagnostic,
    stats: &mut DriverStats,
) -> Delivery {
    let diagnostic = (overflow.pending != 0).then(|| {
        let event = P2pEvent::EventsDropped {
            dropped: overflow.pending,
            total_dropped: overflow.total,
        };
        overflow.pending = 0;
        stats.dispatch_attempted_synthetic = stats.dispatch_attempted_synthetic.saturating_add(1);
        event
    });
    let batch = carry.take(MAX_BATCH_PER_ITER);
    Delivery { diagnostic, batch }
}

fn nat_connect_id(event: &NatEvent) -> Option<u64> {
    match event {
        NatEvent::PathEstablished { connect_id, .. }
        | NatEvent::PathUpgraded { connect_id, .. }
        | NatEvent::HolePunchFailed { connect_id, .. }
        | NatEvent::FellBackToRelay { connect_id, .. }
        | NatEvent::ConnectFailed { connect_id, .. } => Some(connect_id.as_u64()),
        NatEvent::ReachabilityChanged { .. }
        | NatEvent::PublicAddressesChanged { .. }
        | NatEvent::RelayReserved { .. }
        | NatEvent::RelayReservationLost { .. }
        | NatEvent::InboundDirectUpgrade { .. } => None,
    }
}

fn p2p_connect_id(event: &P2pEvent) -> Option<u64> {
    match event {
        P2pEvent::PathEstablished { connect_id, .. }
        | P2pEvent::PathUpgraded { connect_id, .. }
        | P2pEvent::HolePunchFailed { connect_id, .. }
        | P2pEvent::FellBackToRelay { connect_id, .. }
        | P2pEvent::ConnectFailed { connect_id, .. } => Some(*connect_id),
        _ => None,
    }
}

fn record_source_dispatch(cancelled: bool, stats: &mut DriverStats) -> bool {
    if cancelled {
        stats.dropped = stats.dropped.saturating_add(1);
        false
    } else {
        stats.dispatch_attempted = stats.dispatch_attempted.saturating_add(1);
        true
    }
}

fn dispatch(listener: &Arc<dyn P2pEventListener>, event: P2pEvent) {
    let _ = catch_unwind(AssertUnwindSafe(|| listener.on_event(event)));
}

fn failure_kind(error: &Error) -> DriverFailureKind {
    match error {
        Error::Transport(_) => DriverFailureKind::Transport,
        Error::Swarm(_) => DriverFailureKind::Swarm,
        Error::Invariant { .. } | Error::EventBacklogExceeded { .. } | Error::Entropy => {
            DriverFailureKind::Invariant
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn carry_cap_drops_oldest_messages_before_lifecycle_events() {
        let lifecycle = P2pEvent::PeerReady {
            peer_id: "peer".into(),
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

        let first = take_delivery(&mut carry, &mut overflow, &mut stats);
        assert_eq!(first.batch.len(), MAX_BATCH_PER_ITER);
        assert_eq!(
            first.diagnostic,
            Some(P2pEvent::EventsDropped {
                dropped: 10,
                total_dropped: 10,
            })
        );
        assert_eq!(stats.dispatch_attempted_synthetic, 1);
        for _ in &first.batch {
            assert!(record_source_dispatch(false, &mut stats));
        }

        while !carry.is_empty() {
            let delivery = take_delivery(&mut carry, &mut overflow, &mut stats);
            assert!(delivery.batch.len() <= MAX_BATCH_PER_ITER);
            assert!(delivery.diagnostic.is_none());
            for _ in &delivery.batch {
                assert!(record_source_dispatch(false, &mut stats));
            }
        }

        assert_eq!(stats.converted, stats.dispatch_attempted + stats.dropped);
        assert_eq!(stats.converted, (MAX_CARRY_EVENTS + 10) as u64);
        assert_eq!(stats.dropped, 10);
    }

    #[test]
    fn live_cancellation_suppresses_events_already_in_carry() {
        let mut carry = Carry::default();
        carry.push(P2pEvent::ConnectFailed {
            connect_id: 7,
            peer_id: "peer".into(),
            kind: crate::NatErrorKind::NoPathAvailable,
            detail: "no path".into(),
        });
        carry.push(P2pEvent::PingTimeout {
            peer_id: "other".into(),
        });

        let suppressed = carry.suppress_cancelled(&BTreeSet::from([7]));
        let retained = carry.take(MAX_BATCH_PER_ITER);

        assert_eq!(suppressed, 1);
        assert_eq!(
            retained,
            vec![P2pEvent::PingTimeout {
                peer_id: "other".into()
            }]
        );

        let extracted = P2pEvent::PathEstablished {
            connect_id: 7,
            peer_id: "peer".into(),
            path: crate::PathKind::DirectDialed,
        };
        let mut stats = DriverStats::default();
        let cancelled = p2p_connect_id(&extracted).is_some_and(|id| id == 7);
        assert!(!record_source_dispatch(cancelled, &mut stats));
        assert_eq!(stats.dropped, 1);
        assert_eq!(stats.dispatch_attempted, 0);
    }

    #[test]
    fn keepalive_deadline_advances_from_its_previous_schedule() {
        let start = Instant::now();
        let mut deadline = start + KEEPALIVE_INTERVAL;

        advance_keepalive_deadline(
            &mut deadline,
            start + KEEPALIVE_INTERVAL + Duration::from_secs(25),
        );

        assert_eq!(deadline, start + Duration::from_secs(40));
    }

    #[test]
    fn keepalive_targets_include_every_connected_peer() {
        let peers: Vec<_> = (0..32).collect();

        assert_eq!(keepalive_targets(&peers), peers);
    }
}
