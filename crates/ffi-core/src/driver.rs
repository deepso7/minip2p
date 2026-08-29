//! Detached background endpoint driver and event delivery.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use minip2p::{EndpointWake, Error, NatEvent};

use crate::endpoint::{Lifecycle, Shared};
use crate::events::{convert_discovery, convert_nat, convert_pubsub, convert_swarm};
use crate::{DriverFailureKind, EventDoorbell, P2pEvent};

const DRIVER_POLL: Duration = Duration::from_millis(25);
const DRIVER_IDLE_POLL: Duration = Duration::from_millis(500);
const MAX_CARRY_EVENTS: usize = 4096;

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

#[derive(Default)]
pub(crate) struct OverflowDiagnostic {
    pending: u64,
    total: u64,
}

pub(crate) struct Delivery {
    pub(crate) diagnostic: Option<P2pEvent>,
    pub(crate) batch: Vec<P2pEvent>,
}

#[derive(Default)]
pub(crate) struct Carry {
    events: BTreeMap<u64, P2pEvent>,
    payload_ids: VecDeque<u64>,
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

    pub(crate) fn push(&mut self, event: P2pEvent) -> bool {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        if is_payload_event(&event) {
            self.payload_ids.push_back(id);
        }
        self.events.insert(id, event);
        if self.events.len() <= MAX_CARRY_EVENTS {
            return false;
        }
        let dropped = if let Some(payload_id) = self.payload_ids.pop_front() {
            self.events.remove(&payload_id)
        } else {
            self.events.pop_first().map(|(_, event)| event)
        };
        if let Some(connect_id) = dropped.as_ref().and_then(terminal_connect_id) {
            self.dropped_terminal_connect_ids.insert(connect_id);
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
        self.prune_payload_ids();
        batch
    }

    pub(crate) fn suppress_cancelled(&mut self, cancelled: &BTreeSet<u64>) -> usize {
        let before = self.events.len();
        self.events
            .retain(|_, event| p2p_connect_id(event).is_none_or(|id| !cancelled.contains(&id)));
        self.prune_payload_ids();
        before - self.events.len()
    }

    fn take_dropped_terminal_connect_ids(&mut self) -> BTreeSet<u64> {
        core::mem::take(&mut self.dropped_terminal_connect_ids)
    }

    fn prune_payload_ids(&mut self) {
        self.payload_ids.retain(|id| self.events.contains_key(id));
    }
}

fn is_payload_event(event: &P2pEvent) -> bool {
    matches!(
        event,
        P2pEvent::Message { .. } | P2pEvent::StreamData { .. }
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
        state.endpoint.take();
        state.lifecycle = Lifecycle::Stopped;
        self.shared.driver_running.store(false, Ordering::Release);
        drop(state);
        self.shared.stopped_cv.notify_all();
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
        let deadline = if state.active {
            DRIVER_POLL
        } else {
            DRIVER_IDLE_POLL
        };
        let crate::endpoint::EndpointState {
            endpoint,
            cancelled_connect_ids,
            connect_ids,
            carry,
            overflow,
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
            ingest(convert_swarm(event), carry, overflow, stats);
        }
        ingest(
            endpoint.poll()?.into_iter().filter_map(convert_swarm),
            carry,
            overflow,
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
            carry,
            overflow,
            stats,
        );
        ingest(
            endpoint
                .take_pubsub_events()
                .into_iter()
                .map(convert_pubsub),
            carry,
            overflow,
            stats,
        );
        ingest(
            endpoint
                .take_discovery_events()
                .into_iter()
                .map(convert_discovery),
            carry,
            overflow,
            stats,
        );
        for id in carry.take_dropped_terminal_connect_ids() {
            connect_ids.remove(&id);
            cancelled_connect_ids.remove(&id);
        }
        cancelled_connect_ids.clear();
        stats.carry_high_water = stats.carry_high_water.max(carry.len());
        stats.iterations = stats.iterations.saturating_add(1);
        let should_ring = was_empty && !carry.is_empty();
        drop(state);
        if should_ring {
            ring(guard.doorbell.as_ref().expect("doorbell exists"));
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
            total_dropped: overflow.total,
        };
        overflow.pending = 0;
        stats.dispatch_attempted_synthetic = stats.dispatch_attempted_synthetic.saturating_add(1);
        event
    });
    let batch = carry.take(limit.saturating_sub(usize::from(diagnostic.is_some())));
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
        | NatEvent::InboundPathEstablished { .. }
        | NatEvent::InboundDirectUpgrade { .. } => None,
    }
}

pub(crate) fn p2p_connect_id(event: &P2pEvent) -> Option<u64> {
    match event {
        P2pEvent::PathEstablished { connect_id, .. }
        | P2pEvent::PathUpgraded { connect_id, .. }
        | P2pEvent::HolePunchFailed { connect_id, .. }
        | P2pEvent::FellBackToRelay { connect_id, .. }
        | P2pEvent::ConnectFailed { connect_id, .. } => Some(*connect_id),
        _ => None,
    }
}

pub(crate) fn terminal_connect_id(event: &P2pEvent) -> Option<u64> {
    match event {
        P2pEvent::PathEstablished {
            connect_id, path, ..
        } if !matches!(path, crate::PathKind::Relayed { .. }) => Some(*connect_id),
        P2pEvent::PathUpgraded { connect_id, .. }
        | P2pEvent::FellBackToRelay { connect_id, .. }
        | P2pEvent::ConnectFailed { connect_id, .. } => Some(*connect_id),
        _ => None,
    }
}

fn ring(doorbell: &Arc<dyn EventDoorbell>) {
    let _ = catch_unwind(AssertUnwindSafe(|| doorbell.on_events_ready()));
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
                path: crate::PathKind::DirectDialed,
            }),
            Some(7)
        );
        assert_eq!(
            terminal_connect_id(&P2pEvent::PathEstablished {
                connect_id: 8,
                peer_id: "peer".into(),
                path: crate::PathKind::Relayed {
                    relay_peer_id: "relay".into()
                },
            }),
            None
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
    fn stream_data_uses_the_payload_overflow_class() {
        assert!(is_payload_event(&P2pEvent::StreamData {
            peer_id: "peer".into(),
            conn_id: 1,
            stream_id: 2,
            data: vec![3],
        }));
        assert!(!is_payload_event(&P2pEvent::StreamClosed {
            peer_id: "peer".into(),
            conn_id: 1,
            stream_id: 2,
        }));
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
        let retained = carry.take(512);

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
        assert_eq!(p2p_connect_id(&extracted), Some(7));
    }
}
