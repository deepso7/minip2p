//! Detached background endpoint driver.

use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use minip2p::{EndpointWake, Error, NatEvent};

use crate::endpoint::{Lifecycle, Shared};
use crate::events::{convert_discovery, convert_nat, convert_pubsub, convert_swarm};
use crate::{DriverFailureKind, P2pEvent, P2pEventListener};

const DRIVER_POLL: Duration = Duration::from_millis(25);
const DRIVER_IDLE_POLL: Duration = Duration::from_millis(500);
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
    let mut carry = VecDeque::new();
    let mut overflow = OverflowDiagnostic::default();
    loop {
        let mut state = guard.shared.lock_state();
        if state.lifecycle != Lifecycle::Running {
            state.stats.dropped = state.stats.dropped.saturating_add(carry.len() as u64);
            return Ok(());
        }
        if !carry.is_empty() || overflow.pending != 0 {
            let delivery = take_delivery(&mut carry, &mut overflow, &mut state.stats);
            state.stats.iterations = state.stats.iterations.saturating_add(1);
            drop(state);
            let listener = guard.listener.as_ref().expect("listener exists");
            if let Some(event) = delivery.diagnostic {
                dispatch(listener, event);
            }
            for event in delivery.batch {
                dispatch(listener, event);
            }
            continue;
        }
        let deadline = if state.active {
            DRIVER_POLL
        } else {
            DRIVER_IDLE_POLL
        };
        let cancelled_connect_ids = state.cancelled_connect_ids.clone();
        let crate::endpoint::EndpointState {
            endpoint, stats, ..
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

fn ingest(
    events: impl IntoIterator<Item = P2pEvent>,
    carry: &mut VecDeque<P2pEvent>,
    overflow: &mut OverflowDiagnostic,
    stats: &mut DriverStats,
) {
    let before = carry.len();
    carry.extend(events);
    stats.converted = stats
        .converted
        .saturating_add(carry.len().saturating_sub(before) as u64);
    let dropped = trim_carry(carry) as u64;
    stats.dropped = stats.dropped.saturating_add(dropped);
    overflow.pending = overflow.pending.saturating_add(dropped);
    overflow.total = overflow.total.saturating_add(dropped);
}

fn take_delivery(
    carry: &mut VecDeque<P2pEvent>,
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
    let batch: Vec<_> = carry.drain(..carry.len().min(MAX_BATCH_PER_ITER)).collect();
    stats.dispatch_attempted = stats.dispatch_attempted.saturating_add(batch.len() as u64);
    Delivery { diagnostic, batch }
}

fn trim_carry(carry: &mut VecDeque<P2pEvent>) -> usize {
    let excess = carry.len().saturating_sub(MAX_CARRY_EVENTS);
    if excess == 0 {
        return 0;
    }
    let messages_to_drop = excess.min(
        carry
            .iter()
            .filter(|event| matches!(event, P2pEvent::Message { .. }))
            .count(),
    );
    let mut dropped_messages = 0;
    carry.retain(|event| {
        if dropped_messages < messages_to_drop && matches!(event, P2pEvent::Message { .. }) {
            dropped_messages += 1;
            false
        } else {
            true
        }
    });
    for _ in 0..excess - messages_to_drop {
        carry.pop_front();
    }
    excess
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
        let mut carry = VecDeque::from([lifecycle.clone()]);
        carry.extend((0..=MAX_CARRY_EVENTS).map(|index| message(index as u8)));

        let dropped = trim_carry(&mut carry);

        assert_eq!(dropped, 2);
        assert_eq!(carry.len(), MAX_CARRY_EVENTS);
        assert_eq!(carry.front(), Some(&lifecycle));
        assert_eq!(carry.get(1), Some(&message(2)));
    }

    #[test]
    fn carry_cap_falls_back_to_oldest_event_when_no_messages_exist() {
        let mut carry = VecDeque::new();
        for index in 0..=MAX_CARRY_EVENTS {
            carry.push_back(P2pEvent::PingTimeout {
                peer_id: index.to_string(),
            });
        }

        assert_eq!(trim_carry(&mut carry), 1);
        assert_eq!(carry.len(), MAX_CARRY_EVENTS);
        assert_eq!(
            carry.front(),
            Some(&P2pEvent::PingTimeout {
                peer_id: "1".into()
            })
        );
    }

    #[test]
    fn overflow_diagnostic_batch_limit_and_stats_accounting_close() {
        let mut carry = VecDeque::new();
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

        while !carry.is_empty() {
            let delivery = take_delivery(&mut carry, &mut overflow, &mut stats);
            assert!(delivery.batch.len() <= MAX_BATCH_PER_ITER);
            assert!(delivery.diagnostic.is_none());
        }

        assert_eq!(stats.converted, stats.dispatch_attempted + stats.dropped);
        assert_eq!(stats.converted, (MAX_CARRY_EVENTS + 10) as u64);
        assert_eq!(stats.dropped, 10);
    }
}
