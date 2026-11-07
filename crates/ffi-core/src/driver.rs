//! Detached background endpoint driver: a thread that waits on the std
//! endpoint and feeds the shared [`carry`](crate::carry).

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::Duration;

use minip2p::{EndpointWaitOutcome, Error, PeerId, WaitDeadline};

use crate::carry::PUMP_DRAIN_LIMIT;
use crate::endpoint::{Lifecycle, Live, Shared};
use crate::events::{CloseOutcome, UnfinishedConnection, convert_endpoint_event};
use crate::{DriverFailureKind, EventDoorbell, P2pEvent, driver_failure_kind};

pub(crate) struct ExitGuard {
    shared: Arc<Shared>,
    doorbell: Option<Arc<dyn EventDoorbell>>,
}

impl Drop for ExitGuard {
    fn drop(&mut self) {
        drop(self.doorbell.take());
        self.shared.finish_stop(self.shared.lock_state());
    }
}

/// Runs the driver until `stop` or a failure, then closes the endpoint
/// outside the state lock: within the stop's timeout, or at once after a
/// failure. The close's events, but for attempt terminals, are carried
/// ahead of the last event, `EndpointClosed`; the guard then latches
/// stopped. Only a panic leaves the endpoint to the guard's plain drop.
pub(crate) fn run(shared: Arc<Shared>, doorbell: Arc<dyn EventDoorbell>) {
    run_with(shared, doorbell, pump);
}

/// [`run`] around `pump`, which tests replace to inject a driver failure.
pub(crate) fn run_with(
    shared: Arc<Shared>,
    doorbell: Arc<dyn EventDoorbell>,
    pump: impl FnOnce(&mut ExitGuard) -> Result<(), Error>,
) {
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
        let report_failure = matches!(state.lifecycle, Lifecycle::Running(_)) && failed;
        if report_failure {
            guard.shared.begin_stop(&mut state, Duration::ZERO);
        }
        let failure = match result {
            Ok(Err(error)) if report_failure => Some(P2pEvent::DriverFailed {
                kind: driver_failure_kind(&error),
                detail: error.to_string(),
            }),
            Err(_) if report_failure => Some(P2pEvent::DriverFailed {
                kind: DriverFailureKind::Panic,
                detail: "background endpoint driver panicked".into(),
            }),
            _ => None,
        };
        // The pump only returns once shutdown has begun. A panic may have
        // left the endpoint mid-update: the guard drops it.
        let (endpoint, timeout) = match &mut state.lifecycle {
            Lifecycle::Stopping {
                live,
                close_timeout,
            } if !panicked => (
                live.take().map(|live| live.endpoint),
                if failed {
                    Duration::ZERO
                } else {
                    *close_timeout
                },
            ),
            _ => (None, Duration::ZERO),
        };
        (failure, endpoint, timeout)
    };
    // The drain's events (connection ends among them) go to the binding
    // ahead of `EndpointClosed`.
    let mut drained = Vec::new();
    let closed = match endpoint {
        Some(endpoint) => {
            let report = endpoint.close_within(timeout);
            drained.extend(report.events.into_iter().filter_map(convert_endpoint_event));
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
            .carry
            .ingest(failure.into_iter().chain(drained).chain([closed]))
    {
        ring(doorbell);
    }
}

fn pump(guard: &mut ExitGuard) -> Result<(), Error> {
    loop {
        let mut state = guard.shared.lock_state();
        let crate::endpoint::EndpointState {
            lifecycle: Lifecycle::Running(Live { endpoint, writes }),
            published_peers,
            ..
        } = &mut *state
        else {
            return Ok(());
        };
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
                .map(crate::write_accepted_event);
            converted.extend(convert_endpoint_event(event));
            converted.extend(settled);
        }
        // Published and ingested before `state` is released, so no command
        // runs between the endpoint emitting these events and the carry
        // holding them, and the doorbell never rings ahead of the peers.
        guard.shared.publish_peers(endpoint, published_peers);
        let should_ring = {
            let mut events = guard.shared.lock_events();
            events.carry.stats.iterations = events.carry.stats.iterations.saturating_add(1);
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

fn ring(doorbell: &Arc<dyn EventDoorbell>) {
    // Foreign callbacks are advisory; an unwind must not stop event delivery.
    drop(catch_unwind(AssertUnwindSafe(|| {
        doorbell.on_events_ready()
    })));
}
