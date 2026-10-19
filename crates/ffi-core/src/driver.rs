//! Detached background endpoint driver: a thread that waits on the std
//! endpoint and feeds the shared [`carry`](crate::carry).

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use minip2p::{EndpointWaitOutcome, Error, PeerId, WaitDeadline};

use crate::carry::PUMP_DRAIN_LIMIT;
use crate::endpoint::{Lifecycle, Shared};
use crate::events::{CloseOutcome, UnfinishedConnection, convert_endpoint_event};
use crate::{DriverFailureKind, EventDoorbell, P2pEvent, driver_failure_kind};

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
                kind: driver_failure_kind(&error),
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
