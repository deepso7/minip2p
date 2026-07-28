//! Detached background endpoint driver.

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
    loop {
        let mut state = guard.shared.lock_state();
        if state.lifecycle != Lifecycle::Running {
            return Ok(());
        }
        let deadline = if state.active {
            DRIVER_POLL
        } else {
            DRIVER_IDLE_POLL
        };
        let cancelled_connect_ids = state.cancelled_connect_ids.clone();
        let endpoint = state.endpoint.as_mut().expect("running endpoint exists");
        let wake = endpoint.next_wake(deadline)?;
        if matches!(wake, EndpointWake::Interrupted) {
            drop(state);
            while guard.shared.pending_commands.load(Ordering::Acquire) != 0 {
                std::thread::sleep(Duration::from_millis(1));
            }
            continue;
        }

        let mut events = Vec::new();
        if let EndpointWake::Event(event) = wake {
            events.extend(convert_swarm(event));
        }
        events.extend(endpoint.poll()?.into_iter().filter_map(convert_swarm));
        let nat_events = endpoint.take_nat_events();
        events.extend(
            nat_events
                .into_iter()
                .filter(|event| {
                    nat_connect_id(event).is_none_or(|id| !cancelled_connect_ids.contains(&id))
                })
                .map(convert_nat),
        );
        events.extend(
            endpoint
                .take_pubsub_events()
                .into_iter()
                .map(convert_pubsub),
        );
        events.extend(
            endpoint
                .take_discovery_events()
                .into_iter()
                .map(convert_discovery),
        );
        drop(state);

        let listener = guard.listener.as_ref().expect("listener exists");
        for event in events {
            dispatch(listener, event);
        }
    }
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
