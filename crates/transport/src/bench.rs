//! Bench-only wait counters (`bench` feature).
//!
//! A driver sees one return from [`TransportSet`]'s
//! [`wait_for_input`](crate::BlockingTransport::wait_for_input), but with
//! several members that one call takes turns waiting on each of them in short
//! slices, and every slice that ends is a real wakeup. These counters are kept
//! at that member-wait level so an idle bench can count them.
//!
//! The counters are per thread: they count waits made on the calling thread,
//! which is the thread that drives the endpoint. Read a snapshot with
//! [`wait_counters`] before and after a window and subtract with
//! [`WaitCounters::since`].
//!
//! Not for production use; without the feature none of this is compiled.
//!
//! [`TransportSet`]: crate::TransportSet

use core::cell::Cell;
use core::time::Duration;

use crate::WaitOutcome;

/// Snapshot of this thread's [`TransportSet`](crate::TransportSet) wait
/// counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WaitCounters {
    /// Member waits with a non-zero timeout that found input ready.
    pub ready: u64,
    /// Member waits with a non-zero timeout that ran out their timeout.
    pub timed_out: u64,
    /// Member waits with a non-zero timeout ended by a [`WaitHandle`](crate::WaitHandle).
    pub interrupted: u64,
    /// Set waits that found no member able to park and returned
    /// [`WaitOutcome::Unsupported`], sending a blocking driver to its fallback
    /// sleep.
    pub fallback_sleeps: u64,
    /// Outer `TransportSet::wait_for_input` calls: what a driver-level counter
    /// would see. Not included in [`wakeups`](Self::wakeups).
    pub set_waits: u64,
}

impl WaitCounters {
    /// Member waits with a non-zero timeout that returned, whatever ended
    /// them. A `ready` wait may have found input at once, without blocking;
    /// either way the driver wakes to poll.
    pub fn wakeups(&self) -> u64 {
        self.ready + self.timed_out + self.interrupted
    }

    /// The counts accumulated since `earlier`, a snapshot from the same thread.
    pub fn since(&self, earlier: &Self) -> Self {
        Self {
            ready: self.ready - earlier.ready,
            timed_out: self.timed_out - earlier.timed_out,
            interrupted: self.interrupted - earlier.interrupted,
            fallback_sleeps: self.fallback_sleeps - earlier.fallback_sleeps,
            set_waits: self.set_waits - earlier.set_waits,
        }
    }
}

std::thread_local! {
    static COUNTERS: Cell<WaitCounters> = Cell::new(WaitCounters::default());
}

/// This thread's counters so far.
pub fn wait_counters() -> WaitCounters {
    COUNTERS.with(Cell::get)
}

fn update(change: impl FnOnce(&mut WaitCounters)) {
    COUNTERS.with(|counters| {
        let mut value = counters.get();
        change(&mut value);
        counters.set(value);
    });
}

/// Counts one member wait. Non-blocking probes are not wakeups.
pub(crate) fn record_member_wait(timeout: Duration, outcome: WaitOutcome) {
    if timeout.is_zero() {
        return;
    }
    update(|counters| match outcome {
        WaitOutcome::Ready => counters.ready += 1,
        WaitOutcome::TimedOut => counters.timed_out += 1,
        WaitOutcome::Interrupted => counters.interrupted += 1,
        WaitOutcome::Unsupported => {}
    });
}

/// Counts one outer set wait and whether it left the driver to sleep.
pub(crate) fn record_set_wait(outcome: WaitOutcome) {
    update(|counters| {
        counters.set_waits += 1;
        if outcome == WaitOutcome::Unsupported {
            counters.fallback_sleeps += 1;
        }
    });
}
