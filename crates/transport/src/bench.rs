//! Bench-only wait counters (`bench` feature).
//!
//! Counts the blocking waits a [`SharedPoll`](crate::SharedPoll) makes: every
//! harvest with a non-zero timeout, by whether readiness ended it or it ran
//! out its timeout. That is the std swarm's wait, so an idle endpoint's
//! wakeups per second are exactly these. Zero-timeout harvests are not
//! wakeups and are not counted.
//!
//! The counters are per thread: they count waits made on the calling thread,
//! which is the thread that drives the endpoint. Read a snapshot with
//! [`wait_counters`] before and after a window and subtract with
//! [`WaitCounters::since`].
//!
//! Not for production use; without the feature none of this is compiled.

use core::cell::Cell;
use core::time::Duration;

/// Snapshot of this thread's shared-poll wait counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WaitCounters {
    /// Blocking waits that readiness ended: socket input, a host source, or
    /// the shared `Waker`.
    pub ready: u64,
    /// Blocking waits that ran out their timeout.
    pub timed_out: u64,
}

impl WaitCounters {
    /// Blocking waits that returned, whatever ended them.
    pub fn wakeups(&self) -> u64 {
        self.ready + self.timed_out
    }

    /// The counts accumulated since `earlier`, a snapshot from the same thread.
    ///
    /// Saturates at zero, so a snapshot from another thread or one taken
    /// later gives zeros rather than wrapped counts.
    pub fn since(&self, earlier: &Self) -> Self {
        Self {
            ready: self.ready.saturating_sub(earlier.ready),
            timed_out: self.timed_out.saturating_sub(earlier.timed_out),
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

/// Counts one harvest that may have blocked.
pub(crate) fn record_wait(timeout: Duration, events: usize) {
    if timeout.is_zero() {
        return;
    }
    COUNTERS.with(|counters| {
        let mut value = counters.get();
        if events == 0 {
            value.timed_out += 1;
        } else {
            value.ready += 1;
        }
        counters.set(value);
    });
}
