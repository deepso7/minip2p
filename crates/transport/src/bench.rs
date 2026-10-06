//! Bench-only wait counters (`bench` feature).
//!
//! A driver sees one return from [`TransportSet`]'s
//! [`wait_for_input`](crate::BlockingTransport::wait_for_input), but that one
//! call may block more than once: in one `poll(2)` over every member's
//! readiness fd, which a spurious wakeup repeats, or -- in the fallback --
//! taking turns waiting on each member in short slices. Every blocking wait
//! that ends is a real wakeup, so these counters are kept at that level: the
//! set's `poll(2)` waits, and the member waits it makes (which, for a lone
//! dual-stack QUIC member, is its one wait over both sockets).
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
    /// Blocking waits that found input ready. A set `poll(2)` that woke
    /// with nothing for any member, a spurious wakeup, counts here too.
    pub ready: u64,
    /// Blocking waits that ran out their timeout.
    pub timed_out: u64,
    /// Blocking waits ended by a [`WaitHandle`](crate::WaitHandle).
    pub interrupted: u64,
    /// Set waits with a non-zero timeout that found no member able to park
    /// and returned [`WaitOutcome::Unsupported`], sending a blocking driver
    /// to its fallback sleep.
    pub fallback_sleeps: u64,
    /// Outer `TransportSet::wait_for_input` calls with a non-zero timeout:
    /// what a driver-level counter would see. Not included in
    /// [`wakeups`](Self::wakeups).
    pub set_waits: u64,
}

impl WaitCounters {
    /// Blocking waits that returned, whatever ended them. A `ready` wait may have found input at once, without blocking;
    /// either way the driver wakes to poll.
    pub fn wakeups(&self) -> u64 {
        self.ready + self.timed_out + self.interrupted
    }

    /// The counts accumulated since `earlier`, a snapshot from the same thread.
    ///
    /// Saturates at zero, so a snapshot from another thread or one taken
    /// later gives zeros rather than wrapped counts.
    pub fn since(&self, earlier: &Self) -> Self {
        Self {
            ready: self.ready.saturating_sub(earlier.ready),
            timed_out: self.timed_out.saturating_sub(earlier.timed_out),
            interrupted: self.interrupted.saturating_sub(earlier.interrupted),
            fallback_sleeps: self.fallback_sleeps.saturating_sub(earlier.fallback_sleeps),
            set_waits: self.set_waits.saturating_sub(earlier.set_waits),
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

/// Counts one wait that may block: a member wait, or the set's `poll(2)`.
/// Non-blocking probes are not wakeups.
pub(crate) fn record_blocking_wait(timeout: Duration, outcome: WaitOutcome) {
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

/// Counts one outer set wait that may block, and whether it left the driver
/// to sleep. A non-blocking poll is neither.
pub(crate) fn record_set_wait(timeout: Duration, outcome: WaitOutcome) {
    if timeout.is_zero() {
        return;
    }
    update(|counters| {
        counters.set_waits += 1;
        if outcome == WaitOutcome::Unsupported {
            counters.fallback_sleeps += 1;
        }
    });
}
