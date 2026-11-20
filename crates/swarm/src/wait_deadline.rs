//! [`WaitDeadline`]: how long a blocking wait may block.

use std::time::{Duration, Instant};

/// When a blocking wait should give up.
///
/// Everywhere the driver can wait ([`Swarm::poll_next`](crate::Swarm::poll_next), [`Swarm::run_until`](crate::Swarm::run_until))
/// accepts `impl Into<WaitDeadline>`, so callers pass whichever is natural:
///
/// - an [`Instant`] -- absolute deadline,
/// - a [`Duration`] -- relative timeout from now,
/// - [`WaitDeadline::NEVER`] -- wait indefinitely.
///
/// An [`Instant`] that has already passed is the same deadline as
/// [`Duration::ZERO`]: the wait still returns what is already ready and polls
/// once, but never sleeps. A deadline bounds blocking, not delivery, so a
/// caller with a strict operation timeout checks its own clock before each
/// wait.
///
/// # Not [`minip2p_core::platform::Deadline`]
///
/// The two are deliberately distinct types. This one is how
/// long a *caller* is prepared to block, so it is measured in real time and
/// deliberately independent of the driver's injected [`Clock`](minip2p_core::platform::Clock): a test that
/// freezes the clock to exercise protocol timers still wants its own waits to
/// end. The platform type is when a *component* next needs attention, on the
/// monotonic timeline of the samples the driver hands out, and is what
/// [`Transport::next_deadline`](minip2p_transport::Transport::next_deadline)
/// reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitDeadline {
    at: Option<Instant>,
}

impl WaitDeadline {
    /// Wait indefinitely; the call returns only when an event arrives (or,
    /// for `run_until`, when the predicate matches).
    pub const NEVER: WaitDeadline = WaitDeadline { at: None };

    /// Whether the deadline has already passed. [`WaitDeadline::NEVER`] never
    /// passes.
    pub fn has_passed(self) -> bool {
        self.is_expired_at(Instant::now())
    }

    /// The earlier of two deadlines ([`WaitDeadline::NEVER`] is latest).
    ///
    /// Lets callers fold an extra timer source into a wait without access
    /// to the deadline's internals, mirroring how [`Swarm::poll_next`](crate::Swarm::poll_next)
    /// folds the core's protocol timers into its budget.
    pub fn earliest(self, other: WaitDeadline) -> WaitDeadline {
        let at = match (self.at, other.at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        WaitDeadline { at }
    }

    /// Time left until the deadline; `None` for [`WaitDeadline::NEVER`], and
    /// zero once it has passed. Lets a host that blocks on its own budget
    /// (the Endpoint's wait) fold the caller's deadline in.
    pub fn remaining(self) -> Option<Duration> {
        self.remaining_at(Instant::now())
    }

    /// Whether the deadline has passed at `now`.
    pub(crate) fn is_expired_at(self, now: Instant) -> bool {
        self.at.is_some_and(|deadline| now >= deadline)
    }

    /// Time left from `now`; `None` means unbounded.
    pub(crate) fn remaining_at(self, now: Instant) -> Option<Duration> {
        self.at
            .map(|deadline| deadline.saturating_duration_since(now))
    }
}

impl From<Instant> for WaitDeadline {
    fn from(instant: Instant) -> Self {
        WaitDeadline { at: Some(instant) }
    }
}

impl From<Duration> for WaitDeadline {
    /// Relative timeout starting now. A duration too large for `Instant`
    /// arithmetic means [`WaitDeadline::NEVER`].
    fn from(timeout: Duration) -> Self {
        WaitDeadline {
            at: Instant::now().checked_add(timeout),
        }
    }
}
