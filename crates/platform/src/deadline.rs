use core::fmt;

use crate::Now;

/// A point on a clock's monotonic timeline, in milliseconds.
///
/// Caller-driven components report deadlines so the host knows how long it may
/// idle before polling again. A deadline is only comparable to [`Now`] samples
/// from the same [`Clock`](crate::Clock), since monotonic epochs are arbitrary.
///
/// Ordering is chronological, so the earliest deadline in a collection is its
/// minimum and [`NEVER`](Self::NEVER) sorts last.
///
/// # Absent versus distant deadlines
///
/// "Nothing scheduled" is expressed as `Option::None`, not as `NEVER`. `NEVER`
/// is the saturating result of arithmetic that overflows past the end of the
/// timeline, and it never expires.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Deadline(u64);

impl Deadline {
    /// A deadline that never expires.
    ///
    /// Produced by saturating arithmetic such as
    /// [`Now::deadline_after`](Now::deadline_after) with a huge delay.
    pub const NEVER: Self = Self(u64::MAX);

    /// A deadline that has already expired.
    ///
    /// Expired at every point on every timeline, so a component with work
    /// buffered can report "poll me again without idling" without knowing what
    /// the host's clock currently reads.
    pub const IMMEDIATE: Self = Self(0);

    /// Creates a deadline that expires when monotonic time reaches `millis`.
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// Returns the monotonic milliseconds value this deadline expires at.
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Returns whether this deadline never expires.
    pub const fn is_never(self) -> bool {
        self.0 == u64::MAX
    }

    /// Returns whether this deadline has expired as of `now`.
    ///
    /// [`NEVER`](Self::NEVER) is never expired, even at the end of the
    /// timeline.
    pub const fn is_expired_at(self, now: Now) -> bool {
        !self.is_never() && now.monotonic_ms >= self.0
    }

    /// Returns the milliseconds remaining until this deadline, or zero if it
    /// has already expired.
    ///
    /// [`NEVER`](Self::NEVER) always reports `u64::MAX` remaining, however far
    /// monotonic time has advanced, so it stays consistent with
    /// [`is_expired_at`](Self::is_expired_at) never reporting it as due.
    pub const fn millis_until(self, now: Now) -> u64 {
        if self.is_never() {
            return u64::MAX;
        }
        self.0.saturating_sub(now.monotonic_ms)
    }

    /// Returns a deadline `millis` later, saturating at
    /// [`NEVER`](Self::NEVER).
    pub const fn saturating_add_millis(self, millis: u64) -> Self {
        Self(self.0.saturating_add(millis))
    }

    /// Returns whichever of the two deadlines comes first.
    pub const fn earliest(self, other: Self) -> Self {
        if self.0 <= other.0 { self } else { other }
    }

    /// Merges two optional deadlines, keeping whichever comes first.
    ///
    /// Useful for folding the deadlines of several subsystems into the one a
    /// runtime reports to its host.
    pub const fn earliest_opt(left: Option<Self>, right: Option<Self>) -> Option<Self> {
        match (left, right) {
            (Some(left), Some(right)) => Some(left.earliest(right)),
            (Some(only), None) | (None, Some(only)) => Some(only),
            (None, None) => None,
        }
    }
}

impl fmt::Display for Deadline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_never() {
            f.write_str("never")
        } else {
            write!(f, "{}ms", self.0)
        }
    }
}

impl From<u64> for Deadline {
    fn from(value: u64) -> Self {
        Self::from_millis(value)
    }
}

impl From<Deadline> for u64 {
    fn from(value: Deadline) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn expires_once_now_reaches_it() {
        let deadline = Deadline::from_millis(100);
        assert!(!deadline.is_expired_at(Now::from_millis(99)));
        assert!(deadline.is_expired_at(Now::from_millis(100)));
        assert!(deadline.is_expired_at(Now::from_millis(101)));
    }

    #[test]
    fn never_does_not_expire_at_end_of_timeline() {
        assert!(Deadline::NEVER.is_never());
        assert!(!Deadline::NEVER.is_expired_at(Now::from_millis(u64::MAX)));
    }

    #[test]
    fn never_reports_full_remaining_time_however_far_now_has_advanced() {
        // A plain saturating subtraction would shrink this toward zero as time
        // passes while `is_expired_at` still reported "not due", so a host
        // idling for `millis_until` would wake early for no reason.
        for now in [0, 1, 1_000_000, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
            let now = Now::from_millis(now);
            assert_eq!(
                Deadline::NEVER.millis_until(now),
                u64::MAX,
                "millis_until disagreed with is_expired_at at {now:?}"
            );
            assert!(!Deadline::NEVER.is_expired_at(now));
        }
    }

    #[test]
    fn immediate_is_always_due() {
        for now in [0, 1, 1_000_000, u64::MAX] {
            let now = Now::from_millis(now);
            assert!(
                Deadline::IMMEDIATE.is_expired_at(now),
                "IMMEDIATE must be due at {now:?}"
            );
            assert_eq!(Deadline::IMMEDIATE.millis_until(now), 0);
        }
        // Sorts ahead of any real deadline when folding subsystem deadlines.
        assert_eq!(
            Deadline::IMMEDIATE.earliest(Deadline::from_millis(5)),
            Deadline::IMMEDIATE
        );
    }

    #[test]
    fn remaining_time_saturates_at_zero() {
        // Raw millis are read back as an instant, not a duration.
        let deadline = Deadline::from(100u64);
        assert_eq!(deadline.as_millis(), 100);
        assert_eq!(u64::from(deadline), 100);

        assert_eq!(deadline.millis_until(Now::from_millis(40)), 60);
        assert_eq!(deadline.millis_until(Now::from_millis(100)), 0);
        assert_eq!(deadline.millis_until(Now::from_millis(500)), 0);
    }

    #[test]
    fn adding_saturates_at_never() {
        assert_eq!(
            Deadline::from_millis(10).saturating_add_millis(5),
            Deadline::from_millis(15)
        );
        assert_eq!(
            Deadline::from_millis(10).saturating_add_millis(u64::MAX),
            Deadline::NEVER
        );
    }

    #[test]
    fn earliest_picks_the_sooner_deadline() {
        let soon = Deadline::from_millis(10);
        let late = Deadline::from_millis(20);
        assert_eq!(soon.earliest(late), soon);
        assert_eq!(late.earliest(soon), soon);
        assert_eq!(soon.earliest(Deadline::NEVER), soon);
    }

    #[test]
    fn earliest_opt_treats_none_as_unscheduled() {
        let soon = Some(Deadline::from_millis(10));
        let late = Some(Deadline::from_millis(20));
        assert_eq!(Deadline::earliest_opt(soon, late), soon);
        assert_eq!(Deadline::earliest_opt(late, soon), soon);
        assert_eq!(Deadline::earliest_opt(soon, None), soon);
        assert_eq!(Deadline::earliest_opt(None, late), late);
        assert_eq!(Deadline::earliest_opt(None, None), None);
    }

    #[test]
    fn ordering_is_chronological_with_never_last() {
        let mut deadlines = [
            Deadline::NEVER,
            Deadline::from_millis(30),
            Deadline::from_millis(10),
        ];
        deadlines.sort();
        assert_eq!(
            deadlines,
            [
                Deadline::from_millis(10),
                Deadline::from_millis(30),
                Deadline::NEVER
            ]
        );
        assert_eq!(
            deadlines.iter().copied().min(),
            Some(Deadline::from_millis(10))
        );
    }

    #[test]
    fn display_names_the_never_sentinel() {
        assert_eq!(format!("{}", Deadline::from_millis(25)), "25ms");
        assert_eq!(format!("{}", Deadline::NEVER), "never");
    }
}
