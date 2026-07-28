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
    /// [`NEVER`](Self::NEVER) reports `u64::MAX` remaining.
    pub const fn millis_until(self, now: Now) -> u64 {
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
        assert_eq!(Deadline::NEVER.millis_until(Now::from_millis(0)), u64::MAX);
    }

    #[test]
    fn remaining_time_saturates_at_zero() {
        let deadline = Deadline::from_millis(100);
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

    #[test]
    fn converts_to_and_from_raw_millis() {
        assert_eq!(Deadline::from(25u64).as_millis(), 25);
        assert_eq!(u64::from(Deadline::from_millis(25)), 25);
    }
}
