use crate::Deadline;

/// A single time sample handed to caller-driven components.
///
/// Hosts take one sample per drive iteration and pass the same value to every
/// agent, transport, and runtime they poll, so all of them observe a consistent
/// "now".
///
/// # Monotonic time
///
/// [`monotonic_ms`](Self::monotonic_ms) counts milliseconds from an epoch
/// chosen by the [`Clock`] that produced it. The epoch is arbitrary and carries
/// no meaning across clocks: only differences between samples from the *same*
/// clock are meaningful. Samples from one clock never decrease.
///
/// # Wall-clock time
///
/// [`unix_seconds`](Self::unix_seconds) is `None` on platforms with no
/// wall-clock source, such as an embedded board without an RTC or NTP sync.
/// Components that need real time (signed beacon freshness, certificate
/// validity) must handle its absence explicitly rather than substituting
/// monotonic time, which is not comparable across peers.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Now {
    /// Milliseconds since this clock's arbitrary epoch. Never decreases.
    pub monotonic_ms: u64,
    /// Seconds since the Unix epoch, or `None` if the platform has no
    /// wall clock.
    pub unix_seconds: Option<u64>,
}

impl Now {
    /// Creates a sample with monotonic time only and no wall clock.
    pub const fn from_millis(monotonic_ms: u64) -> Self {
        Self {
            monotonic_ms,
            unix_seconds: None,
        }
    }

    /// Creates a sample carrying both monotonic and wall-clock time.
    pub const fn new(monotonic_ms: u64, unix_seconds: u64) -> Self {
        Self {
            monotonic_ms,
            unix_seconds: Some(unix_seconds),
        }
    }

    /// Returns this sample with the given wall-clock time attached.
    pub const fn with_unix_seconds(self, unix_seconds: u64) -> Self {
        Self {
            unix_seconds: Some(unix_seconds),
            ..self
        }
    }

    /// Returns the milliseconds elapsed since `earlier`, saturating at zero.
    ///
    /// Both samples must come from the same clock; comparing across clocks is
    /// meaningless because their epochs are unrelated.
    pub const fn saturating_millis_since(self, earlier: Self) -> u64 {
        self.monotonic_ms.saturating_sub(earlier.monotonic_ms)
    }

    /// Returns a deadline `millis` in the future, saturating at
    /// [`Deadline::NEVER`].
    pub const fn deadline_after(self, millis: u64) -> Deadline {
        Deadline::from_millis(self.monotonic_ms.saturating_add(millis))
    }

    /// Returns the deadline that expires exactly at this sample.
    pub const fn as_deadline(self) -> Deadline {
        Deadline::from_millis(self.monotonic_ms)
    }
}

/// A source of monotonic (and optionally wall-clock) time.
///
/// Implementations live in adapters — never in protocol or orchestrator crates,
/// which receive [`Now`] from their caller instead.
///
/// `now()` takes `&mut self` so implementations can cache or correct state,
/// such as latching a monotonic floor over a clock that can step backwards.
///
/// # Contract
///
/// - `monotonic_ms` never decreases across successive calls.
/// - `unix_seconds` is `None` if and only if the platform has no wall clock;
///   an implementation must not fabricate one from monotonic time.
pub trait Clock {
    /// Samples the current time.
    fn now(&mut self) -> Now;
}

impl<C: Clock + ?Sized> Clock for &mut C {
    fn now(&mut self) -> Now {
        (**self).now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;

    #[test]
    fn from_millis_has_no_wall_clock() {
        let now = Now::from_millis(42);
        assert_eq!(now.monotonic_ms, 42);
        assert_eq!(now.unix_seconds, None);
    }

    #[test]
    fn with_unix_seconds_preserves_monotonic() {
        let now = Now::from_millis(42).with_unix_seconds(1_700_000_000);
        assert_eq!(now.monotonic_ms, 42);
        assert_eq!(now.unix_seconds, Some(1_700_000_000));
        assert_eq!(now, Now::new(42, 1_700_000_000));
    }

    #[test]
    fn elapsed_saturates_instead_of_wrapping() {
        let earlier = Now::from_millis(100);
        let later = Now::from_millis(250);
        assert_eq!(later.saturating_millis_since(earlier), 150);
        assert_eq!(earlier.saturating_millis_since(later), 0);
    }

    #[test]
    fn deadline_after_saturates_at_never() {
        let now = Now::from_millis(10);
        assert_eq!(now.deadline_after(5), Deadline::from_millis(15));
        assert_eq!(now.deadline_after(u64::MAX), Deadline::NEVER);
        assert_eq!(now.as_deadline(), Deadline::from_millis(10));
    }

    struct Fake(u64);

    impl Clock for Fake {
        fn now(&mut self) -> Now {
            self.0 += 1;
            Now::from_millis(self.0)
        }
    }

    /// Generic over `C: Clock`, so passing `&mut Fake` exercises the blanket
    /// impl rather than auto-deref.
    fn sample<C: Clock>(mut clock: C) -> Now {
        clock.now()
    }

    #[test]
    fn mutable_reference_forwards_to_inner_clock() {
        let mut fake = Fake(0);
        assert_eq!(sample(&mut fake).monotonic_ms, 1);
        assert_eq!(sample(&mut fake).monotonic_ms, 2);
        assert_eq!(fake.0, 2);
    }

    #[test]
    fn trait_is_object_safe() {
        let mut clock: Box<dyn Clock> = Box::new(Fake(7));
        assert_eq!(clock.now().monotonic_ms, 8);
    }
}
