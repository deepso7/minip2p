use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::{Clock, EntropyError, EntropySource, Now};

/// [`Clock`] backed by the operating system's clocks.
///
/// Monotonic time is measured from an [`Instant`] epoch captured when the clock
/// is created, so `monotonic_ms` starts near zero and cannot go backwards.
/// Wall-clock time comes from [`SystemTime`] and can jump in either direction
/// as the system clock is adjusted, which is exactly why the two are reported
/// separately.
///
/// # Example
///
/// ```
/// use minip2p_platform::{Clock, StdClock};
///
/// let mut clock = StdClock::new();
/// let start = clock.now();
/// let later = clock.now();
/// assert!(later.monotonic_ms >= start.monotonic_ms);
/// ```
#[derive(Clone, Copy, Debug)]
pub struct StdClock {
    epoch: Instant,
}

impl StdClock {
    /// Creates a clock whose monotonic timeline starts now.
    pub fn new() -> Self {
        Self {
            epoch: Instant::now(),
        }
    }

    /// Creates a clock measuring monotonic time from an existing epoch.
    ///
    /// Use this to keep several clocks on one timeline, so their samples stay
    /// comparable.
    pub fn with_epoch(epoch: Instant) -> Self {
        Self { epoch }
    }

    /// Returns the epoch this clock measures monotonic time from.
    pub fn epoch(&self) -> Instant {
        self.epoch
    }
}

impl Default for StdClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for StdClock {
    fn now(&mut self) -> Now {
        // Saturating: u64 milliseconds covers ~584 million years of uptime, so
        // the clamp is unreachable in practice but keeps the cast total.
        let monotonic_ms = u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
        // `None` when the system clock is set before 1970 — an honest "no
        // usable wall clock" rather than a fabricated timestamp.
        let unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|since_epoch| since_epoch.as_secs());

        Now {
            monotonic_ms,
            unix_seconds,
        }
    }
}

/// [`EntropySource`] backed by the operating system's CSPRNG.
///
/// # Example
///
/// ```
/// use minip2p_platform::{EntropySource, StdEntropy};
///
/// let mut entropy = StdEntropy::new();
/// let mut key = [0u8; 32];
/// entropy.fill_bytes(&mut key).expect("os entropy");
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct StdEntropy;

impl StdEntropy {
    /// Creates a handle to the OS entropy source.
    pub const fn new() -> Self {
        Self
    }
}

impl EntropySource for StdEntropy {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::fill(output).map_err(|error| match error.raw_os_error() {
            Some(code) => EntropyError::failed_with_code("os entropy source failed", code),
            None => EntropyError::failed("os entropy source failed"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn monotonic_time_starts_near_the_epoch_and_advances() {
        let mut clock = StdClock::new();
        let start = clock.now();
        assert!(start.monotonic_ms < 1_000, "expected a fresh timeline");

        sleep(Duration::from_millis(5));
        let later = clock.now();
        assert!(later.monotonic_ms >= start.monotonic_ms + 5);
    }

    #[test]
    fn samples_never_decrease() {
        let mut clock = StdClock::new();
        let mut previous = clock.now();
        for _ in 0..100 {
            let current = clock.now();
            assert!(current.monotonic_ms >= previous.monotonic_ms);
            previous = current;
        }
    }

    #[test]
    fn samples_are_measured_from_the_injected_epoch() {
        const OFFSET_MS: u64 = 5_000;

        let epoch = Instant::now();
        let mut shared = StdClock::with_epoch(epoch);
        // An epoch further in the past must read as further along the
        // timeline, by exactly the offset between the two epochs.
        let mut older = StdClock::with_epoch(epoch - Duration::from_millis(OFFSET_MS));

        let from_shared = shared.now().monotonic_ms;
        let from_older = older.now().monotonic_ms;

        let delta = from_older
            .checked_sub(from_shared)
            .expect("older epoch must read further along the timeline");
        assert!(
            delta.abs_diff(OFFSET_MS) < 1_000,
            "expected ~{OFFSET_MS}ms between epochs, got {delta}ms"
        );
    }

    #[test]
    fn clocks_sharing_an_epoch_produce_comparable_samples() {
        let epoch = Instant::now();
        let mut first = StdClock::with_epoch(epoch);
        let mut second = StdClock::with_epoch(epoch);
        assert_eq!(first.epoch(), second.epoch());

        let before = first.now().monotonic_ms;
        sleep(Duration::from_millis(5));
        let after = second.now().monotonic_ms;

        // Read across two clocks, the sleep must be visible as elapsed time on
        // the shared timeline.
        assert!(
            after >= before + 5,
            "sleep not observable across clocks: {before} -> {after}"
        );
        assert!(after - before < 1_000);
    }

    #[test]
    fn reports_a_plausible_wall_clock() {
        let mut clock = StdClock::new();
        let unix_seconds = clock.now().unix_seconds.expect("hosts have a wall clock");
        // Sometime after 2020; catches a stubbed or zeroed implementation.
        assert!(unix_seconds > 1_577_836_800);
    }

    #[test]
    fn entropy_fills_the_whole_buffer() {
        // Random bytes may legitimately be zero, so "was this byte written?"
        // can't be asked of one byte. Pre-fill with a sentinel and require
        // every window to contain a non-sentinel byte: a partial fill leaves a
        // run of untouched bytes, while a fully-written window surviving as
        // all-sentinel has probability 256^-WINDOW.
        const SENTINEL: u8 = 0x5a;
        const WINDOW: usize = 16;

        let mut entropy = StdEntropy::new();
        let mut buffer = [SENTINEL; 256];
        entropy.fill_bytes(&mut buffer).expect("os entropy");

        for (index, window) in buffer.windows(WINDOW).enumerate() {
            assert!(
                window.iter().any(|&byte| byte != SENTINEL),
                "bytes {index}..{} were left unwritten",
                index + WINDOW
            );
        }
    }

    #[test]
    fn entropy_does_not_repeat_itself() {
        let mut entropy = StdEntropy::new();
        let first = entropy.next_u64().expect("os entropy");
        let second = entropy.next_u64().expect("os entropy");
        assert_ne!(first, second);
    }

    #[test]
    fn empty_buffer_is_not_an_error() {
        let mut entropy = StdEntropy::new();
        entropy.fill_bytes(&mut []).expect("empty fill");
    }
}
