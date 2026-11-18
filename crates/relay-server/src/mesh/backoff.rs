//! The mesh's one retry schedule, shared by member redials (in the
//! Endpoint) and directory stream reopens (in the agent).

/// Retry delays of 1 s, doubling per failure up to 30 s, back to 1 s once
/// the retried thing succeeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Backoff {
    delay_ms: u64,
}

impl Backoff {
    /// The first delay, and the delay after [`Backoff::reset`].
    pub const MIN_MS: u64 = 1_000;
    /// The longest delay.
    pub const MAX_MS: u64 = 30_000;

    /// A schedule at its first delay.
    pub const fn new() -> Self {
        Self {
            delay_ms: Self::MIN_MS,
        }
    }

    /// The delay before this retry, in milliseconds; the next one doubles.
    pub fn next_delay_ms(&mut self) -> u64 {
        let delay = self.delay_ms;
        self.delay_ms = delay.saturating_mul(2).min(Self::MAX_MS);
        delay
    }

    /// Starts over at the first delay, after a success.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::Backoff;

    #[test]
    fn doubles_to_the_cap_and_resets() {
        let mut backoff = Backoff::new();
        let delays: [u64; 7] = core::array::from_fn(|_| backoff.next_delay_ms());
        assert_eq!(delays, [1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000]);
        backoff.reset();
        assert_eq!(backoff.next_delay_ms(), 1_000);
    }
}
