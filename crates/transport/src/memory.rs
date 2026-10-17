use core::fmt;

/// Memory reservations held against one transport's **memory budget**
/// (ADR 0019, ADR 0021): the shared arithmetic each transport builds its
/// own budget on.
///
/// A connection or stream reserves its bytes at admission and releases them
/// when they are gone; a reservation that does not fit is refused, so
/// [`reserved`](Self::reserved) never exceeds [`capacity`](Self::capacity).
/// What a connection or a stream reserves, and what the refusal is called,
/// is the owning transport's to define.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryLedger {
    capacity: usize,
    reserved: usize,
}

impl MemoryLedger {
    /// An empty ledger that may reserve up to `capacity` bytes.
    pub const fn new(capacity: usize) -> Self {
        Self {
            capacity,
            reserved: 0,
        }
    }

    /// A ledger that admits everything, for sessions run without a budget
    /// (tests, fuzzing, benches).
    pub const fn unbounded() -> Self {
        Self::new(usize::MAX)
    }

    /// The bytes this ledger may reserve in total.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The bytes reserved now.
    pub fn reserved(&self) -> usize {
        self.reserved
    }

    /// Whether `bytes` more would fit.
    pub fn fits(&self, bytes: usize) -> bool {
        self.capacity - self.reserved >= bytes
    }

    /// Reserves `bytes` if they fit, returning whether they did.
    pub fn reserve(&mut self, bytes: usize) -> bool {
        let fits = self.fits(bytes);
        if fits {
            self.reserved += bytes;
        }
        fits
    }

    /// Releases `bytes` reserved earlier.
    pub fn release(&mut self, bytes: usize) {
        debug_assert!(self.reserved >= bytes, "released more than reserved");
        self.reserved = self.reserved.saturating_sub(bytes);
    }
}

/// A transport limit that cannot work: a zero where a size is needed,
/// arithmetic that overflows, or a memory budget too small to admit one
/// connection with one stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidLimit {
    /// The offending field.
    pub field: &'static str,
    /// What it must satisfy.
    pub requirement: &'static str,
}

impl fmt::Display for InvalidLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid limit `{}`: {}", self.field, self.requirement)
    }
}

impl core::error::Error for InvalidLimit {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reservation_that_does_not_fit_is_refused_until_bytes_are_released() {
        let mut ledger = MemoryLedger::new(10);
        assert!(ledger.reserve(6));
        assert!(!ledger.reserve(5), "6 + 5 is past the capacity");
        assert_eq!(ledger.reserved(), 6, "a refusal reserves nothing");
        assert!(ledger.reserve(4));
        assert!(!ledger.fits(1));

        ledger.release(6);
        assert!(ledger.reserve(5));
        assert_eq!(ledger.reserved(), 9);
    }

    #[test]
    fn an_unbounded_ledger_admits_everything() {
        let mut ledger = MemoryLedger::unbounded();
        assert!(ledger.reserve(usize::MAX / 2));
        assert!(ledger.reserve(usize::MAX / 2));
    }
}
