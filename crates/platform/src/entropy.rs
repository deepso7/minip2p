use thiserror::Error;

/// Why an [`EntropySource`] could not produce randomness.
///
/// Both variants are fatal for the operation that needed the bytes. Callers
/// must fail that operation rather than fall back to a weaker source: minip2p
/// uses entropy for key generation, Noise handshakes, and nonces, where a
/// predictable substitute is a security bug.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EntropyError {
    /// The platform has no entropy source at all.
    ///
    /// Permanent — retrying will not help. Typically an embedded target built
    /// without a hardware RNG or a configured seed.
    #[error("no entropy source available: {reason}")]
    Unavailable {
        /// What the adapter expected to find.
        reason: &'static str,
    },
    /// The entropy source exists but failed to produce bytes.
    ///
    /// May be transient, for example a hardware RNG reporting a health-check
    /// failure or an exhausted file descriptor table.
    #[error("entropy source failed: {reason}")]
    Failed {
        /// What went wrong.
        reason: &'static str,
        /// Platform error code, when the adapter has one.
        code: Option<i32>,
    },
}

impl EntropyError {
    /// Creates an [`Unavailable`](Self::Unavailable) error.
    pub const fn unavailable(reason: &'static str) -> Self {
        Self::Unavailable { reason }
    }

    /// Creates a [`Failed`](Self::Failed) error without a platform code.
    pub const fn failed(reason: &'static str) -> Self {
        Self::Failed { reason, code: None }
    }

    /// Creates a [`Failed`](Self::Failed) error carrying a platform code.
    pub const fn failed_with_code(reason: &'static str, code: i32) -> Self {
        Self::Failed {
            reason,
            code: Some(code),
        }
    }
}

/// A source of cryptographically secure random bytes.
///
/// Implementations live in adapters and are injected into the components that
/// need randomness, so protocol crates stay deterministic and testable.
///
/// # Contract
///
/// - Bytes must be suitable for cryptographic use: unpredictable to an attacker
///   who has observed every previous output.
/// - On `Ok`, the whole of `output` is filled.
/// - On `Err`, `output` may have been partially written and must be treated as
///   containing no entropy.
pub trait EntropySource {
    /// Fills `output` with random bytes.
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError>;

    /// Draws a random `u64`.
    fn next_u64(&mut self) -> Result<u64, EntropyError> {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
}

impl<E: EntropySource + ?Sized> EntropySource for &mut E {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        (**self).fill_bytes(output)
    }

    fn next_u64(&mut self) -> Result<u64, EntropyError> {
        (**self).next_u64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;

    /// Counter-based stand-in; deterministic so tests can assert on output.
    struct Counter(u8);

    impl EntropySource for Counter {
        fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
            for byte in output.iter_mut() {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    struct Broken;

    impl EntropySource for Broken {
        fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
            // Partial write before failing: callers must not trust `output`.
            if let Some(first) = output.first_mut() {
                *first = 0xff;
            }
            Err(EntropyError::failed_with_code("rng offline", 5))
        }
    }

    #[test]
    fn fill_bytes_fills_the_whole_slice() {
        let mut source = Counter(1);
        let mut buffer = [0u8; 4];
        source.fill_bytes(&mut buffer).expect("fill");
        assert_eq!(buffer, [1, 2, 3, 4]);
    }

    #[test]
    fn next_u64_reads_eight_little_endian_bytes() {
        let mut source = Counter(1);
        let value = source.next_u64().expect("draw");
        assert_eq!(value, u64::from_le_bytes([1, 2, 3, 4, 5, 6, 7, 8]));
    }

    #[test]
    fn failures_propagate_through_next_u64() {
        let mut source = Broken;
        assert_eq!(
            source.next_u64(),
            Err(EntropyError::Failed {
                reason: "rng offline",
                code: Some(5)
            })
        );
    }

    #[test]
    fn constructors_match_their_variants() {
        assert_eq!(
            EntropyError::unavailable("no hardware rng"),
            EntropyError::Unavailable {
                reason: "no hardware rng"
            }
        );
        assert_eq!(
            EntropyError::failed("busy"),
            EntropyError::Failed {
                reason: "busy",
                code: None
            }
        );
    }

    /// Generic over `E: EntropySource`, so passing `&mut Counter` exercises the
    /// blanket impl rather than auto-deref.
    fn draw<E: EntropySource>(mut source: E, buffer: &mut [u8]) -> Result<u64, EntropyError> {
        source.fill_bytes(buffer)?;
        source.next_u64()
    }

    #[test]
    fn mutable_reference_forwards_to_inner_source() {
        let mut source = Counter(1);
        let mut buffer = [0u8; 2];
        let drawn = draw(&mut source, &mut buffer).expect("draw");
        assert_eq!(buffer, [1, 2]);
        assert_eq!(drawn, u64::from_le_bytes([3, 4, 5, 6, 7, 8, 9, 10]));
        assert_eq!(source.0, 11);
    }

    #[test]
    fn trait_is_object_safe() {
        let mut source: Box<dyn EntropySource> = Box::new(Counter(9));
        let mut buffer = [0u8; 2];
        source.fill_bytes(&mut buffer).expect("fill");
        assert_eq!(buffer, [9, 10]);
    }
}
