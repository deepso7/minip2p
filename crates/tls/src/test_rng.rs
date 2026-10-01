//! Deterministic CSPRNG stand-in shared by the crate's unit tests.

use core::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};

/// Linear congruential generator seeded by its field. Not cryptographic.
pub(crate) struct TestRng(pub(crate) u64);

impl TryRng for TestRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        Ok(self.0)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.try_next_u64()?.to_le_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&bytes[..len]);
        }
        Ok(())
    }
}

impl TryCryptoRng for TestRng {}
