/// Endpoint-local identity of one Connection attempt.
///
/// Not unique across endpoints or restarts. One id covers every candidate
/// Transport dial belonging to the attempt, plus any relay fallback and
/// direct-path upgrade.
///
/// Forging an id is harmless: ids are correlation tokens local to one
/// endpoint. Cancelling an unknown id is a no-op.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectId(u64);

impl ConnectId {
    /// Returns the raw numeric value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Constructs an id from a raw numeric value.
    ///
    /// Callers that did not allocate the id (NAT-crate tests, FFI round-trips)
    /// use this to name an attempt. An unknown id is ignored by cancel.
    pub const fn from_u64(id: u64) -> Self {
        Self(id)
    }
}

#[cfg(test)]
mod tests {
    use super::ConnectId;

    #[test]
    fn from_u64_round_trips() {
        let id = ConnectId::from_u64(42);
        assert_eq!(id.as_u64(), 42);
    }
}
