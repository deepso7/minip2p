use core::fmt;

/// Opaque identifier for a stream within a connection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StreamId(u64);

impl StreamId {
    /// Creates a stream id from a raw `u64`.
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Returns the underlying `u64` value.
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for StreamId {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<StreamId> for u64 {
    fn from(value: StreamId) -> Self {
        value.0
    }
}
