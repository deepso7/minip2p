use core::fmt;

/// Opaque identifier for a transport connection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectionId(u64);

impl ConnectionId {
    /// Creates a connection id from a raw `u64`.
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Returns the underlying `u64` value.
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for ConnectionId {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<ConnectionId> for u64 {
    fn from(value: ConnectionId) -> Self {
        value.0
    }
}
