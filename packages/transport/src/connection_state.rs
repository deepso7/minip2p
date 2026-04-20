use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    Connecting,
    Connected,
    Closing,
    Closed,
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connecting => f.write_str("connecting"),
            Self::Connected => f.write_str("connected"),
            Self::Closing => f.write_str("closing"),
            Self::Closed => f.write_str("closed"),
        }
    }
}
