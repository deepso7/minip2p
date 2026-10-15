//! A portable classification of I/O failures.

/// What kind of I/O failure a platform reported, without the platform.
///
/// A portable stand-in for `std::io::ErrorKind`, so a `no_std` carrier (an
/// embedded network stack, say) and a hosted one report failures callers can
/// match on the same way. Hosted adapters convert with `From<std::io::ErrorKind>`
/// (behind `std`); a kind with no counterpart here is [`Other`](Self::Other).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum IoErrorKind {
    /// Something the operation named does not exist.
    NotFound,
    /// The platform refused the operation.
    PermissionDenied,
    /// The address is already bound.
    AddrInUse,
    /// The address is not local, or cannot be bound here.
    AddrNotAvailable,
    /// The network cannot be reached.
    NetworkUnreachable,
    /// The host cannot be reached.
    HostUnreachable,
    /// The remote refused the connection.
    ConnectionRefused,
    /// The remote reset the connection.
    ConnectionReset,
    /// The connection was aborted locally.
    ConnectionAborted,
    /// The socket is not connected.
    NotConnected,
    /// The other side of a pipe or stream has closed.
    BrokenPipe,
    /// The operation would block.
    WouldBlock,
    /// An argument was invalid.
    InvalidInput,
    /// The operation timed out.
    TimedOut,
    /// The operation was interrupted.
    Interrupted,
    /// The platform does not support the operation.
    Unsupported,
    /// The platform ran out of memory or buffers.
    OutOfMemory,
    /// Anything else.
    Other,
}

impl core::fmt::Display for IoErrorKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = match self {
            Self::NotFound => "not found",
            Self::PermissionDenied => "permission denied",
            Self::AddrInUse => "address in use",
            Self::AddrNotAvailable => "address not available",
            Self::NetworkUnreachable => "network unreachable",
            Self::HostUnreachable => "host unreachable",
            Self::ConnectionRefused => "connection refused",
            Self::ConnectionReset => "connection reset",
            Self::ConnectionAborted => "connection aborted",
            Self::NotConnected => "not connected",
            Self::BrokenPipe => "broken pipe",
            Self::WouldBlock => "would block",
            Self::InvalidInput => "invalid input",
            Self::TimedOut => "timed out",
            Self::Interrupted => "interrupted",
            Self::Unsupported => "unsupported",
            Self::OutOfMemory => "out of memory",
            Self::Other => "other error",
        };
        f.write_str(text)
    }
}

#[cfg(feature = "std")]
impl From<std::io::ErrorKind> for IoErrorKind {
    fn from(kind: std::io::ErrorKind) -> Self {
        use std::io::ErrorKind as Std;
        match kind {
            Std::NotFound => Self::NotFound,
            Std::PermissionDenied => Self::PermissionDenied,
            Std::AddrInUse => Self::AddrInUse,
            Std::AddrNotAvailable => Self::AddrNotAvailable,
            Std::NetworkUnreachable => Self::NetworkUnreachable,
            Std::HostUnreachable => Self::HostUnreachable,
            Std::ConnectionRefused => Self::ConnectionRefused,
            Std::ConnectionReset => Self::ConnectionReset,
            Std::ConnectionAborted => Self::ConnectionAborted,
            Std::NotConnected => Self::NotConnected,
            Std::BrokenPipe => Self::BrokenPipe,
            Std::WouldBlock => Self::WouldBlock,
            Std::InvalidInput => Self::InvalidInput,
            Std::TimedOut => Self::TimedOut,
            Std::Interrupted => Self::Interrupted,
            Std::Unsupported => Self::Unsupported,
            Std::OutOfMemory => Self::OutOfMemory,
            _ => Self::Other,
        }
    }
}

/// Back to the standard kind, for a hosted adapter that has to hand a
/// portable failure on as a `std::io::Error`. [`Other`](IoErrorKind::Other)
/// stays `Other`.
#[cfg(feature = "std")]
impl From<IoErrorKind> for std::io::ErrorKind {
    fn from(kind: IoErrorKind) -> Self {
        use std::io::ErrorKind as Std;
        match kind {
            IoErrorKind::NotFound => Std::NotFound,
            IoErrorKind::PermissionDenied => Std::PermissionDenied,
            IoErrorKind::AddrInUse => Std::AddrInUse,
            IoErrorKind::AddrNotAvailable => Std::AddrNotAvailable,
            IoErrorKind::NetworkUnreachable => Std::NetworkUnreachable,
            IoErrorKind::HostUnreachable => Std::HostUnreachable,
            IoErrorKind::ConnectionRefused => Std::ConnectionRefused,
            IoErrorKind::ConnectionReset => Std::ConnectionReset,
            IoErrorKind::ConnectionAborted => Std::ConnectionAborted,
            IoErrorKind::NotConnected => Std::NotConnected,
            IoErrorKind::BrokenPipe => Std::BrokenPipe,
            IoErrorKind::WouldBlock => Std::WouldBlock,
            IoErrorKind::InvalidInput => Std::InvalidInput,
            IoErrorKind::TimedOut => Std::TimedOut,
            IoErrorKind::Interrupted => Std::Interrupted,
            IoErrorKind::Unsupported => Std::Unsupported,
            IoErrorKind::OutOfMemory => Std::OutOfMemory,
            IoErrorKind::Other => Std::Other,
        }
    }
}

#[cfg(feature = "std")]
impl From<&std::io::Error> for IoErrorKind {
    fn from(error: &std::io::Error) -> Self {
        error.kind().into()
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn std_kinds_map_to_their_portable_counterpart() {
        assert_eq!(
            IoErrorKind::from(std::io::ErrorKind::AddrInUse),
            IoErrorKind::AddrInUse
        );
        assert_eq!(
            IoErrorKind::from(std::io::ErrorKind::UnexpectedEof),
            IoErrorKind::Other
        );
        assert_eq!(
            std::io::ErrorKind::from(IoErrorKind::PermissionDenied),
            std::io::ErrorKind::PermissionDenied
        );
    }
}
