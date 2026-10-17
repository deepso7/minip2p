use alloc::string::String;
use core::fmt;

/// Why one connection ended, carried on its close event.
///
/// Every transport reports exactly one of these per connection, on
/// [`TransportEvent::Closed`](crate::TransportEvent::Closed). A failure that
/// ends a connection is reported here, not as a separate
/// [`TransportEvent::Error`](crate::TransportEvent::Error). A Connection
/// replacement is not a close: the swarm reports it as `ConnectionReplaced`,
/// and the replaced connection's own close reads [`Local`](Self::Local).
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConnectionCloseReason {
    /// We closed it: [`Transport::close`](crate::Transport::close), including
    /// the swarm closing a replaced connection or a connection-race loser.
    Local,
    /// The peer closed it, with the code it gave.
    ///
    /// On QUIC `code` is the peer's CONNECTION_CLOSE error code: an
    /// application code (0 is minip2p's orderly close) or, for a transport
    /// close, a QUIC transport error code. On TCP and relay circuits it is
    /// the code of the peer's Yamux `GoAway` (0 normal, 1 protocol error,
    /// 2 internal error).
    Remote { code: u64 },
    /// The peer went silent: a QUIC idle timeout, a Yamux keepalive timeout,
    /// or a handshake that did not finish in time.
    TimedOut,
    /// The peer stopped reading: a TCP send stalled past its timeout.
    Stalled,
    /// Anything else that ended it, such as an I/O or protocol failure, with
    /// a human-readable description.
    Error(String),
}

impl fmt::Display for ConnectionCloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => f.write_str("closed locally"),
            Self::Remote { code } => write!(f, "closed by the peer (code {code})"),
            Self::TimedOut => f.write_str("timed out"),
            Self::Stalled => f.write_str("the peer stopped reading"),
            Self::Error(message) => f.write_str(message),
        }
    }
}
