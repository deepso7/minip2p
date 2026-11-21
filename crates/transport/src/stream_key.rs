use core::fmt;

use crate::{ConnectionId, StreamId};

/// Names one stream: its connection and its id within that connection.
///
/// Stream ids are only unique per connection, so every stream operation
/// needs both; a `StreamKey` carries them together. It is `Copy`, ordered
/// and hashable, so it works directly as a map key.
///
/// ```
/// use minip2p_transport::{ConnectionId, StreamId, StreamKey};
///
/// let key = StreamKey::new(ConnectionId::new(7), StreamId::new(3));
/// assert_eq!(key.conn_id(), ConnectionId::new(7));
/// assert_eq!(key.stream_id(), StreamId::new(3));
/// assert_eq!(key.to_string(), "7/3");
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StreamKey {
    conn_id: ConnectionId,
    stream_id: StreamId,
}

impl StreamKey {
    /// The key of `stream_id` on `conn_id`.
    pub const fn new(conn_id: ConnectionId, stream_id: StreamId) -> Self {
        Self { conn_id, stream_id }
    }

    /// The connection holding the stream.
    pub const fn conn_id(&self) -> ConnectionId {
        self.conn_id
    }

    /// The stream's id within its connection.
    pub const fn stream_id(&self) -> StreamId {
        self.stream_id
    }
}

/// `<connection>/<stream>`, each as its own `Display` writes it.
impl fmt::Display for StreamKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.conn_id, self.stream_id)
    }
}

impl From<(ConnectionId, StreamId)> for StreamKey {
    fn from((conn_id, stream_id): (ConnectionId, StreamId)) -> Self {
        Self::new(conn_id, stream_id)
    }
}
