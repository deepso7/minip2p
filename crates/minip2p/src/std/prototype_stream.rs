//! THROWAWAY #149 API comparison. Enable only after StreamReady, before payload.
use super::{ConnectionId, Endpoint, StreamId, Transport, TransportError};

/// THROWAWAY owned payload and its unreleased credit. Not Clone.
/// Dropping this value does NOT return credit; release it or reset the stream.
#[must_use = "release the chunk after consuming it, or reset the stream"]
pub struct PrototypeChunk {
    conn: ConnectionId,
    stream: StreamId,
    data: Vec<u8>,
}
impl PrototypeChunk {
    /// Borrow the received bytes. Empty means EOF.
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}
impl Endpoint {
    /// THROWAWAY: sampled unread and loaned payload, excluding allocation overhead.
    pub fn prototype_held(
        &mut self,
        conn: ConnectionId,
        stream: StreamId,
    ) -> Result<usize, TransportError> {
        self.swarm.transport_mut().prototype_held(conn, stream)
    }

    /// THROWAWAY: enable after negotiation and before sending application bytes.
    pub fn prototype_enable(
        &mut self,
        conn: ConnectionId,
        stream: StreamId,
    ) -> Result<(), TransportError> {
        self.swarm.transport_mut().prototype_enable(conn, stream)
    }
    /// THROWAWAY: copy available bytes; None is blocked, Some(0) is EOF.
    /// The destination must be nonempty. Poll Endpoint between work turns.
    pub fn prototype_read(
        &mut self,
        conn: ConnectionId,
        stream: StreamId,
        out: &mut [u8],
    ) -> Result<Option<usize>, TransportError> {
        if out.is_empty() {
            return Err(TransportError::PollError {
                reason: "prototype read destination must be nonempty".into(),
            });
        }
        self.swarm
            .transport_mut()
            .prototype_try_read(conn, stream, out)
    }
    /// THROWAWAY: take ownership without returning credit. None is blocked.
    pub fn prototype_chunk(
        &mut self,
        conn: ConnectionId,
        stream: StreamId,
    ) -> Result<Option<PrototypeChunk>, TransportError> {
        Ok(self
            .swarm
            .transport_mut()
            .prototype_take(conn, stream)?
            .map(|data| PrototypeChunk { conn, stream, data }))
    }
    /// THROWAWAY: consume the chunk's credit token. Reset invalidates it.
    pub fn prototype_release(&mut self, chunk: PrototypeChunk) -> Result<(), TransportError> {
        self.swarm
            .transport_mut()
            .prototype_release(chunk.conn, chunk.stream, chunk.data.len())
    }
    /// THROWAWAY: accept a borrowed prefix; zero means blocked for nonempty input.
    pub fn prototype_write(
        &mut self,
        conn: ConnectionId,
        stream: StreamId,
        data: &[u8],
    ) -> Result<usize, TransportError> {
        self.swarm
            .transport_mut()
            .prototype_try_write(conn, stream, data)
    }
}
