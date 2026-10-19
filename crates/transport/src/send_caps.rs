/// ADR 0012's send caps, shared by the transports that queue writes
/// themselves: how much each stream and the whole connection may hold
/// beyond what the transport's output accepted, and the part of the
/// connection cap only control streams may fill.
///
/// A transport counts each stream's pending bytes and the connection's
/// total, accepts a write up to [`room`](Self::room), returns
/// [`TransportError::Full`](crate::TransportError::Full) with the rest, and
/// fires the armed `StreamWritable` once the room reaches
/// [`writable_threshold`](Self::writable_threshold).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendCaps {
    stream: usize,
    connection: usize,
    control_reserve: usize,
}

impl SendCaps {
    /// Caps of `stream` bytes per stream and `connection` bytes per
    /// connection, `control_reserve` of which only control streams may fill.
    /// Callers validate that the reserve is below the connection cap; a
    /// larger one leaves application streams no room at all.
    pub const fn new(stream: usize, connection: usize, control_reserve: usize) -> Self {
        Self {
            stream,
            connection,
            control_reserve,
        }
    }

    /// Bytes a stream may still queue: the smaller of what is left of its
    /// own cap after `stream_pending` and of the connection cap it may fill
    /// after `connection_pending`.
    pub fn room(&self, stream_pending: usize, connection_pending: usize, control: bool) -> usize {
        let stream_room = self.stream.saturating_sub(stream_pending);
        let connection_room = self
            .connection_for(control)
            .saturating_sub(connection_pending);
        stream_room.min(connection_room)
    }

    /// The connection cap a stream may fill: all of it for a control
    /// stream, all but the reserve otherwise.
    fn connection_for(&self, control: bool) -> usize {
        if control {
            self.connection
        } else {
            self.connection.saturating_sub(self.control_reserve)
        }
    }

    /// Room a Full stream needs before its `StreamWritable` fires: half the
    /// smaller cap it may fill. A control stream may be left only the
    /// reserve once application streams fill their share, so a non-zero
    /// reserve bounds its threshold too.
    pub fn writable_threshold(&self, control: bool) -> usize {
        let mut smallest = self.stream.min(self.connection_for(control));
        if control && self.control_reserve != 0 {
            smallest = smallest.min(self.control_reserve);
        }
        (smallest / 2).max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_streams_leave_the_reserve_to_control_streams() {
        let caps = SendCaps::new(100, 300, 50);
        assert_eq!(caps.room(0, 0, false), 100);
        assert_eq!(caps.room(0, 220, false), 30, "250 of 300 for applications");
        assert_eq!(caps.room(0, 220, true), 80);
        assert_eq!(caps.room(90, 0, true), 10, "the stream cap still binds");
        assert_eq!(caps.writable_threshold(false), 50);
        assert_eq!(caps.writable_threshold(true), 25, "half the reserve");
    }
}
