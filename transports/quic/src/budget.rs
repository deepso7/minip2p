//! The QUIC memory budget: what a transport's connections and streams have
//! reserved against [`QuicLimits::memory_budget_bytes`].

use minip2p_transport::TransportError;

use crate::QuicLimits;

/// Memory reservations held against one transport's QUIC memory budget.
///
/// Each socket's retry queue is reserved up front, for the transport's
/// lifetime. A connection reserves its fixed part at admission and releases
/// it when it drains; a stream reserves its receive window when it opens or is admitted
/// and releases it once it settles. A reservation that does not fit is
/// refused, so `reserved` never exceeds the budget.
#[derive(Debug)]
pub(crate) struct MemoryBudget {
    /// What connections and streams may reserve: the budget less the
    /// sockets' retry queues.
    capacity: usize,
    connection: usize,
    stream: usize,
    reserved: usize,
}

impl MemoryBudget {
    /// The budget of a transport with `sockets` bound sockets, or `None`
    /// when it cannot fit their retry queues plus one connection and one
    /// stream. Checked arithmetic: a sum that overflows can never fit.
    pub(crate) fn new(limits: &QuicLimits, sockets: usize) -> Option<Self> {
        let smallest = limits
            .max_pending_connection_bytes
            .checked_mul(2)
            .and_then(|queue| queue.checked_add(limits.send_window))
            .and_then(|fixed| fixed.checked_add(limits.connection_receive_window))
            .and_then(|fixed| fixed.checked_add(limits.stream_receive_window))?;
        let queues = limits
            .max_pending_datagrams
            .checked_mul(crate::config::MAX_DATAGRAM_BYTES)?
            .checked_mul(sockets)?;
        let capacity = limits.memory_budget_bytes.checked_sub(queues)?;
        (capacity >= smallest).then(|| Self {
            capacity,
            connection: limits.connection_reservation_bytes(),
            stream: limits.stream_reservation_bytes(),
            reserved: 0,
        })
    }

    /// The error for a dial or stream open that does not fit.
    pub(crate) fn exhausted() -> TransportError {
        TransportError::ResourceExhausted {
            resource: "QUIC memory budget",
        }
    }

    /// Whether one more connection's fixed part fits.
    pub(crate) fn fits_connection(&self) -> bool {
        self.fits(self.connection)
    }

    /// Reserves one connection's fixed part; the caller checked it fits.
    pub(crate) fn reserve_connection(&mut self) {
        self.reserved += self.connection;
    }

    /// Releases a drained connection's fixed part.
    pub(crate) fn release_connection(&mut self) {
        debug_assert!(
            self.reserved >= self.connection,
            "released more than reserved"
        );
        self.reserved = self.reserved.saturating_sub(self.connection);
    }

    /// Reserves one stream's receive window, if it fits.
    pub(crate) fn reserve_stream(&mut self) -> bool {
        let fits = self.fits(self.stream);
        if fits {
            self.reserved += self.stream;
        }
        fits
    }

    /// Releases the reservations of `count` settled streams.
    pub(crate) fn release_streams(&mut self, count: usize) {
        let bytes = self.stream.saturating_mul(count);
        debug_assert!(self.reserved >= bytes, "released more than reserved");
        self.reserved = self.reserved.saturating_sub(bytes);
    }

    /// Bytes connections and streams reserve now; the retry queues are not
    /// counted.
    #[cfg(test)]
    pub(crate) fn reserved(&self) -> usize {
        self.reserved
    }

    fn fits(&self, bytes: usize) -> bool {
        self.capacity.saturating_sub(self.reserved) >= bytes
    }
}
