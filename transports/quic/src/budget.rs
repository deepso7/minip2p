//! The QUIC memory budget: what a transport's connections and streams have
//! reserved against [`QuicLimits::memory_budget_bytes`].

use minip2p_transport::TransportError;

use crate::QuicLimits;

/// Memory reservations held against one transport's QUIC memory budget.
///
/// A connection reserves its fixed part at admission and releases it when it
/// drains; a stream reserves its receive window when it opens or is admitted
/// and releases it once it settles. A reservation that does not fit is
/// refused, so `reserved` never exceeds the budget.
#[derive(Debug)]
pub(crate) struct MemoryBudget {
    capacity: usize,
    connection: usize,
    stream: usize,
    reserved: usize,
}

impl MemoryBudget {
    pub(crate) fn new(limits: &QuicLimits) -> Self {
        Self {
            capacity: limits.memory_budget_bytes,
            connection: limits.connection_reservation_bytes(),
            stream: limits.stream_reservation_bytes(),
            reserved: 0,
        }
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

    /// Bytes reserved now.
    #[cfg(test)]
    pub(crate) fn reserved(&self) -> usize {
        self.reserved
    }

    fn fits(&self, bytes: usize) -> bool {
        self.capacity.saturating_sub(self.reserved) >= bytes
    }
}
