//! The QUIC memory budget: what a transport's connections and streams have
//! reserved against [`QuicLimits::memory_budget_bytes`].

use minip2p_transport::{MemoryLedger, TransportError};

use crate::QuicLimits;

/// Memory reservations held against one transport's QUIC memory budget.
///
/// Each socket's retry queue is reserved up front, for the transport's
/// lifetime. A connection reserves its fixed part at admission and releases
/// it when it drains; a stream reserves its receive window when it opens or is admitted
/// and releases it once it settles. A reservation that does not fit is
/// refused, so the ledger never exceeds the budget.
#[derive(Debug)]
pub(crate) struct MemoryBudget {
    /// What connections and streams reserve against: the budget less the
    /// sockets' retry queues.
    ledger: MemoryLedger,
    connection: usize,
    stream: usize,
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
            ledger: MemoryLedger::new(capacity),
            connection: limits.connection_reservation_bytes(),
            stream: limits.stream_reservation_bytes(),
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
        self.ledger.fits(self.connection)
    }

    /// Reserves one connection's fixed part; the caller checked it fits.
    pub(crate) fn reserve_connection(&mut self) {
        let reserved = self.ledger.reserve(self.connection);
        debug_assert!(reserved, "reserved a connection that does not fit");
    }

    /// Releases a drained connection's fixed part.
    pub(crate) fn release_connection(&mut self) {
        self.ledger.release(self.connection);
    }

    /// Reserves one stream's receive window, if it fits.
    pub(crate) fn reserve_stream(&mut self) -> bool {
        self.ledger.reserve(self.stream)
    }

    /// Releases the reservations of `count` settled streams.
    pub(crate) fn release_streams(&mut self, count: usize) {
        self.ledger.release(self.stream.saturating_mul(count));
    }

    /// Bytes connections and streams reserve now; the retry queues are not
    /// counted.
    #[cfg(test)]
    pub(crate) fn reserved(&self) -> usize {
        self.ledger.reserved()
    }
}
