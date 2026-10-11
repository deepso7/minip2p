//! The UDP socket a transport owns, and the datagrams it retains while the
//! socket pushes back.

use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, UdpSocket};

use crate::diagnostics::DatagramTally;

/// A datagram retained after the non-blocking socket reported `WouldBlock`.
struct PendingDatagram {
    bytes: Vec<u8>,
    destination: SocketAddr,
}

/// A non-blocking UDP socket plus its bounded retry queue.
pub(crate) struct Socket {
    pub(crate) udp: UdpSocket,
    /// Fixed when the socket was bound.
    pub(crate) local_addr: SocketAddr,
    /// Datagrams waiting for the socket to become writable, oldest first.
    pending: VecDeque<PendingDatagram>,
    max_pending: usize,
    /// Socket datagram counts; empty unless the `diagnostics` feature is on.
    pub(crate) tally: DatagramTally,
}

impl Socket {
    pub(crate) fn new(
        udp: UdpSocket,
        local_addr: SocketAddr,
        max_pending: usize,
        tally: DatagramTally,
    ) -> Self {
        Self {
            udp,
            local_addr,
            pending: VecDeque::new(),
            max_pending,
            tally,
        }
    }

    /// Whether another datagram could be retained if the socket pushed back.
    ///
    /// The engine advances its congestion and loss state for every packet it
    /// hands out, so a caller asks for one only while it could keep it.
    pub(crate) fn has_room(&self) -> bool {
        self.pending.len() < self.max_pending
    }

    /// Whether datagrams are waiting for the socket to become writable.
    pub(crate) fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Sends one datagram of a connection's output.
    ///
    /// Returns `Ok(true)` once it left, and `Ok(false)` when it was retained:
    /// on `WouldBlock`, or behind datagrams already retained so it never
    /// overtakes them. A hard error drops the datagram (the engine's loss
    /// recovery resends what mattered, and a path that stays dead ends in the
    /// connection's idle timeout) and is returned so the caller stops sending.
    pub(crate) fn send(&mut self, bytes: &[u8], destination: SocketAddr) -> io::Result<bool> {
        if self.has_pending() {
            self.retain(bytes, destination);
            return Ok(false);
        }
        match self.udp.send_to(bytes, destination) {
            Ok(_) => {
                self.tally.sent(bytes.len());
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.retain(bytes, destination);
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// Best-effort send for stateless replies (Retry, version negotiation,
    /// stateless reset, refusals) that the peer regenerates by retransmitting.
    /// Retained on `WouldBlock` while there is room; dropped otherwise.
    pub(crate) fn send_stateless(&mut self, bytes: &[u8], destination: SocketAddr) {
        match self.send(bytes, destination) {
            Ok(_) | Err(_) => {}
        }
    }

    /// Retains a datagram for a later flush, dropping it when the queue is
    /// already full.
    pub(crate) fn retain(&mut self, bytes: &[u8], destination: SocketAddr) {
        if !self.has_room() {
            return;
        }
        self.pending.push_back(PendingDatagram {
            bytes: bytes.to_vec(),
            destination,
        });
    }

    /// Retries retained datagrams until the socket pushes back again.
    ///
    /// Retained datagrams may target different destinations, so a dead route
    /// for one neither fails the flush nor blocks the rest: it is dropped.
    pub(crate) fn flush(&mut self) {
        while let Some(datagram) = self.pending.front() {
            match self.udp.send_to(&datagram.bytes, datagram.destination) {
                Ok(_) => {
                    self.tally.sent(datagram.bytes.len());
                    self.pending.pop_front();
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.pending.pop_front();
                }
            }
        }
    }

    /// Drops every retained datagram.
    pub(crate) fn clear(&mut self) {
        self.pending.clear();
    }

    #[cfg(test)]
    pub(crate) fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

/// Non-blocking check for a datagram already queued on `socket`.
///
/// The socket must be in its usual non-blocking mode. Peeks one byte, so no
/// input is consumed. Errors other than `WouldBlock` count as ready so the
/// next `poll()` can surface them.
pub(crate) fn has_queued_input(socket: &UdpSocket) -> bool {
    let mut probe = [0u8; 1];
    match socket.peek_from(&mut probe) {
        Ok(_) => true,
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
        Err(_) => true,
    }
}
