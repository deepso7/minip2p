//! The UDP socket a transport owns, driven through quinn-udp (GSO, GRO, ECN
//! and packet info where the platform has them), and the datagrams it
//! retains while the socket pushes back.
//!
//! Every count here is in logical datagrams: a GSO transmit or a GRO receive
//! of several segments counts once per segment.

use std::collections::VecDeque;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, SocketAddr, UdpSocket};

use quinn_udp::{RecvMeta, UdpSocketState};

use crate::diagnostics::DatagramTally;

/// Largest UDP payload a single datagram can carry.
const MAX_DATAGRAM_SIZE: usize = 65_535;

/// A transmit retained after the non-blocking socket reported `WouldBlock`.
struct PendingTransmit {
    contents: Vec<u8>,
    destination: SocketAddr,
    segment_size: Option<usize>,
    ecn: Option<quinn_udp::EcnCodepoint>,
    src_ip: Option<IpAddr>,
}

impl PendingTransmit {
    fn datagrams(&self) -> usize {
        datagram_count(self.contents.len(), self.segment_size)
    }

    fn as_transmit(&self) -> quinn_udp::Transmit<'_> {
        quinn_udp::Transmit {
            destination: self.destination,
            ecn: self.ecn,
            contents: &self.contents,
            segment_size: self.segment_size,
            src_ip: self.src_ip,
        }
    }
}

/// Logical datagrams in a transmit of `len` bytes cut at `segment_size`.
fn datagram_count(len: usize, segment_size: Option<usize>) -> usize {
    match segment_size {
        Some(size) if size > 0 => len.div_ceil(size),
        _ => 1,
    }
}

/// What one receive call read: one datagram, or a GRO batch of datagrams
/// `stride` bytes apart (the last may be shorter).
pub(crate) struct Received {
    pub(crate) len: usize,
    pub(crate) stride: usize,
    pub(crate) from: SocketAddr,
    pub(crate) ecn: Option<quinn_proto::EcnCodepoint>,
    /// The local address the datagrams were sent to, where the platform
    /// reports it; replies leave from it.
    pub(crate) dst_ip: Option<IpAddr>,
}

impl Received {
    pub(crate) fn datagrams(&self) -> usize {
        datagram_count(self.len, Some(self.stride))
    }
}

/// A non-blocking UDP socket plus its bounded retry queue.
pub(crate) struct Socket {
    pub(crate) udp: UdpSocket,
    state: UdpSocketState,
    /// Fixed when the socket was bound.
    pub(crate) local_addr: SocketAddr,
    /// Transmits waiting for the socket to become writable, oldest first.
    pending: VecDeque<PendingTransmit>,
    /// Logical datagrams in `pending`.
    retained: usize,
    /// Cap on `retained`.
    max_pending: usize,
    /// Socket datagram counts; empty unless the `diagnostics` feature is on.
    pub(crate) tally: DatagramTally,
    /// Test hooks: a cap on segments per transmit, and a socket that
    /// refuses every send with `WouldBlock`.
    #[cfg(test)]
    pub(crate) max_segments: usize,
    #[cfg(test)]
    pub(crate) blocked: bool,
    /// The most logical datagrams one transmit carried.
    #[cfg(test)]
    pub(crate) largest_transmit: usize,
    /// Logical datagrams received.
    #[cfg(test)]
    pub(crate) received: usize,
}

impl Socket {
    /// Wraps a bound, non-blocking socket, enabling what offloads the
    /// platform offers.
    pub(crate) fn new(
        udp: UdpSocket,
        local_addr: SocketAddr,
        max_pending: usize,
        tally: DatagramTally,
    ) -> io::Result<Self> {
        let state = UdpSocketState::new((&udp).into())?;
        Ok(Self {
            udp,
            state,
            local_addr,
            pending: VecDeque::new(),
            retained: 0,
            max_pending,
            tally,
            #[cfg(test)]
            max_segments: usize::MAX,
            #[cfg(test)]
            blocked: false,
            #[cfg(test)]
            largest_transmit: 0,
            #[cfg(test)]
            received: 0,
        })
    }

    /// Whether datagrams sent here can be fragmented on the way, which rules
    /// out path MTU discovery.
    pub(crate) fn may_fragment(&self) -> bool {
        self.state.may_fragment()
    }

    /// A receive buffer that holds one full GRO batch, or one datagram of
    /// any size.
    pub(crate) fn recv_buffer_len(&self, max_udp_payload: usize) -> usize {
        (self.state.gro_segments() * max_udp_payload).max(MAX_DATAGRAM_SIZE)
    }

    /// How many logical datagrams the next transmit may carry: what the
    /// platform can segment, within what the retry queue could still keep if
    /// the socket pushed back. Zero means stop asking the engine for output:
    /// it advances congestion and loss state for every packet it hands out.
    pub(crate) fn allowance(&self) -> usize {
        let segments = self.state.max_gso_segments();
        #[cfg(test)]
        let segments = segments.min(self.max_segments);
        self.max_pending.saturating_sub(self.retained).min(segments)
    }

    /// Whether datagrams are waiting for the socket to become writable.
    pub(crate) fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Sends one engine transmit whose bytes are `contents`.
    ///
    /// Returns `Ok(true)` once it left, and `Ok(false)` when it was retained:
    /// on `WouldBlock`, or behind transmits already retained so it never
    /// overtakes them. A hard error drops it (the engine's loss recovery
    /// resends what mattered, and a path that stays dead ends in the
    /// connection's idle timeout) and is returned so the caller stops
    /// sending. A GSO batch the platform refused this way also turns
    /// segmentation off for later transmits.
    pub(crate) fn send(
        &mut self,
        transmit: &quinn_proto::Transmit,
        contents: &[u8],
    ) -> io::Result<bool> {
        let transmit = quinn_udp::Transmit {
            destination: transmit.destination,
            ecn: transmit
                .ecn
                .and_then(|ecn| quinn_udp::EcnCodepoint::from_bits(ecn as u8)),
            contents,
            segment_size: transmit.segment_size,
            src_ip: transmit.src_ip,
        };
        #[cfg(test)]
        {
            let datagrams = datagram_count(contents.len(), transmit.segment_size);
            self.largest_transmit = self.largest_transmit.max(datagrams);
        }
        if self.has_pending() {
            self.retain(&transmit);
            return Ok(false);
        }
        match self.try_send(&transmit) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.retain(&transmit);
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// Best-effort send for stateless replies (Retry, version negotiation,
    /// stateless reset, refusals) that the peer regenerates by retransmitting.
    /// Retained on `WouldBlock` while there is room; dropped otherwise.
    pub(crate) fn send_stateless(&mut self, transmit: &quinn_proto::Transmit, contents: &[u8]) {
        match self.send(transmit, contents) {
            Ok(_) | Err(_) => {}
        }
    }

    fn try_send(&mut self, transmit: &quinn_udp::Transmit<'_>) -> io::Result<()> {
        #[cfg(test)]
        if self.blocked {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.state.try_send((&self.udp).into(), transmit)?;
        self.tally.sent(
            datagram_count(transmit.contents.len(), transmit.segment_size),
            transmit.contents.len(),
        );
        Ok(())
    }

    /// Retains a transmit for a later flush, dropping it when the queue has
    /// no room for all of its datagrams.
    fn retain(&mut self, transmit: &quinn_udp::Transmit<'_>) {
        let pending = PendingTransmit {
            contents: transmit.contents.to_vec(),
            destination: transmit.destination,
            segment_size: transmit.segment_size,
            ecn: transmit.ecn,
            src_ip: transmit.src_ip,
        };
        let datagrams = pending.datagrams();
        if self.retained + datagrams > self.max_pending {
            return;
        }
        self.retained += datagrams;
        self.pending.push_back(pending);
    }

    /// Retries retained transmits until the socket pushes back again.
    ///
    /// Retained transmits may target different destinations, so a dead route
    /// for one neither fails the flush nor blocks the rest: it is dropped.
    pub(crate) fn flush(&mut self) {
        while let Some(pending) = self.pending.pop_front() {
            match self.try_send(&pending.as_transmit()) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.pending.push_front(pending);
                    break;
                }
                Ok(()) | Err(_) => {
                    self.retained = self.retained.saturating_sub(pending.datagrams());
                }
            }
        }
    }

    /// Drops every retained transmit.
    pub(crate) fn clear(&mut self) {
        self.pending.clear();
        self.retained = 0;
    }

    /// Reads what is queued into `buf`; `None` once nothing is.
    pub(crate) fn recv(&mut self, buf: &mut [u8]) -> io::Result<Option<Received>> {
        let mut meta = [RecvMeta::default()];
        match self
            .state
            .recv((&self.udp).into(), &mut [IoSliceMut::new(buf)], &mut meta)
        {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(e),
        }
        let [meta] = meta;
        let received = Received {
            len: meta.len,
            stride: if meta.stride == 0 {
                meta.len
            } else {
                meta.stride
            },
            from: meta.addr,
            ecn: meta
                .ecn
                .and_then(|ecn| quinn_proto::EcnCodepoint::from_bits(ecn as u8)),
            dst_ip: meta.dst_ip,
        };
        self.tally.received(received.datagrams(), received.len);
        #[cfg(test)]
        {
            self.received += received.datagrams();
        }
        Ok(Some(received))
    }

    /// Segments the platform lets one transmit carry.
    #[cfg(test)]
    pub(crate) fn platform_gso_segments(&self) -> usize {
        self.state.max_gso_segments()
    }

    /// Logical datagrams retained.
    #[cfg(test)]
    pub(crate) fn retained(&self) -> usize {
        self.retained
    }

    /// Retains a datagram as if the socket had pushed back.
    #[cfg(test)]
    pub(crate) fn retain_datagram(&mut self, contents: &[u8], destination: SocketAddr) {
        self.retain(&quinn_udp::Transmit {
            destination,
            ecn: None,
            contents,
            segment_size: None,
            src_ip: None,
        });
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
