//! The UDP socket a transport owns, driven through quinn-udp (GSO, GRO, ECN
//! and packet info where the platform has them), and the datagrams it
//! retains while the socket pushes back.
//!
//! Every count here is in logical datagrams: a GSO transmit or a GRO receive
//! of several segments counts once per segment.

use std::collections::VecDeque;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, SocketAddr, UdpSocket};

use bytes::BytesMut;
use minip2p_transport::{ConnectionIdAllocator, ConnectionNamespace};
use quinn_udp::{RecvMeta, UdpSocketState};

use crate::diagnostics::{DatagramTally, SocketBuffers};

/// Largest UDP payload a single datagram can carry.
const MAX_DATAGRAM_SIZE: usize = 65_535;

/// Most datagrams one transmit carries, whatever the platform could segment.
///
/// Larger GSO trains arrive as bursts a receiver's socket buffer drops;
/// quinn itself caps a transmit at the same 10.
const MAX_TRANSMIT_SEGMENTS: usize = 10;

/// Kernel buffer size asked for in each direction, best effort: a platform
/// may cap it (Linux at `net.core.{w,r}mem_max`) or refuse it, in which case
/// smaller sizes are tried. Platform defaults (about 208 KiB on Linux, a
/// 9216-byte send buffer on macOS, which silently drops part of a batch:
/// mozilla/neqo#3898) overflow under bursts a multi-megabyte send window
/// allows.
pub(crate) const SOCKET_BUFFER_BYTES: usize = 4 << 20;

/// Smallest size [`grow_buffer`] tries before giving up on a direction.
pub(crate) const MIN_SOCKET_BUFFER_BYTES: usize = 64 << 10;

/// Raises a socket buffer toward [`SOCKET_BUFFER_BYTES`], halving the request
/// while the platform refuses it (BSDs and macOS do; Linux caps silently).
/// Stops once a request is no larger than `current`, the size the OS reports
/// now, so it never asks for less. A Linux host whose default exceeds its cap
/// (the sysctls are independent) still ends up at the cap; without
/// `CAP_NET_ADMIN` the default cannot be restored, so that is accepted.
pub(crate) fn grow_buffer(current: usize, mut set: impl FnMut(usize) -> io::Result<()>) {
    let mut bytes = SOCKET_BUFFER_BYTES;
    while bytes > current && bytes >= MIN_SOCKET_BUFFER_BYTES {
        if set(bytes).is_ok() {
            return;
        }
        bytes /= 2;
    }
}

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

/// What one receive slot holds: one datagram, or a GRO batch of datagrams
/// `stride` bytes apart (the last may be shorter).
pub(crate) struct Received {
    /// Where the slot starts in the receive buffer.
    pub(crate) offset: usize,
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

    /// Copies each datagram out of `buf`, the buffer the slot was read into,
    /// into an allocation of exactly its length.
    ///
    /// The engine keeps STREAM frames as slices of their packet, so a chunk
    /// it buffers pins whatever allocation backs the datagram. Separate
    /// allocations bound that to one datagram, not a whole receive call, in
    /// the spirit of ADR 0012's retained-slice rule.
    pub(crate) fn datagrams_in<'a>(&self, buf: &'a [u8]) -> impl Iterator<Item = BytesMut> + 'a {
        buf.get(self.offset..self.offset + self.len)
            .expect("UDP receive lengths fit their slots")
            // A stride of 0 means one datagram, as in `datagram_count`.
            .chunks(match self.stride {
                0 => usize::MAX,
                stride => stride,
            })
            .map(BytesMut::from)
    }
}

/// A non-blocking UDP socket plus its bounded retry queue, and the state the
/// transport keeps per socket: connection ids come from the socket's family
/// namespace, and each socket has its own receive bound, so one family's
/// traffic cannot starve the other's.
pub(crate) struct Socket {
    pub(crate) udp: UdpSocket,
    state: UdpSocketState,
    /// Fixed when the socket was bound.
    pub(crate) local_addr: SocketAddr,
    /// Whether `listen` accepted one of this socket's addresses: only then
    /// are inbound connections admitted.
    pub(crate) listening: bool,
    /// Whether the socket serves libp2p QUIC (ALPN `libp2p`), set at bind.
    pub(crate) quic_v1: bool,
    /// Whether the socket serves WebTransport (ALPN `h3`), set at bind.
    pub(crate) webtransport: bool,
    /// Whether `listen` already announced the `quic-v1` and the
    /// WebTransport address.
    pub(crate) announced: (bool, bool),
    /// Ids for this socket's connections, in its family's namespace.
    pub(crate) ids: ConnectionIdAllocator,
    /// The last receive batch hit its bound, so input may be waiting with no
    /// fresh readiness edge to report it.
    pub(crate) saturated: bool,
    /// Transmits waiting for the socket to become writable, oldest first.
    pending: VecDeque<PendingTransmit>,
    /// Logical datagrams in `pending`.
    retained: usize,
    /// Cap on `retained`.
    max_pending: usize,
    /// Socket datagram counts and granted buffers; empty unless the
    /// `diagnostics` feature is on.
    pub(crate) tally: DatagramTally,
    /// Test hooks: a cap on segments per transmit, and a socket that
    /// refuses every send with `WouldBlock`.
    #[cfg(test)]
    pub(crate) max_segments: usize,
    #[cfg(test)]
    pub(crate) blocked: bool,
    /// Buffer sizes the OS granted.
    #[cfg(test)]
    pub(crate) buffers: SocketBuffers,
    /// The most logical datagrams one transmit carried.
    #[cfg(test)]
    pub(crate) largest_transmit: usize,
    /// Logical datagrams received.
    #[cfg(test)]
    pub(crate) received: usize,
    /// Receive calls that returned input.
    #[cfg(test)]
    pub(crate) recv_calls: usize,
}

impl Socket {
    /// Wraps a bound, non-blocking socket, enabling what offloads the
    /// platform offers and growing its buffers where the platform lets it.
    pub(crate) fn new(
        udp: UdpSocket,
        local_addr: SocketAddr,
        max_pending: usize,
        tally: DatagramTally,
    ) -> io::Result<Self> {
        let state = UdpSocketState::new((&udp).into())?;
        #[cfg(target_vendor = "apple")]
        enable_apple_fast_path(&state);
        let buffers = grow_buffers(&state, &udp);
        tally.record_socket_buffers(buffers);
        let namespace = if local_addr.is_ipv6() {
            ConnectionNamespace::QUIC_IPV6
        } else {
            ConnectionNamespace::QUIC_IPV4
        };
        Ok(Self {
            udp,
            state,
            local_addr,
            listening: false,
            quic_v1: true,
            webtransport: false,
            announced: (false, false),
            ids: ConnectionIdAllocator::new(namespace),
            saturated: false,
            pending: VecDeque::new(),
            retained: 0,
            max_pending,
            tally,
            #[cfg(test)]
            max_segments: usize::MAX,
            #[cfg(test)]
            blocked: false,
            #[cfg(test)]
            buffers,
            #[cfg(test)]
            largest_transmit: 0,
            #[cfg(test)]
            received: 0,
            #[cfg(test)]
            recv_calls: 0,
        })
    }

    /// Whether datagrams sent here can be fragmented on the way, which rules
    /// out path MTU discovery.
    pub(crate) fn may_fragment(&self) -> bool {
        self.state.may_fragment()
    }

    /// Datagram slots one receive call fills: several where the platform
    /// batches receives without GRO, one GRO batch otherwise.
    pub(crate) fn recv_slots(&self) -> usize {
        if self.state.gro_segments() > 1 {
            1
        } else {
            quinn_udp::BATCH_SIZE
        }
    }

    /// A receive buffer of [`Self::recv_slots`] slots: a lone slot holds one
    /// full GRO batch, or one datagram of any size; several each hold one
    /// datagram of up to `max_udp_payload` bytes.
    pub(crate) fn recv_buffer_len(&self, max_udp_payload: usize) -> usize {
        match self.recv_slots() {
            1 => (self.state.gro_segments() * max_udp_payload).max(MAX_DATAGRAM_SIZE),
            slots => slots * max_udp_payload,
        }
    }

    /// How many logical datagrams the next transmit may carry: what the
    /// platform can segment, within what the retry queue could still keep if
    /// the socket pushed back. Zero means stop asking the engine for output:
    /// it advances congestion and loss state for every packet it hands out.
    pub(crate) fn allowance(&self) -> usize {
        let segments = self.state.max_gso_segments().min(MAX_TRANSMIT_SEGMENTS);
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

    /// Reads what is queued into `buf`, cut into [`Self::recv_slots`] equal
    /// slots, and appends one [`Received`] per filled slot to `received`.
    /// Returns `false` once nothing is queued.
    ///
    /// A datagram larger than its slot, which a peer honouring the
    /// endpoint's advertised maximum payload never sends, arrives truncated
    /// and the engine drops it.
    pub(crate) fn recv(
        &mut self,
        buf: &mut [u8],
        received: &mut Vec<Received>,
    ) -> io::Result<bool> {
        let slots = self.recv_slots();
        let slot_len = buf.len() / slots;
        let mut chunks = buf.chunks_mut(slot_len);
        let mut bufs: [IoSliceMut<'_>; quinn_udp::BATCH_SIZE] =
            std::array::from_fn(|_| IoSliceMut::new(chunks.next().unwrap_or_default()));
        let mut meta = [RecvMeta::default(); quinn_udp::BATCH_SIZE];
        let within = "receive slots never exceed quinn-udp's BATCH_SIZE";
        let count = match self.state.recv(
            (&self.udp).into(),
            bufs.get_mut(..slots).expect(within),
            meta.get_mut(..slots).expect(within),
        ) {
            Ok(count) => count,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) => return Err(e),
        };
        for (slot, meta) in meta.iter().take(count).enumerate() {
            let batch = Received {
                offset: slot * slot_len,
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
            self.tally.received(batch.datagrams(), batch.len);
            #[cfg(test)]
            {
                self.received += batch.datagrams();
            }
            received.push(batch);
        }
        self.tally.receive_call();
        #[cfg(test)]
        {
            self.recv_calls += 1;
        }
        Ok(true)
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

/// Switches `state` to Apple's batched `sendmsg_x`/`recvmsg_x` datapath,
/// which lets one call carry several datagrams where `sendmsg` carries one.
///
/// quinn-udp 0.6.3 ignores how many messages `sendmsg_x` reports sent, so a
/// batch the socket only partly takes still counts as sent: its tail is lost
/// in-process and recovered like network loss. The grown send buffer is what
/// keeps that rare (mozilla/neqo#3898); the measured run lost nothing.
#[cfg(target_vendor = "apple")]
#[expect(
    unsafe_code,
    reason = "the workspace's one unsafe exception: Apple's fast datapath (#359, ADR 0019)"
)]
fn enable_apple_fast_path(state: &UdpSocketState) {
    // SAFETY: the calls are private Apple APIs. quinn-udp resolves
    // `sendmsg_x`/`recvmsg_x` through `dlsym` before first use and falls back
    // to `sendmsg`/`recvmsg` for good when either symbol is missing, so an OS
    // without them is never called into.
    unsafe { state.set_apple_fast_path() }
}

/// Grows `udp`'s send and receive buffers, best effort, and reads back what
/// the OS granted (0 where it cannot say). quinn-udp's setters keep Apple's
/// send buffer at its safe minimum for batched sends.
fn grow_buffers(state: &UdpSocketState, udp: &UdpSocket) -> SocketBuffers {
    let send = state.send_buffer_size(udp.into()).unwrap_or(0);
    grow_buffer(send, |bytes| state.set_send_buffer_size(udp.into(), bytes));
    let recv = state.recv_buffer_size(udp.into()).unwrap_or(0);
    grow_buffer(recv, |bytes| state.set_recv_buffer_size(udp.into(), bytes));
    SocketBuffers {
        send_bytes: state.send_buffer_size(udp.into()).unwrap_or(0),
        recv_bytes: state.recv_buffer_size(udp.into()).unwrap_or(0),
    }
}

/// A transport's sockets: one or two, at most one per address family.
pub(crate) struct Sockets(Vec<Socket>);

impl Sockets {
    pub(crate) fn new(sockets: Vec<Socket>) -> Self {
        Self(sockets)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &Socket> {
        self.0.iter()
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut Socket> {
        self.0.iter_mut()
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn get(&self, index: usize) -> Option<&Socket> {
        self.0.get(index)
    }

    pub(crate) fn get_mut(&mut self, index: usize) -> Option<&mut Socket> {
        self.0.get_mut(index)
    }

    /// The socket of `addr`'s family.
    pub(crate) fn for_addr(&mut self, addr: SocketAddr) -> Option<&mut Socket> {
        self.0
            .iter_mut()
            .find(|socket| socket.local_addr.is_ipv6() == addr.is_ipv6())
    }
}

/// Non-blocking check for a datagram already queued on `socket`.
///
/// The socket must be in its usual non-blocking mode. Peeks one byte, so no
/// input is consumed. Errors other than `WouldBlock` count as ready so the
/// next `poll()` can surface them.
#[cfg(test)]
pub(crate) fn has_queued_input(socket: &UdpSocket) -> bool {
    let mut probe = [0u8; 1];
    match socket.peek_from(&mut probe) {
        Ok(_) => true,
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
        Err(_) => true,
    }
}
