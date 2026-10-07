//! Diagnostic counters, compiled in only with the `diagnostics` feature.
//!
//! Two views, both for comparing fast and slow runs rather than for
//! production use:
//!
//! - [`ConnectionDiagnostics`], per connection: datagrams received, flushes
//!   (and how many a received datagram triggered), packet sizes, and packets
//!   cut short while stream data was waiting. Read one with
//!   `QuicTransport::connection_diagnostics`; each connection also prints its
//!   totals to stderr when dropped.
//! - [`DatagramCounters`], per local identity: datagrams actually handed to
//!   or read from the UDP sockets of every transport bound with that
//!   identity, both address families included. Read them from any thread with
//!   [`datagram_counters`].
//!
//! Without the feature the public items here do not exist, and the recording
//! hooks the transport calls are empty inline functions.

#[cfg(feature = "diagnostics")]
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicU64, Ordering::Relaxed},
};

use minip2p_core::PeerId;

/// One connection's counters since it was created.
#[cfg(feature = "diagnostics")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnectionDiagnostics {
    /// Datagrams routed to this connection.
    pub datagrams_received: u64,
    /// Flushes: passes that pulled packets from quiche, from any trigger.
    pub flushes: u64,
    /// Flushes run while handling a received datagram. Once established, a
    /// connection leaves its output for the flush after the receive batch,
    /// so this stays near the handshake's few.
    pub receive_flushes: u64,
    /// Packets quiche generated (sent, retained for a writable socket, or
    /// held for pacing).
    pub packets: u64,
    /// Total bytes of those packets.
    pub packet_bytes: u64,
    /// Packets smaller than the path's maximum UDP payload.
    pub underfilled_packets: u64,
    /// Underfilled packets that ended a flush while stream writes were still
    /// queued: quiche stopped with data waiting, which on an established
    /// connection means the free congestion window (or peer flow control)
    /// cut the packet's size budget. quiche does not expose its free window,
    /// so this approximates "trimmed by the window".
    pub window_limited_packets: u64,
}

#[cfg(feature = "diagnostics")]
impl ConnectionDiagnostics {
    /// Mean packet size in bytes, or 0 before any packet.
    pub fn average_packet_bytes(&self) -> f64 {
        ratio(self.packet_bytes, self.packets)
    }

    /// Flushes per received datagram, from any trigger.
    pub fn flushes_per_datagram(&self) -> f64 {
        ratio(self.flushes, self.datagrams_received)
    }

    /// Flushes run while handling a received datagram, per received datagram.
    pub fn receive_flushes_per_datagram(&self) -> f64 {
        ratio(self.receive_flushes, self.datagrams_received)
    }
}

#[cfg(feature = "diagnostics")]
impl core::fmt::Display for ConnectionDiagnostics {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "datagrams_received={} flushes={} ({:.3}/datagram) receive_flushes={} \
             ({:.3}/datagram) packets={} avg_packet_bytes={:.0} underfilled={} \
             window_limited={}",
            self.datagrams_received,
            self.flushes,
            self.flushes_per_datagram(),
            self.receive_flushes,
            self.receive_flushes_per_datagram(),
            self.packets,
            self.average_packet_bytes(),
            self.underfilled_packets,
            self.window_limited_packets,
        )
    }
}

/// Datagrams one local identity's QUIC sockets moved, since the first
/// transport with that identity was bound.
///
/// `sent` counts datagrams the socket accepted, not packets quiche generated:
/// a datagram retained on `WouldBlock` counts once it actually leaves, and
/// one the socket refused outright never does.
#[cfg(feature = "diagnostics")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DatagramCounters {
    /// Datagrams the sockets accepted for sending.
    pub sent: u64,
    /// Total bytes of those datagrams.
    pub sent_bytes: u64,
    /// Datagrams read from the sockets.
    pub received: u64,
    /// Total bytes of those datagrams.
    pub received_bytes: u64,
}

#[cfg(feature = "diagnostics")]
impl DatagramCounters {
    /// The counts accumulated since `earlier`, saturating at zero.
    pub fn since(&self, earlier: &Self) -> Self {
        Self {
            sent: self.sent.saturating_sub(earlier.sent),
            sent_bytes: self.sent_bytes.saturating_sub(earlier.sent_bytes),
            received: self.received.saturating_sub(earlier.received),
            received_bytes: self.received_bytes.saturating_sub(earlier.received_bytes),
        }
    }
}

/// The counters of every live transport bound with `peer` as its identity;
/// zeros once all of them are dropped, or if none was bound.
#[cfg(feature = "diagnostics")]
pub fn datagram_counters(peer: &PeerId) -> DatagramCounters {
    let registry = REGISTRY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    registry
        .iter()
        .find(|(id, _)| id == peer)
        .and_then(|(_, tally)| tally.upgrade())
        .map_or_else(DatagramCounters::default, |tally| DatagramCounters {
            sent: tally.sent.load(Relaxed),
            sent_bytes: tally.sent_bytes.load(Relaxed),
            received: tally.received.load(Relaxed),
            received_bytes: tally.received_bytes.load(Relaxed),
        })
}

#[cfg(feature = "diagnostics")]
fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

#[cfg(feature = "diagnostics")]
#[derive(Default)]
struct Atomics {
    sent: AtomicU64,
    sent_bytes: AtomicU64,
    received: AtomicU64,
    received_bytes: AtomicU64,
}

/// Live tallies by identity. Transports with the same identity, such as a
/// dual-stack pair, share one; entries whose transports are gone are pruned
/// on the next registration.
#[cfg(feature = "diagnostics")]
static REGISTRY: Mutex<Vec<(PeerId, Weak<Atomics>)>> = Mutex::new(Vec::new());

/// A transport's handle on its identity's [`DatagramCounters`].
#[derive(Clone, Default)]
pub(crate) struct DatagramTally {
    #[cfg(feature = "diagnostics")]
    atomics: Arc<Atomics>,
}

impl DatagramTally {
    /// The tally shared by every live transport bound as `peer`.
    #[cfg_attr(
        not(feature = "diagnostics"),
        expect(
            unused_variables,
            reason = "the hooks record nothing without the feature"
        )
    )]
    pub(crate) fn register(peer: &PeerId) -> Self {
        #[cfg(feature = "diagnostics")]
        {
            let mut registry = REGISTRY
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.retain(|(_, tally)| tally.strong_count() > 0);
            if let Some(atomics) = registry
                .iter()
                .find(|(id, _)| id == peer)
                .and_then(|(_, tally)| tally.upgrade())
            {
                return Self { atomics };
            }
            let atomics = Arc::new(Atomics::default());
            registry.push((peer.clone(), Arc::downgrade(&atomics)));
            Self { atomics }
        }
        #[cfg(not(feature = "diagnostics"))]
        Self {}
    }

    /// The socket accepted a datagram of `len` bytes.
    #[inline]
    #[cfg_attr(
        not(feature = "diagnostics"),
        expect(
            unused_variables,
            reason = "the hooks record nothing without the feature"
        )
    )]
    pub(crate) fn sent(&self, len: usize) {
        #[cfg(feature = "diagnostics")]
        {
            self.atomics.sent.fetch_add(1, Relaxed);
            self.atomics.sent_bytes.fetch_add(len as u64, Relaxed);
        }
    }

    /// The socket delivered a datagram of `len` bytes.
    #[inline]
    #[cfg_attr(
        not(feature = "diagnostics"),
        expect(
            unused_variables,
            reason = "the hooks record nothing without the feature"
        )
    )]
    pub(crate) fn received(&self, len: usize) {
        #[cfg(feature = "diagnostics")]
        {
            self.atomics.received.fetch_add(1, Relaxed);
            self.atomics.received_bytes.fetch_add(len as u64, Relaxed);
        }
    }
}

/// A connection's recording hooks: its own [`ConnectionDiagnostics`] plus
/// its transport's [`DatagramTally`].
pub(crate) struct ConnectionCounters {
    tally: DatagramTally,
    #[cfg(feature = "diagnostics")]
    counts: ConnectionDiagnostics,
    /// The flush's latest packet was underfilled.
    #[cfg(feature = "diagnostics")]
    last_underfilled: bool,
}

#[cfg_attr(
    not(feature = "diagnostics"),
    expect(
        unused_variables,
        reason = "the hooks record nothing without the feature"
    )
)]
impl ConnectionCounters {
    pub(crate) fn new(tally: DatagramTally) -> Self {
        Self {
            tally,
            #[cfg(feature = "diagnostics")]
            counts: ConnectionDiagnostics::default(),
            #[cfg(feature = "diagnostics")]
            last_underfilled: false,
        }
    }

    #[cfg(feature = "diagnostics")]
    pub(crate) fn snapshot(&self) -> ConnectionDiagnostics {
        self.counts
    }

    /// The socket accepted one of this connection's datagrams.
    #[inline]
    pub(crate) fn sent(&self, len: usize) {
        self.tally.sent(len);
    }

    #[inline]
    pub(crate) fn datagram_received(&mut self) {
        #[cfg(feature = "diagnostics")]
        {
            self.counts.datagrams_received += 1;
        }
    }

    /// A received datagram is about to trigger a flush.
    #[inline]
    pub(crate) fn receive_flush(&mut self) {
        #[cfg(feature = "diagnostics")]
        {
            self.counts.receive_flushes += 1;
        }
    }

    /// A flush starts pulling packets from quiche.
    #[inline]
    pub(crate) fn flush(&mut self) {
        #[cfg(feature = "diagnostics")]
        {
            self.counts.flushes += 1;
            self.last_underfilled = false;
        }
    }

    /// quiche generated a `len`-byte packet; `full` is the path's maximum.
    #[inline]
    pub(crate) fn packet(&mut self, len: usize, full: usize) {
        #[cfg(feature = "diagnostics")]
        {
            self.counts.packets += 1;
            self.counts.packet_bytes += len as u64;
            self.last_underfilled = len < full;
            self.counts.underfilled_packets += u64::from(self.last_underfilled);
        }
    }

    /// quiche had nothing more to send this flush.
    #[inline]
    pub(crate) fn quiche_done(&mut self, stream_writes_queued: bool) {
        #[cfg(feature = "diagnostics")]
        {
            self.counts.window_limited_packets +=
                u64::from(self.last_underfilled && stream_writes_queued);
        }
    }
}
