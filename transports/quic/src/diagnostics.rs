//! Diagnostic counters, compiled in only with the `diagnostics` feature.
//!
//! Two views, both for comparing fast and slow runs rather than for
//! production use:
//!
//! - [`ConnectionDiagnostics`], per connection: datagrams routed to it,
//!   flushes, and the engine's own transmit, loss and congestion figures.
//!   Read one with `QuicTransport::connection_diagnostics`; each connection
//!   also prints its totals to stderr when dropped.
//! - [`DatagramCounters`], per local identity: datagrams actually handed to
//!   or read from the UDP sockets of every transport bound with that
//!   identity, both address families included. Read them from any thread with
//!   [`datagram_counters`], and the socket buffer sizes the OS granted with
//!   [`socket_buffers`].
//!
//! Without the feature the public items here do not exist (bar
//! [`SocketBuffers`], which the sockets record either way), and the recording
//! hooks the transport calls are empty inline functions.

#[cfg(feature = "diagnostics")]
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicU64, Ordering::Relaxed},
};
#[cfg(feature = "diagnostics")]
use std::time::Duration;

use minip2p_core::PeerId;

/// One connection's counters since it was created.
#[cfg(feature = "diagnostics")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnectionDiagnostics {
    /// Datagrams routed to this connection.
    pub datagrams_received: u64,
    /// UDP datagrams the engine produced for this connection (sent, or
    /// retained for a writable socket).
    pub datagrams_sent: u64,
    /// Total bytes of those datagrams.
    pub bytes_sent: u64,
    /// Flushes: passes that asked the engine for output, from any trigger.
    pub flushes: u64,
    /// Packets the engine declared lost.
    pub lost_packets: u64,
    /// Current congestion window, in bytes.
    pub cwnd: u64,
    /// Current smoothed round-trip time.
    pub rtt: Duration,
}

#[cfg(feature = "diagnostics")]
impl ConnectionDiagnostics {
    /// Mean sent datagram size in bytes, or 0 before any datagram.
    pub fn average_datagram_bytes(&self) -> f64 {
        ratio(self.bytes_sent, self.datagrams_sent)
    }

    /// Flushes per received datagram, from any trigger.
    pub fn flushes_per_datagram(&self) -> f64 {
        ratio(self.flushes, self.datagrams_received)
    }
}

#[cfg(feature = "diagnostics")]
impl core::fmt::Display for ConnectionDiagnostics {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "datagrams_received={} flushes={} ({:.3}/datagram) datagrams_sent={} \
             avg_datagram_bytes={:.0} lost_packets={} cwnd={} rtt={:?}",
            self.datagrams_received,
            self.flushes,
            self.flushes_per_datagram(),
            self.datagrams_sent,
            self.average_datagram_bytes(),
            self.lost_packets,
            self.cwnd,
            self.rtt,
        )
    }
}

/// Datagrams one local identity's QUIC sockets moved, since the first
/// transport with that identity was bound.
///
/// `sent` counts datagrams the socket accepted, not packets the engine generated:
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

/// Kernel buffer sizes the OS granted a UDP socket, in bytes, as it reports
/// them (Linux reports twice what was set). 0 where the OS could not say.
///
/// The transport asks for a fixed size best effort; there is no knob.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SocketBuffers {
    /// `SO_SNDBUF`.
    pub send_bytes: usize,
    /// `SO_RCVBUF`.
    pub recv_bytes: usize,
}

/// The smallest buffers granted to any socket bound with `peer` as its
/// identity since the first live transport with it was bound, each direction
/// on its own, ignoring sizes the OS could not report; `None` once all of
/// them are dropped, or if none was bound.
#[cfg(feature = "diagnostics")]
pub fn socket_buffers(peer: &PeerId) -> Option<SocketBuffers> {
    let tally = lookup(peer)?;
    *tally
        .buffers
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The counters of every live transport bound with `peer` as its identity;
/// zeros once all of them are dropped, or if none was bound.
#[cfg(feature = "diagnostics")]
pub fn datagram_counters(peer: &PeerId) -> DatagramCounters {
    lookup(peer).map_or_else(DatagramCounters::default, |tally| DatagramCounters {
        sent: tally.sent.load(Relaxed),
        sent_bytes: tally.sent_bytes.load(Relaxed),
        received: tally.received.load(Relaxed),
        received_bytes: tally.received_bytes.load(Relaxed),
    })
}

/// `peer`'s live tally. Only the lookup holds the registry lock; the upgraded
/// `Arc` keeps the counters alive for the reads.
#[cfg(feature = "diagnostics")]
fn lookup(peer: &PeerId) -> Option<Arc<Atomics>> {
    REGISTRY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .find(|(id, _)| id == peer)
        .and_then(|(_, tally)| tally.upgrade())
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
    /// Smallest granted per direction across the identity's sockets.
    buffers: Mutex<Option<SocketBuffers>>,
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

    /// A socket of this identity was granted `buffers`.
    #[cfg_attr(
        not(feature = "diagnostics"),
        expect(
            unused_variables,
            reason = "the hooks record nothing without the feature"
        )
    )]
    pub(crate) fn record_socket_buffers(&self, buffers: SocketBuffers) {
        #[cfg(feature = "diagnostics")]
        {
            let mut smallest = self
                .atomics
                .buffers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // 0 means the OS could not say, so it never wins the minimum.
            let min = |known: usize, granted: usize| match (known, granted) {
                (0, granted) => granted,
                (known, 0) => known,
                (known, granted) => known.min(granted),
            };
            *smallest = Some(smallest.map_or(buffers, |known| SocketBuffers {
                send_bytes: min(known.send_bytes, buffers.send_bytes),
                recv_bytes: min(known.recv_bytes, buffers.recv_bytes),
            }));
        }
    }

    /// The socket accepted `datagrams` datagrams totalling `bytes` bytes.
    #[inline]
    #[cfg_attr(
        not(feature = "diagnostics"),
        expect(
            unused_variables,
            reason = "the hooks record nothing without the feature"
        )
    )]
    pub(crate) fn sent(&self, datagrams: usize, bytes: usize) {
        #[cfg(feature = "diagnostics")]
        {
            self.atomics.sent.fetch_add(datagrams as u64, Relaxed);
            self.atomics.sent_bytes.fetch_add(bytes as u64, Relaxed);
        }
    }

    /// The socket delivered `datagrams` datagrams totalling `bytes` bytes.
    #[inline]
    #[cfg_attr(
        not(feature = "diagnostics"),
        expect(
            unused_variables,
            reason = "the hooks record nothing without the feature"
        )
    )]
    pub(crate) fn received(&self, datagrams: usize, bytes: usize) {
        #[cfg(feature = "diagnostics")]
        {
            self.atomics.received.fetch_add(datagrams as u64, Relaxed);
            self.atomics.received_bytes.fetch_add(bytes as u64, Relaxed);
        }
    }
}

/// A connection's recording hooks: the counts the engine does not keep.
#[derive(Default)]
pub(crate) struct ConnectionCounters {
    #[cfg(feature = "diagnostics")]
    datagrams_received: u64,
    #[cfg(feature = "diagnostics")]
    flushes: u64,
}

impl ConnectionCounters {
    /// These counts plus the engine's `stats`.
    #[cfg(feature = "diagnostics")]
    pub(crate) fn snapshot(&self, stats: &quinn_proto::ConnectionStats) -> ConnectionDiagnostics {
        ConnectionDiagnostics {
            datagrams_received: self.datagrams_received,
            datagrams_sent: stats.udp_tx.datagrams,
            bytes_sent: stats.udp_tx.bytes,
            flushes: self.flushes,
            lost_packets: stats.path.lost_packets,
            cwnd: stats.path.cwnd,
            rtt: stats.path.rtt,
        }
    }

    /// The endpoint routed a datagram to this connection.
    #[inline]
    pub(crate) fn datagram_received(&mut self) {
        #[cfg(feature = "diagnostics")]
        {
            self.datagrams_received += 1;
        }
    }

    /// A flush starts asking the engine for output.
    #[inline]
    pub(crate) fn flush(&mut self) {
        #[cfg(feature = "diagnostics")]
        {
            self.flushes += 1;
        }
    }
}
