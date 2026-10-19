use minip2p_transport::InvalidLimit;

/// Resource limits of one [`WebTransportClient`](crate::WebTransportClient),
/// mirroring the QUIC transport's `QuicLimits` where they mean the same.
///
/// Together they bound what a remote or a slow application can make the
/// client hold: connections, streams, queued writes (in Rust and in the
/// platform), and received bytes the reader has not acknowledged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebTransportLimits {
    /// Most connections held at once, connecting or connected.
    ///
    /// An ended connection whose delivered bytes are not yet acknowledged or
    /// abandoned still counts (ADR 0012's unsettled connection): with every
    /// slot held, dials fail with `ResourceExhausted`.
    pub max_connections: usize,
    /// Most streams per connection in each direction, counting closed
    /// streams whose delivered bytes are not yet acknowledged. Opens past it
    /// fail with `ResourceExhausted`; the server's streams past it are reset
    /// with no event.
    pub max_streams_per_connection: usize,
    /// Most bytes one stream holds from `send_stream` until the platform
    /// reports them written: queued in Rust or in flight in the platform.
    /// Must be non-zero.
    pub max_pending_bytes_per_stream: usize,
    /// Most bytes one connection holds the same way, across its streams.
    /// Must be greater than
    /// [`control_stream_reserve_bytes`](Self::control_stream_reserve_bytes).
    ///
    /// A write takes what fits both this and
    /// [`max_pending_bytes_per_stream`](Self::max_pending_bytes_per_stream)
    /// and returns `Full` with the rest; `StreamWritable` follows once half
    /// the smaller cap is free again.
    pub max_pending_connection_bytes: usize,
    /// Part of [`max_pending_connection_bytes`](Self::max_pending_connection_bytes)
    /// only control streams (ping, Identify, multistream negotiation) may
    /// fill.
    pub control_stream_reserve_bytes: usize,
    /// Each stream's receive budget: the most delivered bytes it holds
    /// unacknowledged, plus reads granted to the platform and not yet
    /// delivered. Must be non-zero.
    pub stream_receive_window: usize,
    /// How long a dial may take from its first poll to `Connected` (the
    /// session, then Noise) before it closes with `TimedOut`. Must be
    /// non-zero.
    pub handshake_timeout_ms: u64,
}

impl WebTransportLimits {
    /// Checks the limits can work.
    pub fn validate(&self) -> Result<(), InvalidLimit> {
        let nonzero = [
            ("max_connections", self.max_connections),
            (
                "max_streams_per_connection",
                self.max_streams_per_connection,
            ),
            (
                "max_pending_bytes_per_stream",
                self.max_pending_bytes_per_stream,
            ),
            ("stream_receive_window", self.stream_receive_window),
        ];
        for (field, value) in nonzero {
            if value == 0 {
                return Err(InvalidLimit {
                    field,
                    requirement: "must be non-zero",
                });
            }
        }
        if self.handshake_timeout_ms == 0 {
            return Err(InvalidLimit {
                field: "handshake_timeout_ms",
                requirement: "must be non-zero",
            });
        }
        if self.max_pending_connection_bytes <= self.control_stream_reserve_bytes {
            return Err(InvalidLimit {
                field: "max_pending_connection_bytes",
                requirement: "must be greater than control_stream_reserve_bytes",
            });
        }
        Ok(())
    }
}

impl Default for WebTransportLimits {
    fn default() -> Self {
        Self {
            max_connections: 1_024,
            max_streams_per_connection: 128,
            max_pending_bytes_per_stream: 256 * 1024,
            max_pending_connection_bytes: 1024 * 1024,
            control_stream_reserve_bytes: 256 * 1024,
            stream_receive_window: 256 * 1024,
            handshake_timeout_ms: 10_000,
        }
    }
}
