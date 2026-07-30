//! Sans-I/O libp2p TCP transport over a pluggable byte-stream provider.
//!
//! ```text
//! TcpTransport            connection + stream ids, the Transport contract
//!   -> SecureMuxSession   multistream-select, Noise XX, Yamux
//!   -> TcpProvider        sockets, listeners, name resolution
//! ```
//!
//! [`TcpTransport`] owns no socket, no clock, and no executor: it turns
//! [`TcpEvent`]s from a provider into [`TransportEvent`]s for the host, and the
//! host's writes into provider writes. That split is what lets the same
//! transport run on hosted sockets and on an embedded stack -- only the
//! provider changes. `no_std + alloc`.
//!
//! [`TransportEvent`]: minip2p_transport::TransportEvent
//!
//! # Backpressure
//!
//! A session produces bytes whether or not the socket will take them, so the
//! transport buffers per connection and retries on
//! [`TcpEvent::Writable`] or on the next
//! [`poll`](minip2p_transport::Transport::poll). While anything is buffered,
//! [`next_deadline`](minip2p_transport::Transport::next_deadline) reports
//! immediate so a driver keeps coming back. A peer that stops reading
//! altogether is bounded by [`TcpConfig::max_buffered_send`], which fails that
//! connection rather than growing without limit.
//!
//! # Identity
//!
//! The upgrade authenticates both ends, so
//! [`Connected`](minip2p_transport::TransportEvent::Connected) always carries a
//! verified peer id. A dial additionally pins the expected identity from its
//! [`PeerAddr`](minip2p_core::PeerAddr): a remote that proves a different one
//! fails the handshake instead of connecting.
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

extern crate alloc;

mod config;
mod provider;
mod transport;

pub use config::TcpConfig;
pub use provider::{SocketHandle, TcpError, TcpEvent, TcpProvider};
pub use transport::TcpTransport;
