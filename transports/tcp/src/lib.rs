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
//! # Providers
//!
//! `StdTcpProvider` is the hosted one: operating-system sockets driven by
//! `mio`, with `/dns*` resolution and a real readiness wait, which makes
//! [`TcpTransport`] a `BlockingTransport` so an idle driver sleeps instead of
//! spinning. It needs the `std` feature.
//!
//! `SmoltcpTcpProvider` is the embedded one, over a [smoltcp] interface the
//! host configures and a link it supplies. It needs the `smoltcp` feature and
//! no operating system. Hosts with neither implement [`TcpProvider`] over their
//! own stack; nothing above the seam changes.
//!
//! [smoltcp]: https://docs.rs/smoltcp
//!
//! # Backpressure
//!
//! A session produces bytes whether or not the socket will take them, so the
//! transport buffers per connection and retries on every
//! [`poll`](minip2p_transport::Transport::poll) -- there is one flush point,
//! not a separate path for [`TcpEvent::Writable`], so a provider that reports
//! readiness coarsely still drains.
//!
//! While a socket is still accepting,
//! [`next_deadline`](minip2p_transport::Transport::next_deadline) reports
//! immediate so a driver keeps coming back. Once one refuses everything, it
//! reports when the stall turns fatal instead: claiming urgency against a
//! socket that takes nothing would spin a deadline-driven host for as long as
//! the peer stayed silent. Two limits bound the damage --
//! [`TcpConfig::max_buffered_send`] on how much may queue, and
//! [`TcpConfig::send_stall_timeout_ms`] on how long it may sit there.
//!
//! # Limits
//!
//! A connection holds a session -- Noise state, Yamux, buffers -- from the
//! moment the byte stream comes up, which is before the peer has proved
//! anything. [`TcpConfig::max_connections`] bounds how many exist at once, and
//! [`TcpConfig::handshake_timeout_ms`] bounds how long one may sit there
//! unauthenticated, so a peer that connects and then says nothing cannot hold
//! a slot indefinitely.
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

#[cfg(feature = "std")]
mod blocking;
mod config;
mod provider;
#[cfg(feature = "smoltcp")]
mod smoltcp_provider;
#[cfg(feature = "std")]
mod std_provider;
mod transport;

#[cfg(feature = "smoltcp")]
pub use minip2p_smoltcp::{SmoltcpStack, smoltcp};

#[cfg(feature = "std")]
pub use blocking::BlockingTcpProvider;
pub use config::TcpConfig;
pub use provider::{SocketHandle, TcpError, TcpEvent, TcpProvider};
#[cfg(feature = "smoltcp")]
pub use smoltcp_provider::{SmoltcpConfig, SmoltcpTcpProvider};
#[cfg(feature = "std")]
pub use std_provider::StdTcpProvider;
pub use transport::TcpTransport;
