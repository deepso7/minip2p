//! Sans-IO transport trait and connection/stream types for minip2p.
//!
//! Defines the [`Transport`] trait that concrete adapters implement, along with
//! event, action, error, and identifier types. `no_std` + `alloc` compatible.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "bench")]
pub mod bench;
mod connection_endpoint;
mod connection_id;
mod connection_state;
mod connection_token;
mod error;
mod event;
mod memory;
#[cfg(feature = "std")]
mod poll;
mod set;
mod stream_id;
mod transport;
mod unsettled;

pub use connection_endpoint::ConnectionEndpoint;
pub use connection_id::{ConnectionId, ConnectionIdAllocator, ConnectionNamespace};
pub use connection_state::ConnectionState;
pub use connection_token::ConnectionToken;
pub use error::TransportError;
pub use event::TransportEvent;
pub use memory::{InvalidLimit, MemoryLedger};
/// Stream payload type, re-exported from [`minip2p_core::Bytes`] so adapters
/// need no extra dependency.
pub use minip2p_core::Bytes;
pub use set::{RejectedTransport, TransportSet, TransportSetError};
pub use stream_id::StreamId;
pub use transport::Transport;
pub use unsettled::UnsettledConnections;

/// The readiness crate std sources register with, re-exported so a
/// [`PollSource`] needs no extra dependency to name its types.
#[cfg(feature = "std")]
pub use mio;
#[cfg(feature = "std")]
pub use poll::{
    BlockingTransport, PollSource, SharedPoll, TokenSpace, TokenSpaceError, WaitHandle, WakeHandle,
};
