//! Sans-IO transport trait and connection/stream types for minip2p.
//!
//! Defines the [`Transport`] trait that concrete adapters implement, along with
//! event, action, error, and identifier types. `no_std` + `alloc` compatible.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod action;
mod connection_endpoint;
mod connection_id;
mod connection_state;
mod error;
mod event;
mod stream_id;
mod transport;

pub use action::TransportAction;
pub use connection_endpoint::ConnectionEndpoint;
pub use connection_id::ConnectionId;
pub use connection_state::ConnectionState;
pub use error::TransportError;
pub use event::TransportEvent;
pub use stream_id::StreamId;
pub use transport::Transport;
