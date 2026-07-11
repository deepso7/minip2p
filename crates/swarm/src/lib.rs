//! Connection and protocol orchestration for minip2p.
//!
//! This crate provides two layers:
//!
//! - [`SwarmCore`] -- pure Sans-I/O state machine. `no_std + alloc`
//!   compatible. Callers feed it [`SwarmInput`] values through
//!   [`SwarmCore::handle_input`], then drain [`SwarmOutput`] values through
//!   [`SwarmCore::poll_output`] until [`SwarmCore::is_idle`] returns true.
//!   Outputs wrap [`SwarmAction`]s for a driver to execute and [`SwarmEvent`]s
//!   for the application to observe. No sockets, no async runtime, no clock
//!   reads.
//!
//! - [`Swarm`] -- std driver that owns a concrete
//!   [`Transport`](minip2p_transport::Transport) and a
//!   monotonic clock ([`std::time::Instant`]), and preserves the one-call
//!   DX (`swarm.dial(addr)`, `swarm.ping(peer)`, `swarm.open_stream`)
//!   by shuttling events and actions between the transport and the core.
//!
//! Most applications want [`Swarm`] and the [`SwarmBuilder`] convenience
//! constructor. Embedded or exotic runtimes that cannot depend on `std`
//! can use [`SwarmCore`] directly.
//!
//! Protocols baked into the core:
//! - `/ipfs/ping/1.0.0` (ping RTT measurement)
//! - `/ipfs/id/1.0.0` (identify)
//! - user-registered protocols (see [`SwarmCore::add_protocol`])

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod core;
mod events;

#[cfg(feature = "std")]
mod builder;
#[cfg(feature = "std")]
mod driver;

pub use crate::core::{RESERVED_PROTOCOL_IDS, SwarmCore};
pub use crate::events::{
    OpenStreamToken, SwarmAction, SwarmError, SwarmErrorKind, SwarmEvent, SwarmInput, SwarmOutput,
    SwarmRuntimeError,
};

#[cfg(feature = "std")]
pub use crate::builder::SwarmBuilder;
#[cfg(feature = "std")]
pub use crate::driver::{Clock, Deadline, DriverError, Swarm};
