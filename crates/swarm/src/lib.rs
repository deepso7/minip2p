//! Connection and protocol orchestration for minip2p.
//!
//! This crate provides three layers:
//!
//! - [`SwarmCore`] -- pure Sans-I/O state machine. `no_std + alloc`
//!   compatible. Callers feed it [`SwarmInput`] values through
//!   [`SwarmCore::handle_input`], then drain [`SwarmOutput`] values through
//!   [`SwarmCore::poll_output`] until [`SwarmCore::is_idle`] returns true.
//!   Outputs wrap [`SwarmAction`]s for a driver to execute and [`SwarmEvent`]s
//!   for the application to observe. No sockets, no async runtime, no clock
//!   reads.
//!
//! - [`SwarmRuntime`] -- `no_std + alloc` action pump. It owns a concrete
//!   [`Transport`](minip2p_transport::Transport) and shuttles events and
//!   actions between it and the core, but reads no clock and draws no
//!   randomness: the caller passes a [`Now`] sample into
//!   [`SwarmRuntime::poll`] and injects an
//!   [`EntropySource`]. It reports its next timer through
//!   [`SwarmRuntime::next_deadline`] so a host can idle instead of spinning.
//!
//! - `Swarm` -- `std` wrapper adding a monotonic clock and blocking drive
//!   loops (`poll_next`, `run_until`) on top of the runtime, preserving the
//!   one-call DX (`swarm.dial(addr)`, `swarm.ping(peer)`,
//!   `swarm.open_stream`) without threading `now_ms` through every call.
//!
//! Most `std` applications want `Swarm` and the [`SwarmBuilder`] convenience
//! constructor. Hosts with no thread to block -- embedded boards,
//! single-threaded event loops -- drive [`SwarmRuntime`] directly.
//!
//! Protocols baked into the core:
//! - `/ipfs/ping/1.0.0` (ping RTT measurement)
//! - `/ipfs/id/1.0.0` (identify)
//! - user-registered protocols (see [`SwarmCore::add_protocol`])

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod core;
mod events;
mod runtime;

mod builder;
#[cfg(feature = "std")]
mod driver;

pub use crate::core::{RESERVED_PROTOCOL_IDS, SwarmCore};
pub use crate::events::{
    ConnectionCloseCause, OpenStreamToken, SwarmAction, SwarmError, SwarmErrorKind, SwarmEvent,
    SwarmInput, SwarmOutput, SwarmRuntimeError,
};
pub use crate::runtime::{DriverError, SwarmRuntime};
// Part of `SwarmEvent::IdentifyReceived`'s public shape; re-exported so
// consumers can name the type without depending on `minip2p-identify`.
pub use minip2p_identify::IdentifyMessage;

pub use crate::builder::SwarmBuilder;
#[cfg(feature = "std")]
pub use crate::driver::{Deadline, PollNext, RUN_UNTIL_SKIP_LIMIT, Swarm};
// Re-exported so callers need not depend on the platform crate directly.
#[cfg(feature = "std")]
pub use minip2p_platform::{Clock, StdClock};
pub use minip2p_platform::{Deadline as PollDeadline, EntropySource, Now};
