//! Connection and protocol orchestration for minip2p.
//!
//! This crate provides two layers:
//!
//! - [`SwarmCore`] -- the swarm itself. `no_std + alloc`. It owns a concrete
//!   [`Transport`](minip2p_transport::Transport) and runs Identify, ping, and
//!   user-protocol negotiation over it, but reads no clock and draws no
//!   randomness: the caller passes a [`Now`] sample into
//!   [`SwarmCore::poll`] and every timed command, and injects an
//!   [`EntropySource`]. It reports its next timer through
//!   [`SwarmCore::next_deadline`] so a host can idle instead of spinning.
//!
//! - `Swarm` -- `std` wrapper adding a monotonic clock and blocking drive
//!   loops (`poll_next`, `run_until`) on top of the core, preserving the
//!   one-call DX (`swarm.ping(peer)`, `swarm.open_stream`) without threading
//!   `now_ms` through every call. Everything that needs no clock is on
//!   `swarm.core()` / `swarm.core_mut()`.
//!
//! Most `std` applications want `Swarm` and the [`SwarmBuilder`] convenience
//! constructor. Hosts with no thread to block -- embedded boards,
//! single-threaded event loops -- drive [`SwarmCore`] directly.
//!
//! Protocols baked into the core:
//! - `/ipfs/ping/1.0.0` (ping RTT measurement)
//! - `/ipfs/id/1.0.0` (identify)
//! - user-registered protocols (see [`SwarmCore::add_protocol`])

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod core;
mod events;
mod held;
mod state;

mod builder;
#[cfg(feature = "std")]
mod driver;

pub use crate::core::{DriverError, SwarmCore};
pub use crate::events::{SwarmError, SwarmErrorKind, SwarmEvent, SwarmRuntimeError};
pub use crate::held::{HeldStream, HeldWrites};
pub use crate::state::{RESERVED_PROTOCOL_IDS, SIMULTANEOUS_DIAL_WINDOW_MS};
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
