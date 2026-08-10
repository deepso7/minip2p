//! Portable platform contracts for minip2p.
//!
//! Every agent, transport, and runtime in minip2p is caller-driven: it never
//! reads a system clock and never draws randomness on its own. Instead the host
//! samples time once per drive iteration and passes the resulting [`Now`] to
//! everything it drives, and supplies an [`EntropySource`] to the components
//! that need randomness.
//!
//! This crate holds those contracts, plus the [`Deadline`] type that
//! caller-driven components use to report when they next need attention. It is
//! `no_std` + `alloc` compatible and has no networking code; the `std` feature
//! adds [`StdClock`] and [`StdEntropy`] for hosted platforms.
//!
//! # Example
//!
//! ```
//! use minip2p_platform::{Clock, Deadline, Now};
//!
//! struct Agent {
//!     fire_at: Deadline,
//! }
//!
//! impl Agent {
//!     // The agent is told what time it is; it never asks.
//!     fn poll(&mut self, now: Now) -> bool {
//!         self.fire_at.is_expired_at(now)
//!     }
//!
//!     fn next_deadline(&self) -> Option<Deadline> {
//!         Some(self.fire_at)
//!     }
//! }
//!
//! # #[cfg(feature = "std")]
//! # {
//! use minip2p_platform::StdClock;
//!
//! let mut clock = StdClock::new();
//! let mut agent = Agent {
//!     fire_at: Deadline::from_millis(0),
//! };
//!
//! // One clock sample drives everything in this iteration.
//! let now = clock.now();
//! assert!(agent.poll(now));
//! # }
//! ```
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod clock;
mod deadline;
mod entropy;

#[cfg(feature = "std")]
mod std_impl;

pub use clock::{Clock, Now};
pub use deadline::Deadline;
pub use entropy::{EntropyError, EntropySource, SharedEntropy};

#[cfg(feature = "std")]
pub use std_impl::{StdClock, StdEntropy};
