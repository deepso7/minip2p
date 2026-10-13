//! Portable and std application-facing APIs for minip2p.
//!
//! There are two endpoint types over one private engine:
//!
//! - [`PortableEndpoint`] is the `no_std + alloc`, caller-driven endpoint
//!   over any [`Transport`]. It owns no clock, executor, sockets, or
//!   operating-system entropy source; the host passes one [`Now`] sample to
//!   each [`PortableEndpoint::poll`] call.
//! - With the default `std` and `quic` features, the batteries-included
//!   `Endpoint` and `EndpointBuilder` add a clock, transport binding, Name
//!   resolution, and a blocking `wait` for OS programs.
//!
//! Both drive the same batches and emit the same ordered [`EndpointEvent`]
//! stream.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
// Lets crate-internal tests include the shared `tests/support` harnesses,
// which are written against the public `minip2p::` paths.
#[cfg(test)]
extern crate self as minip2p;

#[cfg(feature = "_discovery-driver")]
mod discovery;
mod engine;
#[cfg(feature = "_nat-driver")]
mod nat;
mod portable;
#[cfg(feature = "pubsub")]
mod pubsub;
#[cfg(feature = "std")]
mod std;
#[cfg(feature = "pubsub")]
mod stream_conns;

pub use portable::*;
#[cfg(feature = "pubsub")]
pub use pubsub::GossipsubError;
#[cfg(feature = "std")]
pub use std::*;
