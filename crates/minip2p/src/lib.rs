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

mod connect;
#[cfg(feature = "_peer-book")]
mod discovery;
mod engine;
#[cfg(feature = "autonat")]
mod nat;
mod portable;
#[cfg(feature = "pubsub")]
mod pubsub;
#[cfg(feature = "relay-server")]
mod relay_server;
mod setup;
#[cfg(feature = "std")]
mod std;
#[cfg(feature = "pubsub")]
mod stream_conns;
mod writer;

pub use portable::*;
#[cfg(feature = "pubsub")]
pub use pubsub::GossipsubError;
#[cfg(feature = "relay-server")]
pub use relay_server::RelayServerControlError;
#[cfg(feature = "autonat")]
pub use setup::NatConfigError;
#[cfg(feature = "std")]
pub use std::*;
pub use writer::{StreamWriteError, StreamWriter, WriteAccepted, WriteProgress};
