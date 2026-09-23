//! Portable and std application-facing APIs for minip2p.
//!
//! [`PortableEndpoint`] is the `no_std + alloc`, caller-driven endpoint. It
//! owns a transport and protocol runtime but no clock, executor, sockets, or
//! operating-system entropy source. The host passes one [`Now`] sample to
//! each [`PortableEndpoint::poll`] call.
//!
//! With the default `std` and `quic` features, the batteries-included
//! [`Endpoint`] and [`EndpointBuilder`] APIs remain available for OS programs.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "_discovery-driver")]
mod discovery;
#[cfg(feature = "_nat-driver")]
mod nat;
mod portable;
#[cfg(all(
    feature = "pubsub",
    any(feature = "std", feature = "smoltcp", feature = "portable-mdns")
))]
mod pubsub;
#[cfg(feature = "std")]
mod std;

pub use portable::*;
#[cfg(all(feature = "pubsub", any(feature = "std", feature = "smoltcp")))]
pub use pubsub::GossipsubError;
#[cfg(feature = "std")]
pub use std::*;
