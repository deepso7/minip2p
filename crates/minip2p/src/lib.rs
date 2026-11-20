//! Portable and std application-facing APIs for minip2p.
//!
//! There is one endpoint type, [`Endpoint<P>`](Endpoint), over one private
//! engine, generic over the [`Platform`] that supplies what differs between
//! hosts (ADR 0029):
//!
//! - [`Portable`] (named [`PortableEndpoint`]) is the `no_std + alloc`,
//!   caller-driven platform over any [`Transport`]. It owns no clock,
//!   executor, sockets, or operating-system entropy source; the host
//!   supplies a [`Clock`] that every call samples.
//! - With the default `std` and `quic` features, the batteries-included
//!   `StdPlatform` (the default `P`) and `EndpointBuilder` add an OS clock,
//!   transport binding, Name resolution, and a blocking `wait` for OS
//!   programs.
//!
//! Every shared method is implemented once, on `Endpoint<P>`; both drive
//! the same batches and emit the same ordered [`EndpointEvent`] stream.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
// Lets crate-internal tests include the shared `tests/support` harnesses,
// which are written against the public `minip2p::` paths.
#[cfg(test)]
extern crate self as minip2p;

mod common_builder;
mod connect;
#[cfg(feature = "_peer-book")]
mod discovery;
mod endpoint;
mod engine;
mod names;
#[cfg(feature = "autonat")]
mod nat;
mod platform;
mod portable;
mod protocols;
#[cfg(feature = "pubsub")]
mod pubsub;
#[cfg(all(feature = "relay-server", feature = "quic"))]
mod relay_mesh;
#[cfg(feature = "relay-server")]
mod relay_server;
mod setup;
#[cfg(feature = "std")]
mod std;
#[cfg(feature = "pubsub")]
mod stream_conns;
mod writes;

pub use portable::*;
pub use protocols::{ProtocolId, ProtocolRef};
#[cfg(feature = "pubsub")]
pub use pubsub::GossipsubError;
#[cfg(all(feature = "relay-server", feature = "quic"))]
pub use relay_mesh::{DEFAULT_RELAY_MESH_PORT, RelayMeshConfig};
#[cfg(feature = "relay-server")]
pub use relay_server::RelayServerControlError;
#[cfg(feature = "autonat")]
pub use setup::NatConfigError;
#[cfg(feature = "std")]
pub use std::*;
pub use writes::{DEFAULT_WRITE_BUDGET, SendError, SendOutcome};
