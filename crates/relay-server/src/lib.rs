//! Deterministic, caller-driven Circuit Relay v2 server policy.
//!
//! [`RelayServerAgent`] owns reservations, admission, control deadlines,
//! circuit forwarding, limits, and typed lifecycle events. It owns no sockets,
//! clocks, waits, or executor: the host supplies one [`minip2p_platform::Now`]
//! sample, feeds Swarm events, drains [`RelayServerAction`] values, and echoes
//! every result with its opaque [`RelayServerToken`]. After every claimed
//! input, actions and synchronous results must be drained to quiescence before
//! another transport event is delivered. Transport queues then provide the
//! payload backpressure instead of an unbounded agent queue.
//!
//! Call [`RelayServerAgent::handle_tick`] before events sampled at the same
//! time. This deadline-first order makes expiry, duration, and control timeout
//! behavior deterministic. Exact [`minip2p_transport::ConnectionId`] identity
//! is retained throughout; the service relies on Swarm's single live
//! connection per peer while still rejecting stale results from superseded
//! connections.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

extern crate alloc;

mod address;
mod agent;
mod config;
mod limiter;
mod types;

pub use address::{RelayServerAddressError, RelayServerAddressErrorKind};
pub use agent::RelayServerAgent;
pub use config::{
    RateLimit, RelayServerConfig, RelayServerConfigError, RelayServerConfigErrorKind,
};
pub use minip2p_relay::Status;
pub use types::{
    CircuitByteCounts, CircuitCloseReason, CircuitDirection, CircuitLeg, RelayServerAction,
    RelayServerEvent, RelayServerRuntimeError, RelayServerRuntimeErrorKind, RelayServerToken,
    ReservationCloseReason, StreamKey,
};
