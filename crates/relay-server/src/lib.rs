//! Deterministic, caller-driven Circuit Relay v2 server policy.
//!
//! [`RelayServerAgent`] owns reservations, admission, control deadlines,
//! circuit forwarding, limits, and typed lifecycle events. It owns no sockets,
//! clocks, waits, or executor: the host supplies one [`minip2p_platform::Now`]
//! sample, feeds Swarm events, drains [`RelayServerAction`] values, and echoes
//! every result with its opaque [`RelayServerToken`]. After every claimed
//! input, actions and synchronous results must be drained to quiescence before
//! another transport event is delivered.
//!
//! Forwarding follows ADR 0012's backpressure contract. Each circuit direction
//! queues what it reads, in order, and the agent acknowledges those bytes to
//! their sender (through [`RelayServerAction::AckStream`]) only once the other
//! leg accepts them. A send that comes back [`RelayServerSendError::Full`]
//! keeps its unsent tail at the head of the queue until that leg's
//! `StreamWritable`, so a full destination pauses the source through withheld
//! receive credit instead of closing the circuit, and the queue stays within
//! the receive budget the source was granted. A half-close is forwarded after
//! the last queued byte.
//!
//! The first [`RelayServerAgent::handle_event`] for a time sample processes
//! deadlines before it dispatches the event. Call [`RelayServerAgent::handle_tick`]
//! to force the same deadline-first order without an event. Exact
//! [`minip2p_transport::ConnectionId`] identity is retained throughout; the
//! service relies on Swarm's single live connection per peer while still
//! rejecting stale results from replaced connections.

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
    RelayServerEvent, RelayServerRuntimeError, RelayServerRuntimeErrorKind, RelayServerSendError,
    RelayServerToken, ReservationCloseReason, StreamKey,
};
