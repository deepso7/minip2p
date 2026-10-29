//! Deterministic, caller-driven Circuit Relay v2 server policy.
//!
//! [`RelayServerAgent`] owns reservations, admission, control deadlines,
//! circuit forwarding, limits, and typed lifecycle events. It owns no sockets,
//! clocks, waits, or executor: the host supplies one [`minip2p_core::platform::Now`]
//! sample and a [`RelaySwarm`] (implemented for `SwarmCore`) with every
//! [`RelayServerAgent::handle_event`] and [`RelayServerAgent::handle_tick`]
//! call. The agent never stores the swarm: it runs each open, send, ack,
//! half-close, and reset inline and applies the result before the call
//! returns, so a reservation or circuit commits the moment the transport
//! takes its success reply. Only a STOP stream's negotiation completes
//! later, through its `StreamReady` or the swarm error naming it.
//!
//! Forwarding follows ADR 0012's backpressure contract. Each circuit direction
//! queues what it reads, in order, and the agent acknowledges those bytes to
//! their sender (through [`RelaySwarm::ack_stream`]) only once the other leg
//! accepts them. A send refused as `DriverError::Full` keeps its unsent tail
//! at the head of the queue until that leg's `StreamWritable`, so a full
//! destination pauses the source through withheld receive credit instead of
//! closing the circuit, and the queue stays within the receive budget the
//! source was granted. Small reads are coalesced, so the queue's memory stays
//! proportional to its bytes rather than its reads. A half-close is forwarded
//! after the last queued byte.
//!
//! The first [`RelayServerAgent::handle_event`] for a time sample processes
//! deadlines before it dispatches the event. Call [`RelayServerAgent::handle_tick`]
//! to force the same deadline-first order without an event. Exact
//! [`minip2p_transport::ConnectionId`] identity is retained throughout; the
//! service relies on Swarm's single live connection per peer while still
//! rejecting stale events from replaced connections.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

extern crate alloc;

mod address;
mod agent;
mod config;
mod limiter;
mod swarm;
mod types;

pub use address::{RelayServerAddrSource, RelayServerAddressError, RelayServerAddressErrorKind};
pub use agent::RelayServerAgent;
pub use config::{
    RateLimit, RelayServerConfig, RelayServerConfigError, RelayServerConfigErrorKind,
};
pub use minip2p_relay::Status;
pub use swarm::{RelaySwarm, RelaySwarmError};
pub use types::{
    CircuitByteCounts, CircuitCloseReason, CircuitDirection, CircuitLeg, RelayServerEvent,
    RelayServerRuntimeError, RelayServerRuntimeErrorKind, ReservationCloseReason, StreamKey,
};
