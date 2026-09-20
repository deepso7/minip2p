//! Single Endpoint event stream type (ADR 0007).
//!
//! Base connection, Identify, ping, and stream transitions leave through
//! [`EndpointEvent`]. Capability-specific queues remain until a later ticket
//! folds them into this stream.

use minip2p_swarm::SwarmEvent;

/// Ordered application event from the Endpoint's single public stream.
///
/// Today this is [`SwarmEvent`]: connection, Identify, ping, stream, and
/// diagnostic transitions. Prefer this name at the Endpoint boundary.
/// [`crate::Event`] is a migration alias for the same type. NAT, pubsub,
/// discovery, and relay-server output stay on focused queues until a later
/// ticket adds variants here.
///
/// Payloads move by value across the Endpoint boundary; callers own each
/// delivered event.
pub type EndpointEvent = SwarmEvent;
