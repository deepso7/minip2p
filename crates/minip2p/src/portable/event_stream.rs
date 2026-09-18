//! Single Endpoint event stream types (ADR 0007).
//!
//! Base connection, Identify, ping, and stream transitions leave through
//! [`EndpointEvent`]. Capability-specific queues remain until a later ticket
//! folds them into this stream.

use minip2p_swarm::SwarmEvent;

/// Ordered application event from the Endpoint's single public stream.
///
/// Today this is the swarm's connection, Identify, ping, stream, and
/// diagnostic events. NAT, pubsub, discovery, and relay-server output stay on
/// their focused queues until a later ticket.
///
/// Payloads move by value across the Endpoint boundary; callers own each
/// delivered event.
pub type EndpointEvent = SwarmEvent;

/// Why one blocking standard Endpoint wait returned.
///
/// Deadline and interruption are control outcomes, not additional event
/// sources. Unlike the migration-era `EndpointWake` shape, this outcome has no
/// driver-progress variant and does not require draining capability queues.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "EndpointEvent ownership avoids a heap allocation on the ready path."
)]
#[must_use = "handle the wait outcome; an Event has been removed from the endpoint"]
pub enum EndpointWaitOutcome {
    /// An application event from the Endpoint event stream.
    ///
    /// The event has been removed from the endpoint and belongs to the caller.
    Event(EndpointEvent),
    /// The caller's deadline elapsed without an application event.
    Deadline,
    /// The transport wait was interrupted by an external wait handle.
    Interrupted,
}
