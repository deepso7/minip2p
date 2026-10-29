#![allow(
    dead_code,
    reason = "the shared endpoint helper is included by test binaries that use different parts of it"
)]

//! Test-only convenience over `Endpoint::wait`.
//!
//! # Timing
//!
//! These tests run in parallel against a real network stack, so a thread can be
//! descheduled for longer than any budget a test would pick. Drive until what
//! you are waiting for is observable rather than for a fixed slice of time, and
//! keep time limits as failure backstops. The full convention, and the tests
//! that run alone because they cannot follow it, live in `.config/nextest.toml`.

use minip2p::{
    Endpoint, EndpointEvent, EndpointWaitOutcome, Error, SwarmErrorKind, SwarmRuntimeError,
    WaitDeadline,
};

/// Returns the next Endpoint event, or `None` once `deadline` passes.
///
/// Interruptions are retried. Applications should match on
/// [`EndpointWaitOutcome`] directly; tests mostly just want the next event.
pub trait NextEvent {
    fn next_event(
        &mut self,
        deadline: impl Into<WaitDeadline>,
    ) -> Result<Option<EndpointEvent>, Error>;
}

impl NextEvent for Endpoint {
    fn next_event(
        &mut self,
        deadline: impl Into<WaitDeadline>,
    ) -> Result<Option<EndpointEvent>, Error> {
        let deadline = deadline.into();
        loop {
            match self.wait(deadline)? {
                EndpointWaitOutcome::Event(event) => return Ok(Some(event)),
                EndpointWaitOutcome::Deadline => return Ok(None),
                _ => {}
            }
        }
    }
}

/// Whether `error` is an inbound connection from an unknown peer failing its
/// handshake: something other than a libp2p peer dialed a test listener.
///
/// Local tools probe new loopback listeners (T3 Code's port detector sends
/// HTTP and then TLS to every one), and the endpoint correctly rejects them
/// with a transport `Error` naming a connection but no peer or stream. Such a
/// failure touches nothing a test holds, so tests that treat `Error` as
/// teardown skip it; a failure on a connection they hold surfaces as
/// `ConnectionClosed` or names its peer.
pub fn is_stranger_handshake_failure(error: &SwarmRuntimeError) -> bool {
    error.kind == SwarmErrorKind::Transport
        && error.conn_id.is_some()
        && error.peer_id.is_none()
        && error.stream_id.is_none()
}
