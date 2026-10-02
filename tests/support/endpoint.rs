#![allow(
    dead_code,
    reason = "the shared endpoint helper is included by test binaries that use different parts of it"
)]

//! Test-only convenience over `Endpoint::wait`.
//!
//! # Timing
//!
//! These tests run in parallel against a real network stack, so a thread can be
//! descheduled for longer than any budget a test would pick. The convention,
//! also recorded in `.config/nextest.toml`:
//!
//! - Never let a fixed-duration loop stand in for progress. Drive until what
//!   you are waiting for is observable and end the loop there.
//! - A remaining time limit is a failure backstop or the timer under test.
//!   Backstops are generous; they only turn a hang into a readable failure.
//! - Poll once more after an observation window closes. A stall can carry the
//!   loop past its deadline with the event that would have failed it unread.
//! - A test of a deliberately bounded production timer cannot be made
//!   load-proof from the inside. Keep its assertions strict and give it
//!   `threads-required = "num-test-threads"` in `.config/nextest.toml`.
//! - "Nothing happens during this window" assertions are best effort:
//!   starvation can only make them pass when they should fail.

use minip2p::{Deadline, Endpoint, EndpointEvent, EndpointWaitOutcome, Error};

/// Returns the next Endpoint event, or `None` once `deadline` passes.
///
/// Interruptions are retried. Applications should match on
/// [`EndpointWaitOutcome`] directly; tests mostly just want the next event.
pub trait NextEvent {
    fn next_event(&mut self, deadline: impl Into<Deadline>)
    -> Result<Option<EndpointEvent>, Error>;
}

impl NextEvent for Endpoint {
    fn next_event(
        &mut self,
        deadline: impl Into<Deadline>,
    ) -> Result<Option<EndpointEvent>, Error> {
        let deadline = deadline.into();
        loop {
            match self.wait(deadline)? {
                EndpointWaitOutcome::Event(event) => return Ok(Some(event)),
                EndpointWaitOutcome::Deadline => return Ok(None),
                EndpointWaitOutcome::Interrupted => {}
            }
        }
    }
}
