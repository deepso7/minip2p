#![allow(
    dead_code,
    reason = "the shared endpoint helper is included by test binaries that use different parts of it"
)]

//! Test-only convenience over `Endpoint::wait`.

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
