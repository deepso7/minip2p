//! THROWAWAY caller helpers. They retain continuations, not a runtime.
//! The host forwards notifications and schedules runnable helpers before sleeping.
//! Each step makes at most one stream call. No allocation, socket I/O, or clocks.

use crate::{Endpoint, Error, Event, Stream};

/// One borrowed write. Its unaccepted suffix stays with the caller.
#[derive(Debug)]
pub struct PendingWrite<'a> {
    stream: Stream,
    data: &'a [u8],
    offset: usize,
    runnable: bool,
    failure: Option<Error>,
}

/// What one write step accomplished. Acceptance is local, not delivery.
#[derive(Debug, Eq, PartialEq)]
pub enum WriteStep {
    Accepted(usize),
    Waiting,
    Complete,
}

impl<'a> PendingWrite<'a> {
    /// Borrows one buffer; there is no implicit queue of additional writes.
    pub fn new(stream: Stream, data: &'a [u8]) -> Self {
        Self {
            stream,
            data,
            offset: 0,
            runnable: !data.is_empty(),
            failure: None,
        }
    }

    /// Observes relevant notifications without consuming or hiding any event.
    pub fn on_event(&mut self, event: &Event) {
        if matches!(event, Event::Writable(stream) | Event::ConnectionClosed(stream) if *stream == self.stream)
            && !self.is_complete()
            && self.failure.is_none()
        {
            self.runnable = true;
        }
    }

    /// A runnable helper needs another host turn, even without a new event.
    pub fn is_runnable(&self) -> bool {
        self.runnable
    }

    /// True when all bytes have been accepted locally.
    pub fn is_complete(&self) -> bool {
        self.offset == self.data.len()
    }

    /// Unaccepted bytes remain accessible after an error or while blocked.
    pub fn remaining(&self) -> &'a [u8] {
        &self.data[self.offset..]
    }

    /// Attempts one partial write. WouldBlock clears readiness; success retains it.
    /// A terminal error is latched and makes the helper non-runnable.
    pub fn step(&mut self, endpoint: &mut Endpoint) -> Result<WriteStep, Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.is_complete() {
            return Ok(WriteStep::Complete);
        }
        if !self.runnable {
            return Ok(WriteStep::Waiting);
        }
        match endpoint.try_write(self.stream, self.remaining()) {
            Ok(n) => {
                self.offset += n;
                self.runnable = !self.is_complete();
                Ok(WriteStep::Accepted(n))
            }
            Err(Error::WouldBlock) => {
                self.runnable = false;
                Ok(WriteStep::Waiting)
            }
            Err(error) => {
                self.failure = Some(error);
                self.runnable = false;
                Err(error)
            }
        }
    }
}

/// Read continuation for one stream. The application still owns the read buffer.
#[derive(Debug)]
pub struct ReadContinuation {
    stream: Stream,
    runnable: bool,
    eof: bool,
    failure: Option<Error>,
}

/// What one read step accomplished. EmptyBuffer never means EOF.
#[derive(Debug, Eq, PartialEq)]
pub enum ReadStep {
    Data(usize),
    Waiting,
    Eof,
    EmptyBuffer,
}

impl ReadContinuation {
    /// Starts with one speculative read so already-buffered data is discoverable.
    pub fn new(stream: Stream) -> Self {
        Self {
            stream,
            runnable: true,
            eof: false,
            failure: None,
        }
    }

    /// Observes matching readiness/closure, leaving every event visible to the host.
    pub fn on_event(&mut self, event: &Event) {
        if matches!(event, Event::Readable(stream) | Event::RemoteWriteClosed(stream) | Event::ConnectionClosed(stream) if *stream == self.stream)
            && !self.eof
            && self.failure.is_none()
        {
            self.runnable = true;
        }
    }

    /// Remains true after a positive read, including when its handler yields.
    /// The host must schedule another step before sleeping for a notification.
    pub fn is_runnable(&self) -> bool {
        self.runnable
    }

    /// True only after a nonempty-buffer read actually observes EOF.
    pub fn is_eof(&self) -> bool {
        self.eof
    }

    /// Reads at most one caller-buffer chunk; never loops over an application handler.
    pub fn step(&mut self, endpoint: &mut Endpoint, out: &mut [u8]) -> Result<ReadStep, Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if out.is_empty() {
            return Ok(ReadStep::EmptyBuffer);
        }
        if self.eof {
            return Ok(ReadStep::Eof);
        }
        if !self.runnable {
            return Ok(ReadStep::Waiting);
        }
        match endpoint.try_read(self.stream, out) {
            Ok(0) => {
                self.eof = true;
                self.runnable = false;
                Ok(ReadStep::Eof)
            }
            Ok(n) => Ok(ReadStep::Data(n)),
            Err(Error::WouldBlock) => {
                self.runnable = false;
                Ok(ReadStep::Waiting)
            }
            Err(error) => {
                self.failure = Some(error);
                self.runnable = false;
                Err(error)
            }
        }
    }
}
