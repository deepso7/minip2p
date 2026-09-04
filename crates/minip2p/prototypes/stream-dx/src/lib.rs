//! THROWAWAY: a bounded, already-open stream pair for comparing caller code.
//! No sockets, crypto, negotiation, clocks, or production performance claims.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{collections::VecDeque, vec::Vec};

/// Endpoint-local identity, including the connection that owns the stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stream {
    connection: u64,
    stream: u64,
}

/// Application notifications. Reading an event does not consume stream bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    Readable(Stream),
    Writable(Stream),
    RemoteWriteClosed(Stream),
    ConnectionClosed(Stream),
}

/// Only errors needed to explore the interface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    WouldBlock,
    WriteClosed,
    StaleHandle,
}

/// Relevant model state, exposed for the walkthrough.
#[derive(Debug)]
pub struct Snapshot {
    pub queued_send: usize,
    pub queued_receive: usize,
    pub capacity: usize,
    pub queued_events: usize,
    pub read_armed: bool,
    pub write_armed: bool,
    pub local_fin: bool,
    pub remote_fin: bool,
}

/// One ready stream, with a fixed byte capacity in each direction.
pub struct Endpoint {
    stream: Stream,
    capacity: usize,
    tx: VecDeque<u8>,
    rx: VecDeque<u8>,
    events: VecDeque<Event>,
    read_armed: bool,
    write_armed: bool,
    local_fin: bool,
    fin_sent: bool,
    remote_fin: bool,
}

impl Endpoint {
    /// Creates an already-negotiated endpoint. Capacity must be positive.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0);
        Self {
            stream: Stream {
                connection: 1,
                stream: 0,
            },
            capacity,
            tx: VecDeque::with_capacity(capacity),
            rx: VecDeque::with_capacity(capacity),
            events: VecDeque::with_capacity(4),
            read_armed: true,
            write_armed: false,
            local_fin: false,
            fin_sent: false,
            remote_fin: false,
        }
    }

    /// Returns the handle for the model's single ready stream.
    pub fn stream(&self) -> Stream {
        self.stream
    }

    fn check(&self, stream: Stream) -> Result<(), Error> {
        if stream == self.stream {
            Ok(())
        } else {
            Err(Error::StaleHandle)
        }
    }

    /// Copies an accepted prefix into bounded local storage. No drive or I/O.
    pub fn try_write(&mut self, stream: Stream, data: &[u8]) -> Result<usize, Error> {
        self.check(stream)?;
        if self.local_fin {
            return Err(Error::WriteClosed);
        }
        if data.is_empty() {
            return Ok(0);
        }
        let count = data.len().min(self.capacity - self.tx.len());
        if count == 0 {
            self.write_armed = true;
            return Err(Error::WouldBlock);
        }
        self.tx.extend(&data[..count]);
        Ok(count)
    }

    /// Reads buffered bytes. Empty input is a no-op; otherwise zero means EOF.
    /// A WouldBlock result arms the next readable notification.
    pub fn try_read(&mut self, stream: Stream, out: &mut [u8]) -> Result<usize, Error> {
        self.check(stream)?;
        if out.is_empty() {
            return Ok(0);
        }
        if self.rx.is_empty() {
            if self.remote_fin {
                return Ok(0);
            }
            self.read_armed = true;
            return Err(Error::WouldBlock);
        }
        let count = out.len().min(self.rx.len());
        for slot in &mut out[..count] {
            *slot = self.rx.pop_front().unwrap();
        }
        Ok(count)
    }

    /// Orders FIN after accepted bytes. Later writes fail immediately.
    pub fn finish(&mut self, stream: Stream) -> Result<(), Error> {
        self.check(stream)?;
        self.local_fin = true;
        Ok(())
    }

    /// Pops one notification without re-arming it or driving the link.
    pub fn pop_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    fn notify_readable(&mut self) {
        if self.read_armed {
            self.enqueue(Event::Readable(self.stream));
            self.read_armed = false;
        }
    }

    fn enqueue(&mut self, event: Event) {
        if !self.events.contains(&event) {
            self.events.push_back(event);
        }
    }

    /// State for the trace; byte limits exclude allocator overhead.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            queued_send: self.tx.len(),
            queued_receive: self.rx.len(),
            capacity: self.capacity,
            queued_events: self.events.len(),
            read_armed: self.read_armed,
            write_armed: self.write_armed,
            local_fin: self.local_fin,
            remote_fin: self.remote_fin,
        }
    }

    /// Comparison sketch only: accept a complete owned chunk or reject it.
    /// This is not an implementation of today's minip2p transport behavior.
    pub fn legacy_send_owned(&mut self, stream: Stream, data: Vec<u8>) -> Result<(), Error> {
        self.check(stream)?;
        if self.local_fin {
            return Err(Error::WriteClosed);
        }
        if data.len() > self.capacity - self.tx.len() {
            return Err(Error::WouldBlock);
        }
        self.tx.extend(data);
        Ok(())
    }

    /// Comparison sketch only: transfer buffered receive bytes as owned data.
    pub fn legacy_take_data(&mut self) -> Vec<u8> {
        self.rx.drain(..).collect()
    }

    /// Deliberately aborts the old model connection and opens another.
    /// Unread bytes are discarded explicitly. This is not graceful shutdown.
    pub fn replace_connection(&mut self) {
        let old = self.stream;
        let next = old.connection.checked_add(1).unwrap();
        *self = Self::new(self.capacity);
        self.stream.connection = next;
        self.enqueue(Event::ConnectionClosed(old));
    }
}

/// Advances one direction of an in-memory link by at most `budget` bytes.
/// Read credit equals free receive space; popping notifications releases none.
/// This models a future transport contract, not current QUIC/Yamux behavior.
pub fn drive(sender: &mut Endpoint, receiver: &mut Endpoint, budget: usize) -> usize {
    let count = budget
        .min(sender.tx.len())
        .min(receiver.capacity - receiver.rx.len());
    for _ in 0..count {
        receiver.rx.push_back(sender.tx.pop_front().unwrap());
    }
    if count > 0 {
        receiver.notify_readable();
    }
    if sender.write_armed && sender.tx.len() < sender.capacity {
        sender.enqueue(Event::Writable(sender.stream));
        sender.write_armed = false;
    }
    if sender.local_fin && sender.tx.is_empty() && !sender.fin_sent {
        sender.fin_sent = true;
        receiver.remote_fin = true;
        receiver.notify_readable();
        receiver.enqueue(Event::RemoteWriteClosed(receiver.stream));
    }
    count
}
