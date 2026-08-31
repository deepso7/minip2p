//! An in-memory [`TcpProvider`] pair, so the transport can be driven without a
//! socket, a clock, or an executor.
//!
//! The link models what a real TCP socket does to a caller and nothing more:
//! byte streams with no message boundaries, writes that are accepted only in
//! part, half-close, and abort. Those are exactly the behaviours the transport
//! has to absorb, so they are knobs here rather than accidents of timing.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;

use minip2p_core::Multiaddr;
use minip2p_platform::{EntropyError, EntropySource, Now};
use minip2p_tcp::{SocketHandle, TcpError, TcpEvent, TcpProvider};

/// Deterministic entropy, so a failing test reproduces exactly.
pub struct CountingEntropy(pub u8);

impl EntropySource for CountingEntropy {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        for byte in output.iter_mut() {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

/// Entropy that never works, for the rejection paths.
pub struct BrokenEntropy;

impl EntropySource for BrokenEntropy {
    fn fill_bytes(&mut self, _output: &mut [u8]) -> Result<(), EntropyError> {
        Err(EntropyError::unavailable("no RNG in this test"))
    }
}

/// Fails its first `failures` draws, then behaves.
///
/// A hardware RNG reporting a transient health-check failure looks like this,
/// and it is the only way to see what a rejected connection did to the id space.
pub struct FlakyEntropy {
    failures: usize,
    next: u8,
}

impl FlakyEntropy {
    pub fn new(failures: usize, seed: u8) -> Self {
        Self {
            failures,
            next: seed,
        }
    }
}

impl EntropySource for FlakyEntropy {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        if self.failures > 0 {
            self.failures -= 1;
            return Err(EntropyError::failed("transient RNG fault"));
        }
        for byte in output.iter_mut() {
            *byte = self.next;
            self.next = self.next.wrapping_add(1);
        }
        Ok(())
    }
}

/// One end of a virtual byte stream.
#[derive(Default)]
struct End {
    /// Bytes written by the peer and not yet read by this end.
    inbox: VecDeque<u8>,
    /// Most this end's inbox may hold unread, `None` for unbounded.
    ///
    /// This is what makes a peer's socket buffer finite: a writer can only push
    /// until the reader's inbox is full, and gets room back when the reader
    /// drains it.
    capacity: Option<usize>,
    /// This end half-closed its write side.
    write_closed: bool,
    /// This end is gone: aborted locally or fully closed.
    gone: bool,
    /// A short write happened and `Writable` is owed.
    owes_writable: bool,
    /// `RemoteWriteClosed` has already been reported to this end.
    reported_fin: bool,
    /// `Closed` has already been reported to this end.
    reported_closed: bool,
}

#[derive(Default)]
struct Link {
    ends: [End; 2],
}

impl Link {
    /// Returns the local endpoint and its peer for a valid two-party link side.
    fn ends(&self, index: usize) -> Option<(&End, &End)> {
        match (index, &self.ends) {
            (0, [local, peer]) => Some((local, peer)),
            (1, [peer, local]) => Some((local, peer)),
            _ => None,
        }
    }

    /// Returns the local endpoint and its peer mutably for a valid link side.
    fn ends_mut(&mut self, index: usize) -> Option<(&mut End, &mut End)> {
        match (index, &mut self.ends) {
            (0, [local, peer]) => Some((local, peer)),
            (1, [peer, local]) => Some((local, peer)),
            _ => None,
        }
    }
}

#[derive(Default)]
struct Net {
    /// Nodes that never emit `Writable`, standing in for a provider whose
    /// readiness reporting is coarser than the contract's.
    silent_nodes: BTreeMap<usize, bool>,
    /// Nodes whose `connect` fails synchronously.
    failing_connect: BTreeMap<usize, bool>,
    /// Per node: how many times each teardown call was made.
    close_write_calls: BTreeMap<usize, usize>,
    abort_calls: BTreeMap<usize, usize>,
    next_handle: u64,
    next_link: u64,
    next_port: u16,
    /// Listen address -> node that owns the listener.
    listeners: BTreeMap<String, usize>,
    /// Accept/connect notifications waiting for a node's next poll.
    ready: BTreeMap<usize, VecDeque<TcpEvent>>,
    links: BTreeMap<u64, Link>,
    /// Socket handle -> (link, which end).
    sockets: BTreeMap<u64, (u64, usize)>,
    /// Node -> its live handles, in creation order.
    owned: BTreeMap<usize, Vec<u64>>,
}

impl Net {
    fn end(&mut self, handle: u64) -> Option<(&mut Link, usize)> {
        let (link, index) = *self.sockets.get(&handle)?;
        Some((self.links.get_mut(&link)?, index))
    }
}

/// A shared virtual network that hands out connected providers.
#[derive(Clone)]
pub struct VirtualNetwork {
    net: Rc<RefCell<Net>>,
}

impl VirtualNetwork {
    pub fn new() -> Self {
        Self {
            net: Rc::new(RefCell::new(Net {
                next_port: 20_000,
                ..Net::default()
            })),
        }
    }

    /// Whether the network has nothing left to deliver.
    ///
    /// The upgrade takes several round trips that produce no public transport
    /// event at all, so "neither node reported anything" is not quiescence.
    /// Bytes in flight and undelivered accept/connect notifications are.
    pub fn is_quiet(&self) -> bool {
        let net = self.net.borrow();
        net.ready.values().all(VecDeque::is_empty)
            && net
                .links
                .values()
                .all(|link| link.ends.iter().all(|end| end.inbox.is_empty()))
    }

    /// Creates a provider attached to this network.
    pub fn provider(&self) -> VirtualProvider {
        let mut net = self.net.borrow_mut();
        let node = net.owned.len();
        net.owned.insert(node, Vec::new());
        net.ready.insert(node, VecDeque::new());
        VirtualProvider {
            net: Rc::clone(&self.net),
            node,
        }
    }
}

pub struct VirtualProvider {
    net: Rc<RefCell<Net>>,
    node: usize,
}

impl VirtualProvider {
    /// Caps how many bytes this node may have in flight to its peer.
    ///
    /// Writes are accepted only up to the peer's remaining room, so a peer that
    /// stops reading eventually accepts nothing, and one that keeps reading
    /// frees room back up. That is the whole of TCP backpressure as a writer
    /// experiences it.
    pub fn set_in_flight_capacity(&mut self, capacity: Option<usize>) {
        let mut net = self.net.borrow_mut();
        let handles = net.owned.get(&self.node).cloned().unwrap_or_default();
        for handle in handles {
            if let Some((link, index)) = net.end(handle) {
                let Some((_, peer)) = link.ends_mut(index) else {
                    continue;
                };
                peer.capacity = capacity;
            }
        }
    }

    /// Makes `connect` fail outright rather than asynchronously.
    ///
    /// A real provider does this when the address is unusable before any packet
    /// goes out -- no route to host, no file descriptors left.
    pub fn fail_connect(&mut self, failing: bool) {
        self.net
            .borrow_mut()
            .failing_connect
            .insert(self.node, failing);
    }

    /// Stops this node's provider from ever emitting `TcpEvent::Writable`.
    ///
    /// The contract asks providers to emit it after a partial write, but a real
    /// one built on edge-triggered readiness is easy to get subtly wrong. A
    /// transport that only ever retried on `Writable` would stall here.
    pub fn suppress_writable(&mut self) {
        self.net.borrow_mut().silent_nodes.insert(self.node, true);
    }

    /// How many times the transport asked for an orderly half-close.
    pub fn close_write_calls(&self) -> usize {
        self.net
            .borrow()
            .close_write_calls
            .get(&self.node)
            .copied()
            .unwrap_or(0)
    }

    /// How many times the transport discarded a socket outright.
    pub fn abort_calls(&self) -> usize {
        self.net
            .borrow()
            .abort_calls
            .get(&self.node)
            .copied()
            .unwrap_or(0)
    }

    /// Half-closes every one of this node's sockets behind the transport's
    /// back, the way a peer process that exits mid-conversation looks.
    ///
    /// No Yamux `GoAway` precedes it, so the remote sees a truncated stream
    /// rather than an orderly shutdown.
    pub fn half_close_all(&mut self) {
        let mut net = self.net.borrow_mut();
        let handles = net.owned.get(&self.node).cloned().unwrap_or_default();
        for handle in handles {
            if let Some((link, index)) = net.end(handle) {
                let Some((local, _)) = link.ends_mut(index) else {
                    continue;
                };
                local.write_closed = true;
            }
        }
    }

    /// How many bytes are queued for the peer but not yet read.
    pub fn bytes_in_flight_to_peer(&self) -> usize {
        let net = self.net.borrow();
        net.owned
            .get(&self.node)
            .into_iter()
            .flatten()
            .filter_map(|handle| {
                let (link, index) = *net.sockets.get(handle)?;
                let (_, peer) = net.links.get(&link)?.ends(index)?;
                Some(peer.inbox.len())
            })
            .sum()
    }
}

impl TcpProvider for VirtualProvider {
    fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, TcpError> {
        let mut net = self.net.borrow_mut();
        let bound = addr.clone();
        let key = bound.to_string();
        if net.listeners.contains_key(&key) {
            return Err(TcpError::Io {
                operation: "listen",
                reason: format!("{key} is already bound"),
            });
        }
        net.listeners.insert(key, self.node);
        Ok(bound)
    }

    fn connect(&mut self, addr: &Multiaddr) -> Result<SocketHandle, TcpError> {
        let mut net = self.net.borrow_mut();
        if net
            .failing_connect
            .get(&self.node)
            .copied()
            .unwrap_or(false)
        {
            return Err(TcpError::Io {
                operation: "connect",
                reason: "injected connect failure".to_string(),
            });
        }
        let client = net.next_handle;
        net.next_handle += 1;

        let Some(target) = net.listeners.get(&addr.to_string()).copied() else {
            // A refused connect is reported through `Closed`, not returned, so
            // the transport exercises the same path a real one would.
            net.sockets.insert(client, (u64::MAX, 0));
            net.ready
                .entry(self.node)
                .or_default()
                .push_back(TcpEvent::Closed {
                    socket: SocketHandle::new(client),
                    reason: Some("connection refused".to_string()),
                });
            return Ok(SocketHandle::new(client));
        };

        let server = net.next_handle;
        net.next_handle += 1;
        let link = net.next_link;
        net.next_link += 1;
        let port = net.next_port;
        net.next_port += 1;

        net.links.insert(link, Link::default());
        net.sockets.insert(client, (link, 0));
        net.sockets.insert(server, (link, 1));
        net.owned.entry(self.node).or_default().push(client);
        net.owned.entry(target).or_default().push(server);

        net.ready
            .entry(self.node)
            .or_default()
            .push_back(TcpEvent::Connected {
                socket: SocketHandle::new(client),
                remote: addr.clone(),
            });
        let source: Multiaddr = format!("/ip4/127.0.0.1/tcp/{port}")
            .parse::<Multiaddr>()
            .map_err(|error| TcpError::Address {
                context: "synthetic source address",
                reason: error.to_string(),
            })?;
        net.ready
            .entry(target)
            .or_default()
            .push_back(TcpEvent::Accepted {
                socket: SocketHandle::new(server),
                remote: source,
            });
        Ok(SocketHandle::new(client))
    }

    #[expect(
        clippy::panic_in_result_fn,
        reason = "this test provider asserts the transport's non-empty write contract"
    )]
    fn send(&mut self, socket: SocketHandle, data: &[u8]) -> Result<usize, TcpError> {
        assert!(!data.is_empty(), "the transport must not send empty writes");
        let mut net = self.net.borrow_mut();
        let Some((link, index)) = net.end(socket.get()) else {
            return Err(TcpError::UnknownSocket { socket });
        };
        let Some((local, peer)) = link.ends_mut(index) else {
            return Err(TcpError::UnknownSocket { socket });
        };
        if local.gone || peer.gone {
            return Err(TcpError::Io {
                operation: "send",
                reason: "stream is gone".to_string(),
            });
        }
        if local.write_closed {
            return Err(TcpError::Io {
                operation: "send",
                reason: "write side is closed".to_string(),
            });
        }
        let room = peer.capacity.map_or(data.len(), |capacity| {
            capacity.saturating_sub(peer.inbox.len())
        });
        let accepted = room.min(data.len());
        let accepted_data = data.get(..accepted).ok_or(TcpError::Io {
            operation: "send",
            reason: "accepted byte count exceeded write buffer".to_string(),
        })?;
        peer.inbox.extend(accepted_data);
        if accepted < data.len() {
            local.owes_writable = true;
        }
        Ok(accepted)
    }

    fn close_write(&mut self, socket: SocketHandle) -> Result<(), TcpError> {
        let mut net = self.net.borrow_mut();
        *net.close_write_calls.entry(self.node).or_default() += 1;
        let Some((link, index)) = net.end(socket.get()) else {
            return Err(TcpError::UnknownSocket { socket });
        };
        let Some((local, _)) = link.ends_mut(index) else {
            return Err(TcpError::UnknownSocket { socket });
        };
        local.write_closed = true;
        Ok(())
    }

    fn abort(&mut self, socket: SocketHandle) {
        let mut net = self.net.borrow_mut();
        *net.abort_calls.entry(self.node).or_default() += 1;
        if let Some((link, index)) = net.end(socket.get())
            && let Some((local, _)) = link.ends_mut(index)
        {
            local.gone = true;
        }
        // The provider owes nothing further for an aborted handle, so drop it
        // from this node's roster before it can be polled again.
        if let Some(handles) = net.owned.get_mut(&self.node) {
            handles.retain(|handle| *handle != socket.get());
        }
        net.ready
            .entry(self.node)
            .or_default()
            .retain(|event| event_socket(event) != socket);
    }

    fn poll(&mut self, _now: Now) -> Result<Vec<TcpEvent>, TcpError> {
        let mut net = self.net.borrow_mut();
        let mut events: Vec<TcpEvent> = net
            .ready
            .get_mut(&self.node)
            .map(|queue| queue.drain(..).collect())
            .unwrap_or_default();

        let silent = net.silent_nodes.get(&self.node).copied().unwrap_or(false);
        let handles = net.owned.get(&self.node).cloned().unwrap_or_default();
        let mut finished = Vec::new();
        for handle in handles {
            let Some((link, index)) = net.end(handle) else {
                continue;
            };
            let Some((local, peer)) = link.ends_mut(index) else {
                continue;
            };
            let socket = SocketHandle::new(handle);

            if local.owes_writable {
                local.owes_writable = false;
                if !silent {
                    events.push(TcpEvent::Writable { socket });
                }
            }
            if !local.inbox.is_empty() {
                let data: Vec<u8> = local.inbox.drain(..).collect();
                events.push(TcpEvent::Received { socket, data });
            }
            // Received before the FIN, and the FIN before the close: the peer's
            // last bytes are still readable after it stops writing.
            if peer.write_closed && local.inbox.is_empty() && !local.reported_fin {
                local.reported_fin = true;
                events.push(TcpEvent::RemoteWriteClosed { socket });
            }
            if peer.gone && !local.reported_closed {
                local.reported_closed = true;
                events.push(TcpEvent::Closed {
                    socket,
                    reason: None,
                });
                finished.push(handle);
            }
        }
        if let Some(owned) = net.owned.get_mut(&self.node) {
            owned.retain(|handle| !finished.contains(handle));
        }
        Ok(events)
    }

    fn local_addresses(&self) -> Vec<Multiaddr> {
        let net = self.net.borrow();
        net.listeners
            .iter()
            .filter(|(_, node)| **node == self.node)
            .map(|(addr, _)| addr.parse().expect("listener address round-trips"))
            .collect()
    }
}

fn event_socket(event: &TcpEvent) -> SocketHandle {
    match event {
        TcpEvent::Accepted { socket, .. }
        | TcpEvent::Connected { socket, .. }
        | TcpEvent::Received { socket, .. }
        | TcpEvent::RemoteWriteClosed { socket }
        | TcpEvent::Writable { socket }
        | TcpEvent::Closed { socket, .. } => *socket,
    }
}
