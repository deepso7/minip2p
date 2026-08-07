//! Portable and std application-facing APIs for minip2p.
//!
//! [`PortableEndpoint`] is the `no_std + alloc`, caller-driven facade. It
//! owns a transport and protocol runtime but no clock, executor, sockets, or
//! operating-system entropy source. The host passes one [`Now`] sample to
//! each [`PortableEndpoint::poll`] call.
//!
//! With the default `std` and `quic` features, the batteries-included
//! [`Endpoint`] and `EndpointBuilder` APIs remain available for OS programs.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{string::String, vec::Vec};

pub use minip2p_core::{Multiaddr, PeerAddr, PeerId, Protocol, TransportKind};
pub use minip2p_identity::Ed25519Keypair;
pub use minip2p_platform::{Deadline as PollDeadline, EntropySource, Now};
pub use minip2p_swarm::{
    DriverError, IdentifyMessage, SwarmBuilder, SwarmError, SwarmEvent, SwarmRuntime,
};
pub use minip2p_transport::{ConnectionId, StreamId, Transport, TransportError};

#[cfg(feature = "std")]
mod std_endpoint;
#[cfg(feature = "std")]
pub use std_endpoint::*;

/// Portable endpoint entry point when the std facade is not compiled.
///
/// Under `std`, the batteries-included endpoint exposes the same
/// [`Endpoint::portable`] constructor alongside `Endpoint::builder`.
#[cfg(not(feature = "std"))]
pub struct Endpoint;

#[cfg(not(feature = "std"))]
impl Endpoint {
    /// Starts portable endpoint configuration with explicit identity and entropy.
    pub fn portable<E: EntropySource>(
        identity: &Ed25519Keypair,
        entropy: E,
    ) -> PortableEndpointBuilder<E> {
        PortableEndpointBuilder::new(identity, entropy)
    }
}

/// Caller-driven endpoint over an injected transport and entropy source.
///
/// This is the portable facade for embedded systems and deterministic event
/// loops. It performs no blocking and never reads a system clock. Callers
/// drive it with [`poll`](Self::poll) and may inspect
/// [`next_deadline`](Self::next_deadline) to decide how long their platform
/// loop can idle.
pub struct PortableEndpoint<T: Transport, E: EntropySource> {
    runtime: SwarmRuntime<T, E>,
}

/// Lightweight snapshot of portable endpoint state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableEndpointStats {
    /// Number of peers with an established transport connection.
    pub connected_peers: usize,
    /// Number of connected peers that completed Identify and are ready for
    /// application protocols.
    pub ready_peers: usize,
    /// Addresses currently exposed by the transport as listening locally.
    pub listen_addresses: Vec<Multiaddr>,
}

impl<T: Transport, E: EntropySource> PortableEndpoint<T, E> {
    /// Returns this endpoint's peer ID.
    pub fn peer_id(&self) -> &PeerId {
        self.runtime.local_peer_id()
    }

    /// Returns the underlying caller-driven runtime.
    pub fn runtime(&self) -> &SwarmRuntime<T, E> {
        &self.runtime
    }

    /// Returns mutable access to the underlying caller-driven runtime.
    pub fn runtime_mut(&mut self) -> &mut SwarmRuntime<T, E> {
        &mut self.runtime
    }

    /// Consumes the facade and returns its underlying runtime.
    pub fn into_runtime(self) -> SwarmRuntime<T, E> {
        self.runtime
    }

    /// Starts listening on a transport address.
    pub fn listen(&mut self, address: &Multiaddr) -> Result<Multiaddr, DriverError> {
        self.runtime.listen(address)
    }

    /// Starts listening on every address already bound by the transport.
    pub fn listen_all(&mut self) -> Result<Vec<PeerAddr>, DriverError> {
        self.runtime.listen_on_bound_addrs()
    }

    /// Starts dialing a peer address.
    pub fn dial(&mut self, address: &PeerAddr) -> Result<ConnectionId, DriverError> {
        self.runtime.dial(address)
    }

    /// Returns peers with an established transport connection.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.runtime.connected_peers()
    }

    /// Returns whether a peer completed Identify and is ready for application protocols.
    pub fn is_peer_ready(&self, peer_id: &PeerId) -> bool {
        self.runtime.is_peer_ready(peer_id)
    }

    /// Returns the latest Identify information received for a peer.
    pub fn peer_info(&self, peer_id: &PeerId) -> Option<&IdentifyMessage> {
        self.runtime.peer_info(peer_id)
    }

    /// Sets externally validated addresses to advertise through Identify.
    pub fn set_external_addresses(&mut self, addresses: Vec<Multiaddr>) {
        self.runtime.set_external_addresses(addresses);
    }

    /// Requests a ping using the caller's time sample.
    pub fn ping(&mut self, peer_id: &PeerId, now: Now) -> Result<(), DriverError> {
        self.runtime.ping(peer_id, now.monotonic_ms)
    }

    /// Disconnects from a peer.
    pub fn disconnect(&mut self, peer_id: &PeerId, now: Now) -> Result<(), DriverError> {
        self.runtime.disconnect(peer_id, now.monotonic_ms)
    }

    /// Opens an outbound application stream.
    pub fn open_stream(
        &mut self,
        peer_id: &PeerId,
        protocol_id: &str,
        now: Now,
    ) -> Result<StreamId, DriverError> {
        self.runtime
            .open_stream(peer_id, protocol_id, now.monotonic_ms)
    }

    /// Sends bytes on an application stream.
    pub fn send_stream(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
        data: Vec<u8>,
        now: Now,
    ) -> Result<(), DriverError> {
        self.runtime
            .send_stream(peer_id, stream_id, data, now.monotonic_ms)
    }

    /// Half-closes the local write side of an application stream.
    pub fn close_stream_write(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
        now: Now,
    ) -> Result<(), DriverError> {
        self.runtime
            .close_stream_write(peer_id, stream_id, now.monotonic_ms)
    }

    /// Abruptly resets an application stream.
    pub fn reset_stream(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
        now: Now,
    ) -> Result<(), DriverError> {
        self.runtime
            .reset_stream(peer_id, stream_id, now.monotonic_ms)
    }

    /// Resets a stream and removes all swarm bookkeeping for it.
    pub fn abandon_stream(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
        now: Now,
    ) -> Result<(), DriverError> {
        self.runtime
            .abandon_stream(peer_id, stream_id, now.monotonic_ms)
    }

    /// Returns a lightweight state snapshot without driving the endpoint.
    pub fn stats(&self) -> PortableEndpointStats {
        let connected = self.runtime.connected_peers();
        PortableEndpointStats {
            ready_peers: connected
                .iter()
                .filter(|peer_id| self.runtime.is_peer_ready(peer_id))
                .count(),
            connected_peers: connected.len(),
            listen_addresses: self.runtime.transport().local_addresses(),
        }
    }

    /// Advances transport and protocol state using one host-supplied time sample.
    pub fn poll(&mut self, now: Now) -> Result<alloc::vec::Vec<SwarmEvent>, DriverError> {
        self.runtime.poll(now)
    }

    /// Returns when the endpoint next needs to be polled.
    pub fn next_deadline(&self, now: Now) -> Option<PollDeadline> {
        self.runtime.next_deadline(now)
    }

    /// Gracefully closes established peers, drives the resulting actions once,
    /// and consumes the endpoint.
    ///
    /// Consuming `self` is intentional: after the final drive, dropping the
    /// transport releases listeners and in-progress connections as well as
    /// established ones. Every established peer is attempted even if an
    /// earlier close fails. The first close error wins over a later poll error.
    pub fn shutdown(mut self, now: Now) -> Result<Vec<SwarmEvent>, DriverError> {
        let mut first_error = None;
        for peer_id in self.runtime.connected_peers() {
            if let Err(error) = self.runtime.disconnect(&peer_id, now.monotonic_ms)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        let events = self.runtime.poll(now);
        match first_error {
            Some(error) => Err(error),
            None => events,
        }
    }
}

/// Builder for a [`PortableEndpoint`].
pub struct PortableEndpointBuilder<E> {
    swarm: SwarmBuilder,
    entropy: E,
}

impl<E: EntropySource> PortableEndpointBuilder<E> {
    /// Starts a builder with explicit identity and entropy.
    pub fn new(identity: &Ed25519Keypair, entropy: E) -> Self {
        Self {
            swarm: SwarmBuilder::new(identity),
            entropy,
        }
    }

    /// Overrides the Identify agent-version string.
    pub fn agent_version(mut self, value: impl Into<String>) -> Self {
        self.swarm = self.swarm.agent_version(value);
        self
    }

    /// Registers an application stream protocol.
    pub fn protocol(mut self, protocol_id: impl Into<String>) -> Self {
        self.swarm = self.swarm.protocol(protocol_id);
        self
    }

    /// Builds the portable endpoint over a caller-provided transport.
    pub fn build<T: Transport>(self, transport: T) -> Result<PortableEndpoint<T, E>, SwarmError> {
        Ok(PortableEndpoint {
            runtime: self.swarm.build_runtime(transport, self.entropy)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{rc::Rc, vec, vec::Vec};
    use core::cell::Cell;
    use minip2p_platform::EntropyError;
    use minip2p_test_support::InMemoryTransport;
    use minip2p_transport::{ConnectionEndpoint, TransportEvent};

    struct NoopTransport;

    impl Transport for NoopTransport {
        fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
            unreachable!()
        }

        fn listen(&mut self, _: &Multiaddr) -> Result<Multiaddr, TransportError> {
            unreachable!()
        }

        fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
            unreachable!()
        }

        fn send_stream(
            &mut self,
            _: ConnectionId,
            _: StreamId,
            _: Vec<u8>,
        ) -> Result<(), TransportError> {
            unreachable!()
        }

        fn close_stream_write(
            &mut self,
            _: ConnectionId,
            _: StreamId,
        ) -> Result<(), TransportError> {
            unreachable!()
        }

        fn reset_stream(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
            unreachable!()
        }

        fn close(&mut self, _: ConnectionId) -> Result<(), TransportError> {
            unreachable!()
        }

        fn poll(&mut self, _: Now) -> Result<Vec<TransportEvent>, TransportError> {
            Ok(Vec::new())
        }
    }

    struct ZeroEntropy;

    impl EntropySource for ZeroEntropy {
        fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
            output.fill(0);
            Ok(())
        }
    }

    struct RecordingTransport {
        events: Vec<TransportEvent>,
        local_address: Multiaddr,
        next_stream_id: u64,
        closed: Rc<Cell<bool>>,
    }

    impl Transport for RecordingTransport {
        fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
            unreachable!()
        }

        fn listen(&mut self, address: &Multiaddr) -> Result<Multiaddr, TransportError> {
            Ok(address.clone())
        }

        fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
            self.next_stream_id += 1;
            Ok(StreamId::new(self.next_stream_id))
        }

        fn send_stream(
            &mut self,
            _: ConnectionId,
            _: StreamId,
            _: Vec<u8>,
        ) -> Result<(), TransportError> {
            Ok(())
        }

        fn close_stream_write(
            &mut self,
            _: ConnectionId,
            _: StreamId,
        ) -> Result<(), TransportError> {
            Ok(())
        }

        fn reset_stream(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
            Ok(())
        }

        fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
            self.closed.set(true);
            self.events.push(TransportEvent::Closed { id });
            Ok(())
        }

        fn poll(&mut self, _: Now) -> Result<Vec<TransportEvent>, TransportError> {
            Ok(core::mem::take(&mut self.events))
        }

        fn local_addresses(&self) -> Vec<Multiaddr> {
            vec![self.local_address.clone()]
        }
    }

    #[test]
    fn portable_builder_constructs_a_protocol_ready_endpoint() {
        let identity = Ed25519Keypair::from_secret_key_bytes([7; 32]);
        let mut endpoint = Endpoint::portable(&identity, ZeroEntropy)
            .protocol("/example/1.0.0")
            .build(NoopTransport)
            .expect("portable endpoint configuration is valid");
        let remote = Ed25519Keypair::from_secret_key_bytes([8; 32]).peer_id();

        assert_eq!(endpoint.peer_id(), &identity.peer_id());
        assert!(matches!(
            endpoint
                .runtime_mut()
                .open_stream(&remote, "/example/1.0.0", 0),
            Err(DriverError::Swarm(SwarmError::NotConnected { .. }))
        ));
        assert!(matches!(
            endpoint
                .runtime_mut()
                .open_stream(&remote, "/missing/1.0.0", 0),
            Err(DriverError::Swarm(SwarmError::ProtocolNotRegistered { .. }))
        ));

        let error = Endpoint::portable(&identity, ZeroEntropy)
            .protocol(minip2p_swarm::RESERVED_PROTOCOL_IDS[0])
            .build(NoopTransport)
            .err()
            .expect("reserved protocols must be rejected");
        assert!(matches!(error, SwarmError::ReservedProtocol { .. }));
    }

    #[test]
    fn portable_stats_count_identify_ready_peers() {
        let a_identity = Ed25519Keypair::from_secret_key_bytes([11; 32]);
        let b_identity = Ed25519Keypair::from_secret_key_bytes([12; 32]);
        let (a_transport, b_transport) =
            InMemoryTransport::pair(a_identity.peer_id(), b_identity.peer_id());
        let mut a = Endpoint::portable(&a_identity, ZeroEntropy)
            .build(a_transport)
            .expect("a endpoint configuration is valid");
        let mut b = Endpoint::portable(&b_identity, ZeroEntropy)
            .build(b_transport)
            .expect("b endpoint configuration is valid");

        for now_ms in 0..64 {
            a.poll(Now::from_millis(now_ms)).expect("drive a");
            b.poll(Now::from_millis(now_ms)).expect("drive b");
            if a.is_peer_ready(&b_identity.peer_id()) && b.is_peer_ready(&a_identity.peer_id()) {
                break;
            }
        }

        assert_eq!(a.stats().connected_peers, 1);
        assert_eq!(a.stats().ready_peers, 1);
        assert_eq!(b.stats().connected_peers, 1);
        assert_eq!(b.stats().ready_peers, 1);
    }

    #[test]
    fn portable_shutdown_closes_established_peers_and_releases_the_endpoint() {
        let identity = Ed25519Keypair::from_secret_key_bytes([9; 32]);
        let remote = Ed25519Keypair::from_secret_key_bytes([10; 32]).peer_id();
        let address: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().expect("address");
        let conn_id = ConnectionId::new(1);
        let closed = Rc::new(Cell::new(false));
        let transport = RecordingTransport {
            events: vec![TransportEvent::Connected {
                id: conn_id,
                endpoint: ConnectionEndpoint::with_peer_id(address.clone(), remote.clone()),
            }],
            local_address: address.clone(),
            next_stream_id: 0,
            closed: closed.clone(),
        };
        let mut endpoint = Endpoint::portable(&identity, ZeroEntropy)
            .build(transport)
            .expect("portable endpoint configuration is valid");

        endpoint
            .poll(Now::from_millis(1))
            .expect("connection event is accepted");
        assert_eq!(
            endpoint.stats(),
            PortableEndpointStats {
                connected_peers: 1,
                ready_peers: 0,
                listen_addresses: vec![address],
            }
        );

        let events = endpoint
            .shutdown(Now::from_millis(2))
            .expect("shutdown succeeds");
        assert!(
            closed.get(),
            "the established transport connection was closed"
        );
        assert!(events.iter().any(|event| matches!(
            event,
            SwarmEvent::ConnectionClosed { peer_id, conn_id: closed_id }
                if peer_id == &remote && closed_id == &conn_id
        )));
    }
}
