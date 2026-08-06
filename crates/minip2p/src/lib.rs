//! Portable and std application-facing APIs for minip2p.
//!
//! [`PortableEndpoint`] is the `no_std + alloc`, caller-driven facade. It
//! owns a transport and protocol runtime but no clock, executor, sockets, or
//! operating-system entropy source. The host passes one [`Now`] sample to
//! each [`PortableEndpoint::poll`] call.
//!
//! With the default `std` and `quic` features, the existing batteries-included
//! `Endpoint` and `EndpointBuilder` APIs remain available for OS programs.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::String;

pub use minip2p_core::{Multiaddr, PeerAddr, PeerId, Protocol, TransportKind};
pub use minip2p_identity::Ed25519Keypair;
pub use minip2p_platform::{Deadline as PollDeadline, EntropySource, Now};
pub use minip2p_swarm::{DriverError, SwarmBuilder, SwarmError, SwarmEvent, SwarmRuntime};
pub use minip2p_transport::{ConnectionId, StreamId, Transport, TransportError};

#[cfg(feature = "std")]
mod std_endpoint;
#[cfg(feature = "std")]
pub use std_endpoint::*;

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

    /// Starts listening on a transport address.
    pub fn listen(&mut self, address: &Multiaddr) -> Result<Multiaddr, DriverError> {
        self.runtime.listen(address)
    }

    /// Starts dialing a peer address.
    pub fn dial(&mut self, address: &PeerAddr) -> Result<ConnectionId, DriverError> {
        self.runtime.dial(address)
    }

    /// Advances transport and protocol state using one host-supplied time sample.
    pub fn poll(&mut self, now: Now) -> Result<alloc::vec::Vec<SwarmEvent>, DriverError> {
        self.runtime.poll(now)
    }

    /// Returns when the endpoint next needs to be polled.
    pub fn next_deadline(&self, now: Now) -> Option<PollDeadline> {
        self.runtime.next_deadline(now)
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
    use alloc::vec::Vec;
    use minip2p_platform::EntropyError;
    use minip2p_transport::TransportEvent;

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

    #[test]
    fn portable_builder_constructs_a_protocol_ready_endpoint() {
        let identity = Ed25519Keypair::from_secret_key_bytes([7; 32]);
        let mut endpoint = PortableEndpointBuilder::new(&identity, ZeroEntropy)
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

        let error = PortableEndpointBuilder::new(&identity, ZeroEntropy)
            .protocol(minip2p_swarm::RESERVED_PROTOCOL_IDS[0])
            .build(NoopTransport)
            .err()
            .expect("reserved protocols must be rejected");
        assert!(matches!(error, SwarmError::ReservedProtocol { .. }));
    }
}
