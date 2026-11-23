//! How the NAT driver executes responder-side hole-punch datagrams.

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use minip2p_core::platform::{EntropyError, EntropySource, Now};
use minip2p_core::{Multiaddr, PeerAddr};
use minip2p_identity::Ed25519Keypair;
use minip2p_nat::{NatAction, NatAgent, NatConfig, NatEvent};
use minip2p_swarm::{SwarmBuilder, SwarmCore};
use minip2p_transport::{ConnectionId, StreamId, Transport, TransportError, TransportEvent};

use super::NatDriver;

/// An entropy source that always fails, as a broken OS RNG would.
struct FailingEntropy;

impl EntropySource for FailingEntropy {
    fn fill_bytes(&mut self, _: &mut [u8]) -> Result<(), EntropyError> {
        Err(EntropyError::unavailable("no entropy"))
    }
}

/// A transport that records datagrams and answers each send with `answer`.
struct DatagramTransport {
    answer: Result<(), TransportError>,
    sent: Vec<(Multiaddr, Vec<u8>)>,
}

impl Transport for DatagramTransport {
    fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
        Err(TransportError::Unsupported { operation: "dial" })
    }
    fn listen(&mut self, _: &Multiaddr) -> Result<Multiaddr, TransportError> {
        Err(TransportError::Unsupported {
            operation: "listen",
        })
    }
    fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
        Err(TransportError::Unsupported {
            operation: "open_stream",
        })
    }
    fn send_stream(
        &mut self,
        _: ConnectionId,
        _: StreamId,
        _: minip2p_core::Bytes,
    ) -> Result<(), TransportError> {
        Err(TransportError::Unsupported {
            operation: "send_stream",
        })
    }
    fn close_stream_write(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Err(TransportError::Unsupported {
            operation: "close_stream_write",
        })
    }
    fn reset_stream(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Err(TransportError::Unsupported {
            operation: "reset_stream",
        })
    }
    fn ack_stream(&mut self, _: ConnectionId, _: StreamId, _: usize) -> Result<(), TransportError> {
        Ok(())
    }
    fn close(&mut self, _: ConnectionId) -> Result<(), TransportError> {
        Ok(())
    }
    fn poll(&mut self, _: Now) -> Result<Vec<TransportEvent>, TransportError> {
        Ok(Vec::new())
    }
    fn send_datagram(&mut self, target: &Multiaddr, payload: &[u8]) -> Result<(), TransportError> {
        self.sent.push((target.clone(), payload.to_vec()));
        self.answer.clone()
    }
}

fn punch_setup(
    answer: Result<(), TransportError>,
) -> (
    NatDriver<DatagramTransport>,
    SwarmCore<DatagramTransport, FailingEntropy>,
) {
    let identity = Ed25519Keypair::from_secret_key_bytes([1; 32]);
    let agent = NatAgent::new(identity.peer_id(), NatConfig::default());
    let swarm = SwarmBuilder::new(&identity)
        .build_core(
            DatagramTransport {
                answer,
                sent: Vec::new(),
            },
            FailingEntropy,
        )
        .expect("swarm");
    (NatDriver::new(agent, Vec::new(), 0), swarm)
}

fn blast(attempt: u32, target: &Multiaddr) -> NatAction {
    NatAction::SendRandomUdp {
        peer: Ed25519Keypair::from_secret_key_bytes([2; 32]).peer_id(),
        attempt,
        target: target.clone(),
        payload_len: 4,
    }
}

fn target() -> Multiaddr {
    "/ip4/203.0.113.7/udp/4001/quic-v1"
        .parse()
        .expect("address")
}

#[test]
fn a_failing_entropy_source_still_sends_a_zero_filled_punch() {
    let (mut driver, mut swarm) = punch_setup(Ok(()));

    driver.execute(blast(1, &target()), &mut swarm);
    driver.pump(&mut swarm);

    assert_eq!(swarm.transport().sent, vec![(target(), vec![0; 4])]);
    assert!(driver.take_unrouted().is_none());
}

#[test]
fn a_transport_without_raw_udp_stays_silent() {
    let (mut driver, mut swarm) = punch_setup(Err(TransportError::Unsupported {
        operation: "send_datagram",
    }));

    driver.execute(blast(1, &target()), &mut swarm);
    driver.pump(&mut swarm);

    assert!(driver.take_unrouted().is_none());
}

#[test]
fn a_failed_punch_send_is_reported_once_per_round() {
    let error = TransportError::ResourceExhausted {
        resource: "socket buffer",
    };
    let (mut driver, mut swarm) = punch_setup(Err(error.clone()));
    let other: Multiaddr = "/ip4/203.0.113.8/udp/4001/quic-v1"
        .parse()
        .expect("address");

    for attempt in [1, 1, 2] {
        for addr in [target(), other.clone()] {
            driver.execute(blast(attempt, &addr), &mut swarm);
        }
    }
    driver.pump(&mut swarm);

    let events: Vec<_> = core::iter::from_fn(|| driver.take_unrouted()).collect();
    let reported: Vec<_> = events
        .iter()
        .map(|event| match event {
            NatEvent::InboundHolePunchSendFailed {
                attempt,
                target,
                reason,
                ..
            } => (*attempt, target.clone(), reason.clone()),
            other => panic!("unexpected {other:?}"),
        })
        .collect();
    assert_eq!(
        reported,
        vec![
            (1, target(), error.to_string()),
            (2, target(), error.to_string()),
        ]
    );
}
