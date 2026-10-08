//! `NatAgent` against a real `SwarmCore`: the swarm's own command results
//! and event ordering, which the scripted fake only mirrors.

use std::collections::VecDeque;

use minip2p_core::{Multiaddr, PeerAddr, PeerId};
use minip2p_identity::Ed25519Keypair;
use minip2p_nat::{
    ConnectLegs, HOP_PROTOCOL_ID, NatAgent, NatConfig, NatError, NatEvent, Now, ReservationPolicy,
};
use minip2p_platform::{EntropyError, EntropySource, Now as SwarmNow};
use minip2p_swarm::{SwarmBuilder, SwarmCore, SwarmEvent};
use minip2p_test_support::InMemoryTransport;
use minip2p_transport::{Bytes, ConnectionId, StreamId, Transport, TransportError, TransportEvent};

struct ZeroEntropy;

impl EntropySource for ZeroEntropy {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        output.fill(0);
        Ok(())
    }
}

const RELAY_NOW: ConnectLegs = ConnectLegs {
    direct_racing: false,
    allow_relay: true,
    target_addrs: Vec::new(),
    deadline_ms: None,
};

fn maddr(s: &str) -> Multiaddr {
    s.parse().expect("valid multiaddr")
}

fn nat_config(relay: PeerAddr, policy: ReservationPolicy) -> NatConfig {
    NatConfig {
        relays: vec![relay],
        reservation_policy: policy,
        ..NatConfig::default()
    }
}

/// A transport whose dials stay pending forever, counting them.
#[derive(Default)]
struct PendingDials {
    dials: Vec<PeerAddr>,
}

impl Transport for PendingDials {
    fn dial(&mut self, addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        self.dials.push(addr.clone());
        Ok(ConnectionId::new(self.dials.len() as u64))
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
        _: Bytes,
    ) -> Result<(), TransportError> {
        Ok(())
    }

    fn close_stream_write(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Ok(())
    }

    fn reset_stream(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Ok(())
    }

    fn ack_stream(&mut self, _: ConnectionId, _: StreamId, _: usize) -> Result<(), TransportError> {
        Ok(())
    }

    fn close(&mut self, _: ConnectionId) -> Result<(), TransportError> {
        Ok(())
    }

    fn poll(&mut self, _: SwarmNow) -> Result<Vec<TransportEvent>, TransportError> {
        Ok(Vec::new())
    }
}

fn pending_swarm() -> SwarmCore<PendingDials, ZeroEntropy> {
    SwarmBuilder::new(&Ed25519Keypair::from_secret_key_bytes([1; 32]))
        .build_core(PendingDials::default(), ZeroEntropy)
        .expect("valid swarm")
}

#[test]
fn the_bare_swarm_rejects_a_named_relay_dial() {
    let mut swarm = pending_swarm();
    let relay = PeerAddr::new(
        maddr("/dns4/relay.example/udp/4001/quic-v1"),
        PeerId::from_public_key_protobuf(b"relay"),
    )
    .expect("valid relay addr");
    let local = swarm.local_peer_id().clone();
    let mut agent = NatAgent::new(local, nat_config(relay, ReservationPolicy::Never));

    let id = minip2p_core::ConnectId::from_u64(1);
    let target = PeerId::from_public_key_protobuf(b"target");
    agent.connect(&mut swarm, id, target, RELAY_NOW, Now::from_mono(0));

    assert!(swarm.transport().dials.is_empty());
    assert!(matches!(
        agent.poll_event(),
        Some(NatEvent::ConnectFailed {
            connect_id,
            error: NatError::DialFailed(reason),
            ..
        }) if connect_id == id && reason.contains("must be resolved")
    ));
}

#[test]
fn a_reservation_and_a_connect_share_one_relay_dial() {
    let mut swarm = pending_swarm();
    let relay_peer = PeerId::from_public_key_protobuf(b"relay");
    let relay = PeerAddr::new(maddr("/ip4/203.0.113.1/udp/4001/quic-v1"), relay_peer)
        .expect("valid relay addr");
    let local = swarm.local_peer_id().clone();
    let mut agent = NatAgent::new(local, nat_config(relay, ReservationPolicy::Always));

    agent.handle_tick(&mut swarm, Now::from_mono(0));
    let id = minip2p_core::ConnectId::from_u64(1);
    let target = PeerId::from_public_key_protobuf(b"target");
    agent.connect(&mut swarm, id, target, RELAY_NOW, Now::from_mono(1));

    assert_eq!(
        swarm.transport().dials.len(),
        1,
        "the attempt waits on the reservation's in-flight relay dial"
    );
    assert!(agent.poll_event().is_none());
}

#[test]
fn a_command_between_buffered_deliveries_keeps_the_swarm_order() {
    let local_key = Ed25519Keypair::from_secret_key_bytes([2; 32]);
    let relay_key = Ed25519Keypair::from_secret_key_bytes([3; 32]);
    let (local_io, relay_io) = InMemoryTransport::pair(local_key.peer_id(), relay_key.peer_id());
    let mut local = SwarmBuilder::new(&local_key)
        .protocol(HOP_PROTOCOL_ID)
        .build_core(local_io, ZeroEntropy)
        .expect("valid local swarm");
    let mut relay = SwarmBuilder::new(&relay_key)
        .protocol(HOP_PROTOCOL_ID)
        .build_core(relay_io, ZeroEntropy)
        .expect("valid relay swarm");
    let relay_addr = PeerAddr::new(
        maddr("/ip4/192.0.2.2/udp/4002/quic-v1"),
        relay_key.peer_id(),
    )
    .expect("valid relay addr");
    let mut agent = NatAgent::new(
        local_key.peer_id(),
        nat_config(relay_addr, ReservationPolicy::Never),
    );

    // Collect the local swarm's batch until the relay is ready: the swarm
    // state is then ahead of every event still buffered for NAT.
    let mut buffered = VecDeque::new();
    for ms in 0..64 {
        relay.poll(SwarmNow::from_millis(ms)).expect("drive relay");
        buffered.extend(local.poll(SwarmNow::from_millis(ms)).expect("drive local"));
        if local.is_peer_ready(&relay_key.peer_id()) {
            break;
        }
    }
    assert!(local.is_peer_ready(&relay_key.peer_id()));

    // The host delivers the first buffered event, then a connect starts:
    // the swarm reports the relay ready, so the HOP stream opens at once.
    let first = buffered.pop_front().expect("a buffered event");
    agent.handle_event(&mut local, &first, false, Now::from_mono(1));
    let id = minip2p_core::ConnectId::from_u64(1);
    let target = PeerId::from_public_key_protobuf(b"target");
    agent.connect(&mut local, id, target, RELAY_NOW, Now::from_mono(1));

    // The rest of the batch, including the relay's PeerReady, follows the
    // command; it must not start a second exchange.
    for event in buffered {
        agent.handle_event(&mut local, &event, false, Now::from_mono(2));
    }

    // The swarm queued the open's StreamReady after the batch NAT already
    // handled; the HOP CONNECT goes out once it is delivered.
    let mut relay_hop = None;
    let mut relay_hop_data = 0;
    let mut hop_streams = 0;
    for ms in 64..128 {
        for event in local.poll(SwarmNow::from_millis(ms)).expect("drive local") {
            if let SwarmEvent::StreamReady { protocol_id, .. } = &event
                && protocol_id == HOP_PROTOCOL_ID
            {
                hop_streams += 1;
            }
            agent.handle_event(&mut local, &event, false, Now::from_mono(3));
        }
        for event in relay.poll(SwarmNow::from_millis(ms)).expect("drive relay") {
            match event {
                SwarmEvent::StreamReady {
                    stream_id,
                    protocol_id,
                    ..
                } if protocol_id == HOP_PROTOCOL_ID => relay_hop = Some(stream_id),
                SwarmEvent::StreamData {
                    stream_id, data, ..
                } if Some(stream_id) == relay_hop => relay_hop_data += data.len(),
                _ => {}
            }
        }
        if relay_hop_data > 0 {
            break;
        }
    }
    assert_eq!(hop_streams, 1, "exactly one HOP stream was opened");
    assert!(relay_hop_data > 0, "the relay received HOP CONNECT");
    assert!(agent.poll_event().is_none());
}
