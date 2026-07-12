//! Shared scripted-test harness: a fake clock, canned peers, and frame
//! builders for driving a [`NatAgent`] with no I/O.

// Each integration-test binary compiles its own copy of this module and
// uses a different subset of the helpers.
#![allow(dead_code)]

use minip2p_core::{Multiaddr, PeerAddr, PeerId};
use minip2p_dcutr::{HolePunch, HolePunchType, encode_frame as dcutr_encode_frame};
use minip2p_nat::{NatAction, NatAgent, NatConfig, NatEvent, NatToken, Now};
use minip2p_relay::{
    HOP_PROTOCOL_ID, HopMessage, HopMessageType, Status, encode_frame as relay_encode_frame,
};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::StreamId;

pub const TARGET_ADDR: &str = "/ip4/192.0.2.10/udp/4001/quic-v1";
pub const RELAY_TRANSPORT_ADDR: &str = "/ip4/203.0.113.1/udp/4001/quic-v1";
pub const LISTEN_ADDR: &str = "/ip4/198.51.100.5/udp/4500/quic-v1";
pub const REMOTE_OBSERVED_ADDR: &str = "/ip4/192.0.2.99/udp/4002/quic-v1";

pub fn peer(tag: &[u8]) -> PeerId {
    PeerId::from_public_key_protobuf(tag)
}

pub fn maddr(s: &str) -> Multiaddr {
    s.parse().expect("valid multiaddr")
}

pub fn at(ms: u64) -> Now {
    Now::from_mono(ms)
}

pub fn drain_actions(agent: &mut NatAgent) -> Vec<NatAction> {
    core::iter::from_fn(|| agent.poll_action()).collect()
}

pub fn drain_events(agent: &mut NatAgent) -> Vec<NatEvent> {
    core::iter::from_fn(|| agent.poll_event()).collect()
}

/// A framed HOP STATUS response carrying `status`.
pub fn hop_status(status: Status) -> Vec<u8> {
    let msg = HopMessage {
        kind: HopMessageType::Status,
        peer: None,
        reservation: None,
        limit: None,
        status: Some(status),
    };
    relay_encode_frame(&msg.encode())
}

/// A framed DCUtR CONNECT (the responder's reply) advertising `addrs`.
/// Observed addresses travel as binary multiaddrs on the wire.
pub fn dcutr_connect_reply(addrs: &[Multiaddr]) -> Vec<u8> {
    let msg = HolePunch {
        kind: HolePunchType::Connect,
        obs_addrs: addrs.iter().map(Multiaddr::to_bytes).collect(),
    };
    dcutr_encode_frame(&msg.encode())
}

/// Finds the token of the single `Dial` action targeting `peer`.
pub fn dial_token_for(actions: &[NatAction], peer: &PeerId) -> NatToken {
    let mut tokens = actions.iter().filter_map(|action| match action {
        NatAction::Dial { token, addr } if addr.peer_id() == peer => Some(*token),
        _ => None,
    });
    let token = tokens.next().expect("expected a Dial action for the peer");
    assert!(tokens.next().is_none(), "more than one Dial for the peer");
    token
}

/// Counts `Dial` actions targeting `peer`.
pub fn dial_count_for(actions: &[NatAction], peer: &PeerId) -> usize {
    actions
        .iter()
        .filter(|action| matches!(action, NatAction::Dial { addr, .. } if addr.peer_id() == peer))
        .count()
}

/// Finds the token of the single `OpenStream` action.
pub fn open_stream_token(actions: &[NatAction]) -> NatToken {
    let mut tokens = actions.iter().filter_map(|action| match action {
        NatAction::OpenStream { token, .. } => Some(*token),
        _ => None,
    });
    let token = tokens.next().expect("expected an OpenStream action");
    assert!(tokens.next().is_none(), "more than one OpenStream action");
    token
}

pub fn has_hop_open(actions: &[NatAction]) -> bool {
    actions.iter().any(|action| {
        matches!(
            action,
            NatAction::OpenStream { protocol_id, .. } if protocol_id == HOP_PROTOCOL_ID
        )
    })
}

pub fn send_stream_count(actions: &[NatAction]) -> usize {
    actions
        .iter()
        .filter(|action| matches!(action, NatAction::SendStream { .. }))
        .count()
}

pub fn has_reset_for(actions: &[NatAction], stream: StreamId) -> bool {
    actions.iter().any(
        |action| matches!(action, NatAction::ResetStream { stream_id, .. } if *stream_id == stream),
    )
}

/// Scripted world around one agent: a local node, a target peer, and one
/// configured relay.
pub struct Harness {
    pub agent: NatAgent,
    pub local: PeerId,
    pub target: PeerId,
    pub relay: PeerId,
    pub relay_addr: PeerAddr,
}

impl Harness {
    /// An agent with one relay configured and a validated listen address.
    pub fn with_relay(mut config: NatConfig) -> Self {
        let local = peer(b"local-peer");
        let target = peer(b"target-peer");
        let relay = peer(b"relay-peer");
        let relay_addr =
            PeerAddr::new(maddr(RELAY_TRANSPORT_ADDR), relay.clone()).expect("valid relay addr");
        config.relays = vec![relay_addr.clone()];
        let mut agent = NatAgent::new(local.clone(), config);
        agent.set_listen_addrs(&[maddr(LISTEN_ADDR)]);
        Self {
            agent,
            local,
            target,
            relay,
            relay_addr,
        }
    }

    /// An agent with no relay configured.
    pub fn without_relay(config: NatConfig) -> Self {
        let local = peer(b"local-peer");
        let target = peer(b"target-peer");
        let relay = peer(b"relay-peer");
        let relay_addr =
            PeerAddr::new(maddr(RELAY_TRANSPORT_ADDR), relay.clone()).expect("valid relay addr");
        let mut agent = NatAgent::new(local.clone(), config);
        agent.set_listen_addrs(&[maddr(LISTEN_ADDR)]);
        Self {
            agent,
            local,
            target,
            relay,
            relay_addr,
        }
    }

    /// Marks the relay connection as established and identify-complete
    /// (advertising the HOP protocol).
    pub fn relay_session_ready(&mut self, now: Now) {
        self.agent.handle_event(
            &SwarmEvent::ConnectionEstablished {
                peer_id: self.relay.clone(),
            },
            now,
        );
        self.agent.handle_event(
            &SwarmEvent::PeerReady {
                peer_id: self.relay.clone(),
                protocols: vec![HOP_PROTOCOL_ID.to_string()],
            },
            now,
        );
    }

    pub fn stream_ready(&mut self, stream: StreamId, now: Now) {
        self.agent.handle_event(
            &SwarmEvent::StreamReady {
                peer_id: self.relay.clone(),
                stream_id: stream,
                protocol_id: HOP_PROTOCOL_ID.to_string(),
                initiated_locally: true,
            },
            now,
        );
    }

    pub fn stream_data(&mut self, stream: StreamId, data: Vec<u8>, now: Now) {
        self.agent.handle_event(
            &SwarmEvent::StreamData {
                peer_id: self.relay.clone(),
                stream_id: stream,
                data,
            },
            now,
        );
    }

    pub fn target_connected(&mut self, now: Now) {
        self.agent.handle_event(
            &SwarmEvent::ConnectionEstablished {
                peer_id: self.target.clone(),
            },
            now,
        );
    }
}
