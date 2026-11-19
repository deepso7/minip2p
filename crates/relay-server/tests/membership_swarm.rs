//! Membership against a real `SwarmCore` over a scripted transport: a
//! pending backbone connection whose proofs complete in the same poll that
//! replaces it is not promoted, and opens nothing on its replacement.

mod common;

use std::collections::VecDeque;

use minip2p_core::platform::{EntropyError, EntropySource, Now};
use minip2p_core::{Multiaddr, PeerAddr};
use minip2p_identity::Ed25519Keypair;
use minip2p_relay_server::mesh::{
    DIRECTORY_PROTOCOL_ID, MEMBER_ACCEPT, MEMBER_PROTOCOL_ID, MeshConfig, register_backbone_roles,
    sign_member_proof,
};
use minip2p_relay_server::{RelayServerAgent, RelayServerEvent};
use minip2p_swarm::{SwarmBuilder, SwarmCore};
use minip2p_transport::{
    Bytes, ConnectionEndpoint, ConnectionId, ConnectionNamespace, StreamId, Transport,
    TransportError, TransportEvent,
};

use common::mesh::{relay_identity, relay_peer};
use common::unlimited_rates;

/// A transport that plays back scripted events and records what the swarm
/// opens and writes.
#[derive(Default)]
struct ScriptedTransport {
    events: VecDeque<TransportEvent>,
    opened: Vec<(ConnectionId, StreamId)>,
    sent: Vec<(ConnectionId, StreamId, Bytes)>,
    next_stream: u64,
}

impl Transport for ScriptedTransport {
    fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
        Err(TransportError::Unsupported { operation: "dial" })
    }

    fn listen(&mut self, _: &Multiaddr) -> Result<Multiaddr, TransportError> {
        Err(TransportError::Unsupported {
            operation: "listen",
        })
    }

    fn open_stream(&mut self, id: ConnectionId) -> Result<StreamId, TransportError> {
        self.next_stream += 1;
        let stream_id = StreamId::new(100 + self.next_stream);
        self.opened.push((id, stream_id));
        Ok(stream_id)
    }

    fn send_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
    ) -> Result<(), TransportError> {
        self.sent.push((id, stream_id, data));
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

    fn poll(&mut self, _: Now) -> Result<Vec<TransportEvent>, TransportError> {
        Ok(self.events.drain(..).collect())
    }
}

struct ZeroEntropy;

impl EntropySource for ZeroEntropy {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        output.fill(0);
        Ok(())
    }
}

type Backbone = SwarmCore<ScriptedTransport, ZeroEntropy>;

fn multistream_frame(protocol: &str) -> Vec<u8> {
    let mut frame = vec![(protocol.len() + 1) as u8];
    frame.extend_from_slice(protocol.as_bytes());
    frame.push(b'\n');
    frame
}

fn negotiated(protocol: &str) -> Bytes {
    let mut data = multistream_frame("/multistream/1.0.0");
    data.extend_from_slice(&multistream_frame(protocol));
    Bytes::from(data)
}

/// Polls the swarm and feeds every event to the agent.
fn drive(swarm: &mut Backbone, agent: &mut RelayServerAgent, ms: u64) {
    let now = Now::from_millis(ms);
    for event in swarm.poll(now).expect("poll") {
        agent.handle_event(swarm, &event, false, now);
        agent.assert_indexes_consistent();
    }
}

/// Streams the swarm opened on `conn_id` that proposed `protocol`.
fn proposals(swarm: &Backbone, conn_id: ConnectionId, protocol: &str) -> usize {
    let frame = multistream_frame(protocol);
    swarm
        .transport()
        .sent
        .iter()
        .filter(|(id, _, data)| {
            *id == conn_id && data.windows(frame.len()).any(|window| window == frame)
        })
        .count()
}

#[test]
fn proofs_completing_in_the_poll_that_replaces_the_connection_promote_nothing() {
    let backbone = Ed25519Keypair::from_secret_key_bytes([3; 32]);
    let remote = Ed25519Keypair::from_secret_key_bytes([4; 32]);
    let mut swarm = SwarmBuilder::new(&backbone)
        .simultaneous_dial_window_ms(0)
        .build_core(ScriptedTransport::default(), ZeroEntropy)
        .expect("swarm");
    register_backbone_roles(&mut swarm).expect("roles");
    let mut config = unlimited_rates();
    config.mesh = Some(MeshConfig::new(&relay_identity(), &backbone.peer_id()));
    let mut agent = RelayServerAgent::new(relay_peer(), config).expect("agent");

    let conn = |sequence| {
        ConnectionId::namespaced(ConnectionNamespace::MESH_IPV4, sequence).expect("in range")
    };
    let (first, second) = (conn(1), conn(2));
    let connected = |id| TransportEvent::Connected {
        id,
        endpoint: Box::new(ConnectionEndpoint::with_peer_id(
            "/ip4/192.0.2.7/udp/19877/quic-v1".parse().expect("address"),
            remote.peer_id(),
        )),
    };
    swarm.transport_mut().events.push_back(connected(first));
    drive(&mut swarm, &mut agent, 0);
    let proof = sign_member_proof(&relay_identity(), &remote.peer_id());

    // The remote's proof checks out and is answered on the live connection.
    let outbound = prove_remote(&mut swarm, &mut agent, first, &proof, 10);
    // In one poll: the remote's accept of this node's proof, then a second
    // connection that replaces the first.
    swarm.transport_mut().events.extend(
        accept(first, outbound)
            .into_iter()
            .chain([connected(second)]),
    );
    drive(&mut swarm, &mut agent, 20);
    assert_eq!(swarm.connection_peer(first), None);
    assert_eq!(swarm.connection_peer(second), Some(&remote.peer_id()));
    let events: Vec<_> = core::iter::from_fn(|| agent.poll_event()).collect();
    assert!(
        !events.iter().any(|event| matches!(
            event,
            RelayServerEvent::MeshMemberUp { .. } | RelayServerEvent::MeshPeerRejected { .. }
        )),
        "{events:?}"
    );
    assert!(agent.take_verified_links().is_empty());
    for id in [first, second] {
        assert_eq!(proposals(&swarm, id, DIRECTORY_PROTOCOL_ID), 0, "{id}");
    }

    // The replacement runs its own exchange and becomes the link.
    let outbound = prove_remote(&mut swarm, &mut agent, second, &proof, 30);
    swarm
        .transport_mut()
        .events
        .extend(accept(second, outbound));
    drive(&mut swarm, &mut agent, 40);
    let events: Vec<_> = core::iter::from_fn(|| agent.poll_event()).collect();
    assert!(
        events.contains(&RelayServerEvent::MeshMemberUp {
            member: remote.peer_id()
        }),
        "{events:?}"
    );
    assert_eq!(agent.take_verified_links(), [(remote.peer_id(), second)]);
    assert_eq!(proposals(&swarm, first, DIRECTORY_PROTOCOL_ID), 0);
    assert_eq!(proposals(&swarm, second, DIRECTORY_PROTOCOL_ID), 1);
}

/// The stream this node opened on `conn_id` for the member protocol.
fn member_stream(swarm: &Backbone, conn_id: ConnectionId) -> StreamId {
    let member_frame = multistream_frame(MEMBER_PROTOCOL_ID);
    swarm
        .transport()
        .sent
        .iter()
        .find(|(id, _, data)| *id == conn_id && data.ends_with(&member_frame))
        .map(|(_, stream, _)| *stream)
        .expect("a member open")
}

/// Negotiates this node's member stream on `conn_id`, then has the remote
/// send its whole `proof`, from `ms` on. Returns this node's stream; the
/// agent answered the proof on the remote's.
fn prove_remote(
    swarm: &mut Backbone,
    agent: &mut RelayServerAgent,
    conn_id: ConnectionId,
    proof: &[u8],
    ms: u64,
) -> StreamId {
    let outbound = member_stream(swarm, conn_id);
    let inbound = StreamId::new(2);
    swarm.transport_mut().events.extend([
        TransportEvent::StreamOpened {
            id: conn_id,
            stream_id: outbound,
        },
        TransportEvent::StreamData {
            id: conn_id,
            stream_id: outbound,
            data: negotiated(MEMBER_PROTOCOL_ID),
        },
        TransportEvent::IncomingStream {
            id: conn_id,
            stream_id: inbound,
        },
        TransportEvent::StreamData {
            id: conn_id,
            stream_id: inbound,
            data: negotiated(MEMBER_PROTOCOL_ID),
        },
        TransportEvent::StreamData {
            id: conn_id,
            stream_id: inbound,
            data: Bytes::from(proof.to_vec()),
        },
        TransportEvent::StreamRemoteWriteClosed {
            id: conn_id,
            stream_id: inbound,
        },
    ]);
    drive(swarm, agent, ms);
    assert!(
        swarm
            .transport()
            .sent
            .contains(&(conn_id, inbound, Bytes::from(vec![MEMBER_ACCEPT]))),
        "the remote's proof was answered on {conn_id}"
    );
    outbound
}

/// The remote's accept of this node's proof on `outbound`, half-closed.
fn accept(conn_id: ConnectionId, outbound: StreamId) -> [TransportEvent; 2] {
    [
        TransportEvent::StreamData {
            id: conn_id,
            stream_id: outbound,
            data: Bytes::from(vec![MEMBER_ACCEPT]),
        },
        TransportEvent::StreamRemoteWriteClosed {
            id: conn_id,
            stream_id: outbound,
        },
    ]
}
