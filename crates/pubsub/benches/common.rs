use minip2p_core::PeerId;
use minip2p_identity::Ed25519Keypair;
use minip2p_pubsub::{
    GossipsubAction, GossipsubAgent, GossipsubConfig, MESHSUB_PROTOCOL_ID_V11, Rpc, SubOpts,
    encode_frame,
};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{ConnectionId, StreamId};

pub const PEER_COUNT: u8 = 32;
const PAYLOAD_LEN: usize = 60 * 1024;
pub const TOPIC: &str = "benchmark";
const INITIAL_SEQNO: u64 = 100;
const ENTROPY_SEED: u64 = 7;

fn peer(seed: u8) -> PeerId {
    Ed25519Keypair::from_secret_key_bytes([seed; 32]).peer_id()
}

fn ack_sends(agent: &mut GossipsubAgent, remote: &PeerId) {
    loop {
        let mut sends = Vec::new();
        while let Some(action) = agent.poll_action() {
            if let GossipsubAction::SendStream {
                token, stream_id, ..
            } = action
            {
                sends.push((token, stream_id));
            }
        }
        if sends.is_empty() {
            break;
        }
        for (token, stream_id) in sends {
            agent.send_result(remote, stream_id, token, Ok(()), 0);
        }
    }
}

/// Outbound stream carries our subscribe/GRAFT; inbound subscribe is what adds the peer to the mesh.
fn join_mesh_peer(agent: &mut GossipsubAgent, seed: u8) {
    let remote = peer(seed);
    let conn_id = ConnectionId::new(u64::from(seed));
    let outbound = StreamId::new(u64::from(seed) * 2);
    let inbound = StreamId::new(u64::from(seed) * 2 + 1);

    agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            peer_id: remote.clone(),
            conn_id,
        },
        0,
    );
    agent.handle_event(
        &SwarmEvent::PeerReady {
            peer_id: remote.clone(),
            protocols: vec![MESHSUB_PROTOCOL_ID_V11.into()],
        },
        0,
    );

    let mut opened = Vec::new();
    while let Some(action) = agent.poll_action() {
        opened.push(action);
    }
    let token = opened
        .iter()
        .find_map(|action| match action {
            GossipsubAction::OpenStream {
                token,
                peer: opened_peer,
                ..
            } if opened_peer == &remote => Some(*token),
            _ => None,
        })
        .expect("outbound open for mesh peer");
    agent.stream_open_result(&remote, token, Ok(outbound), 0);
    assert!(agent.handle_event(
        &SwarmEvent::StreamReady {
            peer_id: remote.clone(),
            conn_id,
            stream_id: outbound,
            protocol_id: MESHSUB_PROTOCOL_ID_V11.into(),
            initiated_locally: true,
        },
        0,
    ));
    ack_sends(agent, &remote);

    assert!(agent.handle_event(
        &SwarmEvent::StreamReady {
            peer_id: remote.clone(),
            conn_id,
            stream_id: inbound,
            protocol_id: MESHSUB_PROTOCOL_ID_V11.into(),
            initiated_locally: false,
        },
        0,
    ));
    assert!(
        agent.handle_event(
            &SwarmEvent::StreamData {
                peer_id: remote.clone(),
                conn_id,
                stream_id: inbound,
                data: encode_frame(
                    &Rpc {
                        subscriptions: vec![SubOpts {
                            subscribe: Some(true),
                            topic_id: Some(TOPIC.into()),
                        }],
                        publish: Vec::new(),
                        control: None,
                    }
                    .encode(),
                ),
            },
            0,
        )
    );
    ack_sends(agent, &remote);
}

fn subscribed_mesh() -> GossipsubAgent {
    let degree = usize::from(PEER_COUNT);
    let mut agent = GossipsubAgent::new(
        Ed25519Keypair::from_secret_key_bytes([1; 32]),
        GossipsubConfig {
            d: degree,
            d_low: degree,
            d_high: degree,
            ..GossipsubConfig::default()
        },
        INITIAL_SEQNO,
        ENTROPY_SEED,
    )
    .expect("valid gossipsub config");
    agent.subscribe(TOPIC, 0).expect("subscribe");
    for seed in 2..2 + PEER_COUNT {
        join_mesh_peer(&mut agent, seed);
    }
    while agent.poll_event().is_some() {}
    assert_eq!(agent.mesh_peers(TOPIC).len(), degree);
    agent
}

pub fn setup() -> (GossipsubAgent, Vec<u8>) {
    (subscribed_mesh(), vec![0x5a; PAYLOAD_LEN])
}
