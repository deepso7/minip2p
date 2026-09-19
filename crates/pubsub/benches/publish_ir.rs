use gungraun::prelude::*;
use minip2p_identity::Ed25519Keypair;
use minip2p_pubsub::{
    GossipsubAction, GossipsubAgent, GossipsubConfig, MESHSUB_PROTOCOL_ID_V11, Rpc, SubOpts,
    encode_frame,
};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{ConnectionId, StreamId};
use std::hint::black_box;

const PEER_COUNT: u8 = 32;
const PAYLOAD_LEN: usize = 60 * 1024;
const TOPIC: &str = "benchmark";

fn ack_sends(agent: &mut GossipsubAgent, remote: &minip2p_core::PeerId) {
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

fn subscribed_mesh() -> GossipsubAgent {
    let config = GossipsubConfig {
        d: usize::from(PEER_COUNT),
        d_low: usize::from(PEER_COUNT),
        d_high: usize::from(PEER_COUNT),
        ..GossipsubConfig::default()
    };
    let mut agent = GossipsubAgent::new(
        Ed25519Keypair::from_secret_key_bytes([1; 32]),
        config,
        100,
        7,
    )
    .expect("valid gossipsub config");
    agent.subscribe(TOPIC, 0).expect("subscribe");
    for seed in 2..2 + PEER_COUNT {
        let remote = Ed25519Keypair::from_secret_key_bytes([seed; 32]).peer_id();
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
        ack_sends(&mut agent, &remote);

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
        ack_sends(&mut agent, &remote);
    }
    while agent.poll_event().is_some() {}
    assert_eq!(agent.mesh_peers(TOPIC).len(), usize::from(PEER_COUNT));
    agent
}

fn setup() -> (GossipsubAgent, Vec<u8>) {
    (subscribed_mesh(), vec![0x5a; PAYLOAD_LEN])
}

#[library_benchmark]
#[bench::gossipsub_publish_32x60_kib(setup())]
fn gossipsub_publish(input: (GossipsubAgent, Vec<u8>)) {
    let (mut agent, payload) = input;
    black_box(agent.publish(TOPIC, payload, 0)).expect("publish");
}

library_benchmark_group!(name = benches; benchmarks = gossipsub_publish);
gungraun::main!(library_benchmark_groups = benches);
