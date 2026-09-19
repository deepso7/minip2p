use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use minip2p_identity::Ed25519Keypair;
use minip2p_pubsub::{
    GossipsubAction, GossipsubAgent, GossipsubConfig, MESHSUB_PROTOCOL_ID_V11, Rpc, SubOpts,
    encode_frame,
};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{ConnectionId, StreamId};

const PEER_COUNT: u8 = 32;
const PAYLOAD_LEN: usize = 60 * 1024;
const TOPIC: &str = "benchmark";

fn peer(seed: u8) -> minip2p_core::PeerId {
    Ed25519Keypair::from_secret_key_bytes([seed; 32]).peer_id()
}

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
        join_mesh_peer(&mut agent, seed);
    }
    while agent.poll_event().is_some() {}
    assert_eq!(agent.mesh_peers(TOPIC).len(), usize::from(PEER_COUNT));
    agent
}

fn assert_mesh_publish(agent: &mut GossipsubAgent, payload: Vec<u8>) {
    agent.publish(TOPIC, payload, 0).expect("publish");
    let mut sends = 0;
    while let Some(action) = agent.poll_action() {
        if matches!(action, GossipsubAction::SendStream { .. }) {
            sends += 1;
        }
    }
    assert_eq!(sends, usize::from(PEER_COUNT));
}

fn publish(c: &mut Criterion) {
    let payload = vec![0x5a; PAYLOAD_LEN];
    assert_mesh_publish(&mut subscribed_mesh(), payload.clone());

    c.bench_function("pubsub/gossipsub_publish_32x60KiB", |b| {
        b.iter_batched(
            subscribed_mesh,
            |mut agent| {
                let result = agent.publish(TOPIC, payload.clone(), 0);
                black_box(result).expect("publish");
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, publish);
criterion_main!(benches);
