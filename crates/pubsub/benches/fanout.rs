use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use minip2p_identity::Ed25519Keypair;
use minip2p_pubsub::{
    FLOODSUB_PROTOCOL_ID, FloodsubAgent, FloodsubConfig, PubsubAction, Rpc, SubOpts, encode_frame,
};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{ConnectionId, StreamId};

const PEER_COUNT: u8 = 32;
const PAYLOAD_LEN: usize = 60 * 1024;
const TOPIC: &str = "benchmark";

fn peer(seed: u8) -> minip2p_core::PeerId {
    Ed25519Keypair::from_secret_key_bytes([seed; 32]).peer_id()
}

fn subscribed_agent() -> FloodsubAgent {
    let mut agent = FloodsubAgent::new(
        Ed25519Keypair::from_secret_key_bytes([1; 32]),
        FloodsubConfig::default(),
        0,
    );
    let subscription = encode_frame(
        &Rpc {
            subscriptions: vec![SubOpts {
                subscribe: Some(true),
                topic_id: Some(TOPIC.into()),
            }],
            publish: Vec::new(),
            control: None,
        }
        .encode(),
    );
    for seed in 2..2 + PEER_COUNT {
        let peer = peer(seed);
        let stream_id = StreamId::new(u64::from(seed));
        agent.handle_event(
            &SwarmEvent::ConnectionEstablished {
                peer_id: peer.clone(),
                conn_id: ConnectionId::new(u64::from(seed)),
            },
            0,
        );
        agent.handle_event(
            &SwarmEvent::PeerReady {
                peer_id: peer.clone(),
                protocols: vec![FLOODSUB_PROTOCOL_ID.into()],
            },
            0,
        );
        assert!(agent.handle_event(
            &SwarmEvent::StreamReady {
                peer_id: peer.clone(),
                conn_id: ConnectionId::new(u64::from(seed)),
                stream_id,
                protocol_id: FLOODSUB_PROTOCOL_ID.into(),
                initiated_locally: false,
            },
            0,
        ));
        assert!(agent.handle_event(
            &SwarmEvent::StreamData {
                peer_id: peer,
                conn_id: ConnectionId::new(u64::from(seed)),
                stream_id,
                data: subscription.clone(),
            },
            0,
        ));
    }
    agent
}

fn assert_fanout(agent: &mut FloodsubAgent, payload: Vec<u8>) {
    agent.publish(TOPIC, payload, 0).expect("publish");
    let mut opens = 0;
    while let Some(action) = agent.poll_action() {
        if matches!(action, PubsubAction::OpenStream { .. }) {
            opens += 1;
        }
    }
    assert_eq!(opens, usize::from(PEER_COUNT));
}

fn fanout(c: &mut Criterion) {
    let payload = vec![0x5a; PAYLOAD_LEN];
    assert_fanout(&mut subscribed_agent(), payload.clone());

    c.bench_function("pubsub/floodsub_publish_32x60KiB", |b| {
        b.iter_batched(
            subscribed_agent,
            |mut agent| {
                let result = agent.publish(TOPIC, payload.clone(), 0);
                black_box(result).expect("publish");
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, fanout);
criterion_main!(benches);
