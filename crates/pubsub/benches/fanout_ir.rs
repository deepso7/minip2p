use gungraun::prelude::*;
use minip2p_identity::Ed25519Keypair;
use minip2p_pubsub::{
    FLOODSUB_PROTOCOL_ID, FloodsubAgent, FloodsubConfig, Rpc, SubOpts, encode_frame,
};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{ConnectionId, StreamId};
use std::hint::black_box;

const PEER_COUNT: u8 = 32;
const PAYLOAD_LEN: usize = 60 * 1024;
const TOPIC: &str = "benchmark";

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
        let peer = Ed25519Keypair::from_secret_key_bytes([seed; 32]).peer_id();
        let conn_id = ConnectionId::new(u64::from(seed));
        let stream_id = StreamId::new(u64::from(seed));
        agent.handle_event(
            &SwarmEvent::ConnectionEstablished {
                peer_id: peer.clone(),
                conn_id,
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
                conn_id,
                stream_id,
                protocol_id: FLOODSUB_PROTOCOL_ID.into(),
                initiated_locally: false,
            },
            0
        ));
        assert!(agent.handle_event(
            &SwarmEvent::StreamData {
                peer_id: peer,
                conn_id,
                stream_id,
                data: subscription.clone(),
            },
            0
        ));
    }
    agent
}

fn setup() -> (FloodsubAgent, Vec<u8>) {
    (subscribed_agent(), vec![0x5a; PAYLOAD_LEN])
}

#[library_benchmark]
#[bench::floodsub_publish_32x60_kib(setup())]
fn floodsub_publish(input: (FloodsubAgent, Vec<u8>)) {
    let (mut agent, payload) = input;
    black_box(agent.publish(TOPIC, payload, 0)).expect("publish");
}

library_benchmark_group!(name = benches; benchmarks = floodsub_publish);
gungraun::main!(library_benchmark_groups = benches);
