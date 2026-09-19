use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use minip2p_pubsub::{GossipsubAction, GossipsubAgent};

#[path = "common.rs"]
mod common;
use common::{PEER_COUNT, TOPIC, setup};

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
    let (mut probe, payload) = setup();
    assert_mesh_publish(&mut probe, payload);

    c.bench_function("pubsub/gossipsub_publish_32x60KiB", |b| {
        b.iter_batched(
            setup,
            |(mut agent, payload)| {
                black_box(agent.publish(TOPIC, payload, 0)).expect("publish");
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, publish);
criterion_main!(benches);
