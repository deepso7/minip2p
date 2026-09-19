use gungraun::prelude::*;
use minip2p_pubsub::GossipsubAgent;
use std::hint::black_box;

#[path = "common.rs"]
mod common;
use common::{TOPIC, setup};

#[library_benchmark]
#[bench::gossipsub_publish_32x60_kib(setup())]
fn gossipsub_publish(input: (GossipsubAgent, Vec<u8>)) {
    let (mut agent, payload) = input;
    black_box(agent.publish(TOPIC, payload, 0)).expect("publish");
}

library_benchmark_group!(name = benches; benchmarks = gossipsub_publish);
gungraun::main!(library_benchmark_groups = benches);
