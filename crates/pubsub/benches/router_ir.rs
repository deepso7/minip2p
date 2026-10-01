//! Instruction counts for the `router` benches: forwarding to a mesh of N
//! peers and one heartbeat at 1,000 peers and 100 topics. Fixtures are built
//! in `setup` and outcomes asserted in `teardown`, both outside the count.

use gungraun::prelude::*;
use minip2p_pubsub::{GossipsubAction, GossipsubAgent};
use std::hint::black_box;

#[path = "common.rs"]
mod common;
use common::{
    Forward, assert_forwarded, assert_heartbeat_ran, forward, forward_fixture, heartbeat,
    heartbeat_fixture,
};

fn check_forwarded((fixture, actions): (Forward, Vec<GossipsubAction>)) {
    assert_forwarded(&fixture.recipients, actions);
}

#[library_benchmark]
#[bench::gossipsub_forward_1_kib_8(args = (8), setup = forward_fixture, teardown = check_forwarded)]
#[bench::gossipsub_forward_1_kib_32(args = (32), setup = forward_fixture, teardown = check_forwarded)]
#[bench::gossipsub_forward_1_kib_128(args = (128), setup = forward_fixture, teardown = check_forwarded)]
fn gossipsub_forward(mut fixture: Forward) -> (Forward, Vec<GossipsubAction>) {
    let actions = black_box(forward(&mut fixture.agent, &fixture.frame));
    // Returned so drops are not counted.
    (fixture, actions)
}

fn check_heartbeat(mut agent: GossipsubAgent) {
    assert_heartbeat_ran(&mut agent);
}

#[library_benchmark]
#[bench::gossipsub_heartbeat_1000_peers_100_topics(setup = heartbeat_fixture, teardown = check_heartbeat)]
fn gossipsub_heartbeat(mut agent: GossipsubAgent) -> GossipsubAgent {
    heartbeat(black_box(&mut agent));
    agent
}

library_benchmark_group!(name = benches; benchmarks = gossipsub_forward, gossipsub_heartbeat);
gungraun::main!(library_benchmark_groups = benches);
