//! Wall-clock cost of gossipsub routing work: forwarding one inbound message
//! to a mesh of N peers, and one heartbeat at a 1,000-peer, 100-topic
//! topology. Fixtures are described in `common.rs`.
//!
//! Every iteration measures a fresh fixture built outside the timed region,
//! because a reused agent grows its seen cache, message cache and event
//! queue, and repeated heartbeats shift the cache windows. Each iteration's
//! outcome is asserted after the timer stops.

use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{Criterion, SamplingMode, criterion_group, criterion_main};

#[path = "common.rs"]
mod common;
use common::{
    assert_forwarded, assert_heartbeat_ran, forward, forward_fixture, heartbeat, heartbeat_fixture,
};

/// Times `measure` over `iters` fresh fixtures from `setup`, checking each
/// result with `check` outside the timed region.
fn timed<F, R>(
    iters: u64,
    mut setup: impl FnMut() -> F,
    mut measure: impl FnMut(&mut F) -> R,
    mut check: impl FnMut(&mut F, R),
) -> Duration {
    let mut total = Duration::ZERO;
    for _ in 0..iters {
        let mut fixture = setup();
        let start = Instant::now();
        let result = black_box(measure(black_box(&mut fixture)));
        total += start.elapsed();
        check(&mut fixture, result);
    }
    total
}

fn forwarding(c: &mut Criterion) {
    let mut group = c.benchmark_group("pubsub/gossipsub_forward_1KiB");
    // Building a fixture costs several times the forward it feeds, and
    // Criterion sizes runs by measured time only, so shorten the runs.
    group
        .sample_size(50)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1));
    for n in [8, 32, 128] {
        group.bench_function(n.to_string(), |b| {
            b.iter_custom(|iters| {
                timed(
                    iters,
                    || forward_fixture(n),
                    |fixture| forward(&mut fixture.agent, &fixture.frame),
                    |fixture, actions| assert_forwarded(&fixture.recipients, actions),
                )
            });
        });
    }
    group.finish();
}

fn heartbeat_1k(c: &mut Criterion) {
    let mut group = c.benchmark_group("pubsub");
    // Building the fixture takes about 20x longer than the heartbeat runs, and
    // Criterion sizes runs by measured time only, so ask for about a second
    // of heartbeats in 10 equal samples.
    group
        .sampling_mode(SamplingMode::Flat)
        .sample_size(10)
        .warm_up_time(Duration::from_millis(100))
        .measurement_time(Duration::from_secs(1));
    group.bench_function("gossipsub_heartbeat_1000_peers_100_topics", |b| {
        b.iter_custom(|iters| {
            timed(iters, heartbeat_fixture, heartbeat, |agent, ()| {
                assert_heartbeat_ran(agent)
            })
        });
    });
    group.finish();
}

criterion_group!(benches, forwarding, heartbeat_1k);
criterion_main!(benches);
