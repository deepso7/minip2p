//! Heap allocations per forwarded gossipsub message, for a mesh of N = 8, 32
//! and 128 peers (fixture in `common.rs`).
//!
//! `stats_alloc` is this binary's global allocator. Counting runs from handing
//! the inbound frame to the agent through draining its outbound actions;
//! building the fixture and dropping the results stay outside, while growing
//! the `Vec` the actions are drained into is counted. A reallocation
//! counts as one allocation, and only its growth counts toward bytes
//! allocated. These are allocations, not copies into existing buffers.
//!
//! The agent is deterministic, so each N is measured twice on fresh fixtures
//! and the counts must match. Rows go to
//! `target/bench-results/custom/gossipsub_forward_allocs.json` for the
//! `custom` collector in `scripts/bench_results.py`.

use std::alloc::System;

use stats_alloc::{INSTRUMENTED_SYSTEM, Stats, StatsAlloc};

#[path = "common.rs"]
mod common;
use common::{assert_forwarded, forward, forward_fixture};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

/// Allocations and bytes allocated while forwarding one message to a mesh of `n`.
fn forward_allocations(n: u16) -> (usize, usize) {
    let mut fixture = forward_fixture(n);
    let before: Stats = GLOBAL.stats();
    let actions = forward(&mut fixture.agent, &fixture.frame);
    let used = GLOBAL.stats() - before;
    assert_forwarded(&fixture.recipients, actions);
    (used.allocations + used.reallocations, used.bytes_allocated)
}

fn main() {
    let mut rows = Vec::new();
    for n in [8, 32, 128] {
        let (allocs, bytes) = forward_allocations(n);
        assert_eq!(forward_allocations(n), (allocs, bytes), "deterministic");
        let name = format!("pubsub/gossipsub_forward_1KiB/{n}");
        println!("{name}: {allocs} allocs/msg, {bytes} bytes allocated/msg");
        for (metric, value) in [
            ("allocs_per_msg", allocs),
            ("bytes_allocated_per_msg", bytes),
        ] {
            rows.push(format!(
                r#"{{"tier":"rust-micro","name":"{name}","metric":"{metric}","value":{value}}}"#
            ));
        }
    }

    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/bench-results/custom"
    );
    std::fs::create_dir_all(dir).expect("create custom results directory");
    std::fs::write(
        format!("{dir}/gossipsub_forward_allocs.json"),
        format!("[{}]\n", rows.join(",")),
    )
    .expect("write custom rows");
}
