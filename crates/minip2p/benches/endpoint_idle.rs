//! Idle cost of an Endpoint with no peers: wait wakeups and CPU per second.
//!
//! Each variant binds an Endpoint, lets startup settle, then drives it with
//! [`Endpoint::wait`] for a fixed window, as an application event loop would.
//! It reports two informational rows per variant:
//!
//! - `wakeups_per_s`: waits that blocked and then woke, from the `bench`
//!   feature's counters in `minip2p_transport::bench`: the `TransportSet`'s
//!   one `poll(2)` over its members, or a lone member's own wait. A set that
//!   cannot use `poll(2)` takes turns on its members in short slices, and
//!   then every slice is counted. The output also breaks this down by outcome.
//! - `cpu_ms_per_s`: process user+sys CPU over the window per wall second.
//!
//! Variants:
//!
//! - `quic_only`: QUIC alone, no extra services. The reference row.
//! - `quic_dual_stack`: QUIC on IPv4 and IPv6 loopback: the same one-socket-
//!   per-family `DualQuicTransport` that `EndpointBuilder::listen_default()`
//!   binds on the wildcards. Skipped on a host without IPv6 loopback, where
//!   the results collector then reports its rows missing.
//! - `full`: QUIC and TCP bound, relay server, Gossipsub with one subscribed
//!   topic, and mDNS, all started.
//! - `full_no_mdns`: `full` without mDNS, so the rest is visible on its own.
//!
//! Expected periodic work: mDNS polls its sockets every
//! `MdnsConfig::socket_poll_interval_ms` (default 100 ms), which caps every
//! outer wait at that: about 10 `set_waits` a second. It also re-enumerates
//! interfaces every 10 s and may still be sending its exponentially spaced
//! startup queries during the window, so `full` wakes about ten times a second
//! more than `full_no_mdns`. Compare `full` with `full_no_mdns` for the mDNS
//! share, and `full_no_mdns` with `quic_only` for the second transport and the
//! other services.
//!
//! Rows go to `target/bench-results/custom/endpoint_idle.json` for the
//! `custom` collector in `scripts/bench_results.py`.

use std::time::{Duration, Instant};

use cpu_time::ProcessTime;
use minip2p::{Endpoint, EndpointEvent, EndpointWaitOutcome, PeerDiscoveryConfig};
use minip2p_transport::bench::{WaitCounters, wait_counters};

/// Startup work (listen, first mDNS probes, Gossipsub heartbeats) to skip.
const SETTLE: Duration = Duration::from_secs(2);
/// The measured idle window.
const WINDOW: Duration = Duration::from_secs(10);

#[derive(Clone, Copy)]
struct Variant {
    name: &'static str,
    ipv6: bool,
    tcp: bool,
    services: bool,
    mdns: bool,
}

const VARIANTS: [Variant; 4] = [
    Variant {
        name: "quic_only",
        ipv6: false,
        tcp: false,
        services: false,
        mdns: false,
    },
    Variant {
        name: "quic_dual_stack",
        ipv6: true,
        tcp: false,
        services: false,
        mdns: false,
    },
    Variant {
        name: "full",
        ipv6: false,
        tcp: true,
        services: true,
        mdns: true,
    },
    Variant {
        name: "full_no_mdns",
        ipv6: false,
        tcp: true,
        services: true,
        mdns: false,
    },
];

fn bind(variant: Variant) -> Endpoint {
    let mut builder = Endpoint::builder()
        .agent_version("minip2p-bench")
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address");
    if variant.ipv6 {
        builder = builder
            .listen_on("/ip6/::1/udp/0/quic-v1")
            .expect("ipv6 quic listen address");
    }
    if variant.tcp {
        builder = builder
            .listen_on("/ip4/127.0.0.1/tcp/0")
            .expect("tcp listen address");
    }
    if variant.services {
        builder = builder.relay_server().gossipsub();
    }
    if variant.mdns {
        // Nearby mDNS peers must not be dialed: the endpoint stays peerless.
        builder = builder
            .mdns()
            .peer_discovery_config(PeerDiscoveryConfig {
                auto_dial: false,
                ..PeerDiscoveryConfig::default()
            })
            .expect("peer discovery config");
    }
    let mut endpoint = builder.bind().expect("bind endpoint");
    endpoint.listen_all().expect("listen");
    if variant.services {
        endpoint.subscribe("minip2p-bench").expect("subscribe");
    }
    endpoint
}

/// Drives `endpoint` until `until`, dropping every event. A connection would
/// make the sample no longer idle, so it fails the bench instead.
fn drive(endpoint: &mut Endpoint, until: Instant) {
    loop {
        match endpoint.wait(until).expect("endpoint wait") {
            EndpointWaitOutcome::Event(event) => assert!(
                !matches!(event, EndpointEvent::ConnectionEstablished { .. }),
                "an idle endpoint connected: {event:?}"
            ),
            EndpointWaitOutcome::Interrupted => {}
            EndpointWaitOutcome::Deadline => return,
        }
    }
}

struct Measured {
    counters: WaitCounters,
    wall: Duration,
    cpu: Duration,
}

fn measure(variant: Variant) -> Measured {
    let mut endpoint = bind(variant);
    drive(&mut endpoint, Instant::now() + SETTLE);

    let counters = wait_counters();
    let cpu = ProcessTime::now();
    let started = Instant::now();
    drive(&mut endpoint, started + WINDOW);
    let measured = Measured {
        counters: wait_counters().since(&counters),
        wall: started.elapsed(),
        cpu: cpu.elapsed(),
    };
    endpoint.close().expect("close endpoint");
    measured
}

fn main() {
    let mut rows = Vec::new();
    for variant in VARIANTS {
        if variant.ipv6
            && let Err(error) = std::net::UdpSocket::bind("[::1]:0")
        {
            // The collector requires this variant's rows, so a skip still
            // fails a results run loudly; the reason is printed for it.
            println!(
                "endpoint_idle/{}: skipped, cannot bind IPv6 loopback: {error}",
                variant.name
            );
            continue;
        }
        let Measured {
            counters,
            wall,
            cpu,
        } = measure(variant);
        let seconds = wall.as_secs_f64();
        let wakeups_per_s = counters.wakeups() as f64 / seconds;
        let cpu_ms_per_s = cpu.as_secs_f64() * 1e3 / seconds;
        println!(
            "endpoint_idle/{}: {wakeups_per_s:.1} wakeups/s (ready {}, timed out {}, \
             interrupted {}; {} set waits, {} fallback sleeps over {seconds:.1} s), \
             {cpu_ms_per_s:.2} cpu ms/s",
            variant.name,
            counters.ready,
            counters.timed_out,
            counters.interrupted,
            counters.set_waits,
            counters.fallback_sleeps,
        );
        for (metric, value) in [
            ("wakeups_per_s", wakeups_per_s),
            ("cpu_ms_per_s", cpu_ms_per_s),
        ] {
            rows.push(format!(
                r#"{{"tier":"rust-wall","name":"endpoint_idle/{}","metric":"{metric}","value":{value}}}"#,
                variant.name
            ));
        }
    }

    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/bench-results/custom"
    );
    std::fs::create_dir_all(dir).expect("create custom results directory");
    std::fs::write(
        format!("{dir}/endpoint_idle.json"),
        format!("[{}]\n", rows.join(",")),
    )
    .expect("write custom rows");
}
