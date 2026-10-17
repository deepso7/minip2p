//! Scripted housekeeping tests: AutoNAT confidence aggregation and relay
//! reservation lifecycle, with a fake clock and no I/O.

mod common;

use common::*;
use minip2p_swarm::ConnectionCloseReason;

use minip2p_autonat::{AUTONAT_PROTOCOL_ID, ResponseStatus};
use minip2p_core::{PeerAddr, PeerId};
use minip2p_nat::{
    Deadline, MAX_RESERVATION_RETRY_BACKOFF_MS, NatConfig, NatEvent, NatSwarm, Now,
    ReachabilityState, ReservationPolicy,
};
use minip2p_relay::{HOP_PROTOCOL_ID, Status};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{Bytes, ConnectionId, StreamId, TransportError};

const SERVER_ADDR: &str = "/ip4/203.0.113.50/udp/4001/quic-v1";
const RELAY2_TRANSPORT_ADDR: &str = "/ip4/203.0.113.2/udp/4001/quic-v1";

struct Hk {
    agent: Node,
    relay: PeerId,
    relay2: PeerId,
    server: PeerId,
    server2: PeerId,
    /// Every configured AutoNAT server, `server` and `server2` first.
    servers: Vec<PeerId>,
}

/// How a scripted AutoNAT server answers a probe.
enum Answer<'a> {
    Public(&'a [minip2p_core::Multiaddr]),
    DialError,
    DialRefused,
}

/// The `index`th AutoNAT server's peer id and transport address.
fn autonat_server(index: usize) -> (PeerId, String) {
    let peer_id = match index {
        0 => peer(b"autonat-server"),
        1 => peer(b"autonat-server-2"),
        _ => peer(format!("autonat-server-{}", index + 1).as_bytes()),
    };
    (
        peer_id,
        format!("/ip4/203.0.113.{}/udp/4001/quic-v1", 50 + index),
    )
}

fn build(policy: ReservationPolicy, relay_count: usize, server_count: usize) -> Hk {
    build_with_config(policy, relay_count, server_count, |_| {})
}

fn build_with_config(
    policy: ReservationPolicy,
    relay_count: usize,
    server_count: usize,
    configure: impl FnOnce(&mut NatConfig),
) -> Hk {
    let relay = peer(b"relay-peer");
    let relay2 = peer(b"relay-peer-2");
    let servers: Vec<PeerId> = (0..server_count)
        .map(|index| autonat_server(index).0)
        .collect();
    let (server, server2) = (autonat_server(0).0, autonat_server(1).0);

    let mut relays = Vec::new();
    if relay_count >= 1 {
        relays.push(
            PeerAddr::new(maddr(RELAY_TRANSPORT_ADDR), relay.clone())
                .expect("valid relay peer address"),
        );
    }
    if relay_count >= 2 {
        relays.push(
            PeerAddr::new(maddr(RELAY2_TRANSPORT_ADDR), relay2.clone())
                .expect("valid second relay peer address"),
        );
    }
    let autonat_servers = (0..server_count)
        .map(|index| {
            let (peer_id, addr) = autonat_server(index);
            PeerAddr::new(maddr(&addr), peer_id).expect("valid AutoNAT server peer address")
        })
        .collect();

    let mut config = NatConfig {
        reservation_policy: policy,
        relays,
        autonat_servers,
        ..NatConfig::default()
    };
    configure(&mut config);
    let mut agent = Node::new(peer(b"local-peer"), config);
    agent.set_listen_addrs(&[maddr(LISTEN_ADDR)]);
    Hk {
        agent,
        relay,
        relay2,
        server,
        server2,
        servers,
    }
}

impl Hk {
    /// Connection established + PeerReady advertising `protocols`.
    fn session_ready(&mut self, peer: &PeerId, protocols: &[&str], now: Now) {
        self.agent.handle_event(
            &SwarmEvent::ConnectionEstablished {
                conn_id: minip2p_transport::ConnectionId::new(1),
                peer_id: peer.clone(),
            },
            false,
            now,
        );
        self.agent.handle_event(
            &SwarmEvent::PeerReady {
                peer_id: peer.clone(),
                conn_id: ConnectionId::new(1),
                protocols: protocols.iter().map(|p| p.to_string()).collect(),
            },
            false,
            now,
        );
    }

    fn stream_ready(&mut self, peer: &PeerId, stream: StreamId, protocol: &str, now: Now) {
        self.agent.handle_event(
            &SwarmEvent::StreamReady {
                conn_id: minip2p_transport::ConnectionId::new(1),
                peer_id: peer.clone(),
                stream_id: stream,
                protocol_id: protocol.to_string(),
                initiated_locally: true,
            },
            false,
            now,
        );
    }

    fn stream_data(&mut self, peer: &PeerId, stream: StreamId, data: Vec<u8>, now: Now) {
        self.agent.handle_event(
            &SwarmEvent::StreamData {
                conn_id: minip2p_transport::ConnectionId::new(1),
                peer_id: peer.clone(),
                stream_id: stream,
                data: Bytes::from(data),
            },
            false,
            now,
        );
    }

    /// Completes a probe exchange whose `OpenStream` is already queued.
    /// Responds public or private and returns the events it produced.
    fn finish_probe_with_addrs(
        &mut self,
        public_addrs: Option<&[minip2p_core::Multiaddr]>,
        t: u64,
    ) -> Vec<NatEvent> {
        let server = self.server.clone();
        let stream = opened_stream_for(&drain_actions(&mut self.agent), &server);
        self.stream_ready(&server.clone(), stream, AUTONAT_PROTOCOL_ID, at(t + 1));
        let actions = drain_actions(&mut self.agent);
        let request = sent_data_on(&actions, stream);
        let response = autonat_response(&request, public_addrs);
        self.stream_data(&server, stream, response, at(t + 2));
        drain_events(&mut self.agent)
    }

    fn finish_probe(&mut self, public: bool, t: u64) -> Vec<NatEvent> {
        let public_addrs = [maddr(LISTEN_ADDR)];
        self.finish_probe_with_addrs(public.then_some(&public_addrs), t)
    }

    /// Ticks at `t` to start the next probe, connecting its server first if
    /// the probe dials it, and answers with `answer`. Returns the server the
    /// probe went to and the events the answer produced.
    fn probe(&mut self, answer: Answer<'_>, t: u64) -> (PeerId, Vec<NatEvent>) {
        self.probe_taking(answer, t, 2)
    }

    /// [`Self::probe`], answered `span` ms after the tick.
    fn probe_taking(&mut self, answer: Answer<'_>, t: u64, span: u64) -> (PeerId, Vec<NatEvent>) {
        self.agent.handle_tick(at(t));
        let mut actions = drain_actions(&mut self.agent);
        let dialed = self
            .servers
            .iter()
            .find(|server| dial_count_for(&actions, server) == 1)
            .cloned();
        if let Some(server) = dialed {
            self.session_ready(&server, &[AUTONAT_PROTOCOL_ID], at(t));
            actions.extend(drain_actions(&mut self.agent));
        }
        let (server, stream) = actions
            .iter()
            .find_map(|action| match action {
                Out::OpenStream {
                    peer,
                    protocol_id,
                    opened: Some((_, stream)),
                } if protocol_id == AUTONAT_PROTOCOL_ID => Some((peer.clone(), *stream)),
                _ => None,
            })
            .expect("the tick starts a probe");
        self.stream_ready(&server, stream, AUTONAT_PROTOCOL_ID, at(t + span.min(1)));
        let request = sent_data_on(&drain_actions(&mut self.agent), stream);
        let response = match answer {
            Answer::Public(addrs) => autonat_response(&request, Some(addrs)),
            Answer::DialError => autonat_response(&request, None),
            Answer::DialRefused => autonat_error_response(&request, ResponseStatus::DialRefused),
        };
        self.stream_data(&server, stream, response, at(t + span));
        (server, drain_events(&mut self.agent))
    }

    /// Completes a reservation exchange whose `OpenStream` is already
    /// queued, feeding `response`. Returns (events, stream id).
    fn finish_reserve(&mut self, response: Vec<u8>, now: Now) -> (Vec<NatEvent>, StreamId) {
        let relay = self.relay_for_current();
        let stream = opened_stream_for(&drain_actions(&mut self.agent), &relay);
        self.stream_ready(&relay.clone(), stream, HOP_PROTOCOL_ID, now);
        let actions = drain_actions(&mut self.agent);
        let _request = sent_data_on(&actions, stream);
        self.stream_data(&relay, stream, response, now);
        (drain_events(&mut self.agent), stream)
    }

    fn relay_for_current(&self) -> PeerId {
        // Tests drive one relay at a time; the current one is whichever has
        // a queued OpenStream. Defaults to the primary relay.
        self.relay.clone()
    }
}

// ---------------------------------------------------------------------------
// Reachability confidence
// ---------------------------------------------------------------------------

#[test]
fn initial_reservation_policy_arms_only_the_needed_tick() {
    let mut wanted = build(ReservationPolicy::Always, 1, 0);
    assert_eq!(wanted.agent.next_deadline(at(0)), Some(Deadline::IMMEDIATE));
    wanted.agent.handle_tick(at(0));
    let relay = wanted.relay.clone();
    assert_eq!(dial_count_for(&drain_actions(&mut wanted.agent), &relay), 1);

    let not_wanted = build(ReservationPolicy::Never, 1, 0);
    assert_eq!(not_wanted.agent.next_deadline(at(0)), None);
}

#[test]
fn confidence_window_flips_once_and_never_flaps_on_one_probe() {
    let mut hk = build(ReservationPolicy::Never, 0, 3);
    assert_eq!(hk.agent.reachability(), ReachabilityState::Unknown);
    let public = [maddr(LISTEN_ADDR)];

    // Unsettled cadence is 5s; each probe asks the next server.
    let (_, events) = hk.probe(Answer::Public(&public), 0);
    assert!(events.is_empty(), "1 vote of 3: no flip");
    assert_eq!(hk.agent.reachability(), ReachabilityState::Unknown);
    let (_, events) = hk.probe(Answer::Public(&public), 6_000);
    assert!(events.is_empty(), "2 votes of 3: no flip");

    let (_, events) = hk.probe(Answer::Public(&public), 12_000);
    assert!(matches!(
        events.as_slice(),
        [NatEvent::ReachabilityChanged {
            old: ReachabilityState::Unknown,
            new: ReachabilityState::Public,
            confirmed_addrs,
        }] if *confirmed_addrs == vec![maddr(LISTEN_ADDR)]
    ));
    assert_eq!(hk.agent.reachability(), ReachabilityState::Public);

    // Settled cadence is 90s; more agreement changes nothing.
    assert!(hk.probe(Answer::Public(&public), 110_000).1.is_empty());

    // One disagreeing server must never flap the verdict.
    let (_, events) = hk.probe(Answer::DialError, 210_000);
    assert!(
        events.is_empty(),
        "single private vote among public ones: no flip"
    );
    assert_eq!(hk.agent.reachability(), ReachabilityState::Public);

    // Three servers voting private flip it exactly once.
    assert!(hk.probe(Answer::DialError, 310_000).1.is_empty());
    let (_, events) = hk.probe(Answer::DialError, 410_000);
    assert!(matches!(
        events.as_slice(),
        [NatEvent::ReachabilityChanged {
            old: ReachabilityState::Public,
            new: ReachabilityState::Private,
            confirmed_addrs,
        }] if confirmed_addrs.is_empty()
    ));
    assert_eq!(hk.agent.reachability(), ReachabilityState::Private);
}

#[test]
fn confidence_threshold_above_window_clamps_to_unanimity() {
    let mut hk = build_with_config(ReservationPolicy::Never, 0, 3, |config| {
        config.confidence_window = 3;
        config.confidence_threshold = 9;
    });

    // A full (three-server) unanimous window. An unclamped threshold could
    // never settle here.
    let public = [maddr(LISTEN_ADDR)];
    assert!(hk.probe(Answer::Public(&public), 0).1.is_empty());
    assert!(hk.probe(Answer::Public(&public), 6_000).1.is_empty());

    let (_, events) = hk.probe(Answer::Public(&public), 12_000);
    assert!(matches!(
        events.as_slice(),
        [NatEvent::ReachabilityChanged {
            old: ReachabilityState::Unknown,
            new: ReachabilityState::Public,
            ..
        }]
    ));
}

#[test]
fn public_probe_without_a_usable_quic_addr_is_inconclusive() {
    let mut hk = build_with_config(ReservationPolicy::WhenPrivate, 1, 1, |config| {
        config.confidence_window = 1;
        config.confidence_threshold = 1;
    });
    // We ask about a wildcard listen address too, so the server may name it.
    let wildcard = maddr("/ip4/0.0.0.0/udp/4001/quic-v1");
    hk.agent
        .set_listen_addrs(&[maddr(LISTEN_ADDR), wildcard.clone()]);

    // Establish both housekeeping sessions, then hold a relay reservation
    // while reachability is still Unknown.
    hk.agent.handle_tick(at(0));
    let actions = drain_actions(&mut hk.agent);
    assert_eq!(dial_count_for(&actions, &hk.relay), 1);
    assert_eq!(dial_count_for(&actions, &hk.server), 1);
    let relay = hk.relay.clone();
    hk.session_ready(&relay, &[HOP_PROTOCOL_ID], at(2));
    let (events, _) = hk.finish_reserve(hop_reserve_ok(None), at(3));
    assert!(matches!(
        events.as_slice(),
        [NatEvent::RelayReserved { .. }]
    ));
    assert!(hk.agent.active_reservation().is_some());

    let server = hk.server.clone();
    hk.session_ready(&server, &[AUTONAT_PROTOCOL_ID], at(4));
    let events = hk.finish_probe_with_addrs(Some(&[wildcard]), 5);

    assert!(
        events.is_empty(),
        "unusable public evidence is inconclusive"
    );
    assert_eq!(hk.agent.reachability(), ReachabilityState::Unknown);
    assert!(
        hk.agent.active_reservation().is_some(),
        "WhenPrivate must retain its only advertised path"
    );
}

#[test]
fn one_server_answering_repeatedly_casts_a_single_vote() {
    let mut hk = build(ReservationPolicy::Never, 0, 1);
    let public = [maddr(LISTEN_ADDR)];
    for round in 0..5 {
        let (server, events) = hk.probe(Answer::Public(&public), round * 6_000);
        assert_eq!(server, hk.server);
        assert!(events.is_empty(), "round {round}: {events:?}");
    }
    assert_eq!(hk.agent.reachability(), ReachabilityState::Unknown);
}

#[test]
fn a_quorum_of_distinct_servers_confirms_each_address() {
    let mut hk = build(ReservationPolicy::Never, 0, 3);
    let (a, b) = (maddr(LISTEN_ADDR), maddr(OUR_OBSERVED_ADDR));
    hk.agent.set_listen_addrs(&[a.clone(), b.clone()]);

    // Probes rotate across the servers after every completed exchange.
    let (first, events) = hk.probe(Answer::Public(std::slice::from_ref(&a)), 0);
    assert!(events.is_empty());
    let (second, events) = hk.probe(Answer::Public(&[a.clone(), b.clone()]), 6_000);
    assert!(events.is_empty());
    let (third, events) = hk.probe(Answer::Public(std::slice::from_ref(&a)), 12_000);
    assert_eq!([first, second, third], hk.servers[..]);

    // Three servers vouch for `a`, only one for `b`.
    assert!(
        matches!(
            events.as_slice(),
            [NatEvent::ReachabilityChanged {
                old: ReachabilityState::Unknown,
                new: ReachabilityState::Public,
                confirmed_addrs,
            }] if *confirmed_addrs == vec![a.clone()]
        ),
        "{events:?}"
    );
}

#[test]
fn unrelated_returned_addresses_are_ignored() {
    let mut hk = build(ReservationPolicy::Never, 0, 3);
    let unrelated = [maddr(OUR_OBSERVED_ADDR)];
    for round in 0..3 {
        let (_, events) = hk.probe(Answer::Public(&unrelated), round * 6_000);
        assert!(events.is_empty(), "{events:?}");
    }
    assert_eq!(hk.agent.reachability(), ReachabilityState::Unknown);
}

#[test]
fn servers_dialing_back_our_observed_ip_confirm_the_listen_port_there() {
    // rust-libp2p and go-libp2p servers dial back the requested transport
    // and port at the IP they observe, so the probe must ask about our
    // listen port at that IP; the observed port (often ephemeral) is not it.
    let cases = [
        (
            "/ip4/10.0.0.2/tcp/4001",
            "/ip4/203.0.113.77/tcp/51234",
            "/ip4/203.0.113.77/tcp/4001",
        ),
        (
            LISTEN_ADDR,
            OUR_OBSERVED_ADDR,
            "/ip4/203.0.113.77/udp/4500/quic-v1",
        ),
    ];
    for (listen, observed, dialed_back) in cases {
        let mut hk = build(ReservationPolicy::Never, 0, 3);
        hk.agent.set_listen_addrs(&[maddr(listen)]);
        for server in hk.servers.clone() {
            identify_observed(&mut hk.agent, &server, &maddr(observed), at(0));
        }
        let public = [maddr(dialed_back)];
        let mut events = Vec::new();
        for round in 0..3 {
            events = hk.probe(Answer::Public(&public), round * 6_000).1;
        }
        assert!(
            matches!(
                events.as_slice(),
                [NatEvent::ReachabilityChanged {
                    new: ReachabilityState::Public,
                    confirmed_addrs,
                    ..
                }] if *confirmed_addrs == public
            ),
            "{listen}: {events:?}"
        );
    }
}

#[test]
fn a_dual_stack_reporter_contributes_its_ipv4_and_ipv6_observations() {
    let mut hk = build(ReservationPolicy::Never, 0, 3);
    hk.agent.set_listen_addrs(&[
        maddr("/ip4/10.0.0.2/tcp/4001"),
        maddr("/ip6/fd00::2/tcp/4001"),
    ]);
    for server in hk.servers.clone() {
        identify_observed(
            &mut hk.agent,
            &server,
            &maddr("/ip4/203.0.113.77/tcp/51234"),
            at(0),
        );
        identify_observed(
            &mut hk.agent,
            &server,
            &maddr("/ip6/2001:db8::77/tcp/51235"),
            at(0),
        );
    }
    let public = [
        maddr("/ip4/203.0.113.77/tcp/4001"),
        maddr("/ip6/2001:db8::77/tcp/4001"),
    ];
    let mut events = Vec::new();
    for round in 0..3 {
        events = hk.probe(Answer::Public(&public), round * 6_000).1;
    }
    assert!(
        matches!(
            events.as_slice(),
            [NatEvent::ReachabilityChanged {
                new: ReachabilityState::Public,
                confirmed_addrs,
                ..
            }] if *confirmed_addrs == public
        ),
        "{events:?}"
    );
}

#[test]
fn dial_refused_is_never_a_private_vote() {
    let mut hk = build(ReservationPolicy::Never, 0, 3);
    for round in 0..3 {
        let (_, events) = hk.probe(Answer::DialRefused, round * 6_000);
        assert!(events.is_empty(), "{events:?}");
    }
    assert_eq!(hk.agent.reachability(), ReachabilityState::Unknown);

    // A failed dial-back is still a private vote.
    for round in 3..5 {
        assert!(hk.probe(Answer::DialError, round * 6_000).1.is_empty());
    }
    let (_, events) = hk.probe(Answer::DialError, 30_000);
    assert!(
        matches!(
            events.as_slice(),
            [NatEvent::ReachabilityChanged {
                new: ReachabilityState::Private,
                ..
            }]
        ),
        "{events:?}"
    );
}

#[test]
fn votes_expire_after_fifteen_minutes() {
    let mut hk = build(ReservationPolicy::Never, 0, 3);
    let public = [maddr(LISTEN_ADDR)];
    assert!(hk.probe(Answer::Public(&public), 0).1.is_empty());
    assert!(hk.probe(Answer::Public(&public), 10_000).1.is_empty());

    // The first server's vote (cast at 2ms) is over 15 minutes old by the
    // third: two live votes are no quorum.
    let (_, events) = hk.probe(Answer::Public(&public), 900_001);
    assert!(events.is_empty(), "{events:?}");
    assert_eq!(hk.agent.reachability(), ReachabilityState::Unknown);

    // The first server votes again: three live votes.
    let (_, events) = hk.probe(Answer::Public(&public), 906_000);
    assert!(
        matches!(
            events.as_slice(),
            [NatEvent::ReachabilityChanged {
                new: ReachabilityState::Public,
                ..
            }]
        ),
        "{events:?}"
    );
}

#[test]
fn a_settled_verdict_lapses_to_unknown_once_its_votes_expire() {
    let mut hk = build(ReservationPolicy::Never, 0, 3);
    let public = [maddr(LISTEN_ADDR)];
    assert!(hk.probe(Answer::Public(&public), 0).1.is_empty());
    assert!(hk.probe(Answer::Public(&public), 6_000).1.is_empty());
    assert_eq!(hk.probe(Answer::Public(&public), 12_000).1.len(), 1);
    assert_eq!(hk.agent.reachability(), ReachabilityState::Public);

    // Every server only refuses from now on. Once the first vote (cast at
    // 2ms) is 15 minutes old, two live votes are too few to stand on.
    let mut changes = Vec::new();
    for round in 1..=10 {
        changes.extend(hk.probe(Answer::DialRefused, 12_000 + round * 90_100).1);
    }
    assert!(
        matches!(
            changes.as_slice(),
            [NatEvent::ReachabilityChanged {
                old: ReachabilityState::Public,
                new: ReachabilityState::Unknown,
                confirmed_addrs,
            }] if confirmed_addrs.is_empty()
        ),
        "{changes:?}"
    );
}

#[test]
fn a_confirmed_address_needs_a_quorum_to_be_withdrawn() {
    let mut hk = build(ReservationPolicy::Never, 0, 3);
    let (a, b) = (maddr(LISTEN_ADDR), maddr(OUR_OBSERVED_ADDR));
    hk.agent.set_listen_addrs(&[a.clone(), b.clone()]);
    let both = [a.clone(), b.clone()];
    assert!(hk.probe(Answer::Public(&both), 0).1.is_empty());
    assert!(hk.probe(Answer::Public(&both), 6_000).1.is_empty());
    let (_, events) = hk.probe(Answer::Public(&both), 12_000);
    assert!(
        matches!(
            events.as_slice(),
            [NatEvent::ReachabilityChanged { confirmed_addrs, .. }]
                if *confirmed_addrs == both
        ),
        "{events:?}"
    );

    // One, then two servers leave `b` out: it stays advertised.
    let only_a = std::slice::from_ref(&a);
    assert!(hk.probe(Answer::Public(only_a), 17_100).1.is_empty());
    assert!(hk.probe(Answer::Public(only_a), 107_200).1.is_empty());
    // The third makes a quorum without it.
    let (_, events) = hk.probe(Answer::Public(only_a), 197_300);
    assert!(
        matches!(
            events.as_slice(),
            [NatEvent::PublicAddressesChanged { addrs }] if *addrs == vec![a.clone()]
        ),
        "{events:?}"
    );

    // Likewise a quorum of private votes, not one, ends the verdict.
    assert!(hk.probe(Answer::DialError, 287_400).1.is_empty());
    assert!(hk.probe(Answer::DialError, 377_500).1.is_empty());
    let (_, events) = hk.probe(Answer::DialError, 467_600);
    assert!(
        matches!(
            events.as_slice(),
            [NatEvent::ReachabilityChanged {
                new: ReachabilityState::Private,
                ..
            }]
        ),
        "{events:?}"
    );
}

#[test]
fn a_settled_verdict_wakes_the_host_when_its_votes_expire() {
    let mut hk = build_with_config(ReservationPolicy::Never, 0, 3, |config| {
        config.probe_interval_settled_ms = 3_600_000;
    });
    let public = [maddr(LISTEN_ADDR)];
    assert!(hk.probe(Answer::Public(&public), 0).1.is_empty());
    assert!(hk.probe(Answer::Public(&public), 6_000).1.is_empty());
    assert_eq!(hk.probe(Answer::Public(&public), 12_000).1.len(), 1);
    // The probe after the flip is the last for an hour.
    assert!(hk.probe(Answer::Public(&public), 17_002).1.is_empty());
    drain_actions(&mut hk.agent);
    // The oldest live vote, cast at 6_002ms, expires long before then.
    assert_eq!(
        hk.agent.next_deadline(at(20_000)),
        Some(Deadline::from_millis(906_002))
    );
    hk.agent.handle_tick(at(906_002));
    assert!(matches!(
        drain_events(&mut hk.agent).as_slice(),
        [NatEvent::ReachabilityChanged {
            new: ReachabilityState::Unknown,
            ..
        }]
    ));
    // Back to Unknown, it probes again at the unsettled cadence.
    assert_eq!(
        hk.agent.next_deadline(at(906_002)),
        Some(Deadline::from_millis(911_002))
    );
}

#[test]
fn the_window_keeps_the_latest_servers_even_at_one_instant() {
    let mut hk = build_with_config(ReservationPolicy::Never, 0, 6, |config| {
        config.probe_interval_unsettled_ms = 0;
        config.probe_interval_settled_ms = 0;
    });
    let public = [maddr(LISTEN_ADDR)];
    // Every answer lands at 0ms. The first server's is inconclusive, so it
    // votes last.
    assert!(hk.probe_taking(Answer::DialRefused, 0, 0).1.is_empty());
    let mut events = Vec::new();
    for _ in 0..3 {
        events.extend(hk.probe_taking(Answer::DialError, 0, 0).1);
    }
    assert_eq!(hk.agent.reachability(), ReachabilityState::Private);
    for _ in 0..3 {
        events.extend(hk.probe_taking(Answer::Public(&public), 0, 0).1);
    }
    // The sixth vote pushes out the first private one, not itself: the
    // latest five servers hold three public votes.
    assert_eq!(
        hk.agent.reachability(),
        ReachabilityState::Public,
        "{events:?}"
    );
}

#[test]
fn probe_timeout_rotates_to_the_next_server() {
    let mut hk = build(ReservationPolicy::Never, 0, 2);

    hk.agent.handle_tick(at(0));
    drain_actions(&mut hk.agent);
    let server = hk.server.clone();
    hk.session_ready(&server, &[AUTONAT_PROTOCOL_ID], at(2));
    let stream = opened_stream_for(&drain_actions(&mut hk.agent), &server);
    hk.stream_ready(&server.clone(), stream, AUTONAT_PROTOCOL_ID, at(4));
    drain_actions(&mut hk.agent);

    // The server never answers: the probe deadline (20s) aborts the flight.
    hk.agent.handle_tick(at(20_004));
    let actions = drain_actions(&mut hk.agent);
    assert!(
        has_reset_for(&actions, stream),
        "stalled probe stream reset"
    );
    assert!(drain_events(&mut hk.agent).is_empty(), "no sample recorded");

    // The retry goes to the *other* server.
    hk.agent.handle_tick(at(25_004));
    let actions = drain_actions(&mut hk.agent);
    assert_eq!(dial_count_for(&actions, &hk.server2), 1);
    assert_eq!(dial_count_for(&actions, &hk.server), 0);
}

// ---------------------------------------------------------------------------
// Reservation lifecycle
// ---------------------------------------------------------------------------

/// Feeds an asynchronous `DialFailed` for the relay dial on `conn_id`.
fn dial_failed(hk: &mut Hk, conn_id: ConnectionId, reason: &str, now: Now) -> bool {
    let addr = PeerAddr::new(maddr(RELAY_TRANSPORT_ADDR), hk.relay.clone()).expect("relay addr");
    hk.agent.handle_event(
        &SwarmEvent::DialFailed {
            conn_id,
            addr,
            reason: reason.into(),
        },
        false,
        now,
    )
}

/// Bootstraps the relay session and completes the first reservation.
fn reserve_via_relay(hk: &mut Hk, response: Vec<u8>, now: Now) -> (Vec<NatEvent>, StreamId) {
    hk.agent.handle_tick(now);
    let actions = drain_actions(&mut hk.agent);
    assert_eq!(dial_count_for(&actions, &hk.relay), 1);
    let relay = hk.relay.clone();
    hk.session_ready(&relay, &[HOP_PROTOCOL_ID], now);
    hk.finish_reserve(response, now)
}

/// The `renew_at_mono_ms` of the single `RelayReserved` event in `events`.
fn reserved_renew_at(events: &[NatEvent]) -> u64 {
    assert_eq!(
        events.len(),
        1,
        "expected one RelayReserved, got {events:?}"
    );
    events
        .iter()
        .find_map(|event| match event {
            NatEvent::RelayReserved {
                renew_at_mono_ms, ..
            } => Some(*renew_at_mono_ms),
            _ => None,
        })
        .expect("a RelayReserved event")
}

/// Reserves with the relay reporting `expire` while our clock reads unix 1000
/// at mono 10, returning the scheduled renewal.
fn renew_at_for_expire(expire: Option<u64>) -> u64 {
    let mut hk = build_with_config(ReservationPolicy::Always, 1, 0, |config| {
        config.reservation_keep_alive_interval_ms = 0;
    });
    let (events, _) = reserve_via_relay(&mut hk, hop_reserve_ok(expire), at_unix(10, 1_000));
    reserved_renew_at(&events)
}

#[test]
fn reservation_renews_at_half_the_reported_lifetime() {
    let mut hk = build_with_config(ReservationPolicy::Always, 1, 0, |config| {
        config.reservation_keep_alive_interval_ms = 0;
    });

    // Relay reports expiry at unix 1900; the clock says unix 1000 at mono 10.
    let (events, _) = reserve_via_relay(&mut hk, hop_reserve_ok(Some(1_900)), at_unix(10, 1_000));
    // Half of the remaining 900s after mono 10.
    let expected_renew = 10 + 450 * 1_000;
    assert!(matches!(
        events.as_slice(),
        [NatEvent::RelayReserved {
            expires_unix_secs: Some(1_900),
            renew_at_mono_ms,
            ..
        }] if *renew_at_mono_ms == expected_renew
    ));
    let info = hk.agent.active_reservation().expect("reservation held");
    assert_eq!(info.renew_at_mono_ms, expected_renew);
    assert_eq!(
        hk.agent.next_deadline(at(10_000)),
        Some(Deadline::from_millis(expected_renew))
    );
    // The completed exchange closes its write side; drain it.
    drain_actions(&mut hk.agent);

    // Too early: nothing happens.
    hk.agent.handle_tick(at_unix(expected_renew - 1, 1_449));
    assert!(drain_actions(&mut hk.agent).is_empty());

    // At renew time a fresh RESERVE goes out on the still-ready session.
    hk.agent.handle_tick(at_unix(expected_renew, 1_450));
    let (events, _) = hk.finish_reserve(
        hop_reserve_ok(Some(2_350)),
        at_unix(expected_renew + 5, 1_450),
    );
    assert!(matches!(
        events.as_slice(),
        [NatEvent::RelayReserved {
            expires_unix_secs: Some(2_350),
            ..
        }]
    ));
}

#[test]
fn an_expiry_already_past_falls_back_to_the_default_ttl() {
    // The relay reports an expiry 500s in the past: a stale value, or a clock
    // skewed far enough that the remaining lifetime reads as gone. Taken at
    // face value, renewal would fire at once and report the same stale expiry
    // again, for as long as the reservation is held.
    assert_eq!(renew_at_for_expire(Some(500)), 10 + 1_800 * 1_000);
    // An expiry of exactly now leaves no lifetime either.
    assert_eq!(renew_at_for_expire(Some(1_000)), 10 + 1_800 * 1_000);
}

#[test]
fn a_one_second_reservation_renews_before_it_expires() {
    // Relays may grant a 1s TTL. Renewal must land strictly inside it, and a
    // second apart would be at expiry, after the relay already dropped it.
    assert_eq!(renew_at_for_expire(Some(1_001)), 10 + 500);
    assert_eq!(renew_at_for_expire(Some(1_003)), 10 + 1_500);
}

#[test]
fn a_lifetime_just_past_the_old_margin_does_not_renew_every_second() {
    // 121s against the former fixed 120s margin renewed after 1s, and each
    // renewal was granted 121s again: a RESERVE per second, indefinitely.
    assert_eq!(renew_at_for_expire(Some(1_121)), 10 + 60_500);
}

#[test]
fn renewal_lands_before_expiry_despite_a_relay_clock_ahead_of_ours() {
    // The relay grants 600s, but its clock runs 200s ahead, so its absolute
    // `expire` reads as 800s from our now. Renewing a fixed 120s before the
    // reported expiry would fire at 680s, 80s after the reservation is gone.
    let renew_at = renew_at_for_expire(Some(1_800));
    assert_eq!(renew_at, 10 + 400 * 1_000);
    assert!(renew_at < 10 + 600 * 1_000);
}

#[test]
fn an_expiry_beyond_the_default_ttl_is_clamped_to_it() {
    let mut hk = build(ReservationPolicy::Always, 1, 0);
    let (events, _) = reserve_via_relay(&mut hk, hop_reserve_ok(Some(u64::MAX)), at_unix(10, 0));

    // Trusting the relay's expiry saturates the deadline, so renewal never
    // fires: the relay drops the reservation on its own TTL while the
    // connection stays up, no `RelayReservationLost` is emitted, and the
    // holder keeps advertising a ticket dialers get NO_RESERVATION on.
    let expected_renew = 10 + 1_800 * 1_000;
    assert_eq!(reserved_renew_at(&events), expected_renew);
    assert_eq!(
        hk.agent
            .active_reservation()
            .expect("reservation held")
            .renew_at_mono_ms,
        expected_renew
    );
}

#[test]
fn reservation_without_expire_uses_default_ttl() {
    let mut hk = build(ReservationPolicy::Always, 1, 0);
    let (events, _) = reserve_via_relay(&mut hk, hop_reserve_ok(None), at_unix(10, 1_000));
    // Half the 3600s default TTL.
    let expected_renew = 10 + 1_800 * 1_000;
    assert!(matches!(
        events.as_slice(),
        [NatEvent::RelayReserved {
            expires_unix_secs: None,
            renew_at_mono_ms,
            ..
        }] if *renew_at_mono_ms == expected_renew
    ));
}

#[test]
fn reservation_on_clockless_host_uses_default_ttl() {
    let mut hk = build(ReservationPolicy::Always, 1, 0);
    // The relay reports an expiry, but we have no wall clock to compare.
    let (events, _) = reserve_via_relay(&mut hk, hop_reserve_ok(Some(1_900)), at(10));
    let expected_renew = 10 + 1_800 * 1_000;
    assert!(matches!(
        events.as_slice(),
        [NatEvent::RelayReserved {
            expires_unix_secs: Some(1_900),
            renew_at_mono_ms,
            ..
        }] if *renew_at_mono_ms == expected_renew
    ));
}

#[test]
fn reservation_keep_alive_uses_synthetic_time_only_for_quic() {
    let mut quic = build_with_config(ReservationPolicy::Always, 1, 0, |config| {
        config.reservation_keep_alive_interval_ms = 100;
    });
    reserve_via_relay(&mut quic, hop_reserve_ok(None), at(10));
    drain_actions(&mut quic.agent); // completed exchange's close-write

    assert_eq!(
        quic.agent.next_deadline(at(10)),
        Some(Deadline::from_millis(110))
    );
    quic.agent.handle_tick(at(109));
    assert!(drain_actions(&mut quic.agent).is_empty());
    quic.agent.handle_tick(at(110));
    assert!(matches!(
        drain_actions(&mut quic.agent).as_slice(),
        [Out::Ping { peer }] if peer == &quic.relay
    ));

    let mut tcp = build_with_config(ReservationPolicy::Always, 1, 0, |config| {
        let relay = config.relays[0].peer_id().clone();
        config.relays[0] =
            PeerAddr::new(maddr("/ip4/203.0.113.1/tcp/4001"), relay).expect("TCP relay address");
        config.reservation_keep_alive_interval_ms = 100;
    });
    reserve_via_relay(&mut tcp, hop_reserve_ok(None), at(10));
    drain_actions(&mut tcp.agent); // completed exchange's close-write

    tcp.agent.handle_tick(at(110));
    assert!(
        drain_actions(&mut tcp.agent).is_empty(),
        "TCP reservations do not schedule liveness traffic"
    );
}

#[test]
fn refused_reservation_rotates_relay_after_backoff() {
    let mut hk = build(ReservationPolicy::Always, 2, 0);

    let (events, stream) =
        reserve_via_relay(&mut hk, hop_status(Status::ReservationRefused), at(10));
    assert!(events.is_empty(), "refusal before holding emits nothing");
    let actions = drain_actions(&mut hk.agent);
    assert!(has_reset_for(&actions, stream));
    assert!(hk.agent.active_reservation().is_none());

    // Still inside the 500ms backoff: quiet.
    hk.agent.handle_tick(at(400));
    assert!(drain_actions(&mut hk.agent).is_empty());

    // After the backoff (500ms plus under a fifth of jitter) the manager
    // tries the *other* relay.
    hk.agent.handle_tick(at(610));
    let actions = drain_actions(&mut hk.agent);
    assert_eq!(dial_count_for(&actions, &hk.relay2), 1);
    assert_eq!(dial_count_for(&actions, &hk.relay), 0);
}

/// Counts HOP `OpenStream` actions targeting `peer`.
fn hop_open_count(actions: &[Out], peer: &PeerId) -> usize {
    actions
        .iter()
        .filter(|action| {
            matches!(
                action,
                Out::OpenStream { peer: p, protocol_id, .. }
                    if p == peer && protocol_id == HOP_PROTOCOL_ID
            )
        })
        .count()
}

#[test]
fn connect_and_reservation_racing_in_one_tick_share_one_dial() {
    let mut hk = build(ReservationPolicy::Always, 1, 0);

    // Whatever internal order the machines run in, only one dial may reach
    // the relay.
    start(&mut hk.agent, 1, peer(b"target-peer"), RELAY_NOW, at(0));
    hk.agent.handle_tick(at(250));
    let actions = drain_actions(&mut hk.agent);
    assert_eq!(
        dial_count_for(&actions, &hk.relay),
        1,
        "exactly one shared relay dial"
    );

    let relay = hk.relay.clone();
    hk.session_ready(&relay, &[HOP_PROTOCOL_ID], at(300));
    let actions = drain_actions(&mut hk.agent);
    assert_eq!(hop_open_count(&actions, &relay), 2);
}

#[test]
fn lost_relay_connection_emits_lost_and_reacquires() {
    let mut hk = build(ReservationPolicy::Always, 1, 0);
    let (events, _) = reserve_via_relay(&mut hk, hop_reserve_ok(None), at_unix(10, 1_000));
    assert_eq!(events.len(), 1);

    let relay = hk.relay.clone();
    hk.agent.handle_event(
        &SwarmEvent::ConnectionClosed {
            conn_id: minip2p_transport::ConnectionId::new(1),
            peer_id: relay.clone(),
            reason: ConnectionCloseReason::Local,
        },
        false,
        at(5_000),
    );
    let events = drain_events(&mut hk.agent);
    assert!(matches!(
        events.as_slice(),
        [NatEvent::RelayReservationLost { relay: r }] if *r == relay
    ));
    assert!(hk.agent.active_reservation().is_none());

    // After the backoff the (single) relay is dialed again.
    hk.agent.handle_tick(at(5_600));
    let actions = drain_actions(&mut hk.agent);
    assert_eq!(dial_count_for(&actions, &hk.relay), 1);
}

#[test]
fn retiring_another_relay_connection_keeps_the_reservation() {
    let mut hk = build(ReservationPolicy::Always, 1, 0);
    let (events, _) = reserve_via_relay(&mut hk, hop_reserve_ok(None), at_unix(10, 1_000));
    assert!(matches!(
        events.as_slice(),
        [NatEvent::RelayReserved { .. }]
    ));
    drain_actions(&mut hk.agent); // completed exchange's close-write

    // A second connection to the relay comes and goes while the swarm keeps
    // the reservation's connection (1) current. Losing one connection id
    // must not be treated as losing the relay peer, or the reservation made
    // on another connection.
    let relay = hk.relay.clone();
    hk.agent.deliver_late(
        &SwarmEvent::ConnectionEstablished {
            conn_id: ConnectionId::new(2),
            peer_id: relay.clone(),
        },
        false,
        at(20),
    );
    hk.agent.handle_event(
        &SwarmEvent::ConnectionClosed {
            conn_id: ConnectionId::new(2),
            peer_id: relay,
            reason: ConnectionCloseReason::Local,
        },
        false,
        at(21),
    );

    assert!(drain_events(&mut hk.agent).is_empty());
    assert!(hk.agent.active_reservation().is_some());
    hk.agent.handle_tick(at(1_000));
    assert_eq!(
        dial_count_for(&drain_actions(&mut hk.agent), &hk.relay),
        0,
        "a retired duplicate must not trigger reservation reacquisition"
    );
}

/// Replaces the relay connection 1 with 2 and returns the actions the agent
/// queues once the new connection is ready.
fn replace_relay_connection(hk: &mut Hk, now: Now) -> Vec<Out> {
    let relay = hk.relay.clone();
    hk.agent.handle_event(
        &SwarmEvent::ConnectionReplaced {
            peer_id: relay.clone(),
            old: ConnectionId::new(1),
            new: ConnectionId::new(2),
        },
        false,
        now,
    );
    // The relay dropped the reservation with its connection: withdraw it now.
    assert!(matches!(
        drain_events(&mut hk.agent).as_slice(),
        [NatEvent::RelayReservationLost { relay: r }] if *r == relay
    ));
    let actions = drain_actions(&mut hk.agent);
    assert!(
        !actions
            .iter()
            .any(|action| matches!(action, Out::ResetStream { .. })),
        "the old exchange must not reset a stream id on the new connection"
    );
    assert_eq!(
        hop_open_count(&actions, &relay),
        0,
        "waits for PeerReady(new)"
    );
    hk.agent.handle_event(
        &SwarmEvent::PeerReady {
            peer_id: relay,
            conn_id: ConnectionId::new(2),
            protocols: vec![HOP_PROTOCOL_ID.to_string()],
        },
        false,
        now,
    );
    drain_actions(&mut hk.agent)
}

#[test]
fn replacing_the_reservation_connection_reacquires_on_the_new_one() {
    let mut hk = build(ReservationPolicy::Always, 1, 0);
    reserve_via_relay(&mut hk, hop_reserve_ok(None), at_unix(10, 1_000));
    drain_actions(&mut hk.agent); // completed exchange's close-write

    let relay = hk.relay.clone();
    let actions = replace_relay_connection(&mut hk, at(20));
    assert_eq!(hop_open_count(&actions, &relay), 1);
    assert_eq!(dial_count_for(&actions, &relay), 0);
}

#[test]
fn replacement_during_a_refresh_starts_exactly_one_exchange_on_new() {
    let mut hk = build(ReservationPolicy::Always, 1, 0);
    reserve_via_relay(&mut hk, hop_reserve_ok(Some(1_900)), at_unix(10, 1_000));
    drain_actions(&mut hk.agent); // completed exchange's close-write

    // Start the renewal and get its stream allocated on connection 1.
    let renew_at = 10 + 780 * 1_000;
    hk.agent.handle_tick(at_unix(renew_at, 1_790));
    let relay = hk.relay.clone();
    let stream = opened_stream_for(&drain_actions(&mut hk.agent), &relay);

    let actions = replace_relay_connection(&mut hk, at_unix(renew_at + 1, 1_790));
    assert_eq!(hop_open_count(&actions, &relay), 1);
    assert!(
        !hk.agent.owns_stream(ConnectionId::new(1), stream),
        "the old exchange is gone"
    );
}

#[test]
fn reservation_work_started_on_a_replacement_survives_the_replacement_event() {
    let mut hk = build(ReservationPolicy::Always, 1, 0);
    let relay = hk.relay.clone();
    let (old, new) = (ConnectionId::new(1), ConnectionId::new(2));
    // The swarm is ahead of the events NAT has handled: the relay's first
    // connection was already replaced, and the replacement is ready.
    hk.agent
        .swarm
        .make_ready(&relay, new, &[HOP_PROTOCOL_ID.to_string()]);
    hk.agent.handle_tick(at(0));
    let actions = drain_actions(&mut hk.agent);
    assert_eq!(dial_count_for(&actions, &relay), 0);
    let stream = opened_stream_for(&actions, &relay);

    // The buffered lifecycle of the retired connection catches up. Cleanup
    // is scoped to `old`: the exchange on `new` keeps going.
    let hop = || vec![HOP_PROTOCOL_ID.to_string()];
    for event in [
        SwarmEvent::ConnectionEstablished {
            peer_id: relay.clone(),
            conn_id: old,
        },
        SwarmEvent::PeerReady {
            peer_id: relay.clone(),
            conn_id: old,
            protocols: hop(),
        },
        SwarmEvent::ConnectionReplaced {
            peer_id: relay.clone(),
            old,
            new,
        },
        SwarmEvent::PeerReady {
            peer_id: relay.clone(),
            conn_id: new,
            protocols: hop(),
        },
    ] {
        hk.agent.deliver_late(&event, false, at(1));
    }
    let actions = drain_actions(&mut hk.agent);
    assert!(
        actions.is_empty(),
        "no reset and no second exchange: {actions:?}"
    );
    assert!(drain_events(&mut hk.agent).is_empty());
    assert!(hk.agent.owns_stream(new, stream));

    hk.agent.handle_event(
        &SwarmEvent::StreamReady {
            conn_id: new,
            peer_id: relay.clone(),
            stream_id: stream,
            protocol_id: HOP_PROTOCOL_ID.to_string(),
            initiated_locally: true,
        },
        false,
        at(2),
    );
    assert!(matches!(
        drain_actions(&mut hk.agent).as_slice(),
        [Out::SendStream { conn, stream_id, .. }] if *conn == new && *stream_id == stream
    ));
}

#[test]
fn when_private_policy_follows_the_reachability_verdict() {
    let mut hk = build(ReservationPolicy::WhenPrivate, 1, 3);
    let public = [maddr(LISTEN_ADDR)];

    // While reachability is Unknown, both housekeeping flows start: a
    // reservation (dialable now) and a probe (gather evidence).
    hk.agent.handle_tick(at(0));
    let actions = drain_actions(&mut hk.agent);
    assert_eq!(dial_count_for(&actions, &hk.relay), 1);
    assert_eq!(dial_count_for(&actions, &hk.server), 1);
    let relay = hk.relay.clone();
    let server = hk.server.clone();
    hk.session_ready(&relay, &[HOP_PROTOCOL_ID], at(2));
    let (events, _) = hk.finish_reserve(hop_reserve_ok(None), at(3));
    assert!(matches!(
        events.as_slice(),
        [NatEvent::RelayReserved { .. }]
    ));

    hk.session_ready(&server, &[AUTONAT_PROTOCOL_ID], at(4));
    assert!(hk.finish_probe(true, 5).is_empty());
    assert!(hk.probe(Answer::Public(&public), 6_000).1.is_empty());

    // The third server's public vote: the verdict flips and, in the same
    // cascade, the now-unneeded reservation is released.
    let (_, events) = hk.probe(Answer::Public(&public), 12_000);
    assert!(matches!(
        events.as_slice(),
        [
            NatEvent::ReachabilityChanged {
                new: ReachabilityState::Public,
                ..
            },
            NatEvent::RelayReservationLost { .. },
        ]
    ));
    assert!(hk.agent.active_reservation().is_none());

    // Service the next scheduled probe, then verify quiet ticks stay quiet:
    // no reservation reacquisition while confidently public.
    assert!(hk.probe(Answer::Public(&public), 50_000).1.is_empty());
    drain_actions(&mut hk.agent); // the finished probe's close-write
    hk.agent.handle_tick(at(100_000));
    let actions = drain_actions(&mut hk.agent);
    assert!(
        actions.is_empty(),
        "no reservation while confidently public: {actions:?}"
    );

    // Flip back to Private once three servers say so: reacquisition
    // begins in the same cascade.
    assert!(hk.probe(Answer::DialError, 145_000).1.is_empty());
    assert!(hk.probe(Answer::DialError, 236_000).1.is_empty());
    let (_, events) = hk.probe(Answer::DialError, 330_000);
    assert!(matches!(
        events.as_slice(),
        [NatEvent::ReachabilityChanged {
            new: ReachabilityState::Private,
            ..
        }]
    ));
    let actions = drain_actions(&mut hk.agent);
    assert!(
        actions.iter().any(
            |a| matches!(a, Out::OpenStream { protocol_id, .. } if protocol_id == HOP_PROTOCOL_ID)
        ),
        "reservation reacquired once private: {actions:?}"
    );
}

// ---------------------------------------------------------------------------
// Session-dial sharing
// ---------------------------------------------------------------------------

/// Regression test for a failure first seen against a live relay: the
/// reservation manager and a connect attempt's relay leg both dialed the
/// relay while the first handshake was still in flight (real-network RTT),
/// producing two connections — and the second replaced the first, killing
/// the attempt with "relay connection was replaced".
#[test]
fn concurrent_reservation_and_connect_share_one_relay_dial() {
    let mut hk = build(ReservationPolicy::Always, 1, 0);
    let relay = hk.relay.clone();

    // The reservation manager dials the relay first.
    hk.agent.handle_tick(at(0));
    let actions = drain_actions(&mut hk.agent);
    assert_eq!(dial_count_for(&actions, &relay), 1);

    // A connect starts while that dial is still handshaking; its relay leg
    // must wait on the pending connection instead of dialing again.
    let _id = start(&mut hk.agent, 1, peer(b"target-peer"), RELAY_NOW, at(10));
    hk.agent.handle_tick(at(300));
    let actions = drain_actions(&mut hk.agent);
    assert_eq!(
        dial_count_for(&actions, &relay),
        0,
        "a second relay dial replaces the first connection: {actions:?}"
    );

    // The shared connection comes up: both machines proceed, each opening
    // its own HOP stream on it.
    hk.session_ready(&relay, &[HOP_PROTOCOL_ID], at(410));
    let actions = drain_actions(&mut hk.agent);
    let hop_opens = actions
        .iter()
        .filter(
            |a| matches!(a, Out::OpenStream { protocol_id, .. } if protocol_id == HOP_PROTOCOL_ID),
        )
        .count();
    assert_eq!(
        hop_opens, 2,
        "reservation and connect attempt must each open a HOP stream on \
         the shared connection: {actions:?}"
    );
}

/// The in-flight entry must live as long as the owning machine's own flight
/// deadline. A probe dial is legitimate for `probe_deadline_ms` (20s); if
/// the entry expired at the relay-leg deadline (12s) instead, a connect
/// attempt arriving in between would dial the same peer a second time —
/// recreating the replacement this map exists to prevent.
#[test]
fn pending_probe_dial_covers_the_probe_deadline_not_the_relay_legs() {
    // The AutoNAT server doubles as the configured relay, so the probe's
    // dial and the attempt's relay leg target the same peer.
    let mut hk = build_with_config(ReservationPolicy::Never, 1, 0, |config| {
        config.autonat_servers =
            vec![PeerAddr::new(maddr(RELAY_TRANSPORT_ADDR), peer(b"relay-peer")).unwrap()];
    });
    let relay = hk.relay.clone();

    // The probe dials the server; the handshake is slow but still within
    // the probe's own deadline.
    hk.agent.handle_tick(at(0));
    let actions = drain_actions(&mut hk.agent);
    assert_eq!(dial_count_for(&actions, &relay), 1, "{actions:?}");

    // A connect starts past the relay-leg deadline but inside the probe
    // deadline: the probe's dial is still in flight, so the relay leg must
    // join it rather than open a second, replacing connection.
    start(
        &mut hk.agent,
        1,
        peer(b"target-peer"),
        RELAY_NOW,
        at(15_000),
    );
    let actions = drain_actions(&mut hk.agent);
    assert_eq!(
        dial_count_for(&actions, &relay),
        0,
        "the relay leg must wait on the probe's in-flight dial: {actions:?}"
    );
}

/// When the owner of a shared session dial reports failure, waiting
/// attempts must issue their own dial immediately. Nothing else re-enters
/// a waiting relay leg: without the wake-up the attempt would burn its
/// whole leg deadline on a dial that already failed and could time out
/// without ever trying the relay.
#[test]
fn waiting_attempt_redials_when_the_shared_dial_fails() {
    let mut hk = build(ReservationPolicy::Always, 1, 0);
    let relay = hk.relay.clone();

    // The reservation manager owns the relay dial.
    hk.agent.handle_tick(at(0));
    let reserve_dial = dial_conn_for(&drain_actions(&mut hk.agent), &relay);

    // A connect attempt joins the pending dial.
    start(&mut hk.agent, 1, peer(b"target-peer"), RELAY_NOW, at(10));
    let actions = drain_actions(&mut hk.agent);
    assert_eq!(dial_count_for(&actions, &relay), 0, "{actions:?}");

    // The shared dial fails: the waiting attempt re-dials at once.
    dial_failed(&mut hk, reserve_dial, "connection refused", at(500));
    let actions = drain_actions(&mut hk.agent);
    assert_eq!(
        dial_count_for(&actions, &relay),
        1,
        "the waiting attempt must issue its own dial: {actions:?}"
    );
}

/// A driver that defers a dial (to resolve a name) must not echo it into a
/// newer flight: once the owner's deadline passes, the dial is retired and a
/// late result has nowhere to land.
#[test]
fn a_deferred_dial_past_its_flight_is_retired_and_its_late_result_ignored() {
    let mut hk = build_with_config(ReservationPolicy::Always, 1, 0, |config| {
        let relay = config.relays[0].peer_id().clone();
        config.relays[0] = PeerAddr::new(maddr("/dns4/relay.example/udp/4001/quic-v1"), relay)
            .expect("named relay address");
    });
    hk.agent.swarm.park_named = true;
    let relay = hk.relay.clone();
    hk.agent.handle_tick(at(0));
    let actions = drain_actions(&mut hk.agent);
    let reserve_dial = dial_token_for(&actions, &relay);

    assert!(hk.agent.deferred_dial_wanted(reserve_dial, at(1)));
    assert!(!hk.agent.deferred_dial_wanted(reserve_dial, at(3_600_000)));
    assert!(
        !hk.agent.deferred_dial_wanted(reserve_dial, at(1)),
        "a retired dial stays retired"
    );

    let deadline = hk.agent.next_deadline(at(3_600_000));
    hk.agent
        .dial_result(reserve_dial, Err("lookup failed".into()), at(3_600_000));
    assert!(drain_actions(&mut hk.agent).is_empty());
    assert!(hk.agent.poll_event().is_none());
    assert_eq!(hk.agent.next_deadline(at(3_600_000)), deadline);
}

#[test]
fn reserve_dial_failed_event_schedules_backoff() {
    let mut hk = build(ReservationPolicy::Always, 1, 0);
    let relay = hk.relay.clone();
    hk.agent.handle_tick(at(0));
    let conn_id = dial_conn_for(&drain_actions(&mut hk.agent), &relay);
    assert!(dial_failed(&mut hk, conn_id, "connection refused", at(6)));
    let base = NatConfig::default().reservation_retry_backoff_ms;
    let delay = hk
        .agent
        .next_deadline(at(6))
        .expect("a backoff")
        .millis_until(at(6));
    assert!(
        (base..base + base / 5).contains(&delay),
        "refused reservation dial must back off by the base plus jitter: {delay}"
    );
}

/// Consecutive failures back off exponentially up to the cap, and a held
/// reservation starts the next failure from the base again.
#[test]
fn reservation_retries_back_off_exponentially_and_reset_on_success() {
    let mut hk = build(ReservationPolicy::Always, 1, 0);
    let relay = hk.relay.clone();
    let base = NatConfig::default().reservation_retry_backoff_ms;
    let mut now = 0;
    let mut delays = Vec::new();
    for _ in 0..12 {
        hk.agent.handle_tick(at(now));
        let conn_id = dial_conn_for(&drain_actions(&mut hk.agent), &relay);
        assert!(dial_failed(&mut hk, conn_id, "connection refused", at(now)));
        let delay = hk
            .agent
            .next_deadline(at(now))
            .expect("a backoff")
            .millis_until(at(now));
        delays.push(delay);
        now += delay;
    }
    assert!((base..base + base / 5).contains(&delays[0]), "{delays:?}");
    let capped = |delay: u64| delay >= MAX_RESERVATION_RETRY_BACKOFF_MS * 4 / 5;
    for pair in delays.windows(2) {
        assert!(
            pair[1] > pair[0] || capped(pair[1]),
            "delays grow strictly until the cap: {delays:?}"
        );
    }
    assert!(
        delays
            .iter()
            .all(|delay| *delay <= MAX_RESERVATION_RETRY_BACKOFF_MS)
    );
    // At the cap the delays keep a random spread instead of all landing on it.
    let tail = &delays[delays.len() - 4..];
    assert!(tail.iter().all(|delay| capped(*delay)), "{delays:?}");
    assert!(tail.windows(2).any(|pair| pair[0] != pair[1]), "{delays:?}");

    // A held reservation, then its loss: the retry is back at the base.
    let (events, _) = reserve_via_relay(&mut hk, hop_reserve_ok(None), at(now));
    assert_eq!(events.len(), 1, "{events:?}");
    hk.agent.handle_event(
        &SwarmEvent::ConnectionClosed {
            conn_id: hk.agent.swarm.connection(&relay).expect("relay session"),
            peer_id: relay.clone(),
            reason: ConnectionCloseReason::Local,
        },
        false,
        at(now + 1),
    );
    let delay = hk
        .agent
        .next_deadline(at(now + 1))
        .expect("a backoff")
        .millis_until(at(now + 1));
    assert!((base..base + base / 5).contains(&delay), "{delay}");
}

/// When the owner of a shared dial stalls (no result ever arrives), its
/// entry expires at the owner's own flight deadline — and the tick running
/// at that moment must re-drive waiting relay legs. Without the re-drive
/// the attempt idles until its own later deadline and fails without ever
/// dialing the relay itself.
#[test]
fn waiting_attempt_redials_when_the_shared_dial_expires() {
    let mut hk = build_with_config(ReservationPolicy::Never, 1, 0, |config| {
        config.autonat_servers =
            vec![PeerAddr::new(maddr(RELAY_TRANSPORT_ADDR), peer(b"relay-peer")).unwrap()];
    });
    let relay = hk.relay.clone();

    // The probe owns the dial (20s flight); the handshake stalls silently.
    hk.agent.handle_tick(at(0));
    let actions = drain_actions(&mut hk.agent);
    assert_eq!(dial_count_for(&actions, &relay), 1, "{actions:?}");

    // A connect joins the pending dial mid-flight.
    start(
        &mut hk.agent,
        1,
        peer(b"target-peer"),
        RELAY_NOW,
        at(15_000),
    );
    let actions = drain_actions(&mut hk.agent);
    assert_eq!(dial_count_for(&actions, &relay), 0, "{actions:?}");

    // The probe's flight deadline: the entry expires and the same tick must
    // re-drive the waiting relay leg (whose own deadline, 27s, is live).
    hk.agent.handle_tick(at(20_000));
    let actions = drain_actions(&mut hk.agent);
    assert_eq!(
        dial_count_for(&actions, &relay),
        1,
        "the waiting attempt must re-dial when the stalled entry expires: {actions:?}"
    );
}

/// A shared-dial failure arriving after the leg's own deadline (with no
/// tick in between) must not trigger a re-dial: the next tick fails the
/// leg, so a fresh entry would only gate the reservation manager's and
/// prober's dials on a connection nobody is waiting for.
#[test]
fn late_shared_dial_failure_does_not_redial_a_dead_leg() {
    let mut hk = build(ReservationPolicy::Always, 1, 0);
    let relay = hk.relay.clone();

    hk.agent.handle_tick(at(0));
    let reserve_dial = dial_conn_for(&drain_actions(&mut hk.agent), &relay);

    start(&mut hk.agent, 1, peer(b"target-peer"), RELAY_NOW, at(10));
    drain_actions(&mut hk.agent);

    // The failure lands past the attempt's relay-leg deadline (10 + 12s).
    dial_failed(&mut hk, reserve_dial, "timed out", at(12_500));
    let actions = drain_actions(&mut hk.agent);
    assert_eq!(
        dial_count_for(&actions, &relay),
        0,
        "no re-dial past the leg deadline: {actions:?}"
    );
}

/// A session dial whose handshake never completes must not suppress dialing
/// forever: once the reservation deadline fails the acquisition, the retry
/// issues a fresh dial (the stale in-flight entry has expired).
#[test]
fn stalled_session_dial_expires_and_the_retry_redials() {
    let mut hk = build(ReservationPolicy::Always, 1, 0);
    let relay = hk.relay.clone();

    hk.agent.handle_tick(at(0));
    let actions = drain_actions(&mut hk.agent);
    assert_eq!(dial_count_for(&actions, &relay), 1);
    // No dial_result, no connection: the handshake silently stalls.

    // Past the acquisition deadline (relay_timeout_ms) and the retry
    // backoff, the manager tries again — with a real dial, not a wait on
    // the dead one.
    hk.agent.handle_tick(at(12_600));
    let mut actions = drain_actions(&mut hk.agent);
    hk.agent.handle_tick(at(13_500));
    actions.extend(drain_actions(&mut hk.agent));
    assert_eq!(
        dial_count_for(&actions, &relay),
        1,
        "the retry must redial the relay: {actions:?}"
    );
}

/// Announces `conn` to `peer` as established and ready for `protocol`.
fn ready_on(hk: &mut Hk, peer: &PeerId, conn: ConnectionId, protocol: &str, now: Now) {
    hk.agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            conn_id: conn,
            peer_id: peer.clone(),
        },
        false,
        now,
    );
    hk.agent.handle_event(
        &SwarmEvent::PeerReady {
            peer_id: peer.clone(),
            conn_id: conn,
            protocols: vec![protocol.to_string()],
        },
        false,
        now,
    );
}

#[test]
fn late_probe_dial_failure_after_rotation_keeps_the_new_flight() {
    let mut hk = build(ReservationPolicy::Never, 0, 2);
    let (server, server2) = (hk.server.clone(), hk.server2.clone());
    let deadline = NatConfig::default().probe_deadline_ms;

    hk.agent.handle_tick(at(0));
    let old = dial_conn_for(&drain_actions(&mut hk.agent), &server);
    // The first server never answers; the retry dials the second.
    hk.agent.handle_tick(at(deadline));
    hk.agent.handle_tick(at(deadline + 5_000));
    let new = dial_conn_for(&drain_actions(&mut hk.agent), &server2);

    let addr = PeerAddr::new(maddr(SERVER_ADDR), server.clone()).expect("server addr");
    let late = SwarmEvent::DialFailed {
        conn_id: old,
        addr,
        reason: "timed out".into(),
    };
    assert!(hk.agent.handle_event(&late, false, at(deadline + 5_001)));

    ready_on(
        &mut hk,
        &server2,
        new,
        AUTONAT_PROTOCOL_ID,
        at(deadline + 5_002),
    );
    opened_stream_for(&drain_actions(&mut hk.agent), &server2);
}

#[test]
fn late_reserve_dial_failure_after_rotation_keeps_the_new_acquisition() {
    let mut hk = build(ReservationPolicy::Always, 2, 0);
    let (relay, relay2) = (hk.relay.clone(), hk.relay2.clone());
    let config = NatConfig::default();
    // The base backoff plus its most jitter, a fifth.
    let retry_at = config.relay_timeout_ms + config.reservation_retry_backoff_ms * 6 / 5;

    hk.agent.handle_tick(at(0));
    let old = dial_conn_for(&drain_actions(&mut hk.agent), &relay);
    // The first relay never connects; after the backoff the second is dialed.
    hk.agent.handle_tick(at(config.relay_timeout_ms));
    hk.agent.handle_tick(at(retry_at));
    let new = dial_conn_for(&drain_actions(&mut hk.agent), &relay2);

    assert!(dial_failed(&mut hk, old, "timed out", at(retry_at + 1)));

    ready_on(&mut hk, &relay2, new, HOP_PROTOCOL_ID, at(retry_at + 2));
    assert_eq!(hop_open_count(&drain_actions(&mut hk.agent), &relay2), 1);
}

#[test]
fn a_held_request_is_resent_and_closed_after_its_exchange_finishes() {
    let mut hk = build(ReservationPolicy::Always, 1, 0);
    hk.agent.handle_tick(at(0));
    let relay = hk.relay.clone();
    hk.session_ready(&relay, &[HOP_PROTOCOL_ID], at(2));

    // The RESERVE is refused as Full; a relay that answers anyway finishes
    // the exchange, which releases the stream with the tail still held.
    hk.agent.swarm.full_sends = true;
    let (events, stream) = hk.finish_reserve(hop_reserve_ok(None), at(3));
    assert!(matches!(
        events.as_slice(),
        [NatEvent::RelayReserved { .. }]
    ));
    hk.agent.swarm.full_sends = false;
    drain_actions(&mut hk.agent);
    assert!(
        !hk.agent.is_idle(),
        "held bytes are work: an idle agent might not be serviced again"
    );

    hk.agent.handle_event(
        &SwarmEvent::StreamWritable {
            peer_id: relay.clone(),
            conn_id: hk.agent.swarm.connection(&relay).expect("relay session"),
            stream_id: stream,
        },
        false,
        at(4),
    );
    let actions = drain_actions(&mut hk.agent);
    assert!(!sent_data_on(&actions, stream).is_empty());
    assert!(matches!(
        actions.last(),
        Some(Out::CloseStreamWrite { stream_id, .. }) if *stream_id == stream
    ));
    assert!(hk.agent.is_idle());
}

#[test]
fn a_held_request_whose_resend_fails_resets_instead_of_closing() {
    let mut hk = build(ReservationPolicy::Always, 1, 0);
    hk.agent.handle_tick(at(0));
    let relay = hk.relay.clone();
    hk.session_ready(&relay, &[HOP_PROTOCOL_ID], at(2));
    // As above: the finished exchange leaves the tail and its FIN held.
    hk.agent.swarm.full_sends = true;
    let (_, stream) = hk.finish_reserve(hop_reserve_ok(None), at(3));
    hk.agent.swarm.full_sends = false;
    drain_actions(&mut hk.agent);

    // The transport may have taken a prefix before failing.
    let conn_id = hk.agent.swarm.connection(&relay).expect("relay session");
    hk.agent.swarm.failed_sends = Some(TransportError::StreamSendFailed {
        id: conn_id,
        stream_id: stream,
        reason: "broken".into(),
    });
    hk.agent.handle_event(
        &SwarmEvent::StreamWritable {
            peer_id: relay.clone(),
            conn_id,
            stream_id: stream,
        },
        false,
        at(4),
    );
    let actions = drain_actions(&mut hk.agent);
    assert!(
        matches!(
            actions.last(),
            Some(Out::ResetStream { stream_id, .. }) if *stream_id == stream
        ),
        "a truncated request must not end in a clean FIN: {actions:?}"
    );
    assert!(hk.agent.is_idle());
}

#[test]
fn a_partly_accepted_request_is_finished_in_order_before_its_close() {
    // The RESERVE an unconstrained stream carries, for reference.
    let mut reference = build(ReservationPolicy::Always, 1, 0);
    reference.agent.handle_tick(at(0));
    let relay = reference.relay.clone();
    reference.session_ready(&relay, &[HOP_PROTOCOL_ID], at(2));
    let stream = opened_stream_for(&drain_actions(&mut reference.agent), &relay);
    reference.stream_ready(&relay, stream, HOP_PROTOCOL_ID, at(3));
    let request = sent_data_on(&drain_actions(&mut reference.agent), stream);
    assert!(request.len() > 2, "the request must span several writes");

    let mut hk = build(ReservationPolicy::Always, 1, 0);
    hk.agent.handle_tick(at(0));
    hk.session_ready(&relay, &[HOP_PROTOCOL_ID], at(2));
    let stream = opened_stream_for(&drain_actions(&mut hk.agent), &relay);
    let writable = |hk: &mut Hk, t| {
        hk.agent.handle_event(
            &SwarmEvent::StreamWritable {
                peer_id: relay.clone(),
                conn_id: ConnectionId::new(1),
                stream_id: stream,
            },
            false,
            at(t),
        );
    };

    // One byte per write: the first write and its replay each leave a tail.
    hk.agent.swarm.accept_at_most = Some(1);
    hk.stream_ready(&relay, stream, HOP_PROTOCOL_ID, at(3));
    writable(&mut hk, 4);
    // The relay answers early; the finished exchange queues its close behind
    // the tail.
    hk.stream_data(&relay, stream, hop_reserve_ok(None), at(5));
    hk.agent.swarm.accept_at_most = None;
    writable(&mut hk, 6);

    let actions = drain_actions(&mut hk.agent);
    let sent: Vec<u8> = actions
        .iter()
        .filter_map(|action| match action {
            Out::SendStream {
                stream_id, data, ..
            } if *stream_id == stream => Some(data.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(sent, request);
    assert!(matches!(
        actions.last(),
        Some(Out::CloseStreamWrite { stream_id, .. }) if *stream_id == stream
    ));
}
