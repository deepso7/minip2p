//! Scripted housekeeping tests: AutoNAT confidence aggregation and relay
//! reservation lifecycle, with a fake clock and no I/O.

mod common;

use common::*;

use minip2p_autonat::AUTONAT_PROTOCOL_ID;
use minip2p_core::{PeerAddr, PeerId};
use minip2p_nat::{
    NatAction, NatAgent, NatConfig, NatEvent, Now, ReachabilityState, ReservationPolicy,
};
use minip2p_relay::{HOP_PROTOCOL_ID, Status};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{ConnectionId, StreamId};

const SERVER_ADDR: &str = "/ip4/203.0.113.50/udp/4001/quic-v1";
const SERVER2_ADDR: &str = "/ip4/203.0.113.51/udp/4001/quic-v1";
const RELAY2_TRANSPORT_ADDR: &str = "/ip4/203.0.113.2/udp/4001/quic-v1";

struct Hk {
    agent: NatAgent,
    relay: PeerId,
    relay2: PeerId,
    server: PeerId,
    server2: PeerId,
    next_stream: u64,
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
    let server = peer(b"autonat-server");
    let server2 = peer(b"autonat-server-2");

    let mut relays = Vec::new();
    if relay_count >= 1 {
        relays.push(PeerAddr::new(maddr(RELAY_TRANSPORT_ADDR), relay.clone()).unwrap());
    }
    if relay_count >= 2 {
        relays.push(PeerAddr::new(maddr(RELAY2_TRANSPORT_ADDR), relay2.clone()).unwrap());
    }
    let mut autonat_servers = Vec::new();
    if server_count >= 1 {
        autonat_servers.push(PeerAddr::new(maddr(SERVER_ADDR), server.clone()).unwrap());
    }
    if server_count >= 2 {
        autonat_servers.push(PeerAddr::new(maddr(SERVER2_ADDR), server2.clone()).unwrap());
    }

    let mut config = NatConfig {
        reservation_policy: policy,
        relays,
        autonat_servers,
        ..NatConfig::default()
    };
    configure(&mut config);
    let mut agent = NatAgent::new(peer(b"local-peer"), config);
    agent.set_listen_addrs(&[maddr(LISTEN_ADDR)]);
    Hk {
        agent,
        relay,
        relay2,
        server,
        server2,
        next_stream: 100,
    }
}

impl Hk {
    fn fresh_stream(&mut self) -> StreamId {
        self.next_stream += 1;
        StreamId::new(self.next_stream)
    }

    /// Connection established + PeerReady advertising `protocols`.
    fn session_ready(&mut self, peer: &PeerId, protocols: &[&str], now: Now) {
        self.agent.handle_event(
            &SwarmEvent::ConnectionEstablished {
                peer_id: peer.clone(),
            },
            now,
        );
        self.agent.handle_event(
            &SwarmEvent::PeerReady {
                peer_id: peer.clone(),
                protocols: protocols.iter().map(|p| p.to_string()).collect(),
            },
            now,
        );
    }

    fn stream_ready(&mut self, peer: &PeerId, stream: StreamId, protocol: &str, now: Now) {
        self.agent.handle_event(
            &SwarmEvent::StreamReady {
                peer_id: peer.clone(),
                stream_id: stream,
                protocol_id: protocol.to_string(),
                initiated_locally: true,
            },
            now,
        );
    }

    fn stream_data(&mut self, peer: &PeerId, stream: StreamId, data: Vec<u8>, now: Now) {
        self.agent.handle_event(
            &SwarmEvent::StreamData {
                peer_id: peer.clone(),
                stream_id: stream,
                data,
            },
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
        let actions = drain_actions(&mut self.agent);
        let token = open_stream_token_for(&actions, &server);
        let stream = self.fresh_stream();
        self.agent.stream_open_result(token, Ok(stream), at(t));
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

    /// Ticks to start the next probe (the server session must be ready),
    /// then completes it.
    fn run_probe(&mut self, public: bool, t: u64) -> Vec<NatEvent> {
        self.agent.handle_tick(at(t));
        self.finish_probe(public, t + 1)
    }

    /// Completes a reservation exchange whose `OpenStream` is already
    /// queued, feeding `response`. Returns (events, stream id).
    fn finish_reserve(&mut self, response: Vec<u8>, now: Now) -> (Vec<NatEvent>, StreamId) {
        let relay = self.relay_for_current();
        let actions = drain_actions(&mut self.agent);
        let token = open_stream_token_for(&actions, &relay);
        let stream = self.fresh_stream();
        self.agent.stream_open_result(token, Ok(stream), now);
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
fn confidence_window_flips_once_and_never_flaps_on_one_probe() {
    let mut hk = build(ReservationPolicy::Never, 0, 1);
    assert_eq!(hk.agent.reachability(), ReachabilityState::Unknown);

    // First probe bootstraps the server session.
    hk.agent.handle_tick(at(0));
    let actions = drain_actions(&mut hk.agent);
    let dial = dial_token_for(&actions, &hk.server);
    hk.agent.dial_result(dial, Ok(ConnectionId::new(50)), at(1));
    let server = hk.server.clone();
    hk.session_ready(&server, &[AUTONAT_PROTOCOL_ID], at(2));
    assert!(hk.finish_probe(true, 3).is_empty(), "1 vote of 3: no flip");
    assert_eq!(hk.agent.reachability(), ReachabilityState::Unknown);

    // Unsettled cadence is 5s.
    assert!(
        hk.run_probe(true, 6_000).is_empty(),
        "2 votes of 3: no flip"
    );

    let events = hk.run_probe(true, 12_000);
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
    assert!(hk.run_probe(true, 110_000).is_empty());

    // One disagreeing probe must never flap the verdict.
    assert!(
        hk.run_probe(false, 210_000).is_empty(),
        "single private probe in a public window: no flip"
    );
    assert_eq!(hk.agent.reachability(), ReachabilityState::Public);

    // A private majority (3 of the last 5) flips exactly once.
    assert!(hk.run_probe(false, 310_000).is_empty());
    let events = hk.run_probe(false, 410_000);
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
    let mut hk = build_with_config(ReservationPolicy::Never, 0, 1, |config| {
        config.confidence_window = 3;
        config.confidence_threshold = 9;
    });

    // Bootstrap the AutoNAT session, then collect a full (three-vote)
    // unanimous window. An unclamped threshold could never settle here.
    hk.agent.handle_tick(at(0));
    let actions = drain_actions(&mut hk.agent);
    let dial = dial_token_for(&actions, &hk.server);
    hk.agent.dial_result(dial, Ok(ConnectionId::new(50)), at(1));
    let server = hk.server.clone();
    hk.session_ready(&server, &[AUTONAT_PROTOCOL_ID], at(2));
    assert!(hk.finish_probe(true, 3).is_empty());
    assert!(hk.run_probe(true, 6_000).is_empty());

    let events = hk.run_probe(true, 12_000);
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

    // Establish both housekeeping sessions, then hold a relay reservation
    // while reachability is still Unknown.
    hk.agent.handle_tick(at(0));
    let actions = drain_actions(&mut hk.agent);
    let relay_dial = dial_token_for(&actions, &hk.relay);
    let server_dial = dial_token_for(&actions, &hk.server);
    hk.agent
        .dial_result(relay_dial, Ok(ConnectionId::new(60)), at(1));
    hk.agent
        .dial_result(server_dial, Ok(ConnectionId::new(61)), at(1));
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
    let wildcard_only = [maddr("/ip4/0.0.0.0/udp/4001/quic-v1")];
    let events = hk.finish_probe_with_addrs(Some(&wildcard_only), 5);

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
fn probe_timeout_rotates_to_the_next_server() {
    let mut hk = build(ReservationPolicy::Never, 0, 2);

    hk.agent.handle_tick(at(0));
    let actions = drain_actions(&mut hk.agent);
    let dial = dial_token_for(&actions, &hk.server);
    hk.agent.dial_result(dial, Ok(ConnectionId::new(50)), at(1));
    let server = hk.server.clone();
    hk.session_ready(&server, &[AUTONAT_PROTOCOL_ID], at(2));
    let actions = drain_actions(&mut hk.agent);
    let token = open_stream_token_for(&actions, &server);
    let stream = hk.fresh_stream();
    hk.agent.stream_open_result(token, Ok(stream), at(3));
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

/// Bootstraps the relay session and completes the first reservation.
fn reserve_via_relay(hk: &mut Hk, response: Vec<u8>, now: Now) -> (Vec<NatEvent>, StreamId) {
    hk.agent.handle_tick(now);
    let actions = drain_actions(&mut hk.agent);
    let dial = dial_token_for(&actions, &hk.relay);
    hk.agent.dial_result(dial, Ok(ConnectionId::new(60)), now);
    let relay = hk.relay.clone();
    hk.session_ready(&relay, &[HOP_PROTOCOL_ID], now);
    hk.finish_reserve(response, now)
}

#[test]
fn reservation_renews_at_expire_minus_margin() {
    let mut hk = build(ReservationPolicy::Always, 1, 0);

    // Relay reports expiry at unix 1900; the clock says unix 1000 at mono 10.
    let (events, _) = reserve_via_relay(&mut hk, hop_reserve_ok(Some(1_900)), at_unix(10, 1_000));
    // remaining 900s − margin 120s = 780s after mono 10.
    let expected_renew = 10 + 780 * 1_000;
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
    assert_eq!(hk.agent.next_timeout(10_000), Some(expected_renew - 10_000));
    // The completed exchange closes its write side; drain it.
    drain_actions(&mut hk.agent);

    // Too early: nothing happens.
    hk.agent.handle_tick(at_unix(700_000, 1_700));
    assert!(drain_actions(&mut hk.agent).is_empty());

    // At renew time a fresh RESERVE goes out on the still-ready session.
    hk.agent.handle_tick(at_unix(expected_renew, 1_790));
    let (events, _) = hk.finish_reserve(
        hop_reserve_ok(Some(2_700)),
        at_unix(expected_renew + 5, 1_790),
    );
    assert!(matches!(
        events.as_slice(),
        [NatEvent::RelayReserved {
            expires_unix_secs: Some(2_700),
            ..
        }]
    ));
}

#[test]
fn enormous_relay_expiry_saturates_the_renewal_deadline() {
    let mut hk = build(ReservationPolicy::Always, 1, 0);
    let (events, _) = reserve_via_relay(&mut hk, hop_reserve_ok(Some(u64::MAX)), at_unix(10, 0));

    assert!(matches!(
        events.as_slice(),
        [NatEvent::RelayReserved {
            renew_at_mono_ms: u64::MAX,
            ..
        }]
    ));
    assert_eq!(
        hk.agent
            .active_reservation()
            .expect("reservation held")
            .renew_at_mono_ms,
        u64::MAX
    );
}

#[test]
fn reservation_without_expire_uses_default_ttl() {
    let mut hk = build(ReservationPolicy::Always, 1, 0);
    let (events, _) = reserve_via_relay(&mut hk, hop_reserve_ok(None), at_unix(10, 1_000));
    // default TTL 3600s − margin 120s = 3480s.
    let expected_renew = 10 + 3_480 * 1_000;
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
    let expected_renew = 10 + 3_480 * 1_000;
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

    // After the backoff the manager tries the *other* relay.
    hk.agent.handle_tick(at(600));
    let actions = drain_actions(&mut hk.agent);
    assert_eq!(dial_count_for(&actions, &hk.relay2), 1);
    assert_eq!(dial_count_for(&actions, &hk.relay), 0);
}

#[test]
fn lost_relay_connection_emits_lost_and_reacquires() {
    let mut hk = build(ReservationPolicy::Always, 1, 0);
    let (events, _) = reserve_via_relay(&mut hk, hop_reserve_ok(None), at_unix(10, 1_000));
    assert_eq!(events.len(), 1);

    let relay = hk.relay.clone();
    hk.agent.handle_event(
        &SwarmEvent::ConnectionClosed {
            peer_id: relay.clone(),
        },
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
fn relay_supersede_during_renewal_emits_reservation_lost() {
    let mut hk = build(ReservationPolicy::Always, 1, 0);
    let (events, _) = reserve_via_relay(&mut hk, hop_reserve_ok(Some(1_900)), at_unix(10, 1_000));
    assert!(matches!(
        events.as_slice(),
        [NatEvent::RelayReserved { .. }]
    ));
    drain_actions(&mut hk.agent); // completed exchange's close-write

    // Start renewal, then replace the relay connection before the new
    // reservation exchange completes. The old reservation died with the
    // retired connection and must be withdrawn immediately.
    let renew_at = 10 + 780 * 1_000;
    hk.agent.handle_tick(at_unix(renew_at, 1_790));
    let relay = hk.relay.clone();
    hk.agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            peer_id: relay.clone(),
        },
        at_unix(renew_at + 1, 1_790),
    );

    let events = drain_events(&mut hk.agent);
    assert!(matches!(
        events.as_slice(),
        [NatEvent::RelayReservationLost { relay: lost }] if *lost == relay
    ));
    assert!(hk.agent.active_reservation().is_none());
    assert!(
        !drain_actions(&mut hk.agent)
            .iter()
            .any(|action| matches!(action, NatAction::ResetStream { .. })),
        "supersede cleanup must not reset a stream id on the replacement connection"
    );
}

#[test]
fn when_private_policy_follows_the_reachability_verdict() {
    let mut hk = build(ReservationPolicy::WhenPrivate, 1, 1);

    // While reachability is Unknown, both housekeeping flows start: a
    // reservation (dialable now) and a probe (gather evidence).
    hk.agent.handle_tick(at(0));
    let actions = drain_actions(&mut hk.agent);
    let relay_dial = dial_token_for(&actions, &hk.relay);
    let server_dial = dial_token_for(&actions, &hk.server);
    hk.agent
        .dial_result(relay_dial, Ok(ConnectionId::new(60)), at(1));
    hk.agent
        .dial_result(server_dial, Ok(ConnectionId::new(61)), at(1));
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
    assert!(hk.run_probe(true, 6_000).is_empty());

    // Third public probe: the verdict flips and, in the same cascade, the
    // now-unneeded reservation is released.
    let events = hk.run_probe(true, 12_000);
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
    assert!(hk.run_probe(true, 50_000).is_empty());
    drain_actions(&mut hk.agent); // the finished probe's close-write
    hk.agent.handle_tick(at(100_000));
    let actions = drain_actions(&mut hk.agent);
    assert!(
        actions.is_empty(),
        "no reservation while confidently public: {actions:?}"
    );

    // Flip back to Private: reacquisition begins in the same cascade.
    assert!(hk.run_probe(false, 145_000).is_empty());
    assert!(hk.run_probe(false, 236_000).is_empty());
    hk.agent.handle_tick(at(330_000));
    let events = hk.finish_probe(false, 330_001);
    assert!(matches!(
        events.as_slice(),
        [NatEvent::ReachabilityChanged {
            new: ReachabilityState::Private,
            ..
        }]
    ));
    let actions = drain_actions(&mut hk.agent);
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, NatAction::OpenStream { protocol_id, .. } if protocol_id == HOP_PROTOCOL_ID)),
        "reservation reacquired once private: {actions:?}"
    );
}
