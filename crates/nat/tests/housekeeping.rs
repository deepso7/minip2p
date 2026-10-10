//! Scripted housekeeping tests: AutoNAT confidence aggregation and relay
//! reservation lifecycle, with a fake clock and no I/O.

mod common;

use common::*;

use minip2p_autonat::AUTONAT_PROTOCOL_ID;
use minip2p_core::{PeerAddr, PeerId};
use minip2p_nat::{NatConfig, NatEvent, Now, ReachabilityState, ReservationPolicy};
use minip2p_relay::{HOP_PROTOCOL_ID, Status};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{Bytes, ConnectionId, StreamId};

const SERVER_ADDR: &str = "/ip4/203.0.113.50/udp/4001/quic-v1";
const SERVER2_ADDR: &str = "/ip4/203.0.113.51/udp/4001/quic-v1";
const RELAY2_TRANSPORT_ADDR: &str = "/ip4/203.0.113.2/udp/4001/quic-v1";

struct Hk {
    agent: Node,
    relay: PeerId,
    relay2: PeerId,
    server: PeerId,
    server2: PeerId,
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
    let mut autonat_servers = Vec::new();
    if server_count >= 1 {
        autonat_servers.push(
            PeerAddr::new(maddr(SERVER_ADDR), server.clone())
                .expect("valid AutoNAT server peer address"),
        );
    }
    if server_count >= 2 {
        autonat_servers.push(
            PeerAddr::new(maddr(SERVER2_ADDR), server2.clone())
                .expect("valid second AutoNAT server peer address"),
        );
    }

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
    assert_eq!(wanted.agent.next_timeout(0), Some(0));
    wanted.agent.handle_tick(at(0));
    let relay = wanted.relay.clone();
    assert_eq!(dial_count_for(&drain_actions(&mut wanted.agent), &relay), 1);

    let not_wanted = build(ReservationPolicy::Never, 1, 0);
    assert_eq!(not_wanted.agent.next_timeout(0), None);
}

#[test]
fn confidence_window_flips_once_and_never_flaps_on_one_probe() {
    let mut hk = build(ReservationPolicy::Never, 0, 1);
    assert_eq!(hk.agent.reachability(), ReachabilityState::Unknown);

    // First probe bootstraps the server session.
    hk.agent.handle_tick(at(0));
    drain_actions(&mut hk.agent);
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
    drain_actions(&mut hk.agent);
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
    assert_eq!(hk.agent.next_timeout(10_000), Some(expected_renew - 10_000));
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

    assert_eq!(quic.agent.next_timeout(10), Some(100));
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

    // After the backoff the manager tries the *other* relay.
    hk.agent.handle_tick(at(600));
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
    let mut hk = build(ReservationPolicy::WhenPrivate, 1, 1);

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

    let timeout = hk.agent.next_timeout(3_600_000);
    hk.agent
        .dial_result(reserve_dial, Err("lookup failed".into()), at(3_600_000));
    assert!(drain_actions(&mut hk.agent).is_empty());
    assert!(hk.agent.poll_event().is_none());
    assert_eq!(hk.agent.next_timeout(3_600_000), timeout);
}

#[test]
fn reserve_dial_failed_event_schedules_backoff() {
    let mut hk = build(ReservationPolicy::Always, 1, 0);
    let relay = hk.relay.clone();
    hk.agent.handle_tick(at(0));
    let conn_id = dial_conn_for(&drain_actions(&mut hk.agent), &relay);
    assert!(dial_failed(&mut hk, conn_id, "connection refused", at(6)));
    assert_eq!(
        hk.agent.next_timeout(6),
        Some(NatConfig::default().reservation_retry_backoff_ms),
        "refused reservation dial must back off immediately"
    );
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

    // Past the acquisition deadline (relay_leg_deadline_ms) and the retry
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
    let retry_at = config.relay_leg_deadline_ms + config.reservation_retry_backoff_ms;

    hk.agent.handle_tick(at(0));
    let old = dial_conn_for(&drain_actions(&mut hk.agent), &relay);
    // The first relay never connects; after the backoff the second is dialed.
    hk.agent.handle_tick(at(config.relay_leg_deadline_ms));
    hk.agent.handle_tick(at(retry_at));
    let new = dial_conn_for(&drain_actions(&mut hk.agent), &relay2);

    assert!(dial_failed(&mut hk, old, "timed out", at(retry_at + 1)));

    ready_on(&mut hk, &relay2, new, HOP_PROTOCOL_ID, at(retry_at + 2));
    assert_eq!(hop_open_count(&drain_actions(&mut hk.agent), &relay2), 1);
}
