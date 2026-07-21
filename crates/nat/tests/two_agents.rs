//! End-to-end integration of two `NatAgent`s over an in-memory relay
//! emulator: B reserves, A connects through the relay, DCUtR runs over the
//! real bridged bytes on both sides, and the race settles either
//! `DirectPunched` (when the "network" lets the punch land) or `Relayed`
//! (when it withholds the direct connection).
//!
//! No QUIC, no UDP — the emulator speaks the actual HOP/STOP wire format
//! and pipes bridge bytes between the two agents.

mod common;

use common::{LISTEN_ADDR, at, drain_events, identify_observed, maddr, peer};

use minip2p_core::{Multiaddr, PeerAddr, PeerId};
use minip2p_nat::{ConnectId, NatAction, NatAgent, NatConfig, NatEvent, Path, ReservationPolicy};
use minip2p_relay::{HOP_PROTOCOL_ID, STOP_PROTOCOL_ID};
use minip2p_swarm::SwarmEvent;
use minip2p_test_support::{ConnectRequestOutcome, PendingConnectId, RelayEmulator};
use minip2p_transport::{ConnectionId, StreamId};

const A_LISTEN: &str = "/ip4/198.51.100.10/udp/4100/quic-v1";
const RELAY_ADDR: &str = "/ip4/203.0.113.1/udp/4001/quic-v1";
/// Each side's public NAT mapping, as the relay's identify reports it.
const A_PUBLIC: &str = "/ip4/8.8.4.4/udp/40001/quic-v1";
const B_PUBLIC: &str = "/ip4/1.1.1.1/udp/40002/quic-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Side {
    A,
    B,
}

/// What the emulated relay knows about one agent-side stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EmuStream {
    /// Fresh HOP stream; the first frame decides RESERVE vs CONNECT.
    Hop,
    /// A's HOP stream after CONNECT: relay side of the (pending) bridge.
    HopBridge,
    /// B's inbound STOP stream.
    Stop,
}

struct World {
    a: NatAgent,
    b: NatAgent,
    a_id: PeerId,
    b_id: PeerId,
    relay_id: PeerId,
    now: u64,
    next_stream: u64,
    next_conn: u64,
    relay_emulator: RelayEmulator,
    /// Roles of relay-facing streams, per side.
    streams: Vec<(Side, StreamId, EmuStream)>,
    /// (A's bridge stream, B's stop stream, pending CONNECT) while the relay
    /// coordinates the STOP handshake.
    bridge: Option<(StreamId, StreamId, PendingConnectId)>,
    bridged: bool,
    /// Whether dials between A and B produce connections.
    deliver_direct: bool,
    /// Sides that have an emulated relay session.
    relay_sessions: Vec<Side>,
    blasts_from_b: usize,
    punch_dials_from_a: usize,
    punch_dials_from_b: usize,
    punch_dial_addrs_from_a: Vec<Multiaddr>,
    punch_dial_addrs_from_b: Vec<Multiaddr>,
}

impl World {
    fn new() -> Self {
        let a_id = peer(b"agent-a");
        let b_id = peer(b"agent-b");
        let relay_id = peer(b"relay-peer");
        let relay_addr = PeerAddr::new(maddr(RELAY_ADDR), relay_id.clone()).unwrap();

        let mut a = NatAgent::new(
            a_id.clone(),
            NatConfig {
                relays: vec![relay_addr.clone()],
                reservation_policy: ReservationPolicy::Never,
                ..NatConfig::default()
            },
        );
        a.set_listen_addrs(&[maddr(A_LISTEN)]);

        let mut b = NatAgent::new(
            b_id.clone(),
            NatConfig {
                relays: vec![relay_addr],
                reservation_policy: ReservationPolicy::Always,
                ..NatConfig::default()
            },
        );
        b.set_listen_addrs(&[maddr(LISTEN_ADDR)]);

        Self {
            a,
            b,
            a_id,
            b_id,
            relay_id,
            now: 0,
            next_stream: 0,
            next_conn: 0,
            relay_emulator: RelayEmulator::new(),
            streams: Vec::new(),
            bridge: None,
            bridged: false,
            deliver_direct: false,
            relay_sessions: Vec::new(),
            blasts_from_b: 0,
            punch_dials_from_a: 0,
            punch_dials_from_b: 0,
            punch_dial_addrs_from_a: Vec::new(),
            punch_dial_addrs_from_b: Vec::new(),
        }
    }

    fn agent(&mut self, side: Side) -> &mut NatAgent {
        match side {
            Side::A => &mut self.a,
            Side::B => &mut self.b,
        }
    }

    fn peer_of(&self, side: Side) -> PeerId {
        match side {
            Side::A => self.a_id.clone(),
            Side::B => self.b_id.clone(),
        }
    }

    /// Runs both agents until neither has pending actions.
    fn pump(&mut self) {
        loop {
            let mut progressed = false;
            for side in [Side::A, Side::B] {
                while let Some(action) = self.agent(side).poll_action() {
                    self.process(side, action);
                    progressed = true;
                }
            }
            if !progressed {
                break;
            }
        }
    }

    /// Advances the shared clock and ticks both agents.
    fn advance(&mut self, ms: u64) {
        self.now += ms;
        let now = at(self.now);
        self.a.handle_tick(now);
        self.b.handle_tick(now);
        self.pump();
    }

    fn process(&mut self, side: Side, action: NatAction) {
        let now = at(self.now);
        match action {
            NatAction::Dial { token, addr } => {
                if addr.peer_id() == &self.relay_id {
                    self.next_conn += 1;
                    let conn = ConnectionId::new(self.next_conn);
                    self.agent(side).dial_result(token, Ok(conn), now);
                    if !self.relay_sessions.contains(&side) {
                        self.relay_sessions.push(side);
                        let relay = self.relay_id.clone();
                        let agent = self.agent(side);
                        agent.handle_event(
                            &SwarmEvent::ConnectionEstablished {
                                conn_id: minip2p_transport::ConnectionId::new(1),
                                peer_id: relay.clone(),
                            },
                            now,
                        );
                        agent.handle_event(
                            &SwarmEvent::PeerReady {
                                peer_id: relay.clone(),
                                protocols: vec![
                                    HOP_PROTOCOL_ID.to_string(),
                                    STOP_PROTOCOL_ID.to_string(),
                                ],
                            },
                            now,
                        );
                        // Identify over the relay connection reports the
                        // side's public mapping — the real-world source of
                        // cross-NAT punch candidates.
                        let public = match side {
                            Side::A => A_PUBLIC,
                            Side::B => B_PUBLIC,
                        };
                        identify_observed(agent, &relay, &maddr(public), now);
                    }
                } else {
                    // A dial toward the other agent.
                    match side {
                        Side::A => {
                            self.punch_dials_from_a += 1;
                            self.punch_dial_addrs_from_a.push(addr.transport().clone());
                        }
                        Side::B => {
                            self.punch_dials_from_b += 1;
                            self.punch_dial_addrs_from_b.push(addr.transport().clone());
                        }
                    }
                    self.next_conn += 1;
                    let conn = ConnectionId::new(self.next_conn);
                    self.agent(side).dial_result(token, Ok(conn), now);
                    if self.deliver_direct {
                        self.establish_direct();
                    }
                }
            }
            NatAction::OpenStream {
                token,
                peer,
                protocol_id,
            } => {
                assert_eq!(peer, self.relay_id, "agents only open streams to the relay");
                assert_eq!(protocol_id, HOP_PROTOCOL_ID);
                self.next_stream += 1;
                let stream = StreamId::new(self.next_stream);
                self.streams.push((side, stream, EmuStream::Hop));
                let relay = self.relay_id.clone();
                let agent = self.agent(side);
                agent.stream_open_result(token, Ok(stream), now);
                agent.handle_event(
                    &SwarmEvent::StreamReady {
                        conn_id: minip2p_transport::ConnectionId::new(1),
                        peer_id: relay,
                        stream_id: stream,
                        protocol_id,
                        initiated_locally: true,
                    },
                    now,
                );
            }
            NatAction::SendStream {
                stream_id, data, ..
            } => self.on_relay_bytes(side, stream_id, data),
            NatAction::SendRandomUdp { .. } => {
                if side == Side::B {
                    self.blasts_from_b += 1;
                }
            }
            NatAction::PromoteBridge {
                token, remote_peer, ..
            } => {
                self.next_conn += 1;
                let conn_id = ConnectionId::new((1 << 63) | self.next_conn);
                let agent = self.agent(side);
                agent.promote_result(token, Ok(conn_id), now);
                agent.handle_event_with_disposition_classified(
                    &SwarmEvent::ConnectionEstablished {
                        peer_id: remote_peer,
                        conn_id,
                    },
                    true,
                    now,
                );
            }
            NatAction::CloseCircuit { .. } => {}
            NatAction::CloseStreamWrite { .. }
            | NatAction::ResetStream { .. }
            | NatAction::Disconnect { .. } => {}
        }
    }

    /// The emulated relay's byte handling.
    fn on_relay_bytes(&mut self, side: Side, stream: StreamId, data: Vec<u8>) {
        let role = self
            .streams
            .iter()
            .find(|(s, id, _)| *s == side && *id == stream)
            .map(|(_, _, role)| *role);
        match role {
            Some(EmuStream::Hop) => match side {
                Side::B => {
                    let reserver = self.peer_of(side);
                    let trailing = self
                        .relay_emulator
                        .on_reserve_request(&reserver, &data)
                        .expect("valid RESERVE request");
                    assert!(trailing.is_empty(), "no bytes follow RESERVE");
                    let response = self.relay_emulator.drain_hop_bytes_for(&reserver);
                    self.deliver(side, stream, response);
                }
                Side::A => {
                    let initiator = self.peer_of(side);
                    let mut initiator_inbox = Vec::new();
                    let outcome = self
                        .relay_emulator
                        .on_connect_request(&initiator, &data, &mut initiator_inbox)
                        .expect("valid CONNECT request");
                    let ConnectRequestOutcome::Bridging {
                        pending_id,
                        target,
                        trailing,
                    } = outcome
                    else {
                        panic!("B must already hold a reservation");
                    };
                    assert_eq!(target, self.b_id);
                    assert!(trailing.is_empty(), "no pipelining before the bridge");
                    assert!(initiator_inbox.is_empty(), "bridge awaits STOP ack");

                    // Mark A's stream as the relay side of the bridge and
                    // open the queued STOP stream toward B.
                    self.set_role(side, stream, EmuStream::HopBridge);
                    self.next_stream += 1;
                    let stop_stream = StreamId::new(self.next_stream);
                    self.streams.push((Side::B, stop_stream, EmuStream::Stop));
                    self.bridge = Some((stream, stop_stream, pending_id));

                    let relay = self.relay_id.clone();
                    self.b.handle_event(
                        &SwarmEvent::StreamReady {
                            conn_id: minip2p_transport::ConnectionId::new(1),
                            peer_id: relay,
                            stream_id: stop_stream,
                            protocol_id: STOP_PROTOCOL_ID.to_string(),
                            initiated_locally: false,
                        },
                        at(self.now),
                    );
                    let stop_connect = self.relay_emulator.drain_stop_bytes_for(&target);
                    self.deliver(Side::B, stop_stream, stop_connect);
                }
            },
            Some(EmuStream::Stop) if !self.bridged => {
                // B's answer to STOP CONNECT.
                let mut initiator_inbox = Vec::new();
                let (a_bridge, _, pending_id) = self.bridge.expect("bridge pending");
                let trailing = self
                    .relay_emulator
                    .on_stop_ack_from_target(pending_id, &self.b_id, &data, &mut initiator_inbox)
                    .expect("B auto-accepts with STOP STATUS:OK");
                self.bridged = true;
                self.deliver(Side::A, a_bridge, initiator_inbox);
                // Anything B pipelined behind its STATUS already belongs to
                // the bridge.
                if !trailing.is_empty() {
                    self.deliver(Side::A, a_bridge, trailing);
                }
            }
            Some(EmuStream::HopBridge) if self.bridged => {
                let (_, b_stop, _) = self.bridge.expect("bridged");
                self.deliver(Side::B, b_stop, data);
            }
            Some(EmuStream::Stop) => {
                // Post-bridge bytes from B flow to A's bridge stream.
                let (a_bridge, _, _) = self.bridge.expect("bridged");
                self.deliver(Side::A, a_bridge, data);
            }
            Some(EmuStream::HopBridge) => {
                panic!("A wrote bridge bytes before the relay bridged")
            }
            None => panic!("write on an unknown stream"),
        }
    }

    fn set_role(&mut self, side: Side, stream: StreamId, role: EmuStream) {
        for entry in &mut self.streams {
            if entry.0 == side && entry.1 == stream {
                entry.2 = role;
            }
        }
    }

    fn deliver(&mut self, side: Side, stream: StreamId, data: Vec<u8>) {
        let relay = self.relay_id.clone();
        let now = at(self.now);
        self.agent(side).handle_event(
            &SwarmEvent::StreamData {
                conn_id: minip2p_transport::ConnectionId::new(1),
                peer_id: relay,
                stream_id: stream,
                data,
            },
            now,
        );
    }

    /// The punch "lands": both sides observe the direct connection.
    fn establish_direct(&mut self) {
        let (a_id, b_id) = (self.a_id.clone(), self.b_id.clone());
        let now = at(self.now);
        self.a.handle_event(
            &SwarmEvent::ConnectionEstablished {
                conn_id: minip2p_transport::ConnectionId::new(1),
                peer_id: b_id,
            },
            now,
        );
        self.b.handle_event(
            &SwarmEvent::ConnectionEstablished {
                conn_id: minip2p_transport::ConnectionId::new(1),
                peer_id: a_id,
            },
            now,
        );
    }

    /// B acquires its reservation through the emulated relay.
    fn settle_reservation(&mut self) {
        self.advance(1);
        let events = drain_events(&mut self.b);
        assert!(
            matches!(events.as_slice(), [NatEvent::RelayReserved { .. }]),
            "B must hold a reservation, got {events:?}"
        );
    }

    /// A starts connecting to B (relay leg only — no direct candidates).
    fn start_connect(&mut self) -> ConnectId {
        let id = self.a.connect(self.b_id.clone(), Vec::new(), at(self.now));
        self.pump();
        id
    }
}

#[test]
fn two_agents_punch_to_a_direct_connection() {
    let mut world = World::new();
    world.settle_reservation();

    let id = world.start_connect();
    // The whole circuit + DCUtR exchange ran inside the pump; A holds a
    // relayed path and has already dialed B's observed address.
    let events = drain_events(&mut world.a);
    assert!(
        matches!(
            events.as_slice(),
            [NatEvent::PathEstablished {
                connect_id,
                peer,
                path: Path::Relayed { relay },
            }]
                if *connect_id == id && peer == &world.b_id && relay == &world.relay_id
        ),
        "A settles a relayed path first, got {events:?}"
    );
    assert_eq!(
        world.punch_dials_from_a, 1,
        "A dialed only B's global relay-observed public mapping"
    );
    assert!(
        world.punch_dial_addrs_from_a.contains(&maddr(B_PUBLIC)),
        "A's punch targets B's public mapping: {:?}",
        world.punch_dial_addrs_from_a
    );
    assert!(
        drain_events(&mut world.b).is_empty(),
        "inbound circuits surface through normal swarm lifecycle events"
    );

    // B's punch-back is blast-only (DCUtR for QUIC: the initiator dials).
    // A responder dial would race A's — when both land, the second
    // connection supersedes the first and scrubs its streams.
    assert_eq!(
        world.punch_dials_from_b, 0,
        "the responder must not dial: {:?}",
        world.punch_dial_addrs_from_b
    );
    world.advance(100);
    assert!(world.blasts_from_b > 0, "B blasts random UDP");

    // Now the network lets a dial land: both sides converge on direct.
    world.deliver_direct = true;
    world.establish_direct();
    world.pump();

    let events = drain_events(&mut world.a);
    assert!(
        matches!(
            events.as_slice(),
            [NatEvent::PathUpgraded {
                connect_id,
                peer,
                from: Path::Relayed { relay },
                to: Path::DirectPunched,
            }]
                if *connect_id == id && peer == &world.b_id && relay == &world.relay_id
        ),
        "A upgrades explicitly, got {events:?}"
    );
    let events = drain_events(&mut world.b);
    assert!(
        matches!(events.as_slice(), [NatEvent::InboundDirectUpgrade { peer }] if *peer == world.a_id),
        "B reports the inbound upgrade, got {events:?}"
    );
}

#[test]
fn two_agents_fall_back_to_the_relay_when_the_punch_never_lands() {
    let mut world = World::new();
    world.settle_reservation();

    let id = world.start_connect();
    drain_events(&mut world.a);
    drain_events(&mut world.b);

    // Walk through all three punch windows (3s each) with no direct
    // connection ever appearing; B's blasts run and exhaust meanwhile.
    let mut a_events = Vec::new();
    for _ in 0..10 {
        world.advance(1_000);
        a_events.extend(drain_events(&mut world.a));
    }
    assert!(world.blasts_from_b > 0, "B blasted during its window");

    let failures = a_events
        .iter()
        .filter(|e| matches!(e, NatEvent::HolePunchFailed { .. }))
        .count();
    assert_eq!(failures, 3, "one failure per punch window: {a_events:?}");
    assert!(
        matches!(
            a_events.last(),
            Some(NatEvent::FellBackToRelay { connect_id, .. }) if *connect_id == id
        ),
        "the relayed path is the final result: {a_events:?}"
    );
    // Neither side emits anything further; the bridge belongs to the apps.
    assert!(drain_events(&mut world.b).is_empty());
    world.advance(60_000);
    assert!(drain_events(&mut world.a).is_empty());
}
