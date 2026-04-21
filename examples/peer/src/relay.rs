//! Relay-coordinated hole-punch mode.
//!
//! This module orchestrates the full Circuit Relay v2 + DCUtR flow
//! described in `holepunch-plan.md`. It is deliberately procedural:
//! one long event loop per role with an explicit phase enum so the
//! state transitions are visible at a glance.
//!
//! The two public entry points are [`run_listen`] (Peer B, reserves on
//! the relay, accepts an incoming circuit, responds to DCUtR, then
//! hole-punches) and [`run_dial`] (Peer A, opens a circuit through the
//! relay, initiates DCUtR, then hole-punches). Shared helpers at the
//! bottom of the file set up the swarm and parse DCUtR observed
//! addresses back into multiaddrs.

use std::error::Error;
use std::thread;
use std::time::{Duration, Instant};

use minip2p_core::{Multiaddr, PeerAddr, PeerId};
use minip2p_dcutr::{DcutrResponder, ResponderEvent, DCUTR_PROTOCOL_ID};
use minip2p_identity::Ed25519Keypair;
use minip2p_quic::{QuicNodeConfig, QuicTransport};
use minip2p_relay::{
    HopReservation, ReservationOutcome, StopResponder, HOP_PROTOCOL_ID, STOP_PROTOCOL_ID,
};
use minip2p_swarm::{Swarm, SwarmBuilder, SwarmEvent};
use minip2p_transport::StreamId;

use crate::cli::print_event;

// ---------------------------------------------------------------------------
// Shared configuration
// ---------------------------------------------------------------------------

/// Poll interval for the event loop (matches the direct-mode module).
const POLL_INTERVAL: Duration = Duration::from_millis(5);
/// Local bind address. Loopback matches the plan's "v1 scope" -- the
/// flow still exercises the full stack against a real relay, just
/// without escaping the host.
const LOCAL_BIND: &str = "127.0.0.1:0";
/// Agent string advertised via Identify.
const AGENT: &str = "minip2p-peer/0.1.0";
/// Top-level deadline for the listener role: reservation + a full
/// circuit + hole-punch should comfortably fit in this window on a
/// local relay.
const LISTEN_DEADLINE: Duration = Duration::from_secs(60);
/// Hole-punch deadline after SYNC is received.
const HOLEPUNCH_DEADLINE: Duration = Duration::from_secs(10);
/// Cadence of responder-side UDP bombardment during hole-punch.
const HOLEPUNCH_INTERVAL: Duration = Duration::from_millis(100);
/// Initial RTT/2 delay on the responder side before UDP bombardment.
/// Per the plan, v1 uses a fixed value; a future refinement will
/// piggy-back measured RTT on the DCUtR exchange.
const RESPONDER_SYNC_DELAY: Duration = Duration::from_millis(50);
/// Payload length used for the relay-ping fallback.
const RELAY_PING_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Listener (Peer B)
// ---------------------------------------------------------------------------

/// Listener-side phase tracker. The outer event loop drives these
/// transitions based on swarm events and outcome polls on the
/// embedded state machines.
enum ListenerPhase {
    /// Dialed the relay; waiting for `ConnectionEstablished`.
    ConnectingToRelay,
    /// Relay connection established; HOP stream opened and feeding the
    /// HopReservation state machine.
    Reserving {
        hop_stream: StreamId,
        flow: HopReservation,
    },
    /// Reservation accepted; waiting for an incoming STOP stream from
    /// the relay (meaning some other peer is trying to reach us).
    WaitingForCircuit,
    /// STOP stream opened by the relay; feeding its bytes into
    /// `StopResponder` until it produces a `CONNECT` request, at which
    /// point we call `accept()` and transition to `DcutrExchange`.
    StopAccepting {
        bridge_stream: StreamId,
        flow: StopResponder,
    },
    /// Bridge accepted; same stream now carries DCUtR frames.
    DcutrExchange {
        bridge_stream: StreamId,
        flow: DcutrResponder,
        /// The source peer id from the STOP CONNECT (Peer A's id).
        remote_peer_id: PeerId,
        /// Populated when DCUtR CONNECT arrives.
        remote_addrs: Vec<Multiaddr>,
    },
    /// DCUtR SYNC received; bombarding remote addresses over raw UDP
    /// until a direct QUIC connection from `remote_peer_id` arrives or
    /// the deadline expires.
    HolePunching {
        bridge_stream: StreamId,
        remote_peer_id: PeerId,
        remote_addrs: Vec<Multiaddr>,
        started_at: Instant,
        last_blast: Option<Instant>,
    },
    /// Hole-punch succeeded; pinging the direct connection.
    PingingDirect { peer_id: PeerId },
    /// Hole-punch failed; falling back to the bridge as a relay ping.
    RelayPingFallback {
        bridge_stream: StreamId,
        remote_peer_id: PeerId,
    },
}

/// Runs the Peer B role: reserve on the relay, accept an incoming
/// circuit, coordinate DCUtR, attempt hole-punch, fall back to relay
/// ping, exit on the first ping RTT measurement.
pub fn run_listen(relay_addr: PeerAddr) -> Result<(), Box<dyn Error>> {
    let mut swarm = build_swarm_with_relay_protocols()?;
    // Listen on our bound UDP port so an inbound direct QUIC connection
    // from Peer A (during hole-punch) can be accepted without rebinding.
    swarm
        .transport_mut()
        .listen_on_bound_addr()
        .map_err(|e| format!("listen failed: {e}"))?;

    let our_addr = swarm
        .transport()
        .local_peer_addr()
        .map_err(|e| format!("local_peer_addr failed: {e}"))?;
    let our_observed: Vec<Multiaddr> = vec![our_addr.transport().clone()];
    println!("[relay-listen] bound={our_addr}");
    println!("[relay-listen] us={}", swarm.local_peer_id());

    let relay_peer_id = relay_addr.peer_id().clone();
    swarm
        .dial(&relay_addr)
        .map_err(|e| format!("dial relay failed: {e}"))?;
    println!("[relay-listen] dialing-relay {relay_addr}");

    let mut phase = ListenerPhase::ConnectingToRelay;
    let deadline = Instant::now() + LISTEN_DEADLINE;

    loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "listener deadline exceeded ({}s) in phase {}",
                LISTEN_DEADLINE.as_secs(),
                phase_name(&phase)
            )
            .into());
        }

        thread::sleep(POLL_INTERVAL);
        let events = swarm
            .poll()
            .map_err(|e| format!("swarm poll failed: {e}"))?;

        for event in events {
            print_event("relay-listen", &event);
            phase = handle_listener_event(
                phase,
                event,
                &mut swarm,
                &relay_peer_id,
                &our_observed,
            )?;
            if matches!(phase, ListenerPhase::PingingDirect { .. }) {
                // PingingDirect is terminal once PingRttMeasured arrives;
                // that is handled inside handle_listener_event too.
            }
        }

        // Non-event-driven transitions (timers).
        phase = tick_listener(phase, &mut swarm, &relay_peer_id)?;
    }
}

/// Runs the Peer A role. Implemented in Step 5.
pub fn run_dial(
    relay_addr: PeerAddr,
    target: PeerId,
) -> Result<(), Box<dyn Error>> {
    let _ = (relay_addr, target);
    Err(
        "relay dial mode is not yet implemented (Step 5 of holepunch-plan.md)"
            .into(),
    )
}

/// Reacts to a single [`SwarmEvent`] and returns the updated phase.
///
/// Each arm is annotated with the corresponding step in the listener
/// state machine described at the top of this module.
fn handle_listener_event(
    phase: ListenerPhase,
    event: SwarmEvent,
    swarm: &mut Swarm<QuicTransport>,
    relay_peer_id: &PeerId,
    our_observed: &[Multiaddr],
) -> Result<ListenerPhase, Box<dyn Error>> {
    match (phase, event) {
        // --- ConnectingToRelay -> Reserving ---------------------------------
        (ListenerPhase::ConnectingToRelay, SwarmEvent::ConnectionEstablished { peer_id })
            if peer_id == *relay_peer_id =>
        {
            // Open a HOP stream to the relay and start RESERVE.
            let hop_stream = swarm
                .open_user_stream(relay_peer_id, HOP_PROTOCOL_ID)
                .map_err(|e| format!("open HOP stream failed: {e}"))?;
            Ok(ListenerPhase::Reserving {
                hop_stream,
                flow: HopReservation::new(),
            })
        }

        // --- Reserving: flush RESERVE once the HOP stream is ready -----------
        (
            ListenerPhase::Reserving {
                hop_stream,
                mut flow,
            },
            SwarmEvent::UserStreamReady {
                stream_id,
                initiated_locally: true,
                ref protocol_id,
                ..
            },
        ) if stream_id == hop_stream && protocol_id == HOP_PROTOCOL_ID => {
            let outbound = flow.take_outbound();
            if !outbound.is_empty() {
                swarm
                    .send_user_stream(relay_peer_id, hop_stream, outbound)
                    .map_err(|e| format!("send HOP RESERVE failed: {e}"))?;
            }
            Ok(ListenerPhase::Reserving { hop_stream, flow })
        }

        // --- Reserving: STATUS response body ---------------------------------
        (
            ListenerPhase::Reserving {
                hop_stream,
                mut flow,
            },
            SwarmEvent::UserStreamData {
                stream_id, data, ..
            },
        ) if stream_id == hop_stream => {
            flow.on_data(&data).map_err(|e| format!("HOP decode: {e}"))?;
            if let Some(outcome) = flow.outcome() {
                match outcome {
                    ReservationOutcome::Accepted { .. } => {
                        println!("[relay-listen] reserved-on-relay");
                        return Ok(ListenerPhase::WaitingForCircuit);
                    }
                    ReservationOutcome::Refused { status, reason } => {
                        return Err(format!(
                            "relay refused reservation: status={status:?} reason={reason}"
                        )
                        .into());
                    }
                }
            }
            Ok(ListenerPhase::Reserving { hop_stream, flow })
        }

        // --- WaitingForCircuit -> StopAccepting -----------------------------
        (
            ListenerPhase::WaitingForCircuit,
            SwarmEvent::UserStreamReady {
                stream_id,
                initiated_locally: false,
                peer_id,
                ref protocol_id,
            },
        ) if peer_id == *relay_peer_id && protocol_id == STOP_PROTOCOL_ID => {
            println!(
                "[relay-listen] incoming-circuit via-relay stream={stream_id}"
            );
            Ok(ListenerPhase::StopAccepting {
                bridge_stream: stream_id,
                flow: StopResponder::new(),
            })
        }

        // --- StopAccepting: drive the StopResponder -------------------------
        (
            ListenerPhase::StopAccepting {
                bridge_stream,
                mut flow,
            },
            SwarmEvent::UserStreamData {
                stream_id, data, ..
            },
        ) if stream_id == bridge_stream => {
            flow.on_data(&data).map_err(|e| format!("STOP decode: {e}"))?;
            if let Some(request) = flow.request().cloned() {
                let remote_peer_id = PeerId::from_bytes(&request.source_peer_id)
                    .map_err(|e| format!("bad STOP source peer id: {e}"))?;
                println!(
                    "[relay-listen] stop-connect-from peer={remote_peer_id}"
                );
                flow.accept().map_err(|e| format!("STOP accept: {e}"))?;
                let outbound = flow.take_outbound();
                if !outbound.is_empty() {
                    swarm
                        .send_user_stream(relay_peer_id, bridge_stream, outbound)
                        .map_err(|e| format!("STOP STATUS:OK send: {e}"))?;
                }
                // Any bytes pipelined behind STOP STATUS:OK belong to DCUtR.
                let bridge_bytes = flow.take_bridge_bytes();
                let dcutr = DcutrResponder::new(our_observed);
                let mut phase = ListenerPhase::DcutrExchange {
                    bridge_stream,
                    flow: dcutr,
                    remote_peer_id,
                    remote_addrs: Vec::new(),
                };
                if !bridge_bytes.is_empty() {
                    phase = feed_dcutr_listener_bytes(
                        phase,
                        &bridge_bytes,
                        swarm,
                        relay_peer_id,
                    )?;
                }
                return Ok(phase);
            }
            Ok(ListenerPhase::StopAccepting {
                bridge_stream,
                flow,
            })
        }

        // --- DcutrExchange: feed bytes through DcutrResponder ---------------
        (
            ListenerPhase::DcutrExchange {
                bridge_stream,
                flow,
                remote_peer_id,
                remote_addrs,
            },
            SwarmEvent::UserStreamData {
                stream_id, data, ..
            },
        ) if stream_id == bridge_stream => {
            let phase = ListenerPhase::DcutrExchange {
                bridge_stream,
                flow,
                remote_peer_id,
                remote_addrs,
            };
            feed_dcutr_listener_bytes(phase, &data, swarm, relay_peer_id)
        }

        // --- HolePunching: did we get a direct connection? ------------------
        (
            ListenerPhase::HolePunching {
                remote_peer_id,
                bridge_stream,
                ..
            },
            SwarmEvent::ConnectionEstablished { peer_id },
        ) if peer_id == remote_peer_id => {
            println!(
                "[relay-listen] direct-connected peer={peer_id} (hole-punch success)"
            );
            swarm
                .ping(&peer_id)
                .map_err(|e| format!("ping on direct conn: {e}"))?;
            let _ = bridge_stream;
            Ok(ListenerPhase::PingingDirect {
                peer_id: remote_peer_id,
            })
        }

        // --- PingingDirect: exit on RTT -------------------------------------
        (
            ListenerPhase::PingingDirect { peer_id },
            SwarmEvent::PingRttMeasured {
                peer_id: who, rtt_ms,
            },
        ) if who == peer_id => {
            println!(
                "[relay-listen] ping-direct peer={peer_id} rtt={rtt_ms}ms -- done"
            );
            std::process::exit(0);
        }

        // --- RelayPingFallback: echo bytes over the bridge ------------------
        (
            ListenerPhase::RelayPingFallback {
                bridge_stream,
                remote_peer_id,
            },
            SwarmEvent::UserStreamData {
                stream_id, data, ..
            },
        ) if stream_id == bridge_stream => {
            // Echo the payload so Peer A measures an RTT.
            swarm
                .send_user_stream(relay_peer_id, bridge_stream, data)
                .map_err(|e| format!("relay-ping echo: {e}"))?;
            Ok(ListenerPhase::RelayPingFallback {
                bridge_stream,
                remote_peer_id,
            })
        }

        // --- Events we don't care about: pass through ------------------------
        (phase, _) => Ok(phase),
    }
}

/// Owned-phase dispatch for DCUtR stream data: the tuple match in
/// `handle_listener_event` can't move the phase in, so the `UserStreamData`
/// arm for the DCUtR phase is handled here via a secondary match in the
/// main event loop caller.
fn feed_dcutr_listener_bytes(
    phase: ListenerPhase,
    bytes: &[u8],
    swarm: &mut Swarm<QuicTransport>,
    relay_peer_id: &PeerId,
) -> Result<ListenerPhase, Box<dyn Error>> {
    let ListenerPhase::DcutrExchange {
        bridge_stream,
        mut flow,
        remote_peer_id,
        mut remote_addrs,
    } = phase
    else {
        return Ok(phase);
    };

    flow.on_data(bytes)
        .map_err(|e| format!("DCUtR decode: {e}"))?;
    let out = flow.take_outbound();
    if !out.is_empty() {
        swarm
            .send_user_stream(relay_peer_id, bridge_stream, out)
            .map_err(|e| format!("DCUtR send: {e}"))?;
    }

    let mut saw_sync = false;
    for event in flow.poll_events() {
        match event {
            ResponderEvent::ConnectReceived {
                remote_addrs: parsed,
                remote_addr_bytes,
            } => {
                if parsed.len() < remote_addr_bytes.len() {
                    eprintln!(
                        "[relay-listen] dcutr-connect-received: {} of {} remote \
                         addrs failed to parse and were ignored",
                        remote_addr_bytes.len() - parsed.len(),
                        remote_addr_bytes.len()
                    );
                }
                remote_addrs = parsed;
                println!(
                    "[relay-listen] dcutr-connect-received addrs={}",
                    remote_addrs.len()
                );
            }
            ResponderEvent::SyncReceived => {
                println!("[relay-listen] dcutr-sync-received -> holepunching");
                saw_sync = true;
            }
        }
    }

    if saw_sync {
        Ok(ListenerPhase::HolePunching {
            bridge_stream,
            remote_peer_id,
            remote_addrs,
            started_at: Instant::now(),
            last_blast: None,
        })
    } else {
        Ok(ListenerPhase::DcutrExchange {
            bridge_stream,
            flow,
            remote_peer_id,
            remote_addrs,
        })
    }
}

/// Handles time-based transitions in the listener: DCUtR bridge data
/// routing and hole-punch UDP bombardment.
fn tick_listener(
    phase: ListenerPhase,
    swarm: &mut Swarm<QuicTransport>,
    relay_peer_id: &PeerId,
) -> Result<ListenerPhase, Box<dyn Error>> {
    match phase {
        ListenerPhase::HolePunching {
            bridge_stream,
            remote_peer_id,
            remote_addrs,
            started_at,
            mut last_blast,
        } => {
            let now = Instant::now();
            let elapsed = now.saturating_duration_since(started_at);

            if elapsed >= HOLEPUNCH_DEADLINE {
                println!(
                    "[relay-listen] hole-punch-timeout -> relay-ping fallback"
                );
                return Ok(ListenerPhase::RelayPingFallback {
                    bridge_stream,
                    remote_peer_id,
                });
            }

            // Per the plan, responder waits RESPONDER_SYNC_DELAY before
            // starting to blast UDP; then sends at HOLEPUNCH_INTERVAL.
            let should_blast = match last_blast {
                None => elapsed >= RESPONDER_SYNC_DELAY,
                Some(t) => now.duration_since(t) >= HOLEPUNCH_INTERVAL,
            };

            if should_blast {
                blast_remote_addrs(swarm, &remote_addrs);
                last_blast = Some(now);
            }

            Ok(ListenerPhase::HolePunching {
                bridge_stream,
                remote_peer_id,
                remote_addrs,
                started_at,
                last_blast,
            })
        }
        other => {
            let _ = (swarm, relay_peer_id);
            Ok(other)
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Builds a swarm with the relay + DCUtR user protocols registered.
fn build_swarm_with_relay_protocols() -> Result<Swarm<QuicTransport>, Box<dyn Error>> {
    let keypair = Ed25519Keypair::generate();
    let transport = QuicTransport::new(QuicNodeConfig::with_keypair(keypair.clone()), LOCAL_BIND)
        .map_err(|e| format!("quic bind failed: {e}"))?;
    let mut swarm = SwarmBuilder::new(&keypair).agent_version(AGENT).build(transport);
    // Advertise + accept the three user protocols the flow needs.
    swarm.add_user_protocol(HOP_PROTOCOL_ID);
    swarm.add_user_protocol(STOP_PROTOCOL_ID);
    swarm.add_user_protocol(DCUTR_PROTOCOL_ID);
    Ok(swarm)
}

/// Sends a random 32-byte UDP payload to every remote address. Per
/// the DCUtR spec these packets serve to open the NAT binding so that
/// inbound QUIC packets from the remote peer can arrive; their
/// content is irrelevant.
fn blast_remote_addrs(swarm: &Swarm<QuicTransport>, addrs: &[Multiaddr]) {
    let payload = random_bytes(RELAY_PING_LEN);
    for addr in addrs {
        if let Err(e) = swarm.transport().send_raw_udp(addr, &payload) {
            eprintln!("[relay-listen] udp-blast to {addr} failed: {e}");
        }
    }
}

/// Short random byte vector. `getrandom` avoids pulling in `rand`.
fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    // Best-effort randomness; if the OS RNG fails we fall back to
    // deterministic zeros rather than panicking, since the payload
    // content doesn't affect hole-punch semantics.
    let _ = getrandom::fill(&mut buf);
    buf
}

/// Human-readable phase name for error messages.
fn phase_name(phase: &ListenerPhase) -> &'static str {
    match phase {
        ListenerPhase::ConnectingToRelay => "ConnectingToRelay",
        ListenerPhase::Reserving { .. } => "Reserving",
        ListenerPhase::WaitingForCircuit => "WaitingForCircuit",
        ListenerPhase::StopAccepting { .. } => "StopAccepting",
        ListenerPhase::DcutrExchange { .. } => "DcutrExchange",
        ListenerPhase::HolePunching { .. } => "HolePunching",
        ListenerPhase::PingingDirect { .. } => "PingingDirect",
        ListenerPhase::RelayPingFallback { .. } => "RelayPingFallback",
    }
}
