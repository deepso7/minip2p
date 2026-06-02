//! Relay-coordinated hole-punch mode.
//!
//! The two public entry points are [`run_listen`] (Peer B) and
//! [`run_dial`] (Peer A). Each is written as a linear script against
//! `Swarm::run_until`: dial the relay, run HOP/STOP, run DCUtR, attempt
//! hole-punch, ping. No phase enums; every step is an obvious function
//! call.
//!
//! See `holepunch-plan.md` at the repo root for the full design.

use std::error::Error;
use std::time::{Duration, Instant};

use minip2p_autonat::{
    AUTONAT_PROTOCOL_ID, AutoNatClient, AutoNatServer, Reachability, ResponseStatus,
};
use minip2p_core::{
    DirectPathBook, DirectPathSource, ExternalAddressSource, Multiaddr, PeerAddr, PeerId, Protocol,
    select_direct_candidates,
};
use minip2p_dcutr::{
    DCUTR_PROTOCOL_ID, DcutrInitiator, DcutrResponder, InitiatorOutcome, ResponderEvent,
};
use minip2p_identity::Ed25519Keypair;
use minip2p_quic::{QuicNodeConfig, QuicTransport};
use minip2p_relay::{
    ConnectOutcome, HOP_PROTOCOL_ID, HopConnect, HopReservation, ReservationOutcome,
    STOP_PROTOCOL_ID, StopResponder,
};
use minip2p_swarm::{Swarm, SwarmBuilder, SwarmEvent};
use minip2p_transport::{StreamId, Transport};

use crate::cli::{RunOptions, print_event};
use crate::runtime::{bind_addr, load_keypair};

// ---------------------------------------------------------------------------
// Shared configuration
// ---------------------------------------------------------------------------

const AGENT: &str = "minip2p-peer/0.1.0";
/// Top-level deadline: the whole reservation + circuit + hole-punch
/// flow should complete inside this even when AutoNAT has several
/// candidates to probe before the relay circuit is opened.
const LISTEN_DEADLINE: Duration = Duration::from_secs(120);
/// Hole-punch window after SYNC is received / sent.
///
/// Direct dials succeed in milliseconds on LAN/loopback; real-world NATs may
/// need longer because mapping creation and QUIC handshakes race through two
/// consumer NATs.
const HOLEPUNCH_DEADLINE: Duration = Duration::from_secs(10);
/// Minimum UDP blast cadence during hole-punch.
const HOLEPUNCH_INTERVAL_MIN_MS: u64 = 10;
/// Maximum UDP blast cadence during hole-punch.
const HOLEPUNCH_INTERVAL_MAX_MS: u64 = 200;
/// How often to re-open direct QUIC dials while the hole-punch window is open.
const HOLEPUNCH_REDIAL_INTERVAL: Duration = Duration::from_millis(250);
/// DCUtR paths are short-lived and only used during the active punch window,
/// so the std runner controls retry cadence directly.
const HOLEPUNCH_DIRECT_PATH_RETRY_MS: u64 = 0;
/// Approximation of RTT/2 before the responder starts blasting UDP.
const RESPONDER_SYNC_DELAY: Duration = Duration::from_millis(50);
/// Payload length used by the relay-ping fallback.
const RELAY_PING_LEN: usize = 32;
const AUTONAT_IDENTIFY_GRACE: Duration = Duration::from_secs(2);
const AUTONAT_REQUEST_DEADLINE: Duration = Duration::from_secs(5);
// Client deadline must absorb candidate_count * binds_per_candidate * dialback
// deadline. Generic /dns candidates may try two bind families; /ip4, /ip6,
// /dns4, and /dns6 try one.
const AUTONAT_DIALBACK_DEADLINE: Duration = Duration::from_secs(5);
const STUN_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(2);
const LISTEN_FOREVER: Duration = Duration::from_secs(60 * 60 * 24 * 365);
const RELAY_READY_ATTEMPTS: usize = 3;
const RELAY_READY_ATTEMPT_DEADLINE: Duration = Duration::from_secs(12);
const RELAY_READY_RETRY_BACKOFF: Duration = Duration::from_millis(500);

// ---------------------------------------------------------------------------
// Listener (Peer B): reserve, accept STOP, respond DCUtR, hole-punch
// ---------------------------------------------------------------------------

pub fn run_listen(relay_addr: PeerAddr, options: RunOptions) -> Result<(), Box<dyn Error>> {
    let role = "relay-listen";
    let mut swarm = build_swarm_with_relay_protocols(&options, role)?;
    register_manual_external_addrs(&mut swarm, &options);
    let our_addr = swarm
        .listen_on_bound_addr()
        .map_err(|e| format!("listen failed: {e}"))?;
    println!("[{role}] bound={our_addr}");
    println!("[{role}] us={}", swarm.local_peer_id());
    let stun_candidates = discover_stun_candidates(&mut swarm, role, &options);

    let relay_peer_id = relay_addr.peer_id().clone();
    let deadline = Instant::now() + LISTEN_DEADLINE;

    // --- 1. Relay connection ready -----------------------------------------
    prepare_relay(&mut swarm, role, &relay_addr, &relay_peer_id, deadline)?;

    let initial_candidates = candidate_addrs(
        role,
        our_addr.transport(),
        &confirmed_external_addrs(&swarm),
        relay_observed_addr(&swarm, &relay_peer_id, role),
    );
    let initial_candidates = append_stun_candidates(role, initial_candidates, &stun_candidates);
    let mut our_observed = validate_candidates_with_autonat(
        &mut swarm,
        role,
        &options,
        &initial_candidates,
        deadline,
    )?;
    refresh_relay_after_slow_discovery(
        &mut swarm,
        role,
        &options,
        &relay_addr,
        &relay_peer_id,
        &mut our_observed,
        deadline,
    )?;
    print_candidates(role, &our_observed);

    // --- 2. Reserve a slot on the relay via HOP RESERVE --------------------
    let hop_stream = swarm
        .open_user_stream(&relay_peer_id, HOP_PROTOCOL_ID)
        .map_err(|e| format!("open HOP: {e}"))?;
    wait_user_stream_ready(
        &mut swarm,
        role,
        &relay_peer_id,
        hop_stream,
        HOP_PROTOCOL_ID,
        deadline,
    )?;
    let mut reservation = HopReservation::new();
    send(
        &mut swarm,
        &relay_peer_id,
        hop_stream,
        reservation.take_outbound(),
    )?;

    while reservation.outcome().is_none() {
        let data = wait_user_stream_data(&mut swarm, role, &relay_peer_id, hop_stream, deadline)?;
        reservation
            .on_data(&data)
            .map_err(|e| format!("HOP decode: {e}"))?;
    }
    match reservation.outcome() {
        Some(ReservationOutcome::Accepted { .. }) => {
            println!("[{role}] reserved-on-relay");
        }
        Some(ReservationOutcome::Refused { status, reason }) => {
            return Err(
                format!("relay refused reservation: status={status:?} reason={reason}").into(),
            );
        }
        None => unreachable!(),
    }

    // --- 3. Wait for the relay to push a STOP stream at us ------------------
    let bridge_stream =
        wait_inbound_stream(&mut swarm, role, &relay_peer_id, STOP_PROTOCOL_ID, deadline)?;
    println!("[{role}] incoming-circuit via-relay stream={bridge_stream}");

    // --- 4. STOP responder: accept the CONNECT, keep any pipelined bytes ---
    let mut stop = StopResponder::new();
    let remote_peer_id: PeerId = loop {
        let data =
            wait_user_stream_data(&mut swarm, role, &relay_peer_id, bridge_stream, deadline)?;
        stop.on_data(&data)
            .map_err(|e| format!("STOP decode: {e}"))?;
        if let Some(request) = stop.request() {
            break PeerId::from_bytes(&request.source_peer_id)
                .map_err(|e| format!("bad STOP source peer id: {e}"))?;
        }
    };
    println!("[{role}] stop-connect-from peer={remote_peer_id}");
    stop.accept().map_err(|e| format!("STOP accept: {e}"))?;
    send(
        &mut swarm,
        &relay_peer_id,
        bridge_stream,
        stop.take_outbound(),
    )?;
    let bridge_bytes = stop.take_bridge_bytes();

    // --- 5. DCUtR responder over the same bridge stream --------------------
    let mut dcutr = DcutrResponder::new(&our_observed);
    if !bridge_bytes.is_empty() {
        dcutr
            .on_data(&bridge_bytes)
            .map_err(|e| format!("DCUtR decode (pipelined): {e}"))?;
    }
    send(
        &mut swarm,
        &relay_peer_id,
        bridge_stream,
        dcutr.take_outbound(),
    )?;

    // DCUtR responder events arrive across multiple poll cycles:
    // `ConnectReceived` fires in one call, `SyncReceived` in a later
    // one. We thread the captured remote-addrs through the loop so
    // the CONNECT payload isn't thrown away when the SYNC arrives.
    let mut captured_remote_addrs: Option<Vec<Multiaddr>> = None;
    let remote_addrs: Vec<Multiaddr> = loop {
        if drain_dcutr_responder_events(&mut dcutr, role, &mut captured_remote_addrs) {
            break captured_remote_addrs.take().unwrap_or_default();
        }
        let data =
            wait_user_stream_data(&mut swarm, role, &relay_peer_id, bridge_stream, deadline)?;
        dcutr
            .on_data(&data)
            .map_err(|e| format!("DCUtR decode: {e}"))?;
        send(
            &mut swarm,
            &relay_peer_id,
            bridge_stream,
            dcutr.take_outbound(),
        )?;
    };

    // --- 6. Hole-punch: dial + blast UDP, wait for direct or timeout -------
    println!("[{role}] dcutr-sync-received -> holepunching");
    let punch_start = Instant::now();
    let punch_deadline = punch_start + HOLEPUNCH_DEADLINE;
    let mut remote_paths = remote_path_book(&remote_addrs);
    print_remote_paths(role, &remote_paths);
    dial_direct_candidates(
        &mut swarm,
        role,
        &remote_peer_id,
        &mut remote_paths,
        elapsed_ms(punch_start),
    );
    let mut next_blast = punch_start + RESPONDER_SYNC_DELAY;
    let mut next_redial = punch_start + HOLEPUNCH_REDIAL_INTERVAL;

    // Extract the host+port shape of each address we expect the remote
    // to dial from. We compare against the transport addresses (no
    // peer-id suffix) of any inbound QUIC connection; matching on
    // (IP, port) keeps the check robust whether the remote is on the
    // same host (dials from its bound port) or behind a NAT (dials
    // from its NAT-external mapping, which is what DCUtR CONNECT put
    // in `remote_addrs`).
    //
    // Using an address-match heuristic rather than a raw count
    // comparison prevents unrelated inbound connections -- relay
    // probe-backs, autonat probes, random scanners -- from being
    // misinterpreted as hole-punch success.
    let remote_match_targets: Vec<(String, u16)> = remote_paths
        .addrs()
        .iter()
        .filter_map(extract_ip_port)
        .collect();

    // Check any connections already present (e.g. the remote's direct
    // Initial may have arrived BEFORE we observed the SYNC message on
    // a tight local loopback). Only counts if the source matches.
    let mut saw_inbound_conn = any_source_matches(
        &swarm.transport().active_inbound_connection_sources(),
        &remote_match_targets,
    );

    let outcome = 'outer: loop {
        let now = Instant::now();
        if now >= punch_deadline {
            break HolePunchOutcome::Timeout;
        }
        if now >= next_blast {
            blast_remote_paths(&swarm, &remote_paths, role);
            next_blast = now + next_holepunch_delay();
        }
        if now >= next_redial {
            remote_paths.fail_attempts(elapsed_ms(punch_start));
            dial_direct_candidates(
                &mut swarm,
                role,
                &remote_peer_id,
                &mut remote_paths,
                elapsed_ms(punch_start),
            );
            next_redial = now + HOLEPUNCH_REDIAL_INTERVAL;
        }

        // Drain any events the transport has for us. Event ordering
        // within a tick matters: if we see ConnectionEstablished for
        // the remote peer id, prefer that over the coarser count
        // heuristic.
        for ev in swarm.poll().map_err(|e| format!("holepunch poll: {e}"))? {
            print_event(role, &ev);
            if is_direct_connection_event(&ev, &remote_peer_id) {
                if let SwarmEvent::ConnectionEstablished { peer_id } = ev {
                    break 'outer HolePunchOutcome::DirectConnected(peer_id);
                }
            }
            if is_bridge_closed_event(&ev, &relay_peer_id, bridge_stream) {
                break 'outer HolePunchOutcome::BridgeClosed;
            }
        }

        // Sticky: if we've ever seen an inbound connection from one
        // of the remote's advertised addresses, we know the remote
        // went direct even if the connection has since been torn
        // down (e.g. the remote finished pinging and exited).
        //
        // Unrelated inbound connections (autonat probes, scans) do
        // NOT trigger this because their source address won't match
        // `remote_match_targets`.
        if any_source_matches(
            &swarm.transport().active_inbound_connection_sources(),
            &remote_match_targets,
        ) {
            saw_inbound_conn = true;
        }
        if saw_inbound_conn {
            break HolePunchOutcome::InboundConnectionSeen;
        }

        std::thread::sleep(Duration::from_millis(5));
    };

    // --- 7. Resolve based on the hole-punch outcome -------------------------
    match outcome {
        HolePunchOutcome::DirectConnected(peer_id) => {
            print_direct_path_summary(role, "hole-punch-attempts", &remote_paths);
            println!("[{role}] direct-connected peer={peer_id} (hole-punch success)");
            ping_and_exit(&mut swarm, role, peer_id, deadline)
        }
        HolePunchOutcome::InboundConnectionSeen => {
            if swarm.connected_peers().iter().any(|p| p == &remote_peer_id) {
                println!("[{role}] direct-connected peer={remote_peer_id} (mTLS already verified)");
                return ping_and_exit(&mut swarm, role, remote_peer_id, deadline);
            }

            // The address heuristic fired before Swarm surfaced the verified
            // mTLS identity. Give QUIC one short grace window to complete the
            // identity event so this side can direct-ping too.
            println!(
                "[{role}] inbound-direct-connection detected (hole-punch success; \
                 waiting for verified mTLS identity)"
            );
            let grace_deadline = Instant::now() + Duration::from_secs(2);
            let verified = swarm
                .run_until(grace_deadline, |ev| {
                    print_event(role, ev);
                    matches!(ev, SwarmEvent::ConnectionEstablished { peer_id } if peer_id == &remote_peer_id)
                })
                .map_err(|e| format!("grace poll: {e}"))?;
            match verified {
                Some(SwarmEvent::ConnectionEstablished { peer_id }) => {
                    println!("[{role}] direct-connected peer={peer_id} (mTLS verified)");
                    ping_and_exit(&mut swarm, role, peer_id, deadline)
                }
                _ => {
                    println!("[{role}] grace-elapsed before mTLS identity -> relay-ping fallback");
                    relay_ping_fallback(&mut swarm, role, &relay_peer_id, bridge_stream)
                }
            }
        }
        HolePunchOutcome::BridgeClosed => {
            // Relay closed the circuit. Most likely the remote went
            // direct and no longer needs the bridge; this CLI treats
            // that as a clean terminal state.
            println!(
                "[{role}] bridge-closed (remote likely completed via direct path; \
                 relay no longer needed) -- done"
            );
            Ok(())
        }
        HolePunchOutcome::Timeout => {
            remote_paths.fail_attempts(elapsed_ms(punch_start));
            print_direct_path_summary(role, "hole-punch-failed", &remote_paths);
            println!("[{role}] hole-punch-timeout reason=deadline elapsed -> relay-ping fallback");
            relay_ping_fallback(&mut swarm, role, &relay_peer_id, bridge_stream)
        }
    }
}

/// Terminal states the listener's hole-punch loop can resolve to.
enum HolePunchOutcome {
    /// Saw `ConnectionEstablished` for the remote peer id from mTLS.
    DirectConnected(PeerId),
    /// Saw an inbound QUIC source matching the remote's DCUtR address before
    /// the verified identity reached Swarm. Coarse trigger only; the listener
    /// waits for mTLS identity before direct-pinging.
    InboundConnectionSeen,
    /// Relay closed the bridge stream -- strong signal that the
    /// remote went direct and stopped using the circuit.
    BridgeClosed,
    /// None of the above happened within `HOLEPUNCH_DEADLINE`.
    Timeout,
}

fn is_direct_connection_event(ev: &SwarmEvent, remote: &PeerId) -> bool {
    matches!(ev, SwarmEvent::ConnectionEstablished { peer_id } if peer_id == remote)
}

/// Pulls the (IP host, UDP port) tuple out of a QUIC-style multiaddr,
/// returning `None` if the shape isn't a supported host + udp + quic-v1.
///
/// Host is returned as the multiaddr's display form for the IP/DNS
/// component (e.g. `"127.0.0.1"`, `"2001:db8::1"`, `"example.com"`)
/// so the comparison is protocol-aware without us having to case on
/// every host variant.
fn extract_ip_port(addr: &Multiaddr) -> Option<(String, u16)> {
    use minip2p_core::Protocol;
    let protocols = addr.protocols();
    if protocols.len() < 2 {
        return None;
    }
    let host = match &protocols[0] {
        Protocol::Ip4(b) => {
            format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
        }
        Protocol::Ip6(b) => core::net::Ipv6Addr::from(*b).to_string(),
        Protocol::Dns(v) | Protocol::Dns4(v) | Protocol::Dns6(v) => v.clone(),
        _ => return None,
    };
    let port = match &protocols[1] {
        Protocol::Udp(p) => *p,
        _ => return None,
    };
    Some((host, port))
}

/// Returns `true` if at least one of `sources` has the same `(host, port)`
/// as any of `targets`.
///
/// Used by the listener's hole-punch success heuristic to filter out
/// inbound connections from unrelated peers (autonat probes, scans,
/// etc.). A connection source matches only when it came from an
/// address the remote peer advertised via DCUtR.
fn any_source_matches(sources: &[Multiaddr], targets: &[(String, u16)]) -> bool {
    if targets.is_empty() {
        return false;
    }
    sources
        .iter()
        .filter_map(extract_ip_port)
        .any(|src| targets.iter().any(|tgt| &src == tgt))
}

fn is_bridge_closed_event(
    ev: &SwarmEvent,
    relay_peer_id: &PeerId,
    bridge_stream: StreamId,
) -> bool {
    matches!(
        ev,
        SwarmEvent::UserStreamRemoteWriteClosed { peer_id, stream_id }
            if peer_id == relay_peer_id && *stream_id == bridge_stream
    ) || matches!(
        ev,
        SwarmEvent::UserStreamClosed { peer_id, stream_id }
            if peer_id == relay_peer_id && *stream_id == bridge_stream
    )
}

// ---------------------------------------------------------------------------
// Dialer (Peer A): HOP CONNECT, DCUtR initiator, direct-dial, or fallback
// ---------------------------------------------------------------------------

pub fn run_dial(
    relay_addr: PeerAddr,
    target: PeerId,
    options: RunOptions,
) -> Result<(), Box<dyn Error>> {
    let role = "relay-dial";
    let mut swarm = build_swarm_with_relay_protocols(&options, role)?;
    register_manual_external_addrs(&mut swarm, &options);
    let our_addr = swarm
        .listen_on_bound_addr()
        .map_err(|e| format!("listen failed: {e}"))?;
    println!("[{role}] bound={our_addr}");
    println!("[{role}] us={}", swarm.local_peer_id());
    println!("[{role}] target={target}");
    let stun_candidates = discover_stun_candidates(&mut swarm, role, &options);

    let relay_peer_id = relay_addr.peer_id().clone();
    let deadline = Instant::now() + LISTEN_DEADLINE;

    // --- 1. Relay connection ready -----------------------------------------
    prepare_relay(&mut swarm, role, &relay_addr, &relay_peer_id, deadline)?;

    let initial_candidates = candidate_addrs(
        role,
        our_addr.transport(),
        &confirmed_external_addrs(&swarm),
        relay_observed_addr(&swarm, &relay_peer_id, role),
    );
    let initial_candidates = append_stun_candidates(role, initial_candidates, &stun_candidates);
    let mut our_observed = validate_candidates_with_autonat(
        &mut swarm,
        role,
        &options,
        &initial_candidates,
        deadline,
    )?;
    refresh_relay_after_slow_discovery(
        &mut swarm,
        role,
        &options,
        &relay_addr,
        &relay_peer_id,
        &mut our_observed,
        deadline,
    )?;
    print_candidates(role, &our_observed);

    // --- 2. HOP CONNECT to `target` through the relay ----------------------
    let hop_stream = swarm
        .open_user_stream(&relay_peer_id, HOP_PROTOCOL_ID)
        .map_err(|e| format!("open HOP: {e}"))?;
    wait_user_stream_ready(
        &mut swarm,
        role,
        &relay_peer_id,
        hop_stream,
        HOP_PROTOCOL_ID,
        deadline,
    )?;
    let mut hop = HopConnect::new(target.to_bytes());
    send(&mut swarm, &relay_peer_id, hop_stream, hop.take_outbound())?;

    while hop.outcome().is_none() {
        let data = wait_user_stream_data(&mut swarm, role, &relay_peer_id, hop_stream, deadline)?;
        hop.on_data(&data).map_err(|e| format!("HOP decode: {e}"))?;
    }
    match hop.outcome() {
        Some(ConnectOutcome::Bridged { .. }) => {
            println!("[{role}] bridge-established via-relay");
        }
        Some(ConnectOutcome::Refused { status, reason }) => {
            return Err(format!("relay refused CONNECT: status={status:?} reason={reason}").into());
        }
        None => unreachable!(),
    }
    let bridge_stream = hop_stream; // same stream, now carrying DCUtR bytes
    let bridge_bytes = hop.take_bridge_bytes();

    // --- 3. DCUtR initiator over the bridge --------------------------------
    let mut dcutr = DcutrInitiator::new(&our_observed);
    let dcutr_sent_at = Instant::now();
    send(
        &mut swarm,
        &relay_peer_id,
        bridge_stream,
        dcutr.take_outbound(),
    )?;
    if !bridge_bytes.is_empty() {
        dcutr
            .on_data(&bridge_bytes, 0)
            .map_err(|e| format!("DCUtR decode (pipelined): {e}"))?;
    }

    let (remote_addrs, rtt_ms) = loop {
        if let Some(outcome) = dcutr.outcome().cloned() {
            let InitiatorOutcome::DialNow {
                remote_addrs,
                remote_addr_bytes,
                rtt_ms,
            } = outcome;
            if remote_addrs.len() < remote_addr_bytes.len() {
                eprintln!(
                    "[{role}] dcutr-reply: {} of {} addrs unparsable, ignoring",
                    remote_addr_bytes.len() - remote_addrs.len(),
                    remote_addr_bytes.len()
                );
            }
            break (remote_addrs, rtt_ms);
        }
        let data =
            wait_user_stream_data(&mut swarm, role, &relay_peer_id, bridge_stream, deadline)?;
        let elapsed_ms = dcutr_sent_at.elapsed().as_millis() as u64;
        dcutr
            .on_data(&data, elapsed_ms)
            .map_err(|e| format!("DCUtR decode: {e}"))?;
    };
    println!(
        "[{role}] dcutr-dialnow addrs={} rtt={rtt_ms}ms",
        remote_addrs.len()
    );
    let mut remote_paths = remote_path_book(&remote_addrs);
    print_remote_paths(role, &remote_paths);

    // --- 4. Flush SYNC and dial every observed remote address in parallel --
    dcutr
        .send_sync()
        .map_err(|e| format!("DCUtR send_sync: {e}"))?;
    send(
        &mut swarm,
        &relay_peer_id,
        bridge_stream,
        dcutr.take_outbound(),
    )?;

    let punch_start = Instant::now();
    dial_direct_candidates(
        &mut swarm,
        role,
        &target,
        &mut remote_paths,
        elapsed_ms(punch_start),
    );

    // --- 5. Wait for direct connection or hole-punch timeout ---------------
    let punched = wait_for_direct_with_udp_blast(
        &mut swarm,
        role,
        &target,
        &mut remote_paths,
        punch_start,
        punch_start + HOLEPUNCH_DEADLINE,
    )?;

    // --- 6. Direct ping or relay-ping fallback -----------------------------
    if punched {
        println!("[{role}] direct-connected peer={target} (hole-punch success)");
        ping_and_exit(&mut swarm, role, target, deadline)
    } else {
        println!("[{role}] hole-punch-timeout reason=deadline elapsed -> relay-ping fallback");
        let payload = random_bytes(RELAY_PING_LEN);
        let sent_at = Instant::now();
        send(&mut swarm, &relay_peer_id, bridge_stream, payload.clone())?;
        loop {
            let data =
                wait_user_stream_data(&mut swarm, role, &relay_peer_id, bridge_stream, deadline)?;
            if data == payload {
                let rtt = sent_at.elapsed().as_millis();
                println!("[{role}] ping-via-relay peer={target} rtt={rtt}ms -- done");
                return Ok(());
            }
            // Not our echo; keep waiting.
        }
    }
}

// ---------------------------------------------------------------------------
// AutoNAT service: public helper peer for reachability probes
// ---------------------------------------------------------------------------

pub fn run_autonat_server(options: RunOptions) -> Result<(), Box<dyn Error>> {
    let role = "autonat";
    let keypair = load_keypair(&options, role)?;
    let mut swarm = build_autonat_swarm(&options, &keypair)?;
    let peer_addr = swarm
        .listen_on_bound_addr()
        .map_err(|e| format!("listen failed: {e}"))?;
    println!("[{role}] bound={peer_addr}");
    println!("[{role}] us={}", swarm.local_peer_id());
    eprintln!("[{role}] waiting for AutoNAT probes (Ctrl-C to stop)");

    let deadline = Instant::now() + LISTEN_FOREVER;
    while Instant::now() < deadline {
        let ev = swarm
            .run_until(deadline, |ev| {
                print_event(role, ev);
                matches!(
                    ev,
                    SwarmEvent::UserStreamReady {
                        protocol_id,
                        initiated_locally: false,
                        ..
                    } if protocol_id == AUTONAT_PROTOCOL_ID
                )
            })
            .map_err(|e| format!("autonat wait stream: {e}"))?;

        let Some(SwarmEvent::UserStreamReady {
            peer_id, stream_id, ..
        }) = ev
        else {
            break;
        };

        if let Err(e) = handle_autonat_request(&mut swarm, role, peer_id, stream_id) {
            eprintln!("[{role}] request-failed stream={stream_id} reason={e}");
        }
    }

    Ok(())
}

fn handle_autonat_request(
    swarm: &mut Swarm<QuicTransport>,
    role: &str,
    requester_peer: PeerId,
    stream_id: StreamId,
) -> Result<(), Box<dyn Error>> {
    let mut server = AutoNatServer::new();
    let request_deadline = Instant::now() + AUTONAT_REQUEST_DEADLINE;
    let request = loop {
        let data =
            wait_user_stream_data(swarm, role, &requester_peer, stream_id, request_deadline)?;
        server
            .on_data(&data)
            .map_err(|e| format!("AutoNAT decode: {e}"))?;
        if let Some(request) = server.request().cloned() {
            break request;
        }
    };

    println!(
        "[{role}] probe-request peer={} addrs={}",
        request.peer_id,
        request.addrs.len()
    );
    if request.addrs.len() < request.raw_addrs.len() {
        eprintln!(
            "[{role}] probe-request: {} of {} addrs parsed; unsupported addrs ignored",
            request.addrs.len(),
            request.raw_addrs.len()
        );
    }

    if request.peer_id != requester_peer {
        server.respond_error(
            ResponseStatus::BadRequest,
            "AutoNAT request peer id did not match stream peer",
        );
        send(swarm, &requester_peer, stream_id, server.take_outbound())?;
        println!("[{role}] probe-rejected reason=peer-id-mismatch");
        return Ok(());
    }

    let mut dialable = Vec::new();
    for addr in &request.addrs {
        match dialback_candidate(&request.peer_id, addr, AUTONAT_DIALBACK_DEADLINE) {
            Ok(true) => {
                println!("[{role}] dialback-success addr={addr}");
                push_unique(&mut dialable, addr.clone());
            }
            Ok(false) => println!("[{role}] dialback-timeout addr={addr}"),
            Err(e) => eprintln!("[{role}] dialback-bad-addr addr={addr} reason={e}"),
        }
    }

    if !dialable.is_empty() {
        server.respond_public(&dialable);
        println!(
            "[{role}] probe-public peer={} addrs={}",
            request.peer_id,
            dialable.len()
        );
    } else {
        server.respond_error(ResponseStatus::DialError, "dialback deadline elapsed");
        println!(
            "[{role}] probe-private peer={} reason=timeout",
            request.peer_id
        );
    }

    send(swarm, &requester_peer, stream_id, server.take_outbound())
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn prepare_relay(
    swarm: &mut Swarm<QuicTransport>,
    role: &str,
    relay_addr: &PeerAddr,
    relay_peer_id: &PeerId,
    deadline: Instant,
) -> Result<(), Box<dyn Error>> {
    let mut last_protocols = Vec::new();
    for attempt in 1..=RELAY_READY_ATTEMPTS {
        swarm
            .dial(relay_addr)
            .map_err(|e| format!("dial relay attempt {attempt}: {e}"))?;
        println!("[{role}] dialing-relay attempt={attempt} {relay_addr}");

        let attempt_deadline =
            earlier_deadline(Instant::now() + RELAY_READY_ATTEMPT_DEADLINE, deadline);
        let protocols =
            wait_relay_protocols_after_dial(swarm, role, relay_peer_id, attempt_deadline)?;
        let has_hop = protocols.iter().any(|p| p == HOP_PROTOCOL_ID);
        println!(
            "[{role}] relay-ready attempt={attempt} hop={has_hop} protocols=[{}]",
            protocols.join(",")
        );
        if has_hop {
            return Ok(());
        }

        last_protocols = protocols;
        eprintln!(
            "[{role}] relay-hop-not-advertised attempt={attempt}; retrying after relay readiness backoff"
        );
        retry_relay_connection(swarm, role, relay_peer_id)?;
    }

    Err(format!(
        "relay did not advertise {HOP_PROTOCOL_ID} after {RELAY_READY_ATTEMPTS} attempts; advertised=[{}]",
        last_protocols.join(",")
    )
    .into())
}

fn wait_relay_protocols_after_dial(
    swarm: &mut Swarm<QuicTransport>,
    role: &str,
    peer_id: &PeerId,
    deadline: Instant,
) -> Result<Vec<String>, Box<dyn Error>> {
    let ev = swarm
        .run_until(deadline, |ev| {
            if !is_benign_retry_close_error(ev) {
                print_event(role, ev);
            }
            matches!(ev, SwarmEvent::IdentifyReceived { peer_id: p, .. } if p == peer_id)
                || matches!(ev, SwarmEvent::PeerReady { peer_id: p, .. } if p == peer_id)
        })
        .map_err(|e| format!("wait-relay-protocols: {e}"))?
        .ok_or_else(|| {
            format!("deadline exceeded before relay peer {peer_id} advertised protocols")
        })?;

    match ev {
        SwarmEvent::IdentifyReceived { info, .. } => Ok(info.protocols),
        SwarmEvent::PeerReady { protocols, .. } => Ok(protocols),
        _ => unreachable!(),
    }
}

fn retry_relay_connection(
    swarm: &mut Swarm<QuicTransport>,
    role: &str,
    relay_peer_id: &PeerId,
) -> Result<(), Box<dyn Error>> {
    if let Err(e) = swarm.disconnect(relay_peer_id) {
        eprintln!("[{role}] relay-disconnect-for-retry failed: {e}");
    }

    let retry_deadline = Instant::now() + RELAY_READY_RETRY_BACKOFF;
    let _ = swarm
        .run_until(retry_deadline, |ev| {
            if !is_benign_retry_close_error(ev) {
                print_event(role, ev);
            }
            false
        })
        .map_err(|e| format!("relay retry drain: {e}"))?;
    Ok(())
}

fn refresh_relay_after_slow_discovery(
    swarm: &mut Swarm<QuicTransport>,
    role: &str,
    options: &RunOptions,
    relay_addr: &PeerAddr,
    relay_peer_id: &PeerId,
    candidates: &mut Vec<Multiaddr>,
    deadline: Instant,
) -> Result<(), Box<dyn Error>> {
    if options.autonat.is_none() {
        return Ok(());
    }

    println!("[{role}] refreshing-relay after=autonat");
    prepare_relay(swarm, role, relay_addr, relay_peer_id, deadline)?;

    if let Some(addr) = relay_observed_addr(swarm, relay_peer_id, role) {
        let before = candidates.len();
        push_unique(candidates, addr.clone());
        if candidates.len() > before {
            println!("[{role}] candidate-added source=identify-observed-refresh addr={addr}");
        }
    }

    Ok(())
}

fn is_benign_retry_close_error(ev: &SwarmEvent) -> bool {
    matches!(
        ev,
        SwarmEvent::Error(error)
            if error.detail.contains("close on connection")
                && error.detail.contains("close error: Done")
    )
}

fn earlier_deadline(a: Instant, b: Instant) -> Instant {
    if a <= b { a } else { b }
}

/// Wait for `ConnectionEstablished` with `peer_id`.
fn wait_connected(
    swarm: &mut Swarm<QuicTransport>,
    role: &str,
    peer_id: &PeerId,
    deadline: Instant,
) -> Result<(), Box<dyn Error>> {
    let found = swarm
        .run_until(deadline, |ev| {
            print_event(role, ev);
            matches!(ev, SwarmEvent::ConnectionEstablished { peer_id: p } if p == peer_id)
        })
        .map_err(|e| format!("wait-connected: {e}"))?;
    found
        .map(|_| ())
        .ok_or_else(|| format!("deadline exceeded before connection to {peer_id}").into())
}

/// Wait for a locally-initiated `UserStreamReady` on a specific peer stream.
fn wait_user_stream_ready(
    swarm: &mut Swarm<QuicTransport>,
    role: &str,
    peer_id: &PeerId,
    stream_id: StreamId,
    protocol_id: &str,
    deadline: Instant,
) -> Result<(), Box<dyn Error>> {
    let found = swarm
        .run_until(deadline, |ev| {
            print_event(role, ev);
            matches!(
                ev,
                SwarmEvent::UserStreamReady {
                    peer_id: p,
                    stream_id: s,
                    protocol_id: pid,
                    initiated_locally: true,
                } if p == peer_id && *s == stream_id && pid == protocol_id
            ) || matches!(
                ev,
                SwarmEvent::UserStreamClosed { peer_id: p, stream_id: s }
                    if p == peer_id && *s == stream_id
            ) || matches!(
                ev,
                SwarmEvent::Error(error)
                    if error.peer_id.as_ref() == Some(peer_id)
                        && error.detail.contains(&format!("stream {stream_id}"))
            )
        })
        .map_err(|e| format!("wait-user-stream-ready: {e}"))?;
    match found {
        Some(SwarmEvent::UserStreamReady { .. }) => Ok(()),
        Some(SwarmEvent::UserStreamClosed { .. }) => {
            Err(format!("stream {stream_id} closed before becoming ready").into())
        }
        Some(SwarmEvent::Error(error)) => Err(format!(
            "stream {stream_id} failed before becoming ready: {:?}: {}",
            error.kind, error.detail
        )
        .into()),
        Some(_) => unreachable!(),
        None => Err(format!("deadline exceeded before stream {stream_id} ready").into()),
    }
}

/// Wait for an inbound (remotely-initiated) user stream for `protocol_id`
/// from `peer_id`. Returns the allocated stream id.
fn wait_inbound_stream(
    swarm: &mut Swarm<QuicTransport>,
    role: &str,
    peer_id: &PeerId,
    protocol_id: &str,
    deadline: Instant,
) -> Result<StreamId, Box<dyn Error>> {
    let ev = swarm
        .run_until(deadline, |ev| {
            print_event(role, ev);
            matches!(
                ev,
                SwarmEvent::UserStreamReady {
                    peer_id: p,
                    initiated_locally: false,
                    protocol_id: pid,
                    ..
                } if p == peer_id && pid == protocol_id
            )
        })
        .map_err(|e| format!("wait-inbound-stream: {e}"))?
        .ok_or_else(|| format!("deadline exceeded before inbound {protocol_id}"))?;
    let SwarmEvent::UserStreamReady { stream_id, .. } = ev else {
        unreachable!()
    };
    Ok(stream_id)
}

/// Wait for the next `UserStreamData` event on a specific peer stream,
/// returning the data payload.
fn wait_user_stream_data(
    swarm: &mut Swarm<QuicTransport>,
    role: &str,
    peer_id: &PeerId,
    stream_id: StreamId,
    deadline: Instant,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let ev = swarm
        .run_until(deadline, |ev| {
            print_event(role, ev);
            matches!(
                ev,
                SwarmEvent::UserStreamData { peer_id: p, stream_id: s, .. }
                    if p == peer_id && *s == stream_id
            )
        })
        .map_err(|e| format!("wait-user-stream-data: {e}"))?
        .ok_or_else(|| format!("deadline exceeded before data on stream {stream_id}"))?;
    let SwarmEvent::UserStreamData { data, .. } = ev else {
        unreachable!()
    };
    Ok(data)
}

/// Drains any pending DCUtR responder events into the caller's
/// `captured` slot. Returns `true` when `SyncReceived` has fired
/// (i.e. the responder flow is complete).
///
/// `captured` is threaded by reference because `ConnectReceived` and
/// `SyncReceived` can arrive in separate poll cycles -- persisting the
/// captured remote addresses across calls is essential so they aren't
/// lost by the time SYNC arrives.
fn drain_dcutr_responder_events(
    dcutr: &mut DcutrResponder,
    role: &str,
    captured: &mut Option<Vec<Multiaddr>>,
) -> bool {
    let mut sync = false;
    for ev in dcutr.poll_events() {
        match ev {
            ResponderEvent::ConnectReceived {
                remote_addrs,
                remote_addr_bytes,
            } => {
                if remote_addrs.len() < remote_addr_bytes.len() {
                    eprintln!(
                        "[{role}] dcutr-connect-received: {} of {} remote addrs \
                         failed to parse and were ignored",
                        remote_addr_bytes.len() - remote_addrs.len(),
                        remote_addr_bytes.len()
                    );
                }
                println!(
                    "[{role}] dcutr-connect-received addrs={}",
                    remote_addrs.len()
                );
                *captured = Some(remote_addrs);
            }
            ResponderEvent::SyncReceived => sync = true,
        }
    }
    sync
}

fn remote_path_book(addrs: &[Multiaddr]) -> DirectPathBook {
    let mut book = DirectPathBook::new().with_retry_interval_ms(HOLEPUNCH_DIRECT_PATH_RETRY_MS);
    for addr in addrs.iter().rev() {
        book.insert(DirectPathSource::Dcutr, addr.clone(), 0);
    }
    book
}

fn dial_direct_candidates(
    swarm: &mut Swarm<QuicTransport>,
    role: &str,
    peer_id: &PeerId,
    paths: &mut DirectPathBook,
    now_ms: u64,
) {
    let addrs = paths.begin_attempts(now_ms);
    if addrs.is_empty() {
        println!("[{role}] direct-dial-skipped reason=no-path-ready");
        return;
    }

    for addr in addrs {
        match PeerAddr::new(addr.clone(), peer_id.clone()) {
            Ok(peer_addr) => match swarm.dial(&peer_addr) {
                Ok(_) => {
                    let attempts = path_attempts(paths, &addr).unwrap_or_default();
                    println!("[{role}] direct-dial-attempt attempt={attempts} {peer_addr}");
                }
                Err(e) => eprintln!("[{role}] direct-dial-failed addr={peer_addr} reason={e}"),
            },
            Err(e) => eprintln!("[{role}] bad PeerAddr for {addr}: {e}"),
        }
    }
}

fn wait_for_direct_with_udp_blast(
    swarm: &mut Swarm<QuicTransport>,
    role: &str,
    peer_id: &PeerId,
    paths: &mut DirectPathBook,
    started_at: Instant,
    deadline: Instant,
) -> Result<bool, Box<dyn Error>> {
    let mut next_blast = Instant::now();
    let mut next_redial = started_at + HOLEPUNCH_REDIAL_INTERVAL;
    loop {
        let now = Instant::now();
        if now >= deadline {
            paths.fail_attempts(elapsed_ms(started_at));
            print_direct_path_summary(role, "hole-punch-failed", paths);
            return Ok(false);
        }
        if now >= next_blast {
            blast_remote_paths(swarm, paths, role);
            next_blast = now + next_holepunch_delay();
        }
        if now >= next_redial {
            paths.fail_attempts(elapsed_ms(started_at));
            dial_direct_candidates(swarm, role, peer_id, paths, elapsed_ms(started_at));
            next_redial = now + HOLEPUNCH_REDIAL_INTERVAL;
        }

        for ev in swarm.poll().map_err(|e| format!("holepunch poll: {e}"))? {
            print_event(role, &ev);
            if matches!(&ev, SwarmEvent::ConnectionEstablished { peer_id: p } if p == peer_id) {
                print_direct_path_summary(role, "hole-punch-attempts", paths);
                return Ok(true);
            }
        }

        std::thread::sleep(Duration::from_millis(5));
    }
}

fn relay_ping_fallback(
    swarm: &mut Swarm<QuicTransport>,
    role: &str,
    relay_peer_id: &PeerId,
    bridge_stream: StreamId,
) -> Result<(), Box<dyn Error>> {
    // Wait up to ~15s for either an echo payload from Peer A or the bridge to
    // close (meaning A gave up). Longer than the hole-punch deadline because
    // the relay's own idle-circuit GC can take several seconds -- but bounded
    // so we don't hang forever if something goes wrong.
    let fallback_deadline = Instant::now() + Duration::from_secs(15);
    let ev = swarm
        .run_until(fallback_deadline, |ev| {
            print_event(role, ev);
            matches!(
                ev,
                SwarmEvent::UserStreamData { peer_id, stream_id: s, .. }
                    if peer_id == relay_peer_id && *s == bridge_stream
            ) || is_bridge_closed_event(ev, relay_peer_id, bridge_stream)
        })
        .map_err(|e| format!("fallback poll: {e}"))?;

    match ev {
        Some(SwarmEvent::UserStreamData { data, .. }) => {
            send(swarm, relay_peer_id, bridge_stream, data)?;
            println!("[{role}] relay-ping-echoed -- done");
            Ok(())
        }
        Some(_) => {
            println!("[{role}] bridge-closed during fallback -- done");
            Ok(())
        }
        None => Err("fallback deadline exceeded before any bridge activity".into()),
    }
}

/// Send `data` on `stream_id` if non-empty; no-op otherwise.
fn send(
    swarm: &mut Swarm<QuicTransport>,
    peer_id: &PeerId,
    stream_id: StreamId,
    data: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    if data.is_empty() {
        return Ok(());
    }
    swarm
        .send_user_stream(peer_id, stream_id, data)
        .map_err(|e| format!("send_user_stream: {e}").into())
}

/// Ping `peer_id` and wait for the RTT. Prints the result and returns.
fn ping_and_exit(
    swarm: &mut Swarm<QuicTransport>,
    role: &str,
    peer_id: PeerId,
    deadline: Instant,
) -> Result<(), Box<dyn Error>> {
    swarm.ping(&peer_id).map_err(|e| format!("ping: {e}"))?;
    let ev = swarm
        .run_until(deadline, |ev| {
            print_event(role, ev);
            matches!(ev, SwarmEvent::PingRttMeasured { peer_id: p, .. } if p == &peer_id)
        })
        .map_err(|e| format!("wait-rtt: {e}"))?
        .ok_or("deadline exceeded before ping rtt arrived")?;
    let SwarmEvent::PingRttMeasured { rtt_ms, .. } = ev else {
        unreachable!()
    };
    println!("[{role}] ping-direct peer={peer_id} rtt={rtt_ms}ms -- done");
    Ok(())
}

/// Builds a swarm with the relay + DCUtR user protocols registered.
fn build_swarm_with_relay_protocols(
    options: &RunOptions,
    role: &str,
) -> Result<Swarm<QuicTransport>, Box<dyn Error>> {
    let keypair = load_keypair(options, role)?;
    let bind_addr = bind_addr(options)?;
    let transport = QuicTransport::new(QuicNodeConfig::new(keypair.clone()), &bind_addr)
        .map_err(|e| format!("quic bind: {e}"))?;
    let mut swarm = SwarmBuilder::new(&keypair)
        .agent_version(AGENT)
        .build(transport);
    swarm.add_user_protocol(HOP_PROTOCOL_ID);
    swarm.add_user_protocol(STOP_PROTOCOL_ID);
    swarm.add_user_protocol(DCUTR_PROTOCOL_ID);
    swarm.add_user_protocol(AUTONAT_PROTOCOL_ID);
    Ok(swarm)
}

fn build_autonat_swarm(
    options: &RunOptions,
    keypair: &Ed25519Keypair,
) -> Result<Swarm<QuicTransport>, Box<dyn Error>> {
    let bind_addr = bind_addr(options)?;
    let transport = QuicTransport::new(QuicNodeConfig::new(keypair.clone()), &bind_addr)
        .map_err(|e| format!("quic bind: {e}"))?;
    let mut swarm = SwarmBuilder::new(keypair)
        .agent_version(AGENT)
        .build(transport);
    swarm.add_user_protocol(AUTONAT_PROTOCOL_ID);
    Ok(swarm)
}

fn register_manual_external_addrs(swarm: &mut Swarm<QuicTransport>, options: &RunOptions) {
    for addr in &options.external_addrs {
        swarm.add_external_address(addr.clone());
    }
}

fn confirmed_external_addrs(swarm: &Swarm<QuicTransport>) -> Vec<Multiaddr> {
    swarm
        .external_addresses()
        .iter()
        .map(|entry| entry.addr.clone())
        .collect()
}

fn discover_stun_candidates(
    swarm: &mut Swarm<QuicTransport>,
    role: &str,
    options: &RunOptions,
) -> Vec<Multiaddr> {
    let mut candidates = Vec::new();
    for server in &options.stun_servers {
        println!("[{role}] stun-probing server={server}");
        match swarm
            .transport_mut()
            .discover_external_addr_stun(server, STUN_DISCOVERY_TIMEOUT)
        {
            Ok(addr) => {
                if candidates.iter().any(|existing| existing == &addr) {
                    println!("[{role}] stun-candidate-duplicate server={server} addr={addr}");
                } else {
                    println!("[{role}] stun-candidate-added server={server} addr={addr}");
                    candidates.push(addr);
                }
            }
            Err(e) => {
                eprintln!("[{role}] stun-probe-failed server={server} reason={e}");
            }
        }
    }
    candidates
}

fn append_stun_candidates(
    role: &str,
    mut candidates: Vec<Multiaddr>,
    stun_candidates: &[Multiaddr],
) -> Vec<Multiaddr> {
    for addr in stun_candidates {
        let before = candidates.len();
        push_unique(&mut candidates, addr.clone());
        if candidates.len() > before {
            println!("[{role}] candidate-added source=stun addr={addr}");
        } else {
            println!("[{role}] candidate-skipped source=stun addr={addr} reason=duplicate");
        }
    }
    candidates
}

fn dialback_candidate(
    peer_id: &PeerId,
    addr: &Multiaddr,
    timeout: Duration,
) -> Result<bool, Box<dyn Error>> {
    let results = dialback_bind_addrs(addr).iter().map(|bind| {
        dialback_candidate_with_bind(peer_id, addr, timeout, bind).map_err(|e| e.to_string())
    });
    merge_dialback_results(results).map_err(Into::into)
}

fn dialback_candidate_with_bind(
    peer_id: &PeerId,
    addr: &Multiaddr,
    timeout: Duration,
    bind: &str,
) -> Result<bool, Box<dyn Error>> {
    let keypair = Ed25519Keypair::generate();
    let transport = QuicTransport::new(QuicNodeConfig::new(keypair.clone()), bind)
        .map_err(|e| format!("dialback bind {bind}: {e}"))?;
    let mut probe = SwarmBuilder::new(&keypair)
        .agent_version(AGENT)
        .build(transport);
    let peer_addr = PeerAddr::new(addr.clone(), peer_id.clone())
        .map_err(|e| format!("bad dialback peer addr {addr}: {e}"))?;
    probe
        .dial(&peer_addr)
        .map_err(|e| format!("dialback start {peer_addr}: {e}"))?;
    let found = probe
        .run_until(
            Instant::now() + timeout,
            |ev| matches!(ev, SwarmEvent::ConnectionEstablished { peer_id: p } if p == peer_id),
        )
        .map_err(|e| format!("dialback poll {peer_addr}: {e}"))?;
    Ok(found.is_some())
}

fn dialback_bind_addrs(addr: &Multiaddr) -> &'static [&'static str] {
    match addr.protocols().first() {
        Some(Protocol::Ip6(_) | Protocol::Dns6(_)) => &["[::]:0"],
        Some(Protocol::Dns(_)) => &["[::]:0", "0.0.0.0:0"],
        _ => &["0.0.0.0:0"],
    }
}

fn merge_dialback_results(
    results: impl IntoIterator<Item = Result<bool, String>>,
) -> Result<bool, String> {
    let mut last_error = None;
    let mut saw_completion = false;
    for result in results {
        match result {
            Ok(true) => return Ok(true),
            Ok(false) => saw_completion = true,
            Err(e) => last_error = Some(e),
        }
    }

    if saw_completion {
        Ok(false)
    } else if let Some(error) = last_error {
        Err(error)
    } else {
        Ok(false)
    }
}

fn candidate_addrs(
    role: &str,
    bound_addr: &Multiaddr,
    external_addrs: &[Multiaddr],
    observed_addr: Option<Multiaddr>,
) -> Vec<Multiaddr> {
    let selection =
        select_direct_candidates(external_addrs, observed_addr, Some(bound_addr.clone()));

    for candidate in &selection.accepted {
        println!(
            "[{role}] candidate-added source={} addr={}",
            candidate.source.as_str(),
            candidate.addr
        );
    }

    for rejected in &selection.rejected {
        println!(
            "[{role}] candidate-skipped source={} addr={} reason={}",
            rejected.source.as_str(),
            rejected.addr,
            rejected.reason.as_str()
        );
    }

    if selection.is_empty() {
        eprintln!(
            "[{role}] no-dialable-dcutr-candidates; add --external-addr or bind a non-wildcard address"
        );
    }

    selection.into_addrs()
}

fn relay_observed_addr(
    swarm: &Swarm<QuicTransport>,
    relay_peer_id: &PeerId,
    role: &str,
) -> Option<Multiaddr> {
    observed_addr_from_peer(swarm, relay_peer_id, role)
}

fn observed_addr_from_peer(
    swarm: &Swarm<QuicTransport>,
    peer_id: &PeerId,
    role: &str,
) -> Option<Multiaddr> {
    let raw = swarm.peer_info(peer_id)?.observed_addr.as_deref()?;
    match Multiaddr::from_bytes(raw) {
        Ok(addr) => Some(addr),
        Err(e) => {
            eprintln!(
                "[{role}] candidate-skipped source=identify-observed reason=parse-failed error={e}"
            );
            None
        }
    }
}

fn wait_observed_addr_from_peer(
    swarm: &mut Swarm<QuicTransport>,
    role: &str,
    peer_id: &PeerId,
    deadline: Instant,
) -> Result<Option<Multiaddr>, Box<dyn Error>> {
    if let Some(addr) = observed_addr_from_peer(swarm, peer_id, role) {
        return Ok(Some(addr));
    }

    let _ = swarm
        .run_until(deadline, |ev| {
            print_event(role, ev);
            matches!(ev, SwarmEvent::IdentifyReceived { peer_id: p, .. } if p == peer_id)
                || matches!(ev, SwarmEvent::PeerReady { peer_id: p, .. } if p == peer_id)
        })
        .map_err(|e| format!("wait-observed-addr: {e}"))?;

    Ok(observed_addr_from_peer(swarm, peer_id, role))
}

fn validate_candidates_with_autonat(
    swarm: &mut Swarm<QuicTransport>,
    role: &str,
    options: &RunOptions,
    candidates: &[Multiaddr],
    deadline: Instant,
) -> Result<Vec<Multiaddr>, Box<dyn Error>> {
    let Some(service) = &options.autonat else {
        return Ok(candidates.to_vec());
    };

    let service_peer = service.peer_id().clone();
    swarm
        .dial(service)
        .map_err(|e| format!("dial AutoNAT service: {e}"))?;
    println!("[{role}] autonat-dialing {service}");
    wait_connected(swarm, role, &service_peer, deadline)?;

    let mut probe_candidates = candidates.to_vec();
    let identify_deadline = earlier_deadline(Instant::now() + AUTONAT_IDENTIFY_GRACE, deadline);
    if let Some(addr) = wait_observed_addr_from_peer(swarm, role, &service_peer, identify_deadline)?
    {
        let before = probe_candidates.len();
        push_unique(&mut probe_candidates, addr.clone());
        if probe_candidates.len() > before {
            println!("[{role}] autonat-candidate-added source=identify-observed addr={addr}");
        }
    }

    let stream_id = swarm
        .open_user_stream(&service_peer, AUTONAT_PROTOCOL_ID)
        .map_err(|e| format!("open AutoNAT stream: {e}"))?;
    let request_deadline = earlier_deadline(
        Instant::now() + autonat_probe_timeout(&probe_candidates),
        deadline,
    );
    wait_user_stream_ready(
        swarm,
        role,
        &service_peer,
        stream_id,
        AUTONAT_PROTOCOL_ID,
        request_deadline,
    )?;

    let local_peer = swarm.local_peer_id().clone();
    let mut client = AutoNatClient::new(&local_peer, &probe_candidates);
    send(swarm, &service_peer, stream_id, client.take_outbound())?;

    while client.outcome().is_none() {
        let data = wait_user_stream_data(swarm, role, &service_peer, stream_id, request_deadline)?;
        client
            .on_data(&data)
            .map_err(|e| format!("AutoNAT decode: {e}"))?;
    }

    match client.outcome().cloned().expect("outcome checked") {
        Reachability::Public { addrs, raw_addrs } => {
            if addrs.len() < raw_addrs.len() {
                eprintln!(
                    "[{role}] autonat-public: {} of {} addrs parsed; unsupported addrs ignored",
                    addrs.len(),
                    raw_addrs.len()
                );
            }
            println!("[{role}] autonat-public addrs={}", addrs.len());
            let successful = successful_candidates_in_original_order(&probe_candidates, &addrs);
            for addr in &successful {
                swarm.confirm_external_address(ExternalAddressSource::AutoNat, addr.clone());
            }
            Ok(successful)
        }
        Reachability::Private { status, reason } => {
            println!("[{role}] autonat-private status={status:?} reason={reason}");
            Ok(probe_candidates)
        }
        Reachability::Unknown { status, reason } => {
            println!("[{role}] autonat-unknown status={status:?} reason={reason}");
            Ok(probe_candidates)
        }
    }
}

fn autonat_probe_timeout(candidates: &[Multiaddr]) -> Duration {
    let dialback_budget = candidates
        .iter()
        .map(|addr| dialback_bind_addrs(addr).len() as u32)
        .sum::<u32>()
        .max(1);
    AUTONAT_REQUEST_DEADLINE + AUTONAT_DIALBACK_DEADLINE * dialback_budget
}

fn successful_candidates_in_original_order(
    candidates: &[Multiaddr],
    successful: &[Multiaddr],
) -> Vec<Multiaddr> {
    let mut ordered = Vec::new();
    for candidate in candidates {
        if successful.iter().any(|addr| addr == candidate) {
            ordered.push(candidate.clone());
        }
    }
    ordered
}

fn push_unique(addrs: &mut Vec<Multiaddr>, addr: Multiaddr) {
    if !addrs.iter().any(|existing| existing == &addr) {
        addrs.push(addr);
    }
}

fn print_candidates(role: &str, candidates: &[Multiaddr]) {
    let rendered = candidates
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    println!("[{role}] dcutr-candidates [{rendered}]");
}

fn print_remote_paths(role: &str, paths: &DirectPathBook) {
    print_direct_path_summary(role, "remote-direct-paths", paths);
}

fn print_direct_path_summary(role: &str, label: &str, paths: &DirectPathBook) {
    if paths.is_empty() {
        println!("[{role}] {label} []");
        return;
    }

    let rendered = paths
        .paths()
        .iter()
        .map(|path| {
            format!(
                "{};source={};status={};attempts={}",
                path.addr,
                path.source.as_str(),
                path.status.as_str(),
                path.attempts
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    println!("[{role}] {label} [{rendered}]");
}

fn path_attempts(paths: &DirectPathBook, addr: &Multiaddr) -> Option<u32> {
    paths
        .paths()
        .iter()
        .find(|path| &path.addr == addr)
        .map(|path| path.attempts)
}

fn elapsed_ms(started_at: Instant) -> u64 {
    started_at.elapsed().as_millis() as u64
}

/// Sends a random 32-byte UDP payload to every remote address. These
/// packets open the NAT binding so the remote's QUIC packets can reach
/// us; the content is irrelevant per the DCUtR spec.
fn blast_remote_paths(swarm: &Swarm<QuicTransport>, paths: &DirectPathBook, role: &str) {
    let payload = random_bytes(RELAY_PING_LEN);
    let addrs = match paths.usable_addrs() {
        addrs if addrs.is_empty() => paths.addrs(),
        addrs => addrs,
    };
    for addr in addrs {
        if let Err(e) = swarm.transport().send_raw_udp(&addr, &payload) {
            eprintln!("[{role}] udp-blast {addr} failed: {e}");
        }
    }
}

fn next_holepunch_delay() -> Duration {
    let range = HOLEPUNCH_INTERVAL_MAX_MS - HOLEPUNCH_INTERVAL_MIN_MS + 1;
    let mut raw = [0u8; 8];
    let jitter = if getrandom::fill(&mut raw).is_ok() {
        u64::from_le_bytes(raw) % range
    } else {
        range / 2
    };
    Duration::from_millis(HOLEPUNCH_INTERVAL_MIN_MS + jitter)
}

/// Short random byte vector. Best-effort: falls back to zeros rather
/// than panicking since the content doesn't affect hole-punch semantics.
fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let _ = getrandom::fill(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;

    #[test]
    fn generic_dns_dialback_tries_both_ip_families() {
        let addr = Multiaddr::from_str("/dns/example.com/udp/4001/quic-v1").unwrap();

        assert_eq!(dialback_bind_addrs(&addr), &["[::]:0", "0.0.0.0:0"]);
    }

    #[test]
    fn family_specific_dialback_uses_matching_bind() {
        let ip4 = Multiaddr::from_str("/ip4/203.0.113.7/udp/4001/quic-v1").unwrap();
        let dns4 = Multiaddr::from_str("/dns4/example.com/udp/4001/quic-v1").unwrap();
        let ip6 = Multiaddr::from_str("/ip6/2001:db8::1/udp/4001/quic-v1").unwrap();
        let dns6 = Multiaddr::from_str("/dns6/example.com/udp/4001/quic-v1").unwrap();

        assert_eq!(dialback_bind_addrs(&ip4), &["0.0.0.0:0"]);
        assert_eq!(dialback_bind_addrs(&dns4), &["0.0.0.0:0"]);
        assert_eq!(dialback_bind_addrs(&ip6), &["[::]:0"]);
        assert_eq!(dialback_bind_addrs(&dns6), &["[::]:0"]);
    }

    #[test]
    fn autonat_probe_timeout_scales_with_candidates_and_bind_families() {
        let ip4 = Multiaddr::from_str("/ip4/203.0.113.7/udp/4001/quic-v1").unwrap();
        let dns = Multiaddr::from_str("/dns/example.com/udp/4001/quic-v1").unwrap();

        assert_eq!(
            autonat_probe_timeout(&[ip4]),
            AUTONAT_REQUEST_DEADLINE + AUTONAT_DIALBACK_DEADLINE
        );
        assert_eq!(
            autonat_probe_timeout(&[dns]),
            AUTONAT_REQUEST_DEADLINE + AUTONAT_DIALBACK_DEADLINE * 2
        );
    }

    #[test]
    fn dialback_merge_does_not_let_later_error_override_completed_false() {
        assert_eq!(
            merge_dialback_results([Ok(false), Err("bind failed".into())]),
            Ok(false)
        );
        assert_eq!(
            merge_dialback_results([Err("bind failed".into()), Ok(false)]),
            Ok(false)
        );
    }

    #[test]
    fn dialback_merge_prefers_success_and_reports_all_error_case() {
        assert_eq!(
            merge_dialback_results([Err("first".into()), Ok(true), Ok(false)]),
            Ok(true)
        );
        assert_eq!(
            merge_dialback_results([Err("first".into()), Err("last".into())]),
            Err("last".into())
        );
    }

    #[test]
    fn dialback_merge_is_lazy_after_success() {
        let mut calls = 0;
        let results = core::iter::from_fn(|| {
            calls += 1;
            match calls {
                1 => Some(Ok(true)),
                _ => panic!("merge should stop after first success"),
            }
        });

        assert_eq!(merge_dialback_results(results), Ok(true));
        assert_eq!(calls, 1);
    }
}
