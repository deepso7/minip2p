//! Relay-coordinated hole-punch mode.
//!
//! The two public entry points are [`run_listen`] (Peer B) and
//! [`run_dial`] (Peer A). Each is written as a linear script against
//! consuming `Swarm::poll_next` loops (see [`poll_until`]): dial the
//! relay, run HOP/STOP, run DCUtR, attempt hole-punch, ping. No phase
//! enums; every step is an obvious function call.
//!
//! See `examples/peer/README.md` for usage examples.

use std::error::Error;
use std::time::{Duration, Instant};

use minip2p_autonat::{
    AUTONAT_PROTOCOL_ID, AutoNatClient, AutoNatClientInput, AutoNatClientOutput, AutoNatServer,
    AutoNatServerInput, AutoNatServerOutput, Reachability, ResponseStatus,
};
use minip2p_core::{
    DirectCandidateRejectReason, DirectCandidateRejection, Multiaddr, PeerAddr, PeerId, Protocol,
    SansIoProtocol, select_direct_candidates,
};
use minip2p_dcutr::{
    DCUTR_PROTOCOL_ID, DcutrInitiator, DcutrInitiatorInput, DcutrInitiatorOutput, DcutrResponder,
    DcutrResponderInput, DcutrResponderOutput, InitiatorOutcome, ResponderEvent,
};
use minip2p_identity::Ed25519Keypair;
use minip2p_quic::{QuicEndpoint, QuicNodeConfig, QuicTransport};
use minip2p_relay::{
    ConnectOutcome, HOP_PROTOCOL_ID, HopConnect, HopConnectInput, HopConnectOutput, HopReservation,
    HopReservationInput, HopReservationOutput, ReservationOutcome, STOP_PROTOCOL_ID, StopResponder,
    StopResponderInput, StopResponderOutput,
};
use minip2p_swarm::{Deadline, DriverError, Swarm, SwarmBuilder, SwarmEvent};
use minip2p_transport::{StreamId, Transport};

use crate::cli::{RunOptions, print_event};
use crate::runtime::{build_peer_transport, load_keypair};

// ---------------------------------------------------------------------------
// Shared configuration
// ---------------------------------------------------------------------------

const AGENT: &str = "minip2p-peer/0.1.0";
/// Top-level deadline: the whole reservation + circuit + hole-punch
/// flow should complete well inside this on a local relay.
const LISTEN_DEADLINE: Duration = Duration::from_secs(60);
/// Hole-punch window after SYNC is received / sent.
///
/// Direct dials succeed in milliseconds on LAN/loopback; real-world NATs may
/// occasionally need longer but three seconds already works for the common-case
/// symmetric-NAT traversal path.
const HOLEPUNCH_DEADLINE: Duration = Duration::from_secs(3);
/// UDP blast cadence (responder side) during hole-punch.
const HOLEPUNCH_INTERVAL: Duration = Duration::from_millis(100);
/// Approximation of RTT/2 before the responder starts blasting UDP.
const RESPONDER_SYNC_DELAY: Duration = Duration::from_millis(50);
/// Payload length used by the relay-ping fallback.
const RELAY_PING_LEN: usize = 32;
const AUTONAT_CLIENT_DEADLINE: Duration = Duration::from_secs(20);
const AUTONAT_REQUEST_DEADLINE: Duration = Duration::from_secs(5);
// Client deadline must absorb candidate_count * binds_per_candidate * dialback
// deadline. Generic /dns candidates may try two bind families; /ip4, /ip6,
// /dns4, and /dns6 try one.
const AUTONAT_DIALBACK_DEADLINE: Duration = Duration::from_secs(5);
const RELAY_READY_ATTEMPTS: usize = 3;
const RELAY_READY_ATTEMPT_DEADLINE: Duration = Duration::from_secs(12);
const RELAY_READY_RETRY_BACKOFF: Duration = Duration::from_millis(500);

fn listen_on_bound_addrs(
    swarm: &mut Swarm<QuicEndpoint>,
    role: &str,
) -> Result<Vec<PeerAddr>, Box<dyn Error>> {
    let addrs = swarm
        .listen_on_bound_addrs()
        .map_err(|e| format!("listen failed: {e}"))?;
    if addrs.is_empty() {
        return Err("listen completed without any bound peer addresses".into());
    }
    for addr in &addrs {
        println!("[{role}] listen-addr={addr}");
    }
    Ok(addrs)
}

// ---------------------------------------------------------------------------
// Listener (Peer B): reserve, accept STOP, respond DCUtR, hole-punch
// ---------------------------------------------------------------------------

pub fn run_listen(relay_addr: PeerAddr, options: RunOptions) -> Result<(), Box<dyn Error>> {
    let role = "relay-listen";
    let mut swarm = build_swarm_with_relay_protocols(&options, role)?;
    let our_addrs = listen_on_bound_addrs(&mut swarm, role)?;
    println!("[{role}] us={}", swarm.local_peer_id());

    let relay_peer_id = relay_addr.peer_id().clone();
    let deadline = Instant::now() + LISTEN_DEADLINE;

    // --- 1. Relay connection ready -----------------------------------------
    prepare_relay(&mut swarm, role, &relay_addr, &relay_peer_id, deadline)?;

    let initial_candidates = candidate_addrs(
        role,
        &our_addrs
            .iter()
            .map(|addr| addr.transport().clone())
            .collect::<Vec<_>>(),
        &options.external_addrs,
        relay_observed_addr(&swarm, &relay_peer_id, role),
    );
    let our_observed = validate_candidates_with_autonat(
        &mut swarm,
        role,
        &options,
        &initial_candidates,
        Instant::now() + AUTONAT_CLIENT_DEADLINE,
    )?;
    print_candidates(role, &our_observed);

    // --- 2. Reserve a slot on the relay via HOP RESERVE --------------------
    let hop_stream = swarm
        .open_stream(&relay_peer_id, HOP_PROTOCOL_ID)
        .map_err(|e| format!("open HOP: {e}"))?;
    wait_stream_ready(&mut swarm, role, hop_stream, deadline)?;
    let mut reservation = HopReservation::new();
    send(
        &mut swarm,
        &relay_peer_id,
        hop_stream,
        relay_reservation_flush(&mut reservation),
    )?;

    let reservation_outcome = loop {
        let data = wait_stream_data(&mut swarm, role, hop_stream, deadline)?;
        if let Some(outcome) = relay_reservation_feed(&mut reservation, data)? {
            break outcome;
        }
    };
    match reservation_outcome {
        ReservationOutcome::Accepted { .. } => {
            println!("[{role}] reserved-on-relay");
        }
        ReservationOutcome::Refused { status, reason } => {
            return Err(
                format!("relay refused reservation: status={status:?} reason={reason}").into(),
            );
        }
    }

    // --- 3. Wait for the relay to push a STOP stream at us ------------------
    let bridge_stream =
        wait_inbound_stream(&mut swarm, role, &relay_peer_id, STOP_PROTOCOL_ID, deadline)?;
    println!("[{role}] incoming-circuit via-relay stream={bridge_stream}");

    // --- 4. STOP responder: accept the CONNECT, keep any pipelined bytes ---
    let mut stop = StopResponder::new();
    let remote_peer_id: PeerId = loop {
        let data = wait_stream_data(&mut swarm, role, bridge_stream, deadline)?;
        if let Some(request) = stop_feed(&mut stop, data)? {
            break PeerId::from_bytes(&request.source_peer_id)
                .map_err(|e| format!("bad STOP source peer id: {e}"))?;
        }
    };
    println!("[{role}] stop-connect-from peer={remote_peer_id}");
    send(
        &mut swarm,
        &relay_peer_id,
        bridge_stream,
        stop_accept_flush(&mut stop)?,
    )?;
    let bridge_bytes = stop_bridge_bytes(&mut stop);

    // --- 5. DCUtR responder over the same bridge stream --------------------
    let mut dcutr = DcutrResponder::new(&our_observed);
    let mut captured_remote_addrs: Option<Vec<Multiaddr>> = None;
    if !bridge_bytes.is_empty() {
        dcutr_responder_feed(&mut dcutr, bridge_bytes)?;
    }
    send(
        &mut swarm,
        &relay_peer_id,
        bridge_stream,
        drain_dcutr_responder_outputs(&mut dcutr, role, &mut captured_remote_addrs),
    )?;

    // DCUtR responder events arrive across multiple poll cycles:
    // `ConnectReceived` fires in one call, `SyncReceived` in a later
    // one. We thread the captured remote-addrs through the loop so
    // the CONNECT payload isn't thrown away when the SYNC arrives.
    let remote_addrs: Vec<Multiaddr> = loop {
        if dcutr.is_done() {
            break captured_remote_addrs.take().unwrap_or_default();
        }
        let data = wait_stream_data(&mut swarm, role, bridge_stream, deadline)?;
        dcutr_responder_feed(&mut dcutr, data)?;
        let outbound = drain_dcutr_responder_outputs(&mut dcutr, role, &mut captured_remote_addrs);
        send(&mut swarm, &relay_peer_id, bridge_stream, outbound)?;
        if dcutr.is_done() {
            break captured_remote_addrs.take().unwrap_or_default();
        }
    };

    // --- 6. Hole-punch: dial + blast UDP, wait for direct or timeout -------
    println!("[{role}] dcutr-sync-received -> holepunching");
    print_remote_candidates(role, &remote_addrs);
    dial_direct_candidates(&mut swarm, role, &remote_peer_id, &remote_addrs);
    let punch_start = Instant::now();
    let punch_deadline = punch_start + HOLEPUNCH_DEADLINE;
    let mut next_blast = punch_start + RESPONDER_SYNC_DELAY;

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
    let remote_match_targets: Vec<(String, u16)> =
        remote_addrs.iter().filter_map(extract_ip_port).collect();

    // Check any connections already present (e.g. the remote's direct
    // Initial may have arrived BEFORE we observed the SYNC message on
    // a tight local loopback). Only counts if the source matches.
    let mut saw_inbound_conn = any_source_matches(
        &swarm.transport().active_inbound_connection_sources(),
        &remote_match_targets,
    );

    let outcome = 'outer: loop {
        // State check first: the remote's direct dial may have completed
        // while an earlier consuming wait was running (e.g. while step 5
        // was blocked in `wait_stream_data` waiting for SYNC -- the
        // dialer sends SYNC and dials immediately, and the direct QUIC
        // handshake can beat the relayed SYNC bytes). In that case the
        // `ConnectionEstablished` event was already printed and dropped,
        // so the event scan below would never see it; `connected_peers()`
        // still knows.
        if is_connected(&swarm, &remote_peer_id) {
            break HolePunchOutcome::DirectConnected(remote_peer_id.clone());
        }

        let now = Instant::now();
        if now >= punch_deadline {
            break HolePunchOutcome::Timeout;
        }
        if now >= next_blast {
            blast_remote_addrs(&swarm, &remote_addrs, role);
            next_blast = now + HOLEPUNCH_INTERVAL;
        }

        // Drain any events the transport has for us. Event ordering
        // within a tick matters: if we see ConnectionEstablished for
        // the remote peer id, prefer that over the coarser count
        // heuristic.
        for ev in swarm.poll().map_err(|e| format!("holepunch poll: {e}"))? {
            print_event(role, &ev);
            if is_direct_connection_event(&ev, &remote_peer_id)
                && let SwarmEvent::ConnectionEstablished { peer_id } = ev
            {
                break 'outer HolePunchOutcome::DirectConnected(peer_id);
            }
            if is_bridge_closed_event(&ev, bridge_stream) {
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
            println!("[{role}] direct-connected peer={peer_id} (hole-punch success)");
            ping_and_exit(
                &mut swarm,
                role,
                peer_id,
                &relay_peer_id,
                bridge_stream,
                deadline,
            )
        }
        HolePunchOutcome::InboundConnectionSeen => {
            // The address heuristic fired before Swarm surfaced the verified
            // mTLS identity. Give QUIC one short grace window to complete the
            // identity event so this side can direct-ping too.
            println!(
                "[{role}] inbound-direct-connection detected (hole-punch success; \
                 waiting for verified mTLS identity)"
            );
            let grace_deadline = Instant::now() + Duration::from_secs(2);
            // State first (the ConnectionEstablished event may already have
            // been consumed by an earlier wait), event wait second.
            let verified = if is_connected(&swarm, &remote_peer_id) {
                Some(remote_peer_id.clone())
            } else {
                poll_until(&mut swarm, grace_deadline, |ev| {
                    print_event(role, ev);
                    matches!(ev, SwarmEvent::ConnectionEstablished { peer_id } if peer_id == &remote_peer_id)
                })
                .map_err(|e| format!("grace poll: {e}"))?
                .map(|ev| {
                    let SwarmEvent::ConnectionEstablished { peer_id } = ev else {
                        unreachable!()
                    };
                    peer_id
                })
            };
            match verified {
                Some(peer_id) => {
                    println!("[{role}] direct-connected peer={peer_id} (mTLS verified)");
                    ping_and_exit(
                        &mut swarm,
                        role,
                        peer_id,
                        &relay_peer_id,
                        bridge_stream,
                        deadline,
                    )
                }
                None => {
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

fn is_bridge_closed_event(ev: &SwarmEvent, bridge_stream: StreamId) -> bool {
    matches!(
        ev,
        SwarmEvent::StreamRemoteWriteClosed { stream_id, .. }
            if *stream_id == bridge_stream
    ) || matches!(
        ev,
        SwarmEvent::StreamClosed { stream_id, .. } if *stream_id == bridge_stream
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
    let our_addrs = listen_on_bound_addrs(&mut swarm, role)?;
    println!("[{role}] us={}", swarm.local_peer_id());
    println!("[{role}] target={target}");

    let relay_peer_id = relay_addr.peer_id().clone();
    let deadline = Instant::now() + LISTEN_DEADLINE;

    // --- 1. Relay connection ready -----------------------------------------
    prepare_relay(&mut swarm, role, &relay_addr, &relay_peer_id, deadline)?;

    let initial_candidates = candidate_addrs(
        role,
        &our_addrs
            .iter()
            .map(|addr| addr.transport().clone())
            .collect::<Vec<_>>(),
        &options.external_addrs,
        relay_observed_addr(&swarm, &relay_peer_id, role),
    );
    let our_observed = validate_candidates_with_autonat(
        &mut swarm,
        role,
        &options,
        &initial_candidates,
        Instant::now() + AUTONAT_CLIENT_DEADLINE,
    )?;
    print_candidates(role, &our_observed);

    // --- 2. HOP CONNECT to `target` through the relay ----------------------
    let hop_stream = swarm
        .open_stream(&relay_peer_id, HOP_PROTOCOL_ID)
        .map_err(|e| format!("open HOP: {e}"))?;
    wait_stream_ready(&mut swarm, role, hop_stream, deadline)?;
    let mut hop = HopConnect::new(target.to_bytes());
    send(
        &mut swarm,
        &relay_peer_id,
        hop_stream,
        hop_connect_flush(&mut hop),
    )?;

    let hop_outcome = loop {
        let data = wait_stream_data(&mut swarm, role, hop_stream, deadline)?;
        if let Some(outcome) = hop_connect_feed(&mut hop, data)? {
            break outcome;
        }
    };
    match hop_outcome {
        ConnectOutcome::Bridged { .. } => {
            println!("[{role}] bridge-established via-relay");
        }
        ConnectOutcome::Refused { status, reason } => {
            return Err(format!("relay refused CONNECT: status={status:?} reason={reason}").into());
        }
    }
    let bridge_stream = hop_stream; // same stream, now carrying DCUtR bytes
    let bridge_bytes = hop_connect_bridge_bytes(&mut hop);

    // --- 3. DCUtR initiator over the bridge --------------------------------
    let mut dcutr = DcutrInitiator::new(&our_observed);
    let dcutr_sent_at = Instant::now();
    send(
        &mut swarm,
        &relay_peer_id,
        bridge_stream,
        dcutr_initiator_flush(&mut dcutr),
    )?;
    let mut pending_dialnow = None;
    if !bridge_bytes.is_empty() {
        pending_dialnow = dcutr_initiator_feed(&mut dcutr, bridge_bytes, 0)?;
    }

    let (remote_addrs, rtt_ms) = loop {
        let outcome = match pending_dialnow.take() {
            Some(outcome) => Some(outcome),
            None => {
                let data = wait_stream_data(&mut swarm, role, bridge_stream, deadline)?;
                let elapsed_ms = dcutr_sent_at.elapsed().as_millis() as u64;
                dcutr_initiator_feed(&mut dcutr, data, elapsed_ms)?
            }
        };
        if let Some(outcome) = outcome {
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
    };
    println!(
        "[{role}] dcutr-dialnow addrs={} rtt={rtt_ms}ms",
        remote_addrs.len()
    );
    print_remote_candidates(role, &remote_addrs);

    // --- 4. Flush SYNC and dial every observed remote address in parallel --
    send(
        &mut swarm,
        &relay_peer_id,
        bridge_stream,
        dcutr_initiator_send_sync_flush(&mut dcutr)?,
    )?;

    dial_direct_candidates(&mut swarm, role, &target, &remote_addrs);

    // --- 5. Wait for direct connection or hole-punch timeout ---------------
    // State check first: connection facts are queryable at any time via
    // `connected_peers()`, so this wait cannot be defeated by the
    // `ConnectionEstablished` event having been consumed by an earlier
    // wait (see `is_connected`).
    let punch_deadline = Instant::now() + HOLEPUNCH_DEADLINE;
    let punched = is_connected(&swarm, &target)
        || poll_until(&mut swarm, punch_deadline, |ev| {
            print_event(role, ev);
            matches!(
                ev,
                SwarmEvent::ConnectionEstablished { peer_id }
                    if peer_id == &target
            )
        })
        .map_err(|e| format!("holepunch poll: {e}"))?
        .is_some();

    // --- 6. Direct ping or relay-ping fallback -----------------------------
    if punched {
        println!("[{role}] direct-connected peer={target} (hole-punch success)");
        ping_and_exit(
            &mut swarm,
            role,
            target,
            &relay_peer_id,
            bridge_stream,
            deadline,
        )
    } else {
        println!("[{role}] hole-punch-timeout reason=deadline elapsed -> relay-ping fallback");
        let payload = random_bytes(RELAY_PING_LEN);
        let sent_at = Instant::now();
        send(&mut swarm, &relay_peer_id, bridge_stream, payload.clone())?;
        loop {
            let data = wait_stream_data(&mut swarm, role, bridge_stream, deadline)?;
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
    let _ = listen_on_bound_addrs(&mut swarm, role)?;
    println!("[{role}] us={}", swarm.local_peer_id());
    eprintln!("[{role}] waiting for AutoNAT probes (Ctrl-C to stop)");

    loop {
        // Consuming loop: each event is printed exactly once here, then
        // gone. A `run_until` predicate would restore its whole history
        // and re-print it on every iteration of this server loop.
        let ev = poll_until(&mut swarm, Deadline::NEVER, |ev| {
            print_event(role, ev);
            matches!(
                ev,
                SwarmEvent::StreamReady {
                    protocol_id,
                    initiated_locally: false,
                    ..
                } if protocol_id == AUTONAT_PROTOCOL_ID
            )
        })
        .map_err(|e| format!("autonat wait stream: {e}"))?;

        let Some(SwarmEvent::StreamReady {
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
    swarm: &mut Swarm<QuicEndpoint>,
    role: &str,
    requester_peer: PeerId,
    stream_id: StreamId,
) -> Result<(), Box<dyn Error>> {
    let mut server = AutoNatServer::new();
    let request_deadline = Instant::now() + AUTONAT_REQUEST_DEADLINE;
    let request = loop {
        let data = wait_stream_data(swarm, role, stream_id, request_deadline)?;
        if let Some(request) = autonat_server_feed(&mut server, data)? {
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
        server
            .handle_input(AutoNatServerInput::RespondError {
                status: ResponseStatus::BadRequest,
                reason: "AutoNAT request peer id did not match stream peer".into(),
            })
            .map_err(|e| format!("AutoNAT respond: {e}"))?;
        send(
            swarm,
            &requester_peer,
            stream_id,
            autonat_server_flush(&mut server),
        )?;
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
        let dialable_len = dialable.len();
        server
            .handle_input(AutoNatServerInput::RespondPublic { addrs: dialable })
            .map_err(|e| format!("AutoNAT respond: {e}"))?;
        println!(
            "[{role}] probe-public peer={} addrs={}",
            request.peer_id, dialable_len
        );
    } else {
        server
            .handle_input(AutoNatServerInput::RespondError {
                status: ResponseStatus::DialError,
                reason: "dialback deadline elapsed".into(),
            })
            .map_err(|e| format!("AutoNAT respond: {e}"))?;
        println!(
            "[{role}] probe-private peer={} reason=timeout",
            request.peer_id
        );
    }

    send(
        swarm,
        &requester_peer,
        stream_id,
        autonat_server_flush(&mut server),
    )
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn relay_reservation_flush(flow: &mut HopReservation) -> Vec<u8> {
    let _ = flow.handle_input(HopReservationInput::Flush);
    match flow.poll_output() {
        Some(HopReservationOutput::Outbound(bytes)) => bytes,
        _ => Vec::new(),
    }
}

fn relay_reservation_feed(
    flow: &mut HopReservation,
    data: Vec<u8>,
) -> Result<Option<ReservationOutcome>, Box<dyn Error>> {
    flow.handle_input(HopReservationInput::Data(data))
        .map_err(|e| format!("HOP decode: {e}"))?;
    Ok(match flow.poll_output() {
        Some(HopReservationOutput::Outcome(outcome)) => Some(outcome),
        _ => None,
    })
}

fn hop_connect_flush(flow: &mut HopConnect) -> Vec<u8> {
    let _ = flow.handle_input(HopConnectInput::Flush);
    match flow.poll_output() {
        Some(HopConnectOutput::Outbound(bytes)) => bytes,
        _ => Vec::new(),
    }
}

fn hop_connect_feed(
    flow: &mut HopConnect,
    data: Vec<u8>,
) -> Result<Option<ConnectOutcome>, Box<dyn Error>> {
    flow.handle_input(HopConnectInput::Data(data))
        .map_err(|e| format!("HOP decode: {e}"))?;
    Ok(match flow.poll_output() {
        Some(HopConnectOutput::Outcome(outcome)) => Some(outcome),
        _ => None,
    })
}

fn hop_connect_bridge_bytes(flow: &mut HopConnect) -> Vec<u8> {
    match flow.poll_output() {
        Some(HopConnectOutput::BridgeData(bytes)) => bytes,
        _ => Vec::new(),
    }
}

fn stop_feed(
    flow: &mut StopResponder,
    data: Vec<u8>,
) -> Result<Option<minip2p_relay::StopConnectRequest>, Box<dyn Error>> {
    flow.handle_input(StopResponderInput::Data(data))
        .map_err(|e| format!("STOP decode: {e}"))?;
    Ok(match flow.poll_output() {
        Some(StopResponderOutput::Request(request)) => Some(request),
        _ => None,
    })
}

fn stop_accept_flush(flow: &mut StopResponder) -> Result<Vec<u8>, Box<dyn Error>> {
    flow.handle_input(StopResponderInput::Accept)
        .map_err(|e| format!("STOP accept: {e}"))?;
    Ok(match flow.poll_output() {
        Some(StopResponderOutput::Outbound(bytes)) => bytes,
        _ => Vec::new(),
    })
}

fn stop_bridge_bytes(flow: &mut StopResponder) -> Vec<u8> {
    match flow.poll_output() {
        Some(StopResponderOutput::BridgeData(bytes)) => bytes,
        _ => Vec::new(),
    }
}

fn drain_dcutr_responder_outputs(
    flow: &mut DcutrResponder,
    role: &str,
    captured: &mut Option<Vec<Multiaddr>>,
) -> Vec<u8> {
    let _ = flow.handle_input(DcutrResponderInput::Flush);
    let mut outbound = Vec::new();
    while let Some(output) = flow.poll_output() {
        match output {
            DcutrResponderOutput::Outbound(bytes) => outbound.extend(bytes),
            DcutrResponderOutput::Event(ev) => {
                handle_dcutr_responder_event(ev, role, captured);
            }
        }
    }
    outbound
}

fn dcutr_responder_feed(flow: &mut DcutrResponder, data: Vec<u8>) -> Result<(), Box<dyn Error>> {
    flow.handle_input(DcutrResponderInput::Data(data))
        .map_err(|e| format!("DCUtR decode: {e}").into())
}

fn dcutr_initiator_flush(flow: &mut DcutrInitiator) -> Vec<u8> {
    let _ = flow.handle_input(DcutrInitiatorInput::Flush);
    match flow.poll_output() {
        Some(DcutrInitiatorOutput::Outbound(bytes)) => bytes,
        _ => Vec::new(),
    }
}

fn dcutr_initiator_feed(
    flow: &mut DcutrInitiator,
    bytes: Vec<u8>,
    rtt_ms: u64,
) -> Result<Option<InitiatorOutcome>, Box<dyn Error>> {
    flow.handle_input(DcutrInitiatorInput::Data { bytes, rtt_ms })
        .map_err(|e| format!("DCUtR decode: {e}"))?;
    Ok(match flow.poll_output() {
        Some(DcutrInitiatorOutput::Outcome(outcome)) => Some(outcome),
        _ => None,
    })
}

fn dcutr_initiator_send_sync_flush(flow: &mut DcutrInitiator) -> Result<Vec<u8>, Box<dyn Error>> {
    flow.handle_input(DcutrInitiatorInput::SendSync)
        .map_err(|e| format!("DCUtR send_sync: {e}"))?;
    Ok(dcutr_initiator_flush(flow))
}

fn autonat_client_flush(flow: &mut AutoNatClient) -> Vec<u8> {
    let _ = flow.handle_input(AutoNatClientInput::Flush);
    match flow.poll_output() {
        Some(AutoNatClientOutput::Outbound(bytes)) => bytes,
        _ => Vec::new(),
    }
}

fn autonat_client_feed(
    flow: &mut AutoNatClient,
    data: Vec<u8>,
) -> Result<Option<Reachability>, Box<dyn Error>> {
    flow.handle_input(AutoNatClientInput::Data(data))
        .map_err(|e| format!("AutoNAT decode: {e}"))?;
    Ok(match flow.poll_output() {
        Some(AutoNatClientOutput::Outcome(outcome)) => Some(outcome),
        _ => None,
    })
}

fn autonat_server_feed(
    flow: &mut AutoNatServer,
    data: Vec<u8>,
) -> Result<Option<minip2p_autonat::AutoNatRequest>, Box<dyn Error>> {
    flow.handle_input(AutoNatServerInput::Data(data))
        .map_err(|e| format!("AutoNAT decode: {e}"))?;
    Ok(match flow.poll_output() {
        Some(AutoNatServerOutput::Request(request)) => Some(request),
        _ => None,
    })
}

fn autonat_server_flush(flow: &mut AutoNatServer) -> Vec<u8> {
    let _ = flow.handle_input(AutoNatServerInput::Flush);
    match flow.poll_output() {
        Some(AutoNatServerOutput::Outbound(bytes)) => bytes,
        _ => Vec::new(),
    }
}

fn prepare_relay(
    swarm: &mut Swarm<QuicEndpoint>,
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
    swarm: &mut Swarm<QuicEndpoint>,
    role: &str,
    peer_id: &PeerId,
    deadline: Instant,
) -> Result<Vec<String>, Box<dyn Error>> {
    // Consuming loop: `retry_relay_connection` drained the previous
    // attempt's events before the redial, and nothing is restored here,
    // so this match can only be satisfied by a fresh Identify exchange
    // on the new connection -- never by stale pre-disconnect events.
    let ev = poll_until(swarm, deadline, |ev| {
        if !is_benign_retry_close_error(ev) {
            print_event(role, ev);
        }
        matches!(ev, SwarmEvent::IdentifyReceived { peer_id: p, .. } if p == peer_id)
            || matches!(ev, SwarmEvent::PeerReady { peer_id: p, .. } if p == peer_id)
    })
    .map_err(|e| format!("wait-relay-protocols: {e}"))?
    .ok_or_else(|| format!("deadline exceeded before relay peer {peer_id} advertised protocols"))?;

    match ev {
        SwarmEvent::IdentifyReceived { info, .. } => Ok(info.protocols),
        SwarmEvent::PeerReady { protocols, .. } => Ok(protocols),
        _ => unreachable!(),
    }
}

fn retry_relay_connection(
    swarm: &mut Swarm<QuicEndpoint>,
    role: &str,
    relay_peer_id: &PeerId,
) -> Result<(), Box<dyn Error>> {
    if let Err(e) = swarm.disconnect(relay_peer_id) {
        eprintln!("[{role}] relay-disconnect-for-retry failed: {e}");
    }

    // Consume-and-discard everything from the aborted attempt while the
    // backoff elapses. `poll_next` pops events permanently, so the next
    // `wait_relay_protocols_after_dial` cannot re-match a stale
    // `PeerReady`/`IdentifyReceived` from before the disconnect.
    let retry_deadline = Instant::now() + RELAY_READY_RETRY_BACKOFF;
    while let Some(ev) = swarm
        .poll_next(retry_deadline)
        .map_err(|e| format!("relay retry drain: {e}"))?
    {
        if !is_benign_retry_close_error(&ev) {
            print_event(role, &ev);
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

/// Polls events via `Swarm::poll_next` (consuming each one) until
/// `predicate` matches or `deadline` passes.
///
/// This is the app-side idiom for side-effecting waits: every event is
/// handled exactly once at the consumption site. `Swarm::run_until`
/// restores non-matching events to the buffer, so a predicate that
/// prints (like the ones in this file) would re-print history on every
/// subsequent wait and let stale events satisfy later matches.
fn poll_until(
    swarm: &mut Swarm<QuicEndpoint>,
    deadline: impl Into<Deadline>,
    mut predicate: impl FnMut(&SwarmEvent) -> bool,
) -> Result<Option<SwarmEvent>, DriverError> {
    let deadline = deadline.into();
    while let Some(ev) = swarm.poll_next(deadline)? {
        if predicate(&ev) {
            return Ok(Some(ev));
        }
    }
    Ok(None)
}

/// True if the swarm currently holds a verified connection to `peer_id`.
///
/// Connection-level facts must be read from swarm STATE, not caught as
/// events: with consuming `poll_next` loops, a `ConnectionEstablished`
/// that arrives while an earlier wait is running (e.g. while blocked on
/// stream data) is printed and gone forever, but `connected_peers()` is
/// queryable at any time. Waits that target "is X connected?" check this
/// first so they are immune to the event having been consumed already.
fn is_connected(swarm: &Swarm<QuicEndpoint>, peer_id: &PeerId) -> bool {
    swarm.connected_peers().iter().any(|p| p == peer_id)
}

/// Wait until `peer_id` is connected (verified via mTLS).
///
/// Consults `connected_peers()` state first -- see [`is_connected`] --
/// then falls back to waiting for the `ConnectionEstablished` event.
fn wait_connected(
    swarm: &mut Swarm<QuicEndpoint>,
    role: &str,
    peer_id: &PeerId,
    deadline: Instant,
) -> Result<(), Box<dyn Error>> {
    if is_connected(swarm, peer_id) {
        return Ok(());
    }
    let found = poll_until(swarm, deadline, |ev| {
        print_event(role, ev);
        matches!(ev, SwarmEvent::ConnectionEstablished { peer_id: p } if p == peer_id)
    })
    .map_err(|e| format!("wait-connected: {e}"))?;
    found
        .map(|_| ())
        .ok_or_else(|| format!("deadline exceeded before connection to {peer_id}").into())
}

/// Wait for a locally-initiated `StreamReady` on `stream_id`.
fn wait_stream_ready(
    swarm: &mut Swarm<QuicEndpoint>,
    role: &str,
    stream_id: StreamId,
    deadline: Instant,
) -> Result<(), Box<dyn Error>> {
    let found = poll_until(swarm, deadline, |ev| {
        print_event(role, ev);
        matches!(
            ev,
            SwarmEvent::StreamReady {
                stream_id: s,
                initiated_locally: true,
                ..
            } if *s == stream_id
        ) || matches!(
            ev,
            SwarmEvent::StreamClosed { stream_id: s, .. } if *s == stream_id
        ) || matches!(
            ev,
            SwarmEvent::Error(error)
                if error.detail.contains(&format!("stream {stream_id}"))
        )
    })
    .map_err(|e| format!("wait-user-stream-ready: {e}"))?;
    match found {
        Some(SwarmEvent::StreamReady { .. }) => Ok(()),
        Some(SwarmEvent::StreamClosed { .. }) => {
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
    swarm: &mut Swarm<QuicEndpoint>,
    role: &str,
    peer_id: &PeerId,
    protocol_id: &str,
    deadline: Instant,
) -> Result<StreamId, Box<dyn Error>> {
    let ev = poll_until(swarm, deadline, |ev| {
        print_event(role, ev);
        matches!(
            ev,
            SwarmEvent::StreamReady {
                peer_id: p,
                initiated_locally: false,
                protocol_id: pid,
                ..
            } if p == peer_id && pid == protocol_id
        )
    })
    .map_err(|e| format!("wait-inbound-stream: {e}"))?
    .ok_or_else(|| format!("deadline exceeded before inbound {protocol_id}"))?;
    let SwarmEvent::StreamReady { stream_id, .. } = ev else {
        unreachable!()
    };
    Ok(stream_id)
}

/// Wait for the next `StreamData` event on `stream_id`, returning
/// the data payload.
fn wait_stream_data(
    swarm: &mut Swarm<QuicEndpoint>,
    role: &str,
    stream_id: StreamId,
    deadline: Instant,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let ev = poll_until(swarm, deadline, |ev| {
        print_event(role, ev);
        matches!(
            ev,
            SwarmEvent::StreamData { stream_id: s, .. } if *s == stream_id
        )
    })
    .map_err(|e| format!("wait-user-stream-data: {e}"))?
    .ok_or_else(|| format!("deadline exceeded before data on stream {stream_id}"))?;
    let SwarmEvent::StreamData { data, .. } = ev else {
        unreachable!()
    };
    Ok(data)
}

fn handle_dcutr_responder_event(
    ev: ResponderEvent,
    role: &str,
    captured: &mut Option<Vec<Multiaddr>>,
) {
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
        ResponderEvent::SyncReceived => {}
    }
}

fn dial_direct_candidates(
    swarm: &mut Swarm<QuicEndpoint>,
    role: &str,
    peer_id: &PeerId,
    addrs: &[Multiaddr],
) {
    for addr in addrs {
        match PeerAddr::new(addr.clone(), peer_id.clone()) {
            Ok(peer_addr) => match swarm.dial(&peer_addr) {
                Ok(_) => println!("[{role}] direct-dial-attempt {peer_addr}"),
                Err(e) => eprintln!("[{role}] direct-dial-failed addr={peer_addr} reason={e}"),
            },
            Err(e) => eprintln!("[{role}] bad PeerAddr for {addr}: {e}"),
        }
    }
}

fn relay_ping_fallback(
    swarm: &mut Swarm<QuicEndpoint>,
    role: &str,
    relay_peer_id: &PeerId,
    bridge_stream: StreamId,
) -> Result<(), Box<dyn Error>> {
    // Wait up to ~15s for either an echo payload from Peer A or the bridge to
    // close (meaning A gave up). Longer than the hole-punch deadline because
    // the relay's own idle-circuit GC can take several seconds -- but bounded
    // so we don't hang forever if something goes wrong.
    let fallback_deadline = Instant::now() + Duration::from_secs(15);
    let ev = poll_until(swarm, fallback_deadline, |ev| {
        print_event(role, ev);
        matches!(
            ev,
            SwarmEvent::StreamData { stream_id: s, .. } if *s == bridge_stream
        ) || is_bridge_closed_event(ev, bridge_stream)
    })
    .map_err(|e| format!("fallback poll: {e}"))?;

    match ev {
        Some(SwarmEvent::StreamData { data, .. }) => {
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
    swarm: &mut Swarm<QuicEndpoint>,
    peer_id: &PeerId,
    stream_id: StreamId,
    data: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    if data.is_empty() {
        return Ok(());
    }
    swarm
        .send_stream(peer_id, stream_id, data)
        .map_err(|e| format!("send_stream: {e}").into())
}

/// Ping `peer_id` and wait for the RTT. Prints the result and returns.
fn ping_and_exit(
    swarm: &mut Swarm<QuicEndpoint>,
    role: &str,
    peer_id: PeerId,
    relay_peer_id: &PeerId,
    bridge_stream: StreamId,
    deadline: Instant,
) -> Result<(), Box<dyn Error>> {
    swarm.ping(&peer_id).map_err(|e| format!("ping: {e}"))?;
    let ev = poll_until(swarm, deadline, |ev| {
        print_event(role, ev);
        matches!(ev, SwarmEvent::PingRttMeasured { peer_id: p, .. } if p == &peer_id)
    })
    .map_err(|e| format!("wait-rtt: {e}"))?
    .ok_or("deadline exceeded before ping rtt arrived")?;
    let SwarmEvent::PingRttMeasured { rtt_ms, .. } = ev else {
        unreachable!()
    };
    println!("[{role}] ping-direct peer={peer_id} rtt={rtt_ms}ms");
    close_relay_bridge_after_direct_success(swarm, role, relay_peer_id, bridge_stream)?;
    println!("[{role}] ping-direct peer={peer_id} rtt={rtt_ms}ms -- done");
    Ok(())
}

/// Once direct QUIC is proven, the relayed bridge is no longer part of the
/// data path. Half-close our write side so the relay can retire the circuit
/// promptly instead of reporting a later idle timeout.
fn close_relay_bridge_after_direct_success(
    swarm: &mut Swarm<QuicEndpoint>,
    role: &str,
    relay_peer_id: &PeerId,
    bridge_stream: StreamId,
) -> Result<(), Box<dyn Error>> {
    println!("[{role}] bridge-close stream={bridge_stream} reason=direct-path-ready");
    match swarm.close_stream_write(relay_peer_id, bridge_stream) {
        Ok(()) => {}
        Err(e) => {
            // The remote side may have already closed the relayed stream after
            // its own direct success. Treat that as terminally clean for this
            // CLI; the direct ping above is the correctness signal.
            println!("[{role}] bridge-close-skipped stream={bridge_stream} reason={e}");
            return Ok(());
        }
    }

    // Give the close action one short poll window to flush and surface any
    // immediate close event without delaying the successful CLI path.
    let drain_deadline = Instant::now() + Duration::from_millis(200);
    while Instant::now() < drain_deadline {
        let events = swarm
            .poll()
            .map_err(|e| format!("bridge close poll: {e}"))?;
        if events.is_empty() {
            break;
        }
        for ev in events {
            print_event(role, &ev);
            if is_bridge_closed_event(&ev, bridge_stream) {
                return Ok(());
            }
        }
    }

    Ok(())
}

/// Builds a swarm with the relay + DCUtR user protocols registered.
fn build_swarm_with_relay_protocols(
    options: &RunOptions,
    role: &str,
) -> Result<Swarm<QuicEndpoint>, Box<dyn Error>> {
    let keypair = load_keypair(options, role)?;
    let transport = build_peer_transport(options, &keypair)?;
    let mut swarm = SwarmBuilder::new(&keypair)
        .agent_version(AGENT)
        .build(transport)
        .map_err(|e| format!("build swarm: {e}"))?;
    for protocol_id in [
        HOP_PROTOCOL_ID,
        STOP_PROTOCOL_ID,
        DCUTR_PROTOCOL_ID,
        AUTONAT_PROTOCOL_ID,
    ] {
        swarm
            .add_protocol(protocol_id)
            .map_err(|e| format!("add protocol {protocol_id}: {e}"))?;
    }
    Ok(swarm)
}

fn build_autonat_swarm(
    options: &RunOptions,
    keypair: &Ed25519Keypair,
) -> Result<Swarm<QuicEndpoint>, Box<dyn Error>> {
    let transport = build_peer_transport(options, keypair)?;
    let mut swarm = SwarmBuilder::new(keypair)
        .agent_version(AGENT)
        .build(transport)
        .map_err(|e| format!("build swarm: {e}"))?;
    swarm
        .add_protocol(AUTONAT_PROTOCOL_ID)
        .map_err(|e| format!("add protocol {AUTONAT_PROTOCOL_ID}: {e}"))?;
    Ok(swarm)
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
        .build(transport)
        .map_err(|e| format!("build dialback swarm: {e}"))?;
    let peer_addr = PeerAddr::new(addr.clone(), peer_id.clone())
        .map_err(|e| format!("bad dialback peer addr {addr}: {e}"))?;
    probe
        .dial(&peer_addr)
        .map_err(|e| format!("dialback start {peer_addr}: {e}"))?;
    // `run_until` (not `poll_until`) is fine here: the predicate is pure
    // and the probe swarm is dropped right after, so restored events
    // are never seen again.
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
    bound_addrs: &[Multiaddr],
    external_addrs: &[Multiaddr],
    observed_addr: Option<Multiaddr>,
) -> Vec<Multiaddr> {
    let mut selection = select_direct_candidates(external_addrs, observed_addr, None);
    for bound_addr in bound_addrs {
        let bound_selection = select_direct_candidates(&[], None, Some(bound_addr.clone()));
        for candidate in bound_selection.accepted {
            if selection
                .accepted
                .iter()
                .any(|accepted| accepted.addr == candidate.addr)
            {
                selection.rejected.push(DirectCandidateRejection {
                    source: candidate.source,
                    addr: candidate.addr,
                    reason: DirectCandidateRejectReason::Duplicate,
                });
            } else {
                selection.accepted.push(candidate);
            }
        }
        selection.rejected.extend(bound_selection.rejected);
    }

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
    swarm: &Swarm<QuicEndpoint>,
    relay_peer_id: &PeerId,
    role: &str,
) -> Option<Multiaddr> {
    let raw = swarm.peer_info(relay_peer_id)?.observed_addr.as_deref()?;
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

fn validate_candidates_with_autonat(
    swarm: &mut Swarm<QuicEndpoint>,
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

    let stream_id = swarm
        .open_stream(&service_peer, AUTONAT_PROTOCOL_ID)
        .map_err(|e| format!("open AutoNAT stream: {e}"))?;
    wait_stream_ready(swarm, role, stream_id, deadline)?;

    let local_peer = swarm.local_peer_id().clone();
    let mut client = AutoNatClient::new(&local_peer, candidates);
    send(
        swarm,
        &service_peer,
        stream_id,
        autonat_client_flush(&mut client),
    )?;

    let outcome = loop {
        let data = wait_stream_data(swarm, role, stream_id, deadline)?;
        if let Some(outcome) = autonat_client_feed(&mut client, data)? {
            break outcome;
        }
    };

    match outcome {
        Reachability::Public { addrs, raw_addrs } => {
            if addrs.len() < raw_addrs.len() {
                eprintln!(
                    "[{role}] autonat-public: {} of {} addrs parsed; unsupported addrs ignored",
                    addrs.len(),
                    raw_addrs.len()
                );
            }
            println!("[{role}] autonat-public addrs={}", addrs.len());
            Ok(successful_candidates_in_original_order(candidates, &addrs))
        }
        Reachability::Private { status, reason } => {
            println!("[{role}] autonat-private status={status:?} reason={reason}");
            Ok(candidates.to_vec())
        }
        Reachability::Unknown { status, reason } => {
            println!("[{role}] autonat-unknown status={status:?} reason={reason}");
            Ok(candidates.to_vec())
        }
    }
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

fn print_remote_candidates(role: &str, candidates: &[Multiaddr]) {
    let rendered = candidates
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    println!("[{role}] remote-dcutr-candidates [{rendered}]");
}

/// Sends a random 32-byte UDP payload to every remote address. These
/// packets open the NAT binding so the remote's QUIC packets can reach
/// us; the content is irrelevant per the DCUtR spec.
fn blast_remote_addrs(swarm: &Swarm<QuicEndpoint>, addrs: &[Multiaddr], role: &str) {
    let payload = random_bytes(RELAY_PING_LEN);
    for addr in addrs {
        if let Err(e) = swarm.transport().send_raw_udp(addr, &payload) {
            eprintln!("[{role}] udp-blast {addr} failed: {e}");
        }
    }
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
