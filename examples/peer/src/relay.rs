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

use minip2p_core::{Multiaddr, PeerAddr, PeerId};
use minip2p_dcutr::{
    DcutrInitiator, DcutrResponder, InitiatorOutcome, ResponderEvent,
    DCUTR_PROTOCOL_ID,
};
use minip2p_identity::Ed25519Keypair;
use minip2p_quic::{QuicNodeConfig, QuicTransport};
use minip2p_relay::{
    ConnectOutcome, HopConnect, HopReservation, ReservationOutcome, StopResponder,
    HOP_PROTOCOL_ID, STOP_PROTOCOL_ID,
};
use minip2p_swarm::{Swarm, SwarmBuilder, SwarmEvent};
use minip2p_transport::{StreamId, Transport};

use crate::cli::print_event;

// ---------------------------------------------------------------------------
// Shared configuration
// ---------------------------------------------------------------------------

const LOCAL_BIND: &str = "127.0.0.1:0";
const AGENT: &str = "minip2p-peer/0.1.0";
/// Top-level deadline: the whole reservation + circuit + hole-punch
/// flow should complete well inside this on a local relay.
const LISTEN_DEADLINE: Duration = Duration::from_secs(60);
/// Hole-punch window after SYNC is received / sent.
///
/// Kept short because on the listener side we fall back to an
/// inbound-connection-count heuristic for early exit (since without
/// mutual TLS we can't directly observe the remote's verified peer
/// id). On the dialer side, direct dials succeed in milliseconds on
/// LAN/loopback; real-world NATs may occasionally need longer but
/// three seconds already works for the common-case symmetric-NAT
/// traversal path.
const HOLEPUNCH_DEADLINE: Duration = Duration::from_secs(3);
/// UDP blast cadence (responder side) during hole-punch.
const HOLEPUNCH_INTERVAL: Duration = Duration::from_millis(100);
/// Approximation of RTT/2 before the responder starts blasting UDP.
const RESPONDER_SYNC_DELAY: Duration = Duration::from_millis(50);
/// Payload length used by the relay-ping fallback.
const RELAY_PING_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Listener (Peer B): reserve, accept STOP, respond DCUtR, hole-punch
// ---------------------------------------------------------------------------

pub fn run_listen(relay_addr: PeerAddr) -> Result<(), Box<dyn Error>> {
    let role = "relay-listen";
    let mut swarm = build_swarm_with_relay_protocols()?;
    swarm
        .transport_mut()
        .listen_on_bound_addr()
        .map_err(|e| format!("listen failed: {e}"))?;
    let our_addr = swarm
        .transport()
        .local_peer_addr()
        .map_err(|e| format!("local_peer_addr: {e}"))?;
    let our_observed: Vec<Multiaddr> = vec![our_addr.transport().clone()];
    println!("[{role}] bound={our_addr}");
    println!("[{role}] us={}", swarm.local_peer_id());

    let relay_peer_id = relay_addr.peer_id().clone();
    swarm
        .dial(&relay_addr)
        .map_err(|e| format!("dial relay: {e}"))?;
    println!("[{role}] dialing-relay {relay_addr}");

    let deadline = Instant::now() + LISTEN_DEADLINE;

    // --- 1. Relay connection established -----------------------------------
    wait_connected(&mut swarm, role, &relay_peer_id, deadline)?;

    // --- 2. Reserve a slot on the relay via HOP RESERVE --------------------
    let hop_stream = swarm
        .open_user_stream(&relay_peer_id, HOP_PROTOCOL_ID)
        .map_err(|e| format!("open HOP: {e}"))?;
    wait_user_stream_ready(&mut swarm, role, hop_stream, deadline)?;
    let mut reservation = HopReservation::new();
    send(&mut swarm, &relay_peer_id, hop_stream, reservation.take_outbound())?;

    while reservation.outcome().is_none() {
        let data = wait_user_stream_data(&mut swarm, role, hop_stream, deadline)?;
        reservation.on_data(&data).map_err(|e| format!("HOP decode: {e}"))?;
    }
    match reservation.outcome() {
        Some(ReservationOutcome::Accepted { .. }) => {
            println!("[{role}] reserved-on-relay");
        }
        Some(ReservationOutcome::Refused { status, reason }) => {
            return Err(format!(
                "relay refused reservation: status={status:?} reason={reason}"
            )
            .into());
        }
        None => unreachable!(),
    }

    // --- 3. Wait for the relay to push a STOP stream at us ------------------
    let bridge_stream = wait_inbound_stream(
        &mut swarm,
        role,
        &relay_peer_id,
        STOP_PROTOCOL_ID,
        deadline,
    )?;
    println!("[{role}] incoming-circuit via-relay stream={bridge_stream}");

    // --- 4. STOP responder: accept the CONNECT, keep any pipelined bytes ---
    let mut stop = StopResponder::new();
    let remote_peer_id: PeerId = loop {
        let data = wait_user_stream_data(&mut swarm, role, bridge_stream, deadline)?;
        stop.on_data(&data).map_err(|e| format!("STOP decode: {e}"))?;
        if let Some(request) = stop.request() {
            break PeerId::from_bytes(&request.source_peer_id)
                .map_err(|e| format!("bad STOP source peer id: {e}"))?;
        }
    };
    println!("[{role}] stop-connect-from peer={remote_peer_id}");
    stop.accept().map_err(|e| format!("STOP accept: {e}"))?;
    send(&mut swarm, &relay_peer_id, bridge_stream, stop.take_outbound())?;
    let bridge_bytes = stop.take_bridge_bytes();

    // --- 5. DCUtR responder over the same bridge stream --------------------
    let mut dcutr = DcutrResponder::new(&our_observed);
    if !bridge_bytes.is_empty() {
        dcutr
            .on_data(&bridge_bytes)
            .map_err(|e| format!("DCUtR decode (pipelined): {e}"))?;
    }
    send(&mut swarm, &relay_peer_id, bridge_stream, dcutr.take_outbound())?;

    // DCUtR responder events arrive across multiple poll cycles:
    // `ConnectReceived` fires in one call, `SyncReceived` in a later
    // one. We thread the captured remote-addrs through the loop so
    // the CONNECT payload isn't thrown away when the SYNC arrives.
    let mut captured_remote_addrs: Option<Vec<Multiaddr>> = None;
    let remote_addrs: Vec<Multiaddr> = loop {
        if drain_dcutr_responder_events(&mut dcutr, role, &mut captured_remote_addrs) {
            break captured_remote_addrs.take().unwrap_or_default();
        }
        let data = wait_user_stream_data(&mut swarm, role, bridge_stream, deadline)?;
        dcutr.on_data(&data).map_err(|e| format!("DCUtR decode: {e}"))?;
        send(&mut swarm, &relay_peer_id, bridge_stream, dcutr.take_outbound())?;
    };

    // --- 6. Hole-punch: blast UDP, wait for direct or timeout --------------
    println!("[{role}] dcutr-sync-received -> holepunching");
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
    let remote_match_targets: Vec<(String, u16)> = remote_addrs
        .iter()
        .filter_map(extract_ip_port)
        .collect();

    // Check any connections already present (e.g. the remote's direct
    // Initial may have arrived BEFORE we observed the SYNC message on
    // a tight local loopback). Only counts if the source matches.
    let mut saw_inbound_conn = any_source_matches(
        &swarm.transport().active_connection_sources(),
        &remote_match_targets,
    );

    let outcome = 'outer: loop {
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
            if is_direct_connection_event(&ev, &remote_peer_id) {
                if let SwarmEvent::ConnectionEstablished { peer_id } = ev {
                    break 'outer HolePunchOutcome::DirectConnected(peer_id);
                }
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
            &swarm.transport().active_connection_sources(),
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
            ping_and_exit(&mut swarm, role, peer_id, deadline)
        }
        HolePunchOutcome::InboundConnectionSeen => {
            // We can't ping the remote from our side (don't know their
            // verified peer id without mTLS), and we can't detect when
            // the remote's own ping round-trip completes either. Run
            // the event loop for a short grace window so we stay
            // responsive to inbound streams (including the remote's
            // ping, which would otherwise time out waiting on our
            // echo).
            println!(
                "[{role}] inbound-direct-connection detected (hole-punch success; \
                 remote peer-id unverified pre-mTLS)"
            );
            let grace_deadline = Instant::now() + Duration::from_secs(2);
            let _ = swarm
                .run_until(grace_deadline, |ev| {
                    print_event(role, ev);
                    false // keep draining until the grace period elapses
                })
                .map_err(|e| format!("grace poll: {e}"))?;
            println!("[{role}] grace-elapsed -- done");
            Ok(())
        }
        HolePunchOutcome::BridgeClosed => {
            // Relay closed the circuit. Most likely the remote went
            // direct and no longer needs the bridge; we just can't
            // confirm that independently without mutual TLS on the
            // QUIC server side. Exit cleanly.
            println!(
                "[{role}] bridge-closed (remote likely completed via direct path; \
                 mTLS gap prevents confirmation) -- done"
            );
            Ok(())
        }
        HolePunchOutcome::Timeout => {
            println!("[{role}] hole-punch-timeout -> relay-ping fallback");
            // Wait up to ~15s for either an echo payload from Peer A
            // or the bridge to close (meaning A gave up). Longer
            // than the hole-punch deadline because the relay's own
            // idle-circuit GC can take several seconds -- but bounded
            // so we don't hang forever if something goes wrong.
            let fallback_deadline = Instant::now() + Duration::from_secs(15);
            let ev = swarm
                .run_until(fallback_deadline, |ev| {
                    print_event(role, ev);
                    matches!(
                        ev,
                        SwarmEvent::UserStreamData { stream_id: s, .. } if *s == bridge_stream
                    ) || is_bridge_closed_event(ev, bridge_stream)
                })
                .map_err(|e| format!("fallback poll: {e}"))?;
            match ev {
                Some(SwarmEvent::UserStreamData { data, .. }) => {
                    send(&mut swarm, &relay_peer_id, bridge_stream, data)?;
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
    }
}

/// Terminal states the listener's hole-punch loop can resolve to.
enum HolePunchOutcome {
    /// Saw `ConnectionEstablished` for the remote peer id (only
    /// possible once mutual TLS is implemented; see Milestone 6).
    DirectConnected(PeerId),
    /// `transport.active_connection_count()` grew beyond the relay
    /// baseline. Almost certainly the remote peer coming in direct.
    /// Coarse heuristic; not suitable for security decisions but
    /// fine for this demo binary.
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
        SwarmEvent::UserStreamRemoteWriteClosed { stream_id, .. }
            if *stream_id == bridge_stream
    ) || matches!(
        ev,
        SwarmEvent::UserStreamClosed { stream_id, .. } if *stream_id == bridge_stream
    )
}

// ---------------------------------------------------------------------------
// Dialer (Peer A): HOP CONNECT, DCUtR initiator, direct-dial, or fallback
// ---------------------------------------------------------------------------

pub fn run_dial(relay_addr: PeerAddr, target: PeerId) -> Result<(), Box<dyn Error>> {
    let role = "relay-dial";
    let mut swarm = build_swarm_with_relay_protocols()?;
    swarm
        .transport_mut()
        .listen_on_bound_addr()
        .map_err(|e| format!("listen failed: {e}"))?;
    let our_addr = swarm
        .transport()
        .local_peer_addr()
        .map_err(|e| format!("local_peer_addr: {e}"))?;
    let our_observed: Vec<Multiaddr> = vec![our_addr.transport().clone()];
    println!("[{role}] bound={our_addr}");
    println!("[{role}] us={}", swarm.local_peer_id());
    println!("[{role}] target={target}");

    let relay_peer_id = relay_addr.peer_id().clone();
    swarm
        .dial(&relay_addr)
        .map_err(|e| format!("dial relay: {e}"))?;
    println!("[{role}] dialing-relay {relay_addr}");

    let deadline = Instant::now() + LISTEN_DEADLINE;

    // --- 1. Relay connection established -----------------------------------
    wait_connected(&mut swarm, role, &relay_peer_id, deadline)?;

    // --- 2. HOP CONNECT to `target` through the relay ----------------------
    let hop_stream = swarm
        .open_user_stream(&relay_peer_id, HOP_PROTOCOL_ID)
        .map_err(|e| format!("open HOP: {e}"))?;
    wait_user_stream_ready(&mut swarm, role, hop_stream, deadline)?;
    let mut hop = HopConnect::new(target.to_bytes());
    send(&mut swarm, &relay_peer_id, hop_stream, hop.take_outbound())?;

    while hop.outcome().is_none() {
        let data = wait_user_stream_data(&mut swarm, role, hop_stream, deadline)?;
        hop.on_data(&data).map_err(|e| format!("HOP decode: {e}"))?;
    }
    match hop.outcome() {
        Some(ConnectOutcome::Bridged { .. }) => {
            println!("[{role}] bridge-established via-relay");
        }
        Some(ConnectOutcome::Refused { status, reason }) => {
            return Err(format!(
                "relay refused CONNECT: status={status:?} reason={reason}"
            )
            .into());
        }
        None => unreachable!(),
    }
    let bridge_stream = hop_stream; // same stream, now carrying DCUtR bytes
    let bridge_bytes = hop.take_bridge_bytes();

    // --- 3. DCUtR initiator over the bridge --------------------------------
    let mut dcutr = DcutrInitiator::new(&our_observed);
    let dcutr_sent_at = Instant::now();
    send(&mut swarm, &relay_peer_id, bridge_stream, dcutr.take_outbound())?;
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
        let data = wait_user_stream_data(&mut swarm, role, bridge_stream, deadline)?;
        let elapsed_ms = dcutr_sent_at.elapsed().as_millis() as u64;
        dcutr
            .on_data(&data, elapsed_ms)
            .map_err(|e| format!("DCUtR decode: {e}"))?;
    };
    println!("[{role}] dcutr-dialnow addrs={} rtt={rtt_ms}ms", remote_addrs.len());

    // --- 4. Flush SYNC and dial every observed remote address in parallel --
    dcutr.send_sync().map_err(|e| format!("DCUtR send_sync: {e}"))?;
    send(&mut swarm, &relay_peer_id, bridge_stream, dcutr.take_outbound())?;

    for addr in &remote_addrs {
        match PeerAddr::new(addr.clone(), target.clone()) {
            Ok(pa) => match swarm.dial(&pa) {
                Ok(_) => println!("[{role}] dialing-direct {pa}"),
                Err(e) => eprintln!("[{role}] direct-dial {pa} failed: {e}"),
            },
            Err(e) => eprintln!("[{role}] bad PeerAddr for {addr}: {e}"),
        }
    }

    // --- 5. Wait for direct connection or hole-punch timeout ---------------
    let punch_deadline = Instant::now() + HOLEPUNCH_DEADLINE;
    let punched = swarm
        .run_until(punch_deadline, |ev| {
            print_event(role, ev);
            matches!(
                ev,
                SwarmEvent::ConnectionEstablished { peer_id }
                    if peer_id == &target
            )
        })
        .map_err(|e| format!("holepunch poll: {e}"))?;

    // --- 6. Direct ping or relay-ping fallback -----------------------------
    if punched.is_some() {
        println!("[{role}] direct-connected peer={target} (hole-punch success)");
        ping_and_exit(&mut swarm, role, target, deadline)
    } else {
        println!("[{role}] hole-punch-timeout -> relay-ping fallback");
        let payload = random_bytes(RELAY_PING_LEN);
        let sent_at = Instant::now();
        send(&mut swarm, &relay_peer_id, bridge_stream, payload.clone())?;
        loop {
            let data = wait_user_stream_data(&mut swarm, role, bridge_stream, deadline)?;
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
// Small helpers
// ---------------------------------------------------------------------------

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
    found.map(|_| ()).ok_or_else(|| {
        format!("deadline exceeded before connection to {peer_id}").into()
    })
}

/// Wait for a locally-initiated `UserStreamReady` on `stream_id`.
fn wait_user_stream_ready(
    swarm: &mut Swarm<QuicTransport>,
    role: &str,
    stream_id: StreamId,
    deadline: Instant,
) -> Result<(), Box<dyn Error>> {
    let found = swarm
        .run_until(deadline, |ev| {
            print_event(role, ev);
            matches!(
                ev,
                SwarmEvent::UserStreamReady {
                    stream_id: s,
                    initiated_locally: true,
                    ..
                } if *s == stream_id
            )
        })
        .map_err(|e| format!("wait-user-stream-ready: {e}"))?;
    found
        .map(|_| ())
        .ok_or_else(|| format!("deadline exceeded before stream {stream_id} ready").into())
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

/// Wait for the next `UserStreamData` event on `stream_id`, returning
/// the data payload.
fn wait_user_stream_data(
    swarm: &mut Swarm<QuicTransport>,
    role: &str,
    stream_id: StreamId,
    deadline: Instant,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let ev = swarm
        .run_until(deadline, |ev| {
            print_event(role, ev);
            matches!(
                ev,
                SwarmEvent::UserStreamData { stream_id: s, .. } if *s == stream_id
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
fn build_swarm_with_relay_protocols() -> Result<Swarm<QuicTransport>, Box<dyn Error>> {
    let keypair = Ed25519Keypair::generate();
    let transport = QuicTransport::new(QuicNodeConfig::with_keypair(keypair.clone()), LOCAL_BIND)
        .map_err(|e| format!("quic bind: {e}"))?;
    let mut swarm = SwarmBuilder::new(&keypair).agent_version(AGENT).build(transport);
    swarm.add_user_protocol(HOP_PROTOCOL_ID);
    swarm.add_user_protocol(STOP_PROTOCOL_ID);
    swarm.add_user_protocol(DCUTR_PROTOCOL_ID);
    Ok(swarm)
}

/// Sends a random 32-byte UDP payload to every remote address. These
/// packets open the NAT binding so the remote's QUIC packets can reach
/// us; the content is irrelevant per the DCUtR spec.
fn blast_remote_addrs(swarm: &Swarm<QuicTransport>, addrs: &[Multiaddr], role: &str) {
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


