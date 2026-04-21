use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use minip2p_core::{PeerAddr, PeerId};
use minip2p_multistream_select::{MultistreamOutput, MultistreamSelect};
use minip2p_ping::{PING_PAYLOAD_LEN, PING_PROTOCOL_ID, PingAction, PingEvent, PingProtocol};
use minip2p_quic::{QuicNodeConfig, QuicTransport};
use minip2p_transport::{ConnectionId, StreamId, Transport, TransportEvent};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn drive_pair_once(
    server: &mut QuicTransport,
    client: &mut QuicTransport,
) -> (Vec<TransportEvent>, Vec<TransportEvent>) {
    std::thread::sleep(std::time::Duration::from_millis(5));
    let server_events = server.poll().expect("server poll");
    let client_events = client.poll().expect("client poll");
    (server_events, client_events)
}

fn apply_ping_actions(
    transport: &mut QuicTransport,
    connection_id: ConnectionId,
    actions: Vec<PingAction>,
) {
    for action in actions {
        match action {
            PingAction::Send {
                stream_id, data, ..
            } => {
                transport
                    .send_stream(connection_id, stream_id, data.to_vec())
                    .expect("send ping payload");
            }
            PingAction::CloseStreamWrite { stream_id, .. } => {
                transport
                    .close_stream_write(connection_id, stream_id)
                    .expect("close ping stream write");
            }
            PingAction::ResetStream { stream_id, .. } => {
                transport
                    .reset_stream(connection_id, stream_id)
                    .expect("reset ping stream");
            }
        }
    }
}

fn assert_no_protocol_violations(events: &[PingEvent]) {
    for event in events {
        if let PingEvent::ProtocolViolation {
            peer_id,
            stream_id,
            reason,
        } = event
        {
            panic!("ping protocol violation on peer {peer_id} stream {stream_id}: {reason}");
        }
    }
}

/// Fully connected + verified + negotiated ping harness ready for use.
struct PingHarness {
    server: QuicTransport,
    client: QuicTransport,
    peer_addr: PeerAddr,
    server_conn_id: ConnectionId,
    client_conn_id: ConnectionId,
    client_stream: StreamId,
    client_ping: PingProtocol,
    server_ping: PingProtocol,
    server_negotiators: BTreeMap<StreamId, MultistreamSelect>,
    server_ping_streams: BTreeSet<StreamId>,
    start: Instant,
}

impl PingHarness {
    /// Create a connected, verified, and multistream-negotiated ping pair.
    fn new(client_conn_id_raw: u64) -> Self {
        let mut server =
            QuicTransport::new(QuicNodeConfig::dev_listener(), "127.0.0.1:0").expect("server bind");
        let mut client =
            QuicTransport::new(QuicNodeConfig::dev_dialer(), "127.0.0.1:0").expect("client bind");

        server.listen_on_bound_addr().expect("server listen");
        let peer_addr = server.local_peer_addr().expect("peer addr");

        // Connect.
        let client_conn_id = ConnectionId::new(client_conn_id_raw);
        client
            .dial(client_conn_id, &peer_addr)
            .expect("client dial");

        let server_conn_id = Self::wait_for_connection(
            &mut server,
            &mut client,
            client_conn_id,
            &peer_addr,
            250,
        )
        .expect("server should observe connection");

        // Identity is now auto-verified from the TLS certificate. No manual
        // verify_connection_peer_id call needed.

        // Open stream and negotiate multistream-select for ping.
        let client_stream = client
            .open_stream(client_conn_id)
            .expect("open client ping stream");

        let mut client_negotiator = MultistreamSelect::dialer(PING_PROTOCOL_ID);
        for output in client_negotiator.start() {
            if let MultistreamOutput::OutboundData(bytes) = output {
                client
                    .send_stream(client_conn_id, client_stream, bytes)
                    .expect("send dialer multistream header");
            }
        }

        let mut server_negotiators: BTreeMap<StreamId, MultistreamSelect> = BTreeMap::new();
        let mut server_ping_streams: BTreeSet<StreamId> = BTreeSet::new();
        let mut client_ping = PingProtocol::default();
        let mut server_ping = PingProtocol::default();

        let start = Instant::now();
        let mut client_negotiated = false;

        for _ in 0..200 {
            let (server_events, client_events) = drive_pair_once(&mut server, &mut client);

            Self::handle_server_events(
                &server_events,
                &mut server,
                server_conn_id,
                &peer_addr,
                &mut server_negotiators,
                &mut server_ping_streams,
                &mut server_ping,
                &start,
                &mut None,
            );

            for event in client_events {
                if let TransportEvent::StreamData {
                    id,
                    stream_id,
                    data,
                } = event
                {
                    assert_eq!(id, client_conn_id);
                    if !client_negotiated {
                        let outputs = client_negotiator.receive(&data);
                        for output in outputs {
                            match output {
                                MultistreamOutput::OutboundData(bytes) => {
                                    client
                                        .send_stream(client_conn_id, client_stream, bytes)
                                        .expect("send dialer negotiation bytes");
                                }
                                MultistreamOutput::Negotiated { protocol } => {
                                    assert_eq!(protocol, PING_PROTOCOL_ID);
                                    assert_eq!(stream_id, client_stream);
                                    client_ping
                                        .register_outbound_stream(
                                            peer_addr.peer_id().clone(),
                                            client_stream,
                                        )
                                        .expect("register outbound ping stream");
                                    client_negotiated = true;
                                }
                                MultistreamOutput::NotAvailable => {
                                    panic!(
                                        "dialer reported protocol not available unexpectedly"
                                    )
                                }
                                MultistreamOutput::ProtocolError { reason } => {
                                    panic!("dialer multistream protocol error: {reason}")
                                }
                            }
                        }
                    }
                }
            }

            if client_negotiated {
                break;
            }
        }
        assert!(client_negotiated, "multistream negotiation should complete");

        Self {
            server,
            client,
            peer_addr,
            server_conn_id,
            client_conn_id,
            client_stream,
            client_ping,
            server_ping,
            server_negotiators,
            server_ping_streams,
            start,
        }
    }

    fn wait_for_connection(
        server: &mut QuicTransport,
        client: &mut QuicTransport,
        expected_client_conn: ConnectionId,
        expected_peer: &PeerAddr,
        max_iters: usize,
    ) -> Option<ConnectionId> {
        let mut server_conn = None;
        let mut client_connected = false;

        for _ in 0..max_iters {
            let (server_events, client_events) = drive_pair_once(server, client);

            for event in server_events {
                match event {
                    TransportEvent::IncomingConnection { id, endpoint } => {
                        assert!(endpoint.peer_id().is_none());
                        server_conn = Some(id);
                    }
                    TransportEvent::Connected { id, .. } => {
                        if server_conn.is_none() {
                            server_conn = Some(id);
                        }
                    }
                    _ => {}
                }
            }

            for event in client_events {
                if let TransportEvent::Connected { id, endpoint } = event {
                    if id == expected_client_conn {
                        assert_eq!(endpoint.peer_id(), Some(expected_peer.peer_id()));
                        client_connected = true;
                    }
                }
            }

            if client_connected && server_conn.is_some() {
                return server_conn;
            }
        }

        None
    }

    /// Process server-side transport events (negotiation + ping echo).
    fn handle_server_events(
        events: &[TransportEvent],
        server: &mut QuicTransport,
        server_conn_id: ConnectionId,
        peer_addr: &PeerAddr,
        negotiators: &mut BTreeMap<StreamId, MultistreamSelect>,
        ping_streams: &mut BTreeSet<StreamId>,
        server_ping: &mut PingProtocol,
        start: &Instant,
        on_remote_write_closed: &mut Option<StreamId>,
    ) {
        for event in events {
            match event {
                TransportEvent::IncomingStream { id, stream_id } => {
                    assert_eq!(*id, server_conn_id);
                    let mut listener =
                        MultistreamSelect::listener([PING_PROTOCOL_ID.to_string()]);
                    let start_outputs = listener.start();
                    negotiators.insert(*stream_id, listener);

                    for output in start_outputs {
                        if let MultistreamOutput::OutboundData(bytes) = output {
                            server
                                .send_stream(server_conn_id, *stream_id, bytes)
                                .expect("send listener multistream header");
                        }
                    }
                }
                TransportEvent::StreamData {
                    id,
                    stream_id,
                    data,
                } => {
                    assert_eq!(*id, server_conn_id);
                    if let Some(negotiator) = negotiators.get_mut(stream_id) {
                        let outputs = negotiator.receive(data);
                        let mut negotiated_ping = false;

                        for output in outputs {
                            match output {
                                MultistreamOutput::OutboundData(bytes) => {
                                    server
                                        .send_stream(server_conn_id, *stream_id, bytes)
                                        .expect("send listener negotiation bytes");
                                }
                                MultistreamOutput::Negotiated { protocol } => {
                                    assert_eq!(protocol, PING_PROTOCOL_ID);
                                    negotiated_ping = true;

                                    let actions = server_ping.register_inbound_stream(
                                        peer_addr.peer_id().clone(),
                                        *stream_id,
                                    );
                                    apply_ping_actions(server, server_conn_id, actions);
                                }
                                MultistreamOutput::NotAvailable => {
                                    panic!(
                                        "listener reported protocol not available unexpectedly"
                                    )
                                }
                                MultistreamOutput::ProtocolError { reason } => {
                                    panic!("listener multistream protocol error: {reason}")
                                }
                            }
                        }

                        if negotiated_ping {
                            negotiators.remove(stream_id);
                            ping_streams.insert(*stream_id);
                        }
                    } else if ping_streams.contains(stream_id) {
                        let actions = server_ping.on_stream_data(
                            peer_addr.peer_id(),
                            *stream_id,
                            data,
                            start.elapsed().as_millis() as u64,
                        );
                        apply_ping_actions(server, server_conn_id, actions);
                    } else {
                        panic!("server received data for unknown stream {stream_id}");
                    }
                }
                TransportEvent::StreamRemoteWriteClosed { id, stream_id } => {
                    assert_eq!(*id, server_conn_id);
                    let actions = server_ping
                        .on_stream_remote_write_closed(peer_addr.peer_id(), *stream_id);
                    apply_ping_actions(server, server_conn_id, actions);
                    *on_remote_write_closed = Some(*stream_id);
                }
                TransportEvent::StreamClosed { id, stream_id } => {
                    assert_eq!(*id, server_conn_id);
                    server_ping.on_stream_closed(peer_addr.peer_id(), *stream_id);
                    ping_streams.remove(stream_id);
                    negotiators.remove(stream_id);
                }
                _ => {}
            }
        }
    }

    /// Run the event loop for one iteration, returning all client events.
    fn drive_once(&mut self) -> Vec<TransportEvent> {
        let (server_events, client_events) = drive_pair_once(&mut self.server, &mut self.client);

        Self::handle_server_events(
            &server_events,
            &mut self.server,
            self.server_conn_id,
            &self.peer_addr,
            &mut self.server_negotiators,
            &mut self.server_ping_streams,
            &mut self.server_ping,
            &self.start,
            &mut None,
        );

        let now_ms = self.start.elapsed().as_millis() as u64;
        apply_ping_actions(
            &mut self.server,
            self.server_conn_id,
            self.server_ping.on_tick(now_ms),
        );
        assert_no_protocol_violations(&self.server_ping.poll_events());

        client_events
    }

    /// Drive the event loop including a custom server-side remote-write-closed
    /// callback (needed by the close-write test).
    fn drive_once_with_server_close_hook(
        &mut self,
    ) -> (Vec<TransportEvent>, Option<StreamId>) {
        let (server_events, client_events) = drive_pair_once(&mut self.server, &mut self.client);

        let mut closed_stream = None;
        Self::handle_server_events(
            &server_events,
            &mut self.server,
            self.server_conn_id,
            &self.peer_addr,
            &mut self.server_negotiators,
            &mut self.server_ping_streams,
            &mut self.server_ping,
            &self.start,
            &mut closed_stream,
        );

        // When server sees remote write closed, it closes its own write side.
        if let Some(stream_id) = closed_stream {
            self.server
                .close_stream_write(self.server_conn_id, stream_id)
                .expect("server closes ping stream write after remote close");
        }

        let now_ms = self.start.elapsed().as_millis() as u64;
        apply_ping_actions(
            &mut self.server,
            self.server_conn_id,
            self.server_ping.on_tick(now_ms),
        );
        assert_no_protocol_violations(&self.server_ping.poll_events());

        (client_events, closed_stream)
    }

    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    fn peer_id(&self) -> &PeerId {
        self.peer_addr.peer_id()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn ping_roundtrip_after_identity_verification_and_multistream_negotiation() {
    let mut h = PingHarness::new(400);
    let peer_id = h.peer_id().clone();

    let payload: [u8; PING_PAYLOAD_LEN] = core::array::from_fn(|i| i as u8);
    let mut ping_sent = false;
    let mut measured_rtt_ms = None;

    for _ in 0..400 {
        let client_events = h.drive_once();

        for event in client_events {
            match event {
                TransportEvent::StreamData {
                    id,
                    stream_id,
                    data,
                } => {
                    assert_eq!(id, h.client_conn_id);
                    let now = h.now_ms();
                    let actions =
                        h.client_ping.on_stream_data(&peer_id, stream_id, &data, now);
                    apply_ping_actions(&mut h.client, h.client_conn_id, actions);
                }
                TransportEvent::StreamRemoteWriteClosed { id, stream_id } => {
                    assert_eq!(id, h.client_conn_id);
                    let actions =
                        h.client_ping.on_stream_remote_write_closed(&peer_id, stream_id);
                    apply_ping_actions(&mut h.client, h.client_conn_id, actions);
                }
                TransportEvent::StreamClosed { id, stream_id } => {
                    assert_eq!(id, h.client_conn_id);
                    h.client_ping.on_stream_closed(&peer_id, stream_id);
                }
                _ => {}
            }
        }

        let now_ms = h.now_ms();
        apply_ping_actions(
            &mut h.client,
            h.client_conn_id,
            h.client_ping.on_tick(now_ms),
        );

        if !ping_sent {
            let send = h
                .client_ping
                .send_ping(&peer_id, &payload, now_ms)
                .expect("prepare ping request");
            apply_ping_actions(&mut h.client, h.client_conn_id, vec![send]);
            ping_sent = true;
        }

        for event in h.client_ping.poll_events() {
            match event {
                PingEvent::RttMeasured {
                    peer_id: pid,
                    stream_id,
                    rtt_ms,
                } => {
                    assert_eq!(pid, peer_id);
                    assert_eq!(stream_id, h.client_stream);
                    measured_rtt_ms = Some(rtt_ms);
                }
                PingEvent::ProtocolViolation {
                    peer_id,
                    stream_id,
                    reason,
                } => {
                    panic!(
                        "client ping protocol violation on peer {peer_id} stream {stream_id}: {reason}"
                    );
                }
                _ => {}
            }
        }

        if measured_rtt_ms.is_some() {
            break;
        }
    }

    let measured_rtt_ms = measured_rtt_ms.expect("ping roundtrip should complete");
    assert!(measured_rtt_ms < 5_000, "rtt should be bounded in test env");
}

#[test]
fn repeated_ping_on_same_stream_then_close_write_exits_listener_loop() {
    let mut h = PingHarness::new(401);
    let peer_id = h.peer_id().clone();

    let payloads = [
        core::array::from_fn::<_, PING_PAYLOAD_LEN, _>(|i| i as u8),
        core::array::from_fn::<_, PING_PAYLOAD_LEN, _>(|i| (i as u8).wrapping_add(17)),
    ];

    let mut next_ping_idx = 0usize;
    let mut measured_rtts: Vec<u64> = Vec::new();
    let mut close_requested = false;
    let mut server_saw_remote_write_closed = false;
    let mut client_saw_remote_write_closed = false;

    for _ in 0..500 {
        let (client_events, server_closed_stream) = h.drive_once_with_server_close_hook();

        if server_closed_stream.is_some() {
            server_saw_remote_write_closed = true;
        }

        for event in client_events {
            match event {
                TransportEvent::StreamData {
                    id,
                    stream_id,
                    data,
                } => {
                    assert_eq!(id, h.client_conn_id);
                    let now = h.now_ms();
                    let actions =
                        h.client_ping.on_stream_data(&peer_id, stream_id, &data, now);
                    apply_ping_actions(&mut h.client, h.client_conn_id, actions);
                }
                TransportEvent::StreamRemoteWriteClosed { id, stream_id } => {
                    assert_eq!(id, h.client_conn_id);
                    if stream_id == h.client_stream {
                        client_saw_remote_write_closed = true;
                    }
                    let actions =
                        h.client_ping.on_stream_remote_write_closed(&peer_id, stream_id);
                    apply_ping_actions(&mut h.client, h.client_conn_id, actions);
                }
                TransportEvent::StreamClosed { id, stream_id } => {
                    assert_eq!(id, h.client_conn_id);
                    h.client_ping.on_stream_closed(&peer_id, stream_id);
                }
                _ => {}
            }
        }

        let now_ms = h.now_ms();
        apply_ping_actions(
            &mut h.client,
            h.client_conn_id,
            h.client_ping.on_tick(now_ms),
        );

        if next_ping_idx < payloads.len() && measured_rtts.len() == next_ping_idx {
            let send = h
                .client_ping
                .send_ping(&peer_id, &payloads[next_ping_idx], now_ms)
                .expect("prepare ping request");
            apply_ping_actions(&mut h.client, h.client_conn_id, vec![send]);
            next_ping_idx += 1;
        }

        for event in h.client_ping.poll_events() {
            match event {
                PingEvent::RttMeasured {
                    peer_id: pid,
                    stream_id,
                    rtt_ms,
                } => {
                    assert_eq!(pid, peer_id);
                    assert_eq!(stream_id, h.client_stream);
                    measured_rtts.push(rtt_ms);
                }
                PingEvent::ProtocolViolation {
                    peer_id,
                    stream_id,
                    reason,
                } => {
                    panic!(
                        "client ping protocol violation on peer {peer_id} stream {stream_id}: {reason}"
                    );
                }
                _ => {}
            }
        }

        if measured_rtts.len() == payloads.len() && !close_requested {
            let close = h
                .client_ping
                .close_outbound_stream_write(&peer_id)
                .expect("close ping write side");
            apply_ping_actions(&mut h.client, h.client_conn_id, vec![close]);
            close_requested = true;
        }

        if close_requested && server_saw_remote_write_closed && client_saw_remote_write_closed {
            break;
        }
    }

    assert_eq!(
        measured_rtts.len(),
        payloads.len(),
        "both ping RTTs should be measured"
    );
    assert!(
        measured_rtts.iter().all(|rtt| *rtt < 5_000),
        "rtts should be bounded in test env"
    );
    assert!(
        server_saw_remote_write_closed,
        "listener should observe dialer write close"
    );
    assert!(
        client_saw_remote_write_closed,
        "dialer should observe listener loop exit via remote write close"
    );
}
