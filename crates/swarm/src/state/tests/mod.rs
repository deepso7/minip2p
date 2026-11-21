use alloc::boxed::Box;
use core::str::FromStr;

use minip2p_identify::IdentifyConfig;
use minip2p_multistream_select::MULTISTREAM_PROTOCOL_ID;
use minip2p_transport::{
    ConnectionCloseReason, ConnectionEndpoint, ConnectionId, StreamId, TransportEvent,
};

use super::*;

fn test_core() -> SwarmState {
    SwarmState::new(
        IdentifyConfig {
            protocol_version: "minip2p-test/0.1.0".into(),
            agent_version: "minip2p-test/0.1.0".into(),
            protocols: Vec::new(),
            public_key: Vec::new(),
        },
        SwarmTimeouts::default(),
    )
}

fn loopback_transport() -> Multiaddr {
    Multiaddr::from_str("/ip4/127.0.0.1/udp/4001/quic-v1").expect("valid multiaddr")
}

fn feed(core: &mut SwarmState, event: TransportEvent) {
    core.handle_transport_event(event, 0);
}

/// One step of the state's queues in delivery order: ordinary actions,
/// then events, then deferred closes.
#[derive(Debug)]
#[expect(clippy::large_enum_variant, reason = "test-only queue view")]
enum Output {
    Action(Action),
    Event(SwarmEvent),
}

impl SwarmState {
    fn poll_output(&mut self) -> Option<Output> {
        if !self.actions.is_empty()
            && let Some(action) = self.next_action()
        {
            return Some(Output::Action(action));
        }
        if let Some(event) = self.next_event() {
            return Some(Output::Event(event));
        }
        self.next_action().map(Output::Action)
    }

    /// What `SwarmCore::open_stream` does before its transport call,
    /// queued instead so tests can observe it.
    fn open_stream(&mut self, peer_id: &PeerId, protocol_id: &str) -> Result<(), SwarmError> {
        let conn_id = self.admit_user_open(peer_id, protocol_id)?;
        self.actions.push_back(Action::OpenStream {
            conn_id,
            protocol: protocol_id.into(),
            target: ProtocolKind::User(protocol_id.into()),
        });
        Ok(())
    }

    /// What `SwarmCore::send_stream` does before its transport call,
    /// queued instead so tests can observe it.
    fn send_stream(
        &mut self,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
    ) -> Result<(), SwarmError> {
        let data = self.admit_user_write(peer_id, conn_id, stream_id, data)?;
        self.actions.push_back(Action::SendStream {
            conn_id,
            stream_id,
            data,
        });
        Ok(())
    }

    /// Reports `stream_id` opened for the open of `protocol_id` on
    /// `conn_id` in `actions`, as `SwarmCore` does once the transport
    /// answers.
    fn opened(
        &mut self,
        actions: Vec<Action>,
        conn_id: ConnectionId,
        protocol_id: &str,
        stream_id: StreamId,
    ) {
        let target = actions
            .into_iter()
            .find_map(|action| match action {
                Action::OpenStream {
                    conn_id: open_conn,
                    protocol,
                    target,
                } if open_conn == conn_id && protocol == protocol_id => Some(target),
                _ => None,
            })
            .expect("an OpenStream for the protocol on the connection");
        self.start_outbound(conn_id, stream_id, protocol_id, target);
    }
}

fn drain_actions(core: &mut SwarmState) -> Vec<Action> {
    let mut actions = Vec::new();
    while let Some(output) = core.poll_output() {
        match output {
            Output::Action(action) => actions.push(action),
            Output::Event(_) => {}
        }
    }
    actions
}

fn drain_events(core: &mut SwarmState) -> Vec<SwarmEvent> {
    let mut events = Vec::new();
    while let Some(output) = core.poll_output() {
        match output {
            Output::Action(_) => {}
            Output::Event(event) => events.push(event),
        }
    }
    events
}

fn multistream_frame(protocol: &str) -> Vec<u8> {
    let payload_len = protocol.len() + 1;
    assert!(
        payload_len < 128,
        "test helper only encodes one-byte lengths"
    );
    let mut frame = vec![payload_len as u8];
    frame.extend_from_slice(protocol.as_bytes());
    frame.push(b'\n');
    frame
}

/// Feeds a second connection to an already connected peer, as the
/// dialer (`Connected`) or the listener (`IncomingConnection` first).
fn connect_again(core: &mut SwarmState, peer_id: &PeerId, conn_id: ConnectionId, inbound: bool) {
    if inbound {
        feed(
            core,
            TransportEvent::IncomingConnection {
                id: conn_id,
                endpoint: Box::new(ConnectionEndpoint::new(loopback_transport())),
            },
        );
    }
    feed(
        core,
        TransportEvent::Connected {
            id: conn_id,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                loopback_transport(),
                *peer_id,
            )),
        },
    );
}

/// Registers `peer_id` as connected on `conn_id` with a fully
/// negotiated outbound ping stream, draining all setup outputs.
fn setup_outbound_ping_stream(
    core: &mut SwarmState,
    peer_id: &PeerId,
    conn_id: ConnectionId,
    stream_id: StreamId,
) {
    feed(
        core,
        TransportEvent::Connected {
            id: conn_id,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                loopback_transport(),
                *peer_id,
            )),
        },
    );
    while core.poll_output().is_some() {}
    // Only ping's timer is under test.
    core.first_identify.clear();
    core.insert_stream_owner(conn_id, stream_id, ProtocolKind::Ping);
    core.ping
        .register_outbound_stream(*peer_id, stream_id)
        .expect("register outbound ping stream");
    while core.ping.poll_output().is_some() {}
}

/// The `control` values of the control-stream marks in `actions` for
/// `stream_id`, in order.
fn control_marks(actions: &[Action], stream_id: StreamId) -> Vec<bool> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::SetControlStream {
                stream_id: marked,
                control,
                ..
            } if *marked == stream_id => Some(*control),
            _ => None,
        })
        .collect()
}

/// A connected peer with a user stream for `/app/1` opened on stream 7,
/// still negotiating, opened at `now_ms`.
fn negotiating_user_stream(now_ms: u64) -> (SwarmState, ConnectionId, StreamId) {
    let mut core = test_core();
    let peer = PeerId::from_public_key_protobuf(b"negotiating-peer");
    let conn = ConnectionId::new(61);
    let stream = StreamId::new(7);
    feed(
        &mut core,
        TransportEvent::Connected {
            id: conn,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(loopback_transport(), peer)),
        },
    );
    drain_actions(&mut core);
    drain_events(&mut core);
    // Only the user stream's timer is under test.
    core.first_identify.clear();
    core.add_protocol("/app/1").expect("register");
    core.open_stream(&peer, "/app/1").expect("admit open");
    let actions = drain_actions(&mut core);
    let target = actions
        .into_iter()
        .find_map(|action| match action {
            Action::OpenStream { target, .. } => Some(target),
            _ => None,
        })
        .expect("an open");
    core.start_outbound(conn, stream, "/app/1", target);
    core.handle_transport_event(
        TransportEvent::StreamOpened {
            id: conn,
            stream_id: stream,
        },
        now_ms,
    );
    drain_actions(&mut core);
    (core, conn, stream)
}

/// The lifecycle events and the `old` close action among `outputs`, in order.
fn lifecycle(outputs: &[Output]) -> Vec<String> {
    outputs
        .iter()
        .filter_map(|output| match output {
            Output::Event(SwarmEvent::ConnectionEstablished { conn_id, .. }) => {
                Some(format!("established {conn_id}"))
            }
            Output::Event(SwarmEvent::ConnectionClosed { conn_id, .. }) => {
                Some(format!("closed {conn_id}"))
            }
            Output::Event(SwarmEvent::ConnectionReplaced { old, new, .. }) => {
                Some(format!("replaced {old}->{new}"))
            }
            Output::Action(Action::CloseConnection { conn_id }) => Some(format!("close {conn_id}")),
            _ => None,
        })
        .collect()
}

fn ready_conns(events: &[SwarmEvent]) -> Vec<ConnectionId> {
    events
        .iter()
        .filter_map(|event| match event {
            SwarmEvent::PeerReady { conn_id, .. } => Some(*conn_id),
            _ => None,
        })
        .collect()
}

/// Completes the Identify exchange the core opened on `conn_id`,
/// advertising `protocols`.
fn identify_on(
    core: &mut SwarmState,
    conn_id: ConnectionId,
    stream_id: StreamId,
    protocols: &[&str],
) {
    use minip2p_core::encode_frame;

    let actions = drain_actions(core);
    core.opened(actions, conn_id, IDENTIFY_PROTOCOL_ID, stream_id);
    let mut accept = multistream_frame(MULTISTREAM_PROTOCOL_ID);
    accept.extend_from_slice(&multistream_frame(IDENTIFY_PROTOCOL_ID));
    feed(
        core,
        TransportEvent::StreamData {
            id: conn_id,
            stream_id,
            data: Bytes::from(accept),
        },
    );
    let info = IdentifyMessage {
        protocol_version: Some("ipfs/0.1.0".into()),
        agent_version: Some("test".into()),
        public_key: None,
        listen_addrs: Vec::new(),
        observed_addr: None,
        protocols: protocols.iter().map(|p| (*p).into()).collect(),
    };
    feed(
        core,
        TransportEvent::StreamData {
            id: conn_id,
            stream_id,
            data: Bytes::from(encode_frame(&info.encode())),
        },
    );
    feed(
        core,
        TransportEvent::StreamRemoteWriteClosed {
            id: conn_id,
            stream_id,
        },
    );
}

mod admission;
mod connections;
mod dials;
mod identify;
mod negotiation;
mod ping;
mod replacement;
mod simultaneous_dial;
mod streams;
mod writes;
