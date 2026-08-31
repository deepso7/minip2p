use std::collections::VecDeque;

use minip2p_core::{Multiaddr, PeerAddr, PeerId};
use minip2p_identity::Ed25519Keypair;
use minip2p_platform::{EntropyError, EntropySource, Now};
use minip2p_relay::{HOP_PROTOCOL_ID, STOP_PROTOCOL_ID};
use minip2p_relay_server::RelayServerAgent;
use minip2p_swarm::{DriverError, SwarmBuilder, SwarmError, SwarmEvent};
use minip2p_transport::{
    ConnectionEndpoint, ConnectionId, StreamId, Transport, TransportError, TransportEvent,
};

#[derive(Default)]
struct ScriptedTransport {
    events: VecDeque<TransportEvent>,
    sent: Vec<(StreamId, Vec<u8>)>,
    next_stream: u64,
}

impl Transport for ScriptedTransport {
    fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
        Err(TransportError::Unsupported { operation: "dial" })
    }

    fn listen(&mut self, _: &Multiaddr) -> Result<Multiaddr, TransportError> {
        Err(TransportError::Unsupported {
            operation: "listen",
        })
    }

    fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
        self.next_stream += 1;
        Ok(StreamId::new(100 + self.next_stream))
    }

    fn send_stream(
        &mut self,
        _: ConnectionId,
        stream_id: StreamId,
        data: Vec<u8>,
    ) -> Result<(), TransportError> {
        self.sent.push((stream_id, data));
        Ok(())
    }

    fn close_stream_write(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Ok(())
    }

    fn reset_stream(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Ok(())
    }

    fn close(&mut self, _: ConnectionId) -> Result<(), TransportError> {
        Ok(())
    }

    fn poll(&mut self, _: Now) -> Result<Vec<TransportEvent>, TransportError> {
        Ok(self.events.drain(..).collect())
    }
}

struct ZeroEntropy;

impl EntropySource for ZeroEntropy {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        output.fill(0);
        Ok(())
    }
}

#[test]
fn relay_server_registers_hop_and_stop_with_directional_swarm_roles() {
    let keypair = Ed25519Keypair::generate();
    let mut swarm = SwarmBuilder::new(&keypair)
        .build_runtime(ScriptedTransport::default(), ZeroEntropy)
        .unwrap();
    RelayServerAgent::register_swarm_roles(&mut swarm).unwrap();
    let peer = PeerId::from_public_key_protobuf(b"unconnected-role-probe");

    assert!(matches!(
        swarm.open_stream(&peer, HOP_PROTOCOL_ID, 0),
        Err(DriverError::Swarm(SwarmError::ProtocolNotRegistered { .. }))
    ));
    assert!(matches!(
        swarm.open_stream(&peer, STOP_PROTOCOL_ID, 0),
        Err(DriverError::Swarm(SwarmError::NotConnected { .. }))
    ));

    const IDENTIFY_PROTOCOL_ID: &str = "/ipfs/id/1.0.0";
    let conn_id = ConnectionId::new(1);
    let hop_stream = StreamId::new(1);
    let stop_stream = StreamId::new(2);
    let identify_stream = StreamId::new(3);
    let negotiation = |stream_id, protocol_id| {
        let mut data = multistream_frame("/multistream/1.0.0");
        data.extend_from_slice(&multistream_frame(protocol_id));
        [
            TransportEvent::IncomingStream {
                id: conn_id,
                stream_id,
            },
            TransportEvent::StreamData {
                id: conn_id,
                stream_id,
                data,
            },
        ]
    };
    let transport = swarm.transport_mut();
    transport.events.push_back(TransportEvent::Connected {
        id: conn_id,
        endpoint: ConnectionEndpoint::with_peer_id(
            "/ip4/192.0.2.1/tcp/4001".parse().unwrap(),
            peer.clone(),
        ),
    });
    transport
        .events
        .extend(negotiation(hop_stream, HOP_PROTOCOL_ID));
    transport
        .events
        .extend(negotiation(stop_stream, STOP_PROTOCOL_ID));
    transport
        .events
        .extend(negotiation(identify_stream, IDENTIFY_PROTOCOL_ID));

    let events = swarm.poll(Now::from_millis(0)).unwrap();
    let _ = swarm.poll(Now::from_millis(0)).unwrap();
    assert!(events.iter().any(|event| matches!(
        event,
        SwarmEvent::StreamReady {
            peer_id,
            stream_id,
            protocol_id,
            initiated_locally: false,
            ..
        } if peer_id == &peer && *stream_id == hop_stream && protocol_id == HOP_PROTOCOL_ID
    )));
    assert!(events.iter().all(|event| !matches!(
        event,
        SwarmEvent::StreamReady {
            stream_id,
            initiated_locally: false,
            ..
        } if *stream_id == stop_stream
    )));

    let sent = &swarm.transport().sent;
    assert!(
        sent.iter()
            .any(|(stream, data)| *stream == stop_stream && data == &multistream_frame("na"))
    );
    let identify_bytes: Vec<_> = sent
        .iter()
        .filter(|(stream, _)| *stream == identify_stream)
        .flat_map(|(_, data)| data.iter().copied())
        .collect();
    assert!(contains(&identify_bytes, HOP_PROTOCOL_ID.as_bytes()));
    assert!(!contains(&identify_bytes, STOP_PROTOCOL_ID.as_bytes()));
}

fn multistream_frame(protocol: &str) -> Vec<u8> {
    let mut frame = vec![(protocol.len() + 1) as u8];
    frame.extend_from_slice(protocol.as_bytes());
    frame.push(b'\n');
    frame
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
