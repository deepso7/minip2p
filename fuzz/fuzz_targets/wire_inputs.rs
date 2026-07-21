#![no_main]

use libfuzzer_sys::fuzz_target;
use minip2p_autonat::{AutoNatClient, AutoNatClientInput, AutoNatServer, AutoNatServerInput};
use minip2p_circuit::{BridgeAdoption, CircuitRole, CircuitTransport, EntropyError, EntropySource};
use minip2p_core::{Multiaddr, PeerAddr, PeerId, SansIoProtocol};
use minip2p_dcutr::{FrameDecode as DcutrFrame, HolePunch};
use minip2p_discovery::{Beacon, DiscoveryAgent, DiscoveryConfig};
use minip2p_identify::{IdentifyConfig, IdentifyInput, IdentifyMessage, IdentifyProtocol};
use minip2p_identity::{KeyType, PublicKey};
use minip2p_multistream_select::{MultistreamInput, MultistreamSelect};
use minip2p_noise::{NoiseConfig, NoiseHandshakePayload, NoiseInput, NoiseRole, NoiseSession};
use minip2p_pubsub::{FrameDecode as PubsubFrame, RawMessage, Rpc};
use minip2p_relay::{FrameDecode as RelayFrame, HopMessage, StopMessage};
use minip2p_transport::{
    ConnectionEndpoint, ConnectionId, StreamId, Transport, TransportError, TransportEvent,
};
use minip2p_yamux::{FrameDecoder as YamuxFrameDecoder, YamuxRole, YamuxSession};

fuzz_target!(|data: &[u8]| {
    let _ = Multiaddr::from_bytes(data);
    if let Ok(text) = core::str::from_utf8(data) {
        let _ = text.parse::<Multiaddr>();
    }

    fuzz_multistream(data);
    fuzz_identify(data);
    fuzz_autonat(data);
    fuzz_discovery(data);
    fuzz_noise(data);
    fuzz_pubsub(data);
    fuzz_yamux(data);
    fuzz_circuit(data);

    if let RelayFrame::Complete { payload, .. } = minip2p_relay::decode_frame(data) {
        let _ = HopMessage::decode(payload);
        let _ = StopMessage::decode(payload);
    }
    if let DcutrFrame::Complete { payload, .. } = minip2p_dcutr::decode_frame(data) {
        let _ = HolePunch::decode(payload);
    }
});

/// Exercises pubsub framing, RPC/control decoding, canonical re-encoding,
/// and StrictSign validation with arbitrary wire bytes.
fn fuzz_pubsub(data: &[u8]) {
    if let PubsubFrame::Complete { payload, .. } = minip2p_pubsub::decode_frame(data)
        && let Ok(rpc) = Rpc::decode(payload)
    {
        let _ = rpc.encode();
    }
    if let Ok(rpc) = Rpc::decode(data) {
        let _ = rpc.encode();
    }
    if let Ok(message) = RawMessage::decode(data) {
        let _ = message.to_wire();
        let _ = message.verify(false);
        let _ = message.verify(true);
    }
}

/// Feeds the input to both negotiation roles so `decode_message` and the
/// per-state handlers see attacker-controlled bytes.
fn fuzz_multistream(data: &[u8]) {
    let machines = [
        MultistreamSelect::dialer("/ipfs/ping/1.0.0"),
        MultistreamSelect::listener(["/ipfs/ping/1.0.0".to_string()]),
    ];
    for mut machine in machines {
        let _ = machine.handle_input(MultistreamInput::Start);
        let _ = machine.handle_input(MultistreamInput::Data(data.to_vec()));
        while machine.poll_output().is_some() {}
        let _ = machine.take_remaining_buffer();
    }
}

struct FixedEntropy;

impl EntropySource for FixedEntropy {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(7);
        Ok(())
    }
}

struct FuzzTransport {
    initial: Option<TransportEvent>,
}

impl FuzzTransport {
    fn new(relay: PeerId) -> Self {
        Self {
            initial: Some(TransportEvent::Connected {
                id: ConnectionId::new(1),
                endpoint: ConnectionEndpoint::with_peer_id(
                    "/ip4/192.0.2.1/udp/4001/quic-v1"
                        .parse()
                        .expect("static fuzz address"),
                    relay,
                ),
            }),
        }
    }
}

impl Transport for FuzzTransport {
    fn dial(&mut self, _addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        Err(TransportError::InvalidConfig {
            reason: "fuzz transport does not dial".into(),
        })
    }

    fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, TransportError> {
        Ok(addr.clone())
    }

    fn open_stream(&mut self, _id: ConnectionId) -> Result<StreamId, TransportError> {
        Ok(StreamId::new(1))
    }

    fn send_stream(
        &mut self,
        _id: ConnectionId,
        _stream_id: StreamId,
        _data: Vec<u8>,
    ) -> Result<(), TransportError> {
        Ok(())
    }

    fn close_stream_write(
        &mut self,
        _id: ConnectionId,
        _stream_id: StreamId,
    ) -> Result<(), TransportError> {
        Ok(())
    }

    fn reset_stream(
        &mut self,
        _id: ConnectionId,
        _stream_id: StreamId,
    ) -> Result<(), TransportError> {
        Ok(())
    }

    fn close(&mut self, _id: ConnectionId) -> Result<(), TransportError> {
        Ok(())
    }

    fn poll(&mut self) -> Result<Vec<TransportEvent>, TransportError> {
        Ok(self.initial.take().into_iter().collect())
    }
}

/// Drives attacker-controlled bridge bytes through circuit negotiation.
fn fuzz_circuit(data: &[u8]) {
    // A valid fragmented multistream-select exchange advances both roles into
    // the Noise decoder before attacker-controlled bytes begin.
    const NOISE_SELECTION: &[u8] = b"\x13/multistream/1.0.0\n\x07/noise\n";
    let relay = fuzz_peer_id();
    let remote = PeerId::from_public_key_protobuf(b"minip2p-fuzz-circuit-remote");
    let chunk_len = data.first().map_or(1, |byte| usize::from(byte % 16) + 1);
    for role in [CircuitRole::Initiator, CircuitRole::Responder] {
        let identity = minip2p_identity::Ed25519Keypair::from_secret_key_bytes([5; 32]);
        let mut transport =
            CircuitTransport::new(FuzzTransport::new(relay.clone()), identity, FixedEntropy);
        let _ = transport.poll();
        let _ = transport.adopt_bridge(BridgeAdoption {
            inner_conn: ConnectionId::new(1),
            bridge_stream: StreamId::new(1),
            relay: relay.clone(),
            remote_peer: remote.clone(),
            role,
            pending_data: NOISE_SELECTION[..1].to_vec(),
            remote_write_closed: false,
        });
        for chunk in NOISE_SELECTION[1..].chunks(chunk_len) {
            transport.inject_bridge_data(ConnectionId::new(1), StreamId::new(1), chunk.to_vec());
        }
        for chunk in data.chunks(chunk_len) {
            transport.inject_bridge_data(ConnectionId::new(1), StreamId::new(1), chunk.to_vec());
        }
        transport.inject_bridge_remote_write_closed(ConnectionId::new(1), StreamId::new(1));
        transport.inject_bridge_closed(ConnectionId::new(1), StreamId::new(1));
        transport.inject_bridge_data(ConnectionId::new(1), StreamId::new(1), data.to_vec());
        let _ = transport.poll();
    }
}

fn fuzz_discovery(data: &[u8]) {
    let _ = Beacon::decode(data);
    let local = PublicKey::new(KeyType::Ed25519, vec![1; 32]);
    let remote = PublicKey::new(KeyType::Ed25519, vec![2; 32]);
    let remote_peer = PeerId::from_public_key(&remote);
    let config = DiscoveryConfig {
        auto_dial: false,
        ..DiscoveryConfig::default()
    };
    let mut agent = DiscoveryAgent::new(local, config).expect("default discovery config");
    agent.handle_beacon(&remote_peer, data, true, 0);
    let authenticated = Beacon {
        public_key: remote.encode_protobuf(),
        addrs: vec![data.to_vec()],
    }
    .encode();
    agent.handle_beacon(&remote_peer, &authenticated, true, 1);
    while agent.poll_action().is_some() {}
    while agent.poll_event().is_some() {}
}

/// Exercises both the raw message decoder and the state-machine path that
/// runs the private length-prefixed framing decoder.
fn fuzz_identify(data: &[u8]) {
    let _ = IdentifyMessage::decode(data);

    let peer_id = fuzz_peer_id();
    let stream_id = StreamId::new(1);
    let mut identify = IdentifyProtocol::new(IdentifyConfig {
        protocol_version: "fuzz/1.0.0".into(),
        agent_version: "minip2p-fuzz/0.0.0".into(),
        protocols: vec!["/ipfs/id/1.0.0".into()],
        public_key: b"fuzz-public-key".to_vec(),
    });
    let _ = identify.handle_input(IdentifyInput::RegisterInboundStream {
        peer_id: peer_id.clone(),
        stream_id,
    });
    let _ = identify.handle_input(IdentifyInput::StreamData {
        peer_id: peer_id.clone(),
        stream_id,
        data: data.to_vec(),
    });
    // Closing the remote write side decodes the buffered length-prefixed
    // message.
    let _ = identify.handle_input(IdentifyInput::StreamRemoteWriteClosed { peer_id, stream_id });
    while identify.poll_output().is_some() {}
}

/// Runs the frame decoder plus both state machines so the message-level
/// `read_len_delimited` path sees the decoded payload.
fn fuzz_autonat(data: &[u8]) {
    let _ = minip2p_autonat::decode_frame(data);

    let mut server = AutoNatServer::new();
    let _ = server.handle_input(AutoNatServerInput::Data(data.to_vec()));
    while server.poll_output().is_some() {}

    let mut client = AutoNatClient::new(&fuzz_peer_id(), &[]);
    let _ = client.handle_input(AutoNatClientInput::Data(data.to_vec()));
    while client.poll_output().is_some() {}
}

fn fuzz_peer_id() -> PeerId {
    PeerId::from_public_key_protobuf(b"minip2p-fuzz-peer")
}

/// Exercises framing, both XX roles, payload protobuf decoding, and handshake
/// parsing with arbitrary wire bytes.
fn fuzz_noise(data: &[u8]) {
    let _ = NoiseHandshakePayload::decode(data);
    for role in [NoiseRole::Initiator, NoiseRole::Responder] {
        let identity = minip2p_identity::Ed25519Keypair::from_secret_key_bytes([1; 32]);
        let mut session = NoiseSession::new(NoiseConfig {
            role,
            identity,
            static_secret: [2; 32],
            ephemeral_secret: [3; 32],
            expected_peer: None,
        });
        let _ = session.handle_input(NoiseInput::Start);
        let _ = session.handle_input(NoiseInput::Data(data.to_vec()));
        while session.poll_output().is_some() {}
    }
}

/// Exercises the bounded frame decoder and both stream-ID roles.
fn fuzz_yamux(data: &[u8]) {
    let mut decoder = YamuxFrameDecoder::new(64 * 1024);
    decoder.push(data);
    while matches!(decoder.next_frame(), Ok(Some(_))) {}

    for role in [YamuxRole::Client, YamuxRole::Server] {
        let mut session = YamuxSession::new(role);
        let _ = session.handle_data(data);
        while session.poll_output().is_some() {}
    }
}
