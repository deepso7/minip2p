#![no_main]

use std::collections::{BTreeMap, VecDeque};
use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use minip2p_autonat::{AutoNatClient, AutoNatServer};
use minip2p_circuit::{BridgeAdoption, CircuitRole, CircuitTransport};
use minip2p_core::platform::{EntropyError, EntropySource, Now};
use minip2p_core::{Bytes, Multiaddr, Multihash, PeerAddr, PeerId, Protocol, TransportKind};
use minip2p_dcutr::{DcutrInitiator, DcutrResponder, FrameDecode as DcutrFrame, HolePunch};
use minip2p_discovery::{
    Beacon, BeaconAgent, BeaconConfig, BeaconEvent, DiscoverySource, Observation,
    PeerDiscoveryAgent, PeerDiscoveryConfig,
};
use minip2p_identify::{IdentifyConfig, IdentifyMessage, IdentifyProtocol};
use minip2p_identity::{KeyType, PublicKey};
use minip2p_mdns::{
    DnsMessage, InterfaceId, InterfaceSnapshot, IpFamily, IpNet, MdnsAgent, MdnsConfig,
};
use minip2p_multistream_select::MultistreamSelect;
use minip2p_ping::{PING_PAYLOAD_LEN, PingAction, PingConfig, PingEvent, PingOutput, PingProtocol};
use minip2p_pubsub::{
    FrameDecode as PubsubFrame, GossipsubAgent, GossipsubConfig, MESHSUB_PROTOCOL_ID_V11,
    RawMessage, Rpc,
};
use minip2p_relay::{
    FrameDecode as RelayFrame, HopConnect, HopMessage, HopReservation, HopResponder, StopInitiator,
    StopMessage, StopResponder,
};
use minip2p_relay_server::mesh;
use minip2p_secure_mux::noise::{
    NoiseConfig, NoiseExtensions, NoiseHandshakePayload, NoiseOutput, NoiseRole, NoiseSession,
};
use minip2p_secure_mux::yamux::{FrameDecoder as YamuxFrameDecoder, YamuxRole, YamuxSession};
use minip2p_secure_mux::{
    SecureMuxSession, SessionConfig, SessionOutput, SessionRole, YamuxConfig,
};
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{
    ConnectionEndpoint, ConnectionId, StreamId, Transport, TransportError, TransportEvent,
};
use minip2p_webtransport::{
    IoError, IoEvent, SessionHandle, StreamHandle, WebTransportClient, WebTransportIo,
    WebTransportLimits,
};

fuzz_target!(|data: &[u8]| {
    fuzz_multiaddr(data);

    fuzz_multistream(data);
    fuzz_identify(data);
    fuzz_autonat(data);
    fuzz_discovery(data);
    fuzz_mdns(data);
    fuzz_noise(data);
    fuzz_pubsub(data);
    fuzz_yamux(data);
    fuzz_webtransport(data);
    fuzz_secure_mux(data);
    fuzz_circuit(data);
    fuzz_relay_server_machines(data);
    fuzz_handshake_machines(data);
    fuzz_ping(data);
    fuzz_webtransport_client(data);

    // Peer TLS certificates are attacker-controlled X.509 DER.
    let _ = minip2p_tls::verify_libp2p_certificate(
        data,
        core::time::Duration::from_secs(1_700_000_000),
    );

    if let RelayFrame::Complete { payload, .. } = minip2p_relay::decode_frame(data) {
        let _ = HopMessage::decode(payload);
        let _ = StopMessage::decode(payload);
    }
    if let DcutrFrame::Complete { payload, .. } = minip2p_dcutr::decode_frame(data) {
        let _ = HolePunch::decode(payload);
    }
    fuzz_relay_mesh(data);
});

/// Decodes both relay-mesh frames, and feeds the input to a directory stream
/// as one read and as two, so frames split across reads take the same path.
fn fuzz_relay_mesh(data: &[u8]) {
    let _ = mesh::decode_mesh_frame(data, mesh::DirectoryMessage::decode);
    let _ = mesh::decode_mesh_frame(data, mesh::ForwardMessage::decode);

    let member = fuzz_peer_id();
    let split = data.first().map_or(0, |b| usize::from(*b)).min(data.len());
    let (head, tail) = data.split_at(split);
    let mut whole = mesh::Directory::new(4);
    whole.stream_opened(member.clone(), 0u8);
    let whole_input = whole.stream_data(&member, &0, data);
    let mut parts = mesh::Directory::new(4);
    parts.stream_opened(member.clone(), 0u8);
    let first = parts.stream_data(&member, &0, head);
    let parts_input = match first {
        mesh::DirectoryInput::Reset(_) => first,
        _ => parts.stream_data(&member, &0, tail),
    };
    let reset = |input: &mesh::DirectoryInput| matches!(input, mesh::DirectoryInput::Reset(_));
    assert_eq!(reset(&whole_input), reset(&parts_input));
    assert_eq!(whole.entry_count(&member), parts.entry_count(&member));
    assert_eq!(whole.is_synced(&member), parts.is_synced(&member));
}

/// Exercises the relay-side incremental framing and terminal-action boundary.
fn fuzz_relay_server_machines(data: &[u8]) {
    let mut hop = HopResponder::new();
    let _ = hop.on_data(data);
    hop.on_remote_write_closed();
    while hop.poll_output().is_some() {}

    let mut stop = StopInitiator::new(fuzz_peer_id(), None);
    while stop.poll_output().is_some() {}
    stop.on_data(data);
    stop.on_remote_write_closed();
    while stop.poll_output().is_some() {}
}

/// Feeds the relay client and DCUtR handshake machines the input in two
/// halves, so a frame header can straddle buffered bytes and the incoming
/// chunk, and the bytes behind a decoded frame take each machine's
/// trailing-byte path.
fn fuzz_handshake_machines(data: &[u8]) {
    let (head, tail) = data.split_at(data.len() / 2);

    let mut reservation = HopReservation::new();
    while reservation.poll_output().is_some() {}
    for chunk in [head, tail] {
        let _ = reservation.on_data(chunk);
    }
    let _ = reservation.on_remote_write_closed();
    while reservation.poll_output().is_some() {}

    if let Ok(mut connect) = HopConnect::new(fuzz_peer_id().to_bytes()) {
        while connect.poll_output().is_some() {}
        for chunk in [head, tail] {
            let _ = connect.on_data(chunk);
        }
        while connect.poll_output().is_some() {}
    }

    let mut stop = StopResponder::new();
    for chunk in [head, tail] {
        let _ = stop.on_data(chunk);
    }
    let _ = stop.accept();
    while stop.poll_output().is_some() {}

    if let Ok(mut initiator) = DcutrInitiator::new(&[]) {
        while initiator.poll_output().is_some() {}
        for chunk in [head, tail] {
            let _ = initiator.on_data(chunk, 0);
        }
        let _ = initiator.send_sync();
        while initiator.poll_output().is_some() {}
        let _ = initiator.take_trailing_data();
    }

    if let Ok(mut responder) = DcutrResponder::new(&[]) {
        for chunk in [head, tail] {
            let _ = responder.on_data(chunk);
        }
        let _ = responder.on_remote_write_closed();
        while responder.poll_output().is_some() {}
        let _ = responder.take_trailing_data();
    }
}

/// Exercises pubsub framing, RPC/control decoding, canonical re-encoding,
/// and StrictSign validation with arbitrary wire bytes.
fn fuzz_pubsub(data: &[u8]) {
    if let PubsubFrame::Complete { payload, .. } = minip2p_pubsub::decode_frame(data)
        && let Ok(rpc) = Rpc::decode(payload)
    {
        let _ = rpc.encode();
    }
    if let Ok(rpc) = Rpc::decode(data) {
        let encoded = rpc.encode();
        assert_eq!(Rpc::decode(&encoded), Ok(rpc));
    }
    if let Ok(message) = RawMessage::decode(data) {
        let _ = message.to_wire();
        let _ = message.verify(false);
        let _ = message.verify(true);
    }

    // Exercise the bounded incremental framing and RPC/control processing
    // paths after a valid meshsub connection setup.
    let identity = minip2p_identity::Ed25519Keypair::from_secret_key_bytes([11; 32]);
    let remote = fuzz_peer_id();
    let stream_id = StreamId::new(1);
    let mut agent = GossipsubAgent::new(identity, GossipsubConfig::default(), 1, 7)
        .expect("default gossipsub config");
    let _ = agent.handle_event(
        &SwarmEvent::ConnectionEstablished {
            peer_id: remote.clone(),
            conn_id: ConnectionId::new(1),
        },
        0,
    );
    let _ = agent.handle_event(
        &SwarmEvent::PeerReady {
            peer_id: remote.clone(),
            conn_id: ConnectionId::new(1),
            protocols: vec![MESHSUB_PROTOCOL_ID_V11.to_string()],
        },
        0,
    );
    let _ = agent.handle_event(
        &SwarmEvent::StreamReady {
            peer_id: remote.clone(),
            conn_id: ConnectionId::new(1),
            stream_id,
            protocol_id: MESHSUB_PROTOCOL_ID_V11.to_string(),
            initiated_locally: false,
        },
        0,
    );
    let _ = agent.handle_event(
        &SwarmEvent::StreamData {
            peer_id: remote,
            conn_id: ConnectionId::new(1),
            stream_id,
            data: Bytes::copy_from_slice(data),
        },
        1,
    );
    agent.handle_tick(1_000);
    while agent.poll_action().is_some() {}
    while agent.poll_event().is_some() {}
}

/// Feeds the input to both negotiation roles so `decode_message` and the
/// per-state handlers see attacker-controlled bytes.
fn fuzz_multistream(data: &[u8]) {
    let machines = [
        MultistreamSelect::dialer("/ipfs/ping/1.0.0"),
        MultistreamSelect::listener(["/ipfs/ping/1.0.0".to_string()]),
    ];
    for mut machine in machines {
        machine.start();
        machine.on_data(data);
        while machine.poll_output().is_some() {}
        let _ = machine.take_remaining_buffer();
    }
}

struct FixedEntropy;

impl EntropySource for FixedEntropy {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        output.fill(7);
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
    fn ack_stream(
        &mut self,
        _id: ConnectionId,
        _stream_id: StreamId,
        _bytes: usize,
    ) -> Result<(), TransportError> {
        Ok(())
    }

    fn dial(&mut self, _addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        Err(TransportError::Unsupported { operation: "dial" })
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
        _data: Bytes,
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

    fn poll(&mut self, _now: Now) -> Result<Vec<TransportEvent>, TransportError> {
        Ok(self.initial.take().into_iter().collect())
    }
}

/// Independent oracle for [`Multiaddr::transport_kind`].
///
/// Reads the protocol slice directly, so a divergence between the documented
/// address shapes and the classification helpers shows up as a mismatch.
fn expected_transport_kind(addr: &Multiaddr) -> Option<TransportKind> {
    match addr.protocols() {
        [host, Protocol::Tcp(_)] if host.is_host() => Some(TransportKind::Tcp),
        [host, Protocol::Udp(_), Protocol::QuicV1] if host.is_host() => Some(TransportKind::Quic),
        // WebTransport rides the QUIC transport: quic-v1, webtransport, then
        // only certhashes.
        [
            host,
            Protocol::Udp(_),
            Protocol::QuicV1,
            Protocol::WebTransport,
            rest @ ..,
        ] if host.is_host()
            && rest
                .iter()
                .all(|protocol| matches!(protocol, Protocol::Certhash(_))) =>
        {
            Some(TransportKind::Quic)
        }
        _ => None,
    }
}

/// Drives attacker-controlled bytes through both multiaddr codecs.
fn fuzz_multiaddr(data: &[u8]) {
    if let Ok(addr) = Multiaddr::from_bytes(data) {
        // Anything that decodes must re-encode and print back identically:
        // a decoder accepting a shape the encoder cannot reproduce is a
        // round-trip hole.
        let reencoded = addr.to_bytes();
        let decoded = Multiaddr::from_bytes(&reencoded).expect("re-decode own encoding");
        assert_eq!(decoded, addr);

        // The empty multiaddr is the one shape whose text form does not
        // round-trip: `from_bytes(&[])` accepts it and it prints as "", but
        // the text parser rejects "" as `EmptyInput`. That asymmetry predates
        // `/tcp`; exclude it rather than assert a contract the library does
        // not make.
        if !addr.protocols().is_empty() {
            let text = addr.to_string();
            let parsed: Multiaddr = text.parse().expect("re-parse own text");
            assert_eq!(parsed, addr);
        }

        // Classification must match the shape rules, checked here against the
        // protocol slice directly rather than through the same helpers
        // `transport_kind` is built from -- otherwise the assertion is
        // entailed by the implementation and cannot fail.
        assert_eq!(addr.transport_kind(), expected_transport_kind(&addr));
    }

    if let Ok(addr) = core::str::from_utf8(data)
        .map_err(|_| ())
        .and_then(|text| text.parse::<Multiaddr>().map_err(|_| ()))
    {
        let _ = addr.to_bytes();
        let _ = addr.transport_kind();
    }
}

/// Drives attacker-controlled bytes through the secure-mux upgrade.
///
/// `handle_input` decodes peer-supplied bytes at every phase of the stack, so
/// it gets the same fuzz treatment as the wire decoders underneath it. Both
/// roles are driven, and the bytes are also fed in chunks so a frame split
/// across reads exercises the partial-buffer paths.
fn fuzz_secure_mux(data: &[u8]) {
    let chunk_len = usize::from(data.first().copied().unwrap_or(1)).max(1);

    for role in [SessionRole::Initiator, SessionRole::Responder] {
        let identity = minip2p_identity::Ed25519Keypair::from_secret_key_bytes([7; 32]);
        let mut session = SecureMuxSession::new(SessionConfig {
            role,
            identity,
            static_secret: [11; 32],
            ephemeral_secret: [13; 32],
            expected_peer: None,
            yamux: YamuxConfig::default(),
        });
        if session.start().is_err() {
            continue;
        }

        let mut established = false;
        for chunk in data.chunks(chunk_len) {
            if session.handle_input(chunk.to_vec()).is_err() {
                break;
            }
            while let Some(output) = session.poll_output() {
                if matches!(output, SessionOutput::Established { .. }) {
                    established = true;
                }
            }
            while let Ok(Some(_)) = session.poll_write() {}
        }

        // An unauthenticated peer must never reach the established state from
        // arbitrary bytes: that would mean the Noise handshake was skippable.
        // Establishing is gated on decrypting an AEAD-protected Yamux
        // selection under a key derived from statics this harness never puts
        // on the wire, so the assertion cannot fire on a lucky mutation --
        // reaching it at all is the defect it is looking for.
        assert!(
            !established,
            "arbitrary bytes must not complete the upgrade"
        );
        assert!(!session.is_established());
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
        let _ = transport.poll(Now::from_millis(0));
        let _ = transport.adopt_bridge(BridgeAdoption {
            inner_conn: ConnectionId::new(1),
            bridge_stream: StreamId::new(1),
            relay: relay.clone(),
            remote_peer: remote.clone(),
            role,
            pending_data: Bytes::copy_from_slice(&NOISE_SELECTION[..1]),
            unsent_prefix: Bytes::new(),
            remote_write_closed: false,
        });
        for chunk in NOISE_SELECTION[1..].chunks(chunk_len) {
            transport.inject_bridge_data(
                ConnectionId::new(1),
                StreamId::new(1),
                Bytes::copy_from_slice(chunk),
            );
        }
        for chunk in data.chunks(chunk_len) {
            transport.inject_bridge_data(
                ConnectionId::new(1),
                StreamId::new(1),
                Bytes::copy_from_slice(chunk),
            );
        }
        transport.inject_bridge_remote_write_closed(ConnectionId::new(1), StreamId::new(1));
        transport.inject_bridge_closed(ConnectionId::new(1), StreamId::new(1));
        transport.inject_bridge_data(
            ConnectionId::new(1),
            StreamId::new(1),
            Bytes::copy_from_slice(data),
        );
        let _ = transport.poll(Now::from_millis(0));
    }
}

fn fuzz_discovery(data: &[u8]) {
    let _ = Beacon::decode(data);
    let local = PublicKey::new(KeyType::Ed25519, vec![1; 32]);
    let remote = PublicKey::new(KeyType::Ed25519, vec![2; 32]);
    let local_peer = PeerId::from_public_key(&local);
    let remote_peer = PeerId::from_public_key(&remote);
    let mut beacon =
        BeaconAgent::new(local, BeaconConfig::default()).expect("default beacon config");
    let mut book = PeerDiscoveryAgent::new(
        local_peer,
        PeerDiscoveryConfig {
            max_known_peers: 2,
            max_addrs_per_peer: 2,
            max_observed_ttl_ms: 1_000,
            mdns_dial_window_ms: 100,
            max_mdns_dials_per_window: 2,
            max_mdns_dials_per_window_global: 2,
            max_pending_violations: 2,
            dial_tie_break: false,
            ..PeerDiscoveryConfig::default()
        },
    )
    .expect("bounded fuzz discovery config");

    beacon.handle_beacon(&remote_peer, data, true);
    let authenticated = Beacon {
        public_key: remote.encode_protobuf(),
        addrs: vec![data.to_vec()],
    }
    .encode();
    beacon.handle_beacon(&remote_peer, &authenticated, true);
    while let Some(event) = beacon.poll_event() {
        match event {
            BeaconEvent::Observation(observation) => book.observe_beacon(observation, 0),
            BeaconEvent::ProtocolViolation { peer, reason } => {
                book.report_violation(Some(peer), DiscoverySource::SignedBeacon, &reason)
            }
        }
    }

    let mut beacon_addrs = vec![
        "/ip4/127.0.0.1/udp/4001/quic-v1"
            .parse()
            .expect("static fuzz address"),
    ];
    if let Ok(addr) = Multiaddr::from_bytes(data) {
        beacon_addrs.push(addr);
    }
    book.observe_beacon(
        Observation {
            peer: remote_peer.clone(),
            addrs: beacon_addrs,
        },
        1,
    );

    let ttl_ms = data.first().map_or(0, |byte| u64::from(*byte) * 8);
    book.observe_mdns(
        remote_peer.clone(),
        vec![(
            "/ip4/127.0.0.1/udp/4002/quic-v1"
                .parse()
                .expect("static fuzz address"),
            ttl_ms,
        )],
        2,
    );
    let reason = core::str::from_utf8(data).unwrap_or("non-UTF-8 fuzz input");
    book.report_violation(Some(remote_peer.clone()), DiscoverySource::Mdns, reason);
    book.dial_failed(&remote_peer, reason, 3);
    if data.get(1).is_some_and(|byte| byte & 1 == 0) {
        book.peer_connected(&remote_peer, 4);
        book.peer_disconnected(&remote_peer, 5);
    }
    book.handle_tick(2_u64.saturating_add(ttl_ms));
    let _ = book.next_deadline(Now::from_millis(6));
    let _ = book.known_peers();
    while book.poll_action().is_some() {}
    while book.poll_event().is_some() {}
    while beacon.poll_action().is_some() {}
}

fn fuzz_mdns(data: &[u8]) {
    let _ = DnsMessage::decode(data);
    let local = fuzz_peer_id();
    let mut agent =
        MdnsAgent::new(local, MdnsConfig::default(), [7; 32]).expect("default mDNS config");
    agent.set_interfaces(
        &[InterfaceSnapshot {
            id: InterfaceId::new(1),
            index: 1,
            family: IpFamily::V4,
            addrs: vec![
                IpNet::new(core::net::IpAddr::V4(core::net::Ipv4Addr::LOCALHOST), 8)
                    .expect("valid loopback prefix"),
            ],
        }],
        0,
    );
    agent.handle_packet(
        InterfaceId::new(1),
        core::net::SocketAddr::from(([127, 0, 0, 1], 5353)),
        data,
        1,
    );
    agent.handle_tick(1);
    while agent.poll_action().is_some() {}
    while agent.poll_event().is_some() {}
}

/// Exercises both the raw message decoder and the state-machine path that
/// runs the length-prefixed framing decoder. The input is fed in two halves so
/// a frame header can straddle buffered bytes and the incoming chunk.
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
    identify.register_inbound_stream(peer_id.clone(), stream_id);
    let (head, tail) = data.split_at(data.len() / 2);
    for chunk in [head, tail] {
        identify.on_stream_data(peer_id.clone(), stream_id, chunk);
    }
    // Closing the remote write side decodes the buffered length-prefixed
    // message.
    identify.on_stream_remote_write_closed(peer_id, stream_id);
    while identify.poll_output().is_some() {}
}

/// Runs the frame decoder plus both state machines so the message-level
/// `read_len_delimited` path sees the decoded payload. The state machines get
/// the input in two halves so a frame header can straddle buffered bytes and
/// the incoming chunk.
fn fuzz_autonat(data: &[u8]) {
    let _ = minip2p_autonat::decode_frame(data);
    let (head, tail) = data.split_at(data.len() / 2);

    let observed: Multiaddr = "/ip4/203.0.113.7/udp/4001/quic-v1"
        .parse()
        .expect("valid observed address");
    let mut server = AutoNatServer::new(fuzz_peer_id(), &observed);
    for chunk in [head, tail] {
        let _ = server.on_data(chunk);
    }
    while server.poll_output().is_some() {}

    // A well-formed DIAL from the authenticated requester, carrying fuzzed
    // addresses, so the observed-IP filter and the forwarding path run too
    // (raw bytes almost never name the requester's peer id).
    let offered: Vec<Multiaddr> = data
        .chunks(24)
        .filter_map(|chunk| Multiaddr::from_bytes(chunk).ok())
        .collect();
    let mut dial = AutoNatClient::new(&fuzz_peer_id(), &offered);
    let mut server = AutoNatServer::new(fuzz_peer_id(), &observed);
    while let Some(output) = dial.poll_output() {
        if let minip2p_autonat::AutoNatClientOutput::Outbound(bytes) = output {
            let _ = server.on_data(&bytes);
        }
    }
    while let Some(output) = server.poll_output() {
        if let minip2p_autonat::AutoNatServerOutput::Request(request) = output {
            assert!(
                request
                    .addrs
                    .iter()
                    .all(|addr| addr.protocols().first() == observed.protocols().first()),
                "the server forwarded an address off the observed IP: {:?}",
                request.addrs
            );
            server.respond_public(&request.addrs);
        }
    }

    let mut client = AutoNatClient::new(&fuzz_peer_id(), &[]);
    for chunk in [head, tail] {
        let _ = client.on_data(chunk);
    }
    while client.poll_output().is_some() {}
}

fn fuzz_peer_id() -> PeerId {
    PeerId::from_public_key_protobuf(b"minip2p-fuzz-peer")
}

/// Exercises framing, both XX roles, payload and extensions protobuf
/// decoding, and handshake parsing with arbitrary wire bytes.
fn fuzz_noise(data: &[u8]) {
    let _ = NoiseHandshakePayload::decode(data);
    let _ = NoiseExtensions::decode(data);
    for role in [NoiseRole::Initiator, NoiseRole::Responder] {
        let identity = minip2p_identity::Ed25519Keypair::from_secret_key_bytes([1; 32]);
        let mut session = NoiseSession::new(NoiseConfig {
            role,
            identity,
            static_secret: [2; 32],
            ephemeral_secret: [3; 32],
            expected_peer: None,
            local_extensions: None,
        });
        let _ = session.start();
        let _ = session.on_data(data.to_vec());
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

fn fuzz_webtransport(data: &[u8]) {
    use minip2p_webtransport::h3::{
        CapsuleDecoder, Frame, FrameDecoder, Settings, UniStreamHeaderDecoder, varint,
    };
    use minip2p_webtransport::qpack::{
        DecoderStreamReader, MAX_FIELD_SECTION_SIZE, MAX_FIELDS, QpackDecoder,
    };

    let _ = varint::decode(data);
    let _ = Settings::decode_payload(data);
    let _ = UniStreamHeaderDecoder::new().decode(&mut &data[..]);

    let _ = DecoderStreamReader::new().read(data);

    let mut qpack = QpackDecoder::new();
    if let Ok(section) = qpack.decode(data) {
        let size: usize = section
            .iter()
            .map(|f| f.name.len() + f.value.len() + 32)
            .sum();
        assert!(size <= MAX_FIELD_SECTION_SIZE && section.len() <= MAX_FIELDS);
    }

    // Feed the stream decoders in two chunks so the incremental paths run:
    // frames, with DATA payloads going on to the capsule decoder.
    let split = data.first().map_or(0, |&b| usize::from(b)).min(data.len());
    let mut frames = FrameDecoder::new();
    let mut capsules = CapsuleDecoder::new();
    'stream: for chunk in [&data[..split], &data[split..]] {
        let mut input = chunk;
        loop {
            match frames.decode(&mut input) {
                Ok(Some(Frame::Data(mut payload))) => {
                    while let Ok(Some(_)) = capsules.decode(&mut payload) {}
                }
                Ok(Some(Frame::Headers(block))) => {
                    let _ = qpack.decode(&block);
                }
                Ok(Some(Frame::WebTransportStream { .. })) | Err(_) => break 'stream,
                Ok(Some(_)) => {}
                Ok(None) => break,
            }
        }
    }

    let mut capsules = CapsuleDecoder::new();
    let mut input = data;
    while let Ok(Some(_)) = capsules.decode(&mut input) {}
}

/// Drives the ping state machine in both roles: the input is the peer's
/// bytes on an inbound stream (echoed back) and on an outbound stream with a
/// ping in flight (checked against the payload sent), split at a
/// data-derived point so the receive buffers see fragments, overflow and
/// trailing bytes, then both streams are closed.
fn fuzz_ping(data: &[u8]) {
    const SENT: [u8; PING_PAYLOAD_LEN] = [7; PING_PAYLOAD_LEN];
    let peer = fuzz_peer_id();
    let inbound = StreamId::new(1);
    let outbound = StreamId::new(2);
    let split = data.first().map_or(0, |&b| usize::from(b)).min(data.len());
    let (head, tail) = data.split_at(split);

    let mut ping = PingProtocol::new(PingConfig {
        request_timeout_ms: 10,
    });
    ping.register_inbound_stream(peer.clone(), inbound);
    let _ = ping.register_outbound_stream(peer.clone(), outbound);
    let _ = ping.send_ping(&peer, &SENT, 0);
    // Every payload sent back on the inbound stream, and whether the
    // outbound ping measured an RTT.
    let mut echoes = Vec::new();
    let mut measured = false;
    let mut drain = |ping: &mut PingProtocol| {
        while let Some(output) = ping.poll_output() {
            match output {
                PingOutput::Action(PingAction::Send {
                    stream_id, data, ..
                }) if stream_id == inbound => echoes.push(data),
                PingOutput::Event(PingEvent::RttMeasured { stream_id, .. })
                    if stream_id == outbound =>
                {
                    measured = true;
                }
                _ => {}
            }
        }
    };

    for chunk in [head, tail] {
        ping.on_stream_data(&peer, inbound, chunk, 1);
        ping.on_stream_data(&peer, outbound, chunk, 1);
        drain(&mut ping);
    }
    // Idle again only if the echo matched; otherwise this is refused.
    let _ = ping.close_outbound_stream_write(&peer);
    ping.on_stream_data(&peer, StreamId::new(3), head, 2);
    ping.on_stream_remote_write_closed(&peer, inbound);
    ping.on_stream_remote_write_closed(&peer, outbound);
    ping.on_tick(100);
    ping.on_stream_closed(&peer, outbound);
    drain(&mut ping);

    // The outbound stream's reply is the input's first payload: an RTT is
    // measured only if it echoes what we sent; a short or wrong reply never is.
    assert!(
        !measured || data.get(..PING_PAYLOAD_LEN) == Some(&SENT[..]),
        "an RTT was measured for a reply that does not echo the ping"
    );
    // The responder only ever echoes a complete payload the peer sent.
    for echo in echoes {
        assert!(data.windows(PING_PAYLOAD_LEN).any(|window| window == echo));
    }
}

/// Server-side state of one stream in [`FuzzWtIo`].
#[derive(Default)]
struct FuzzWtStream {
    /// Accepted bytes not yet read by the harness.
    written: Vec<u8>,
    /// Accepted writes not yet completed, oldest first.
    in_flight: VecDeque<usize>,
    /// Granted and not yet delivered.
    granted: usize,
    /// Reset by us: writes are refused.
    reset: bool,
    /// The peer finished or reset its side: nothing more is delivered.
    read_ended: bool,
    /// The peer stopped our side: writes are refused and never complete.
    write_stopped: bool,
}

/// A fake platform for [`fuzz_webtransport_client`]. It keeps the
/// [`WebTransportIo`] contract (deliveries never exceed grants, completions
/// match accepted writes, a small in-flight cap forces short writes), so
/// anything the fuzzer finds is the client's fault, not the fake's.
#[derive(Default)]
struct FuzzWtIo {
    next: u64,
    streams: BTreeMap<u64, FuzzWtStream>,
    events: VecDeque<IoEvent>,
    /// Every write fails, as for a platform that lost its streams.
    refuse_writes: bool,
}

impl FuzzWtIo {
    const IN_FLIGHT_CAP: usize = 128;

    fn handle(&mut self) -> u64 {
        self.next += 1;
        self.next
    }

    /// Queues up to `bytes.len()` bytes on `stream`, cut to its grant.
    fn deliver(&mut self, stream: StreamHandle, bytes: &[u8]) {
        let Some(state) = self.streams.get_mut(&stream.0) else {
            return;
        };
        let len = if state.read_ended {
            0
        } else {
            bytes.len().min(state.granted)
        };
        if len == 0 {
            return;
        }
        state.granted -= len;
        self.events.push_back(IoEvent::Data {
            stream,
            bytes: Bytes::copy_from_slice(&bytes[..len]),
        });
    }

    /// The peer ends its side of `stream` with `event` (FIN or reset), once.
    fn end_read(&mut self, stream: StreamHandle, event: IoEvent) {
        if let Some(state) = self.streams.get_mut(&stream.0)
            && !state.read_ended
        {
            state.read_ended = true;
            state.granted = 0;
            self.events.push_back(event);
        }
    }

    /// The peer stops our side of `stream`, discarding its in-flight writes.
    fn stop_write(&mut self, stream: StreamHandle, code: u8) {
        if let Some(state) = self.streams.get_mut(&stream.0)
            && !state.write_stopped
        {
            state.write_stopped = true;
            state.in_flight.clear();
            self.events.push_back(IoEvent::StopSending { stream, code });
        }
    }

    /// Completes the oldest accepted write on `stream`, if any.
    fn complete(&mut self, stream: StreamHandle) {
        if let Some(bytes) = self
            .streams
            .get_mut(&stream.0)
            .and_then(|state| state.in_flight.pop_front())
        {
            self.events
                .push_back(IoEvent::WriteCompleted { stream, bytes });
        }
    }
}

impl WebTransportIo for FuzzWtIo {
    fn connect(&mut self, _url: &str, _certhashes: &[Multihash]) -> Result<SessionHandle, IoError> {
        Ok(SessionHandle(self.handle()))
    }

    fn open_stream(&mut self, _session: SessionHandle) -> Result<StreamHandle, IoError> {
        let stream = StreamHandle(self.handle());
        self.streams.insert(stream.0, FuzzWtStream::default());
        self.events.push_back(IoEvent::StreamOpened { stream });
        Ok(stream)
    }

    fn write(&mut self, stream: StreamHandle, data: &[u8]) -> Result<usize, IoError> {
        let refuse = self.refuse_writes;
        let state = self
            .streams
            .get_mut(&stream.0)
            .filter(|state| !state.reset && !state.write_stopped && !refuse)
            .ok_or_else(|| IoError("not writable".into()))?;
        let in_flight: usize = state.in_flight.iter().sum();
        let accepted = data.len().min(Self::IN_FLIGHT_CAP - in_flight);
        if accepted > 0 {
            state.written.extend_from_slice(&data[..accepted]);
            state.in_flight.push_back(accepted);
        }
        Ok(accepted)
    }

    fn close_write(&mut self, _stream: StreamHandle) {}

    fn reset(&mut self, stream: StreamHandle, _code: u8) {
        if let Some(state) = self.streams.get_mut(&stream.0) {
            state.reset = true;
            state.in_flight.clear();
            state.granted = 0;
        }
    }

    fn stop(&mut self, _stream: StreamHandle, _code: u8) {}

    fn grant_read(&mut self, stream: StreamHandle, bytes: usize) {
        if let Some(state) = self.streams.get_mut(&stream.0) {
            state.granted += bytes;
        }
    }

    fn close(&mut self, _session: SessionHandle, _code: u32, _reason: &str) {}

    fn poll_event(&mut self) -> Option<IoEvent> {
        self.events.pop_front()
    }
}

/// Reads fuzz bytes as a bounded script of choices.
struct Script<'a>(&'a [u8]);

impl<'a> Script<'a> {
    fn byte(&mut self) -> Option<u8> {
        let (&first, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(first)
    }

    fn take(&mut self, len: usize) -> &'a [u8] {
        let (head, tail) = self.0.split_at(len.min(self.0.len()));
        self.0 = tail;
        head
    }
}

/// The fixed identities and dial address of [`fuzz_webtransport_client`],
/// derived once: key setup dominates a run that never gets far.
struct WtFixture {
    client: minip2p_identity::Ed25519Keypair,
    server: minip2p_identity::Ed25519Keypair,
    addr: PeerAddr,
    certhashes: Vec<Multihash>,
}

static WT_FIXTURE: LazyLock<WtFixture> = LazyLock::new(|| {
    const HASH: &str = "uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g";
    let server = minip2p_identity::Ed25519Keypair::from_secret_key_bytes([9; 32]);
    let addr: PeerAddr = format!(
        "/ip4/192.0.2.1/udp/4001/quic-v1/webtransport/certhash/{HASH}/p2p/{}",
        server.peer_id()
    )
    .parse()
    .expect("static fuzz address");
    let certhashes = addr.transport().certhashes().copied().collect();
    WtFixture {
        client: minip2p_identity::Ed25519Keypair::from_secret_key_bytes([8; 32]),
        server,
        addr,
        certhashes,
    }
});

/// Dials a [`WebTransportClient`] over [`FuzzWtIo`] with a real Noise
/// responder on the server side, then lets the input script the peer and
/// the caller: honest handshake rounds (fragmented at data-derived points),
/// injected Noise bytes, server streams, data, FIN, resets, stops, write
/// completions, caller stream calls, time and the session's end. Pumps are
/// the most common op, so short inputs get past the handshake and the
/// connected-session paths run too.
fn fuzz_webtransport_client(data: &[u8]) {
    const MAX_OPS: usize = 64;
    const WINDOW: usize = 256;

    let mut script = Script(data);
    let mode = script.byte().unwrap_or(0);
    let fixture = &*WT_FIXTURE;
    // Mostly the dialed hash; sometimes no extensions or a hash-free list,
    // which the client must reject.
    let mut offered = match mode % 4 {
        0 => None,
        1 => Some(Vec::new()),
        _ => Some(fixture.certhashes.clone()),
    };
    // Built on the first honest round, so inputs that never pump skip its
    // key setup.
    let mut responder: Option<NoiseSession> = None;
    let mut responder_ok = true;

    let mut client = WebTransportClient::with_limits(
        FuzzWtIo::default(),
        fixture.client.clone(),
        FixedEntropy,
        WebTransportLimits {
            max_connections: 2,
            max_streams_per_connection: 3,
            max_pending_bytes_per_stream: 100,
            max_pending_connection_bytes: 200,
            control_stream_reserve_bytes: 50,
            stream_receive_window: WINDOW,
            handshake_timeout_ms: 5_000,
        },
    )
    .expect("valid fuzz limits");
    let Ok(id) = client.dial(&fixture.addr) else {
        return;
    };
    let session = SessionHandle(client.io_mut().next);
    client
        .io_mut()
        .events
        .push_back(IoEvent::SessionReady { session });

    let mut now = 0_u64;
    // Delivered, unacknowledged bytes per caller stream, from the events.
    let mut unacked: BTreeMap<StreamId, usize> = BTreeMap::new();
    // One poll more than ops, so the last op's effects are polled and checked.
    for step in 0..=MAX_OPS {
        let Ok(events) = client.poll(Now::from_millis(now)) else {
            break;
        };
        for event in events {
            match event {
                TransportEvent::StreamData {
                    stream_id, data, ..
                } => {
                    let held = unacked.entry(stream_id).or_default();
                    *held += data.len();
                    // Grants never let the platform deliver past the window.
                    assert!(*held <= WINDOW, "{held} unacknowledged bytes");
                }
                TransportEvent::Closed { .. } => unacked.clear(),
                _ => {}
            }
        }

        if step == MAX_OPS {
            break;
        }
        let Some(op) = script.byte() else {
            break;
        };
        let arg = script.byte().unwrap_or(0);
        let io = client.io_mut();
        // The Noise stream is the first one the client opens.
        let noise = StreamHandle(session.0 + 1);
        let handles: Vec<u64> = io.streams.keys().copied().collect();
        let chosen = handles
            .get(usize::from(arg) % handles.len().max(1))
            .map(|&h| StreamHandle(h));
        match op % 20 {
            // An honest handshake round: complete the client's writes, feed
            // them to the responder and deliver its reply in two fragments.
            0..=5 => {
                while io
                    .streams
                    .get(&noise.0)
                    .is_some_and(|s| !s.in_flight.is_empty())
                {
                    io.complete(noise);
                }
                let written = io
                    .streams
                    .get_mut(&noise.0)
                    .map(|s| core::mem::take(&mut s.written))
                    .unwrap_or_default();
                let mut reply = Vec::new();
                if responder_ok && !written.is_empty() {
                    let server = responder.get_or_insert_with(|| {
                        let mut server = NoiseSession::new(NoiseConfig {
                            role: NoiseRole::Responder,
                            identity: fixture.server.clone(),
                            static_secret: [21; 32],
                            ephemeral_secret: [22; 32],
                            expected_peer: None,
                            local_extensions: offered.take().map(|webtransport_certhashes| {
                                NoiseExtensions {
                                    webtransport_certhashes,
                                    stream_muxers: Vec::new(),
                                }
                            }),
                        });
                        responder_ok = server.start().is_ok();
                        server
                    });
                    responder_ok = responder_ok && server.on_data(written).is_ok();
                    while let Some(output) = server.poll_output() {
                        if let NoiseOutput::Outbound(frame) = output {
                            reply.extend_from_slice(&frame);
                        }
                    }
                }
                let (head, tail) = reply.split_at(usize::from(arg).min(reply.len()));
                io.deliver(noise, head);
                io.deliver(noise, tail);
            }
            6 => {
                let bytes = script.take(usize::from(arg % 64));
                io.deliver(noise, bytes);
            }
            7 => {
                let stream = StreamHandle(io.handle());
                io.streams.insert(stream.0, FuzzWtStream::default());
                io.events
                    .push_back(IoEvent::IncomingStream { session, stream });
            }
            8 => {
                if let Some(stream) = chosen {
                    let bytes = script.take(usize::from(arg % 128));
                    io.deliver(stream, bytes);
                }
            }
            9 => {
                if let Some(stream) = chosen {
                    io.end_read(stream, IoEvent::Fin { stream });
                }
            }
            10 => {
                if let Some(stream) = chosen {
                    io.end_read(stream, IoEvent::Reset { stream, code: arg });
                }
            }
            11 => {
                if let Some(stream) = chosen {
                    io.stop_write(stream, arg);
                }
            }
            12 => {
                if let Some(stream) = chosen {
                    io.complete(stream);
                }
            }
            13 => {
                let _ = client.open_stream(id);
            }
            14 => {
                if let Some(stream) = chosen {
                    let payload = Bytes::from(vec![arg; usize::from(arg)]);
                    let _ = client.send_stream(id, StreamId::new(stream.0), payload);
                }
            }
            15 => {
                if let Some(stream) = chosen {
                    let _ = client.close_stream_write(id, StreamId::new(stream.0));
                }
            }
            16 => {
                if let Some(stream) = chosen {
                    let stream_id = StreamId::new(stream.0);
                    if client.reset_stream(id, stream_id).is_ok() {
                        unacked.remove(&stream_id);
                    }
                }
            }
            17 => {
                if let Some(stream) = chosen {
                    let stream_id = StreamId::new(stream.0);
                    let bytes = usize::from(arg);
                    if client.ack_stream(id, stream_id, bytes).is_ok()
                        && let Some(held) = unacked.get_mut(&stream_id)
                    {
                        *held = held.saturating_sub(bytes);
                    }
                }
            }
            // Past the reset grace with small steps, the handshake timeout
            // with large ones.
            18 => now = now.saturating_add(u64::from(arg) * 32),
            _ => match arg % 6 {
                0 => io.events.push_back(IoEvent::SessionClosed {
                    session,
                    code: u32::from(arg),
                    reason: String::new(),
                }),
                1 => io.events.push_back(IoEvent::SessionFailed {
                    session,
                    reason: String::new(),
                }),
                2 => io.refuse_writes = !io.refuse_writes,
                3 => {
                    if let Some(stream) = chosen {
                        client.set_control_stream(id, StreamId::new(stream.0), true);
                    }
                }
                4 => {
                    let _ = client.close(id);
                }
                _ => {
                    let _ = client.next_deadline();
                }
            },
        }
    }
}
