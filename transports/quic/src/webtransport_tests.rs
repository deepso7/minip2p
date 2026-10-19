//! The WebTransport listener against a hand-driven HTTP/3 client: the
//! validation matrix, CONNECT checks, draft selection, session flow control
//! and pre-auth limits (plan Decisions 4 and 6).

use std::time::{Duration, Instant};

use minip2p_core::platform::{EntropySource, StdEntropy};
use minip2p_identity::Ed25519Keypair;
use minip2p_secure_mux::noise::{NoiseConfig, NoiseOutput, NoiseRole, NoiseSession};
use minip2p_transport::ConnectionCloseReason;
use minip2p_webtransport::LIBP2P_WEBTRANSPORT_PATH;
use minip2p_webtransport::h3::{
    Capsule, Frame, FrameDecoder, Settings, UniStreamType, code, encode_frame,
    encode_uni_stream_type, encode_webtransport_bidi_header, frame_type, setting,
};
use minip2p_webtransport::qpack::{QpackDecoder, encode_field_section};
use quinn_proto::{ConnectionError, Dir, Event, StreamEvent};

use super::*;
use crate::test_peer::{RawPeer, foreign_client_config, now};

/// What Chrome and Firefox offer.
const DRAFT02: &[(u64, u64)] = &[(setting::ENABLE_WEBTRANSPORT, 1), (setting::H3_DATAGRAM, 1)];

/// A listening transport serving `quic-v1` and WebTransport on one loopback
/// socket, with `limits`.
fn server_with(limits: QuicLimits) -> QuicTransport {
    let addrs = [
        "/ip4/127.0.0.1/udp/0/quic-v1".parse().expect("multiaddr"),
        "/ip4/127.0.0.1/udp/0/quic-v1/webtransport"
            .parse()
            .expect("multiaddr"),
    ];
    let config = QuicNodeConfig::generate().with_limits(limits);
    let mut server = QuicTransport::bind(config, &addrs).expect("bind");
    server.listen_on_bound_addrs().expect("listen");
    server
}

fn server() -> QuicTransport {
    server_with(QuicLimits::default())
}

/// A raw `h3` client, scripted by each test.
struct H3Peer {
    raw: RawPeer,
    /// The CONNECT stream, once sent.
    connect: Option<u64>,
    /// What the server sent on the CONNECT stream so far.
    response: Vec<u8>,
}

impl H3Peer {
    /// Connects and drives until the QUIC handshake completes.
    fn connect(server: &mut QuicTransport, events: &mut Vec<TransportEvent>) -> Self {
        let raw = RawPeer::connect_with(
            server.local_addr(),
            foreign_client_config(&[b"h3"], None, Arc::default()),
        );
        let mut peer = Self {
            raw,
            connect: None,
            response: Vec::new(),
        };
        peer.drive(server, events, "the QUIC handshake", |peer, _| {
            peer.raw
                .events
                .iter()
                .any(|event| matches!(event, Event::Connected))
        });
        peer
    }

    /// Polls the server and pumps the peer until `done`.
    fn drive(
        &mut self,
        server: &mut QuicTransport,
        events: &mut Vec<TransportEvent>,
        what: &str,
        mut done: impl FnMut(&mut Self, &[TransportEvent]) -> bool,
    ) {
        let start = Instant::now();
        while !done(self, events) {
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "timed out waiting for {what}; server events: {events:?}"
            );
            std::thread::sleep(Duration::from_millis(1));
            self.raw.pump();
            events.extend(server.poll(now()).expect("poll"));
            self.raw.pump();
            if let Some(connect) = self.connect {
                let (bytes, _) = self.raw.read(connect);
                self.response.extend(bytes);
            }
        }
    }

    /// The `:status` the server answered the CONNECT with, once it arrived.
    fn status(&self) -> Option<String> {
        let mut input = &self.response[..];
        let Ok(Some(Frame::Headers(block))) = FrameDecoder::new().decode(&mut input) else {
            return None;
        };
        let mut decoder = QpackDecoder::new();
        let section = decoder.decode(&block).ok()?;
        section
            .get(b":status")
            .map(|status| String::from_utf8_lossy(status).into_owned())
    }

    /// Opens a unidirectional stream carrying `bytes`.
    fn uni(&mut self, bytes: &[u8]) -> u64 {
        let stream = u64::from(
            self.raw
                .conn()
                .streams()
                .open(Dir::Uni)
                .expect("uni credit"),
        );
        assert_eq!(self.raw.write(stream, bytes), bytes.len());
        stream
    }

    /// Opens the control stream with `settings`.
    fn control(&mut self, settings: &[(u64, u64)]) -> u64 {
        let mut frame = Settings::new();
        for &(id, value) in settings {
            frame.set(id, value);
        }
        let mut bytes = Vec::new();
        frame.encode_frame(&mut bytes).expect("SETTINGS");
        self.control_bytes(&bytes)
    }

    /// Opens the control stream with raw frames after its type.
    fn control_bytes(&mut self, frames: &[u8]) -> u64 {
        let mut bytes = Vec::new();
        encode_uni_stream_type(UniStreamType::Control, &mut bytes).expect("type");
        bytes.extend_from_slice(frames);
        self.uni(&bytes)
    }

    /// Sends a request with `fields` on a new bidi stream, which becomes the
    /// CONNECT stream.
    fn request(&mut self, fields: &[(&[u8], &[u8])]) -> u64 {
        let mut block = Vec::new();
        encode_field_section(fields.iter().copied(), &mut block);
        self.request_block(&block)
    }

    /// Sends a raw field section in a HEADERS frame on a new bidi stream.
    fn request_block(&mut self, block: &[u8]) -> u64 {
        let mut bytes = Vec::new();
        encode_frame(frame_type::HEADERS, block, &mut bytes).expect("HEADERS");
        let stream = self.raw.open();
        assert_eq!(self.raw.write(stream, &bytes), bytes.len());
        self.connect = Some(stream);
        stream
    }

    /// The libp2p CONNECT a browser sends.
    fn libp2p_connect(&mut self) -> u64 {
        self.request(&libp2p_request(b"webtransport"))
    }

    /// Opens a WebTransport bidi stream: its prefix, then `bytes`.
    fn wt_stream(&mut self, bytes: &[u8]) -> u64 {
        let mut data = Vec::new();
        let session = self.connect.expect("a CONNECT stream");
        encode_webtransport_bidi_header(session, &mut data).expect("prefix");
        data.extend_from_slice(bytes);
        let stream = self.raw.open();
        assert_eq!(self.raw.write(stream, &data), data.len());
        stream
    }

    /// Writes all of `bytes` on `stream`, driving while the stream's credit
    /// runs short.
    fn write_all(
        &mut self,
        server: &mut QuicTransport,
        events: &mut Vec<TransportEvent>,
        stream: u64,
        mut bytes: &[u8],
    ) {
        self.drive(server, events, "the write", |peer, _| {
            let written = peer.raw.write(stream, bytes);
            bytes = bytes.get(written..).unwrap_or_default();
            bytes.is_empty()
        });
    }

    /// Sends one capsule on the CONNECT stream, in a DATA frame.
    fn capsule(&mut self, capsule: &Capsule) {
        let mut raw = Vec::new();
        capsule.encode(&mut raw).expect("capsule");
        let mut bytes = Vec::new();
        encode_frame(frame_type::DATA, &raw, &mut bytes).expect("DATA");
        let connect = self.connect.expect("a CONNECT stream");
        assert_eq!(self.raw.write(connect, &bytes), bytes.len());
    }

    /// Runs Noise as initiator on a fresh WebTransport stream until the
    /// server reports `Connected`.
    fn authenticate(&mut self, server: &mut QuicTransport, events: &mut Vec<TransportEvent>) {
        self.authenticate_with(server, events, |_, _, _| {});
    }

    /// [`Self::authenticate`], with `early` run once the Noise stream is
    /// open, before the handshake can complete.
    fn authenticate_with(
        &mut self,
        server: &mut QuicTransport,
        events: &mut Vec<TransportEvent>,
        early: impl FnOnce(&mut Self, &mut QuicTransport, &mut Vec<TransportEvent>),
    ) {
        let mut noise = initiator();
        let first = outbound(&mut noise).0;
        let stream = self.wt_stream(&first);
        early(self, server, events);
        let mut done = false;
        self.drive(server, events, "Noise", |peer, events| {
            if !done {
                let (bytes, _) = peer.raw.read(stream);
                if !bytes.is_empty() {
                    noise.on_data(bytes).expect("noise data");
                    let (out, complete) = outbound(&mut noise);
                    assert_eq!(peer.raw.write(stream, &out), out.len());
                    done = complete;
                }
            }
            connected(events)
        });
    }

    /// The application close the server sent: its code and reason.
    fn closed_with(
        &mut self,
        server: &mut QuicTransport,
        events: &mut Vec<TransportEvent>,
    ) -> (u64, String) {
        self.drive(server, events, "the server to close", |peer, events| {
            peer.raw.is_closed() && server_closed(events)
        });
        self.raw
            .events
            .iter()
            .find_map(|event| match event {
                Event::ConnectionLost {
                    reason: ConnectionError::ApplicationClosed(close),
                } => Some((
                    close.error_code.into_inner(),
                    String::from_utf8_lossy(&close.reason).into_owned(),
                )),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no application close: {:?}", self.raw.events))
    }
}

/// A started Noise initiator with a fresh identity.
fn initiator() -> NoiseSession {
    let mut entropy = StdEntropy::new();
    let mut secrets = [[0u8; 32]; 2];
    for secret in &mut secrets {
        entropy.fill_bytes(secret).expect("entropy");
    }
    let [static_secret, ephemeral_secret] = secrets;
    let mut noise = NoiseSession::new(NoiseConfig {
        role: NoiseRole::Initiator,
        identity: Ed25519Keypair::generate(),
        static_secret,
        ephemeral_secret,
        expected_peer: None,
        local_extensions: None,
    });
    noise.start().expect("noise start");
    noise
}

/// Everything Noise wants to send, and whether the handshake completed.
fn outbound(noise: &mut NoiseSession) -> (Vec<u8>, bool) {
    let mut bytes = Vec::new();
    let mut complete = false;
    while let Some(output) = noise.poll_output() {
        match output {
            NoiseOutput::Outbound(frame) => bytes.extend_from_slice(&frame),
            NoiseOutput::HandshakeComplete { .. } => complete = true,
            NoiseOutput::Decrypted(_) => {}
        }
    }
    (bytes, complete)
}

/// A request's fields, in order.
type Fields = Vec<(&'static [u8], &'static [u8])>;

/// The libp2p CONNECT request with `protocol` as `:protocol`.
fn libp2p_request(protocol: &'static [u8]) -> Fields {
    vec![
        (b":method", b"CONNECT"),
        (b":protocol", protocol),
        (b":scheme", b"https"),
        (b":authority", b"127.0.0.1"),
        (b":path", LIBP2P_WEBTRANSPORT_PATH.as_bytes()),
    ]
}

fn connected(events: &[TransportEvent]) -> bool {
    events
        .iter()
        .any(|event| matches!(event, TransportEvent::Connected { .. }))
}

fn server_closed(events: &[TransportEvent]) -> bool {
    events
        .iter()
        .any(|event| matches!(event, TransportEvent::Closed { .. }))
}

fn close_reason(events: &[TransportEvent]) -> Option<&ConnectionCloseReason> {
    events.iter().find_map(|event| match event {
        TransportEvent::Closed { reason, .. } => Some(reason),
        _ => None,
    })
}

/// A server whose WebTransport handshake times out quickly.
fn impatient_server() -> QuicTransport {
    server_with(QuicLimits {
        webtransport_handshake_timeout_ms: 200,
        ..QuicLimits::default()
    })
}

#[test]
fn a_client_that_never_sends_connect_times_out_without_connecting() {
    let mut server = impatient_server();
    let mut events = Vec::new();
    let mut peer = H3Peer::connect(&mut server, &mut events);
    peer.control(DRAFT02);
    let (code, _) = peer.closed_with(&mut server, &mut events);
    assert_eq!(code, code::H3_EXCESSIVE_LOAD);
    assert!(!connected(&events), "{events:?}");
    assert_eq!(
        close_reason(&events),
        Some(&ConnectionCloseReason::TimedOut)
    );
}

#[test]
fn a_client_that_never_finishes_noise_times_out_without_connecting() {
    let mut server = impatient_server();
    let mut events = Vec::new();
    let mut peer = H3Peer::connect(&mut server, &mut events);
    peer.control(DRAFT02);
    peer.libp2p_connect();
    // Noise's stream opens, and nothing follows its prefix.
    peer.wt_stream(&[]);
    let (code, _) = peer.closed_with(&mut server, &mut events);
    assert_eq!(code, code::H3_EXCESSIVE_LOAD);
    assert!(!connected(&events), "{events:?}");
    assert_eq!(
        close_reason(&events),
        Some(&ConnectionCloseReason::TimedOut)
    );
}

#[test]
fn a_draft02_client_authenticates() {
    let mut server = impatient_server();
    let mut events = Vec::new();
    let mut peer = H3Peer::connect(&mut server, &mut events);
    peer.control(DRAFT02);
    peer.libp2p_connect();
    peer.authenticate(&mut server, &mut events);
    // Past the handshake deadline, the connection stays up.
    let until = Instant::now() + Duration::from_millis(400);
    peer.drive(&mut server, &mut events, "the old deadline", |_, _| {
        Instant::now() >= until
    });
    assert!(!server_closed(&events), "{events:?}");
}

/// The SETTINGS frame a draft-02 client sends.
fn draft02_settings() -> Vec<u8> {
    let mut settings = Settings::new();
    for &(id, value) in DRAFT02 {
        settings.set(id, value);
    }
    let mut bytes = Vec::new();
    settings.encode_frame(&mut bytes).expect("SETTINGS");
    bytes
}

/// `frames` after a valid draft-02 SETTINGS frame.
fn after_settings(frames: &[u8]) -> Vec<u8> {
    let mut bytes = draft02_settings();
    bytes.extend_from_slice(frames);
    bytes
}

/// A GOAWAY frame for stream 0.
const GOAWAY: &[u8] = &[0x07, 0x01, 0x00];

/// Runs `script` against a fresh server, then returns the code and reason
/// it closed the connection with, checking it never connected.
fn close_after(script: impl FnOnce(&mut H3Peer)) -> (u64, String) {
    let mut server = server();
    let mut events = Vec::new();
    let mut peer = H3Peer::connect(&mut server, &mut events);
    script(&mut peer);
    let closed = peer.closed_with(&mut server, &mut events);
    assert!(!connected(&events), "{events:?}");
    // The handshake deadline would close it anyway, with a code of its own.
    assert_ne!(
        close_reason(&events),
        Some(&ConnectionCloseReason::TimedOut),
        "{closed:?}"
    );
    closed
}

#[test]
fn every_validation_matrix_row_closes_with_its_code() {
    type Script = fn(&mut H3Peer);
    let rows: &[(&str, Script, u64)] = &[
        (
            "a second control stream",
            |peer| {
                peer.control(DRAFT02);
                peer.control(DRAFT02);
            },
            code::H3_STREAM_CREATION_ERROR,
        ),
        (
            "a second QPACK encoder stream",
            |peer| {
                peer.uni(&[0x02]);
                peer.uni(&[0x02]);
            },
            code::H3_STREAM_CREATION_ERROR,
        ),
        (
            "a second QPACK decoder stream",
            |peer| {
                peer.uni(&[0x03]);
                peer.uni(&[0x03]);
            },
            code::H3_STREAM_CREATION_ERROR,
        ),
        (
            "the control stream finished",
            |peer| {
                let control = peer.control(DRAFT02);
                peer.raw.finish(control);
            },
            code::H3_CLOSED_CRITICAL_STREAM,
        ),
        (
            "the QPACK encoder stream finished",
            |peer| {
                let encoder = peer.uni(&[0x02]);
                peer.raw.finish(encoder);
            },
            code::H3_CLOSED_CRITICAL_STREAM,
        ),
        (
            "a control stream not starting with SETTINGS",
            |peer| {
                peer.control_bytes(GOAWAY);
            },
            code::H3_MISSING_SETTINGS,
        ),
        (
            "a second SETTINGS",
            |peer| {
                peer.control_bytes(&after_settings(&draft02_settings()));
            },
            code::H3_FRAME_UNEXPECTED,
        ),
        (
            "DATA on the control stream",
            |peer| {
                peer.control_bytes(&after_settings(&[0x00, 0x01, 0xaa]));
            },
            code::H3_FRAME_UNEXPECTED,
        ),
        (
            "HEADERS on the control stream",
            |peer| {
                peer.control_bytes(&after_settings(&[0x01, 0x00]));
            },
            code::H3_FRAME_UNEXPECTED,
        ),
        (
            "a duplicate setting",
            |peer| {
                peer.control_bytes(&[0x04, 0x04, 0x33, 0x01, 0x33, 0x01]);
            },
            code::H3_SETTINGS_ERROR,
        ),
        (
            "an HTTP/2-only setting",
            |peer| {
                peer.control_bytes(&[0x04, 0x02, 0x02, 0x00]);
            },
            code::H3_SETTINGS_ERROR,
        ),
        (
            "a QPACK encoder instruction",
            |peer| {
                // Set Dynamic Table Capacity 0x100.
                peer.uni(&[0x02, 0x3f, 0xe1, 0x01]);
            },
            code::QPACK_ENCODER_STREAM_ERROR,
        ),
        (
            "a required insert count other than 0",
            |peer| {
                peer.control(DRAFT02);
                peer.request_block(&[0x01, 0x00, 0xd1]);
            },
            code::QPACK_DECOMPRESSION_FAILED,
        ),
        (
            "a dynamic table reference",
            |peer| {
                peer.control(DRAFT02);
                peer.request_block(&[0x00, 0x00, 0x80]);
            },
            code::QPACK_DECOMPRESSION_FAILED,
        ),
        (
            "a post-base reference",
            |peer| {
                peer.control(DRAFT02);
                peer.request_block(&[0x00, 0x00, 0x10]);
            },
            code::QPACK_DECOMPRESSION_FAILED,
        ),
        (
            "GOAWAY from the client",
            |peer| {
                peer.control_bytes(&after_settings(GOAWAY));
            },
            code::H3_NO_ERROR,
        ),
        (
            "the CONNECT stream finished mid-frame",
            |peer| {
                peer.control(DRAFT02);
                let connect = peer.libp2p_connect();
                // A DATA frame declaring 4 bytes, with only 1.
                let mut data = frame_header(frame_type::DATA, 4);
                data.push(0);
                assert_eq!(peer.raw.write(connect, &data), data.len());
                peer.raw.finish(connect);
            },
            code::H3_FRAME_ERROR,
        ),
        (
            "the CONNECT stream finished mid-capsule",
            |peer| {
                peer.control(DRAFT02);
                let connect = peer.libp2p_connect();
                // A whole DATA frame holding only a capsule's header.
                let capsule = frame_header(RESERVED_FRAME, 8);
                let mut data = frame_header(frame_type::DATA, capsule.len() as u64);
                data.extend(capsule);
                assert_eq!(peer.raw.write(connect, &data), data.len());
                peer.raw.finish(connect);
            },
            code::H3_MESSAGE_ERROR,
        ),
    ];
    for &(row, script, expected) in rows {
        let (code, reason) = close_after(script);
        assert_eq!(code, expected, "{row}: closed with {code:#x} ({reason})");
    }
}

#[test]
fn a_reset_critical_stream_closes_the_connection() {
    for ty in [UniStreamType::Control, UniStreamType::QpackDecoder] {
        let mut server = server();
        let mut events = Vec::new();
        let mut peer = H3Peer::connect(&mut server, &mut events);
        let mut bytes = Vec::new();
        encode_uni_stream_type(ty, &mut bytes).expect("type");
        let stream = peer.uni(&bytes);
        // The server must learn the stream's type before the reset, which
        // discards what it has not read.
        let until = Instant::now() + Duration::from_millis(50);
        peer.drive(&mut server, &mut events, "the type", |_, _| {
            Instant::now() >= until
        });
        peer.raw.reset(stream, 0);
        let (code, reason) = peer.closed_with(&mut server, &mut events);
        assert_eq!(code, code::H3_CLOSED_CRITICAL_STREAM, "{ty:?}: {reason}");
    }
}

/// The status a request with `fields` is refused with, after checking the
/// session then closed without an error.
fn refused_with(settings: &[(u64, u64)], fields: &[(&[u8], &[u8])]) -> String {
    let mut server = server();
    let mut events = Vec::new();
    let mut peer = H3Peer::connect(&mut server, &mut events);
    peer.control(settings);
    peer.request(fields);
    let (code, reason) = peer.closed_with(&mut server, &mut events);
    assert_eq!(code, code::H3_NO_ERROR, "{reason}");
    assert!(!connected(&events), "{events:?}");
    peer.status().expect("a response")
}

#[test]
fn connect_requests_are_checked_field_by_field() {
    let path = LIBP2P_WEBTRANSPORT_PATH.as_bytes();
    let base = libp2p_request(b"webtransport");
    let with = |name: &[u8], value: &'static [u8]| {
        base.iter()
            .map(|&(field, old)| (field, if field == name { value } else { old }))
            .collect::<Vec<_>>()
    };
    let without = |name: &[u8]| {
        base.iter()
            .copied()
            .filter(|&(field, _)| field != name)
            .collect::<Vec<_>>()
    };
    let plus = |field: (&'static [u8], &'static [u8])| {
        let mut fields = base.clone();
        fields.push(field);
        fields
    };
    let rows: Vec<(&str, Fields, &str)> = vec![
        ("another path", with(b":path", b"/index.html"), "404"),
        (
            "another query",
            with(b":path", b"/.well-known/libp2p-webtransport?type=other"),
            "400",
        ),
        (
            "no query",
            with(b":path", b"/.well-known/libp2p-webtransport"),
            "400",
        ),
        ("GET", with(b":method", b"GET"), "400"),
        ("http", with(b":scheme", b"http"), "400"),
        ("no :scheme", without(b":scheme"), "400"),
        ("no :authority", without(b":authority"), "400"),
        ("no :protocol", without(b":protocol"), "400"),
        ("a second :path", plus((b":path", path)), "400"),
        (
            "an unknown pseudo-header",
            plus((b":status", b"200")),
            "400",
        ),
        (
            "a pseudo-header after a regular field",
            {
                let mut fields = vec![(&b"origin"[..], &b"https://example.com"[..])];
                fields.extend(base.iter().copied());
                fields
            },
            "400",
        ),
        (
            "draft-15's token",
            with(b":protocol", b"webtransport-h3"),
            "400",
        ),
    ];
    for (row, fields, expected) in rows {
        assert_eq!(refused_with(DRAFT02, &fields), expected, "{row}");
    }
}

/// What Safari offers: draft-13/14 with flow-control limits.
const DRAFT14: &[(u64, u64)] = &[
    (setting::WT_MAX_SESSIONS, 1),
    (setting::H3_DATAGRAM, 1),
    (setting::ENABLE_CONNECT_PROTOCOL, 1),
    (setting::WT_INITIAL_MAX_DATA, 1 << 20),
    (setting::WT_INITIAL_MAX_STREAMS_BIDI, 100),
    (setting::WT_INITIAL_MAX_STREAMS_UNI, 100),
];

#[test]
fn a_boolean_setting_other_than_0_or_1_is_a_settings_error_whatever_else_is_offered() {
    let mut draft14_and_bad_draft02 = DRAFT14.to_vec();
    draft14_and_bad_draft02.push((setting::ENABLE_WEBTRANSPORT, 2));
    let offers: [&[(u64, u64)]; 4] = [
        &[(setting::ENABLE_WEBTRANSPORT, 2)],
        &draft14_and_bad_draft02,
        &[(setting::ENABLE_WEBTRANSPORT, 1), (setting::H3_DATAGRAM, 2)],
        &[
            (setting::ENABLE_WEBTRANSPORT, 1),
            (setting::ENABLE_CONNECT_PROTOCOL, 2),
        ],
    ];
    for settings in offers {
        let (code, reason) = close_after(|peer| {
            peer.control(settings);
        });
        assert_eq!(code, code::H3_SETTINGS_ERROR, "{settings:?}: {reason}");
    }
}

#[test]
fn zero_draft_settings_offer_nothing() {
    let settings = [
        (setting::ENABLE_WEBTRANSPORT, 0),
        (setting::WT_MAX_SESSIONS, 0),
    ];
    let fields = libp2p_request(b"webtransport");
    assert_eq!(refused_with(&settings, &fields), "400");
}

#[test]
fn draft15s_token_is_refused_under_either_draft() {
    let fields = libp2p_request(b"webtransport-h3");
    assert_eq!(refused_with(DRAFT02, &fields), "400");
    assert_eq!(refused_with(DRAFT14, &fields), "400");
}

#[test]
fn a_draft14_client_authenticates() {
    let mut server = server();
    let mut events = Vec::new();
    let mut peer = H3Peer::connect(&mut server, &mut events);
    peer.control(DRAFT14);
    peer.libp2p_connect();
    peer.authenticate(&mut server, &mut events);
}

/// An authenticated session whose client offered `settings`, with the
/// server's id for it.
fn established(settings: &[(u64, u64)]) -> (QuicTransport, H3Peer, ConnectionId) {
    let mut server = server();
    let mut events = Vec::new();
    let mut peer = H3Peer::connect(&mut server, &mut events);
    peer.control(settings);
    peer.libp2p_connect();
    peer.authenticate(&mut server, &mut events);
    let id = events
        .iter()
        .find_map(|event| match event {
            TransportEvent::Connected { id, .. } => Some(*id),
            _ => None,
        })
        .expect("connected");
    (server, peer, id)
}

/// The application bytes the client has read on a server stream, after the
/// stream's prefix: `None` while the stream has not arrived.
fn server_stream_data(peer: &mut H3Peer, raw: u64) -> Option<Vec<u8>> {
    let (bytes, _) = peer.raw.read(raw);
    let mut input = &bytes[..];
    let mut frames = FrameDecoder::new();
    match frames.decode(&mut input) {
        Ok(Some(Frame::WebTransportStream { .. })) => Some(input.to_vec()),
        _ => None,
    }
}

/// Drives a while, adding to `read` what the client reads on each server
/// stream, and returns it.
fn settle(
    server: &mut QuicTransport,
    peer: &mut H3Peer,
    streams: &[u64],
    read: &mut [Option<Vec<u8>>],
) -> Vec<Option<Vec<u8>>> {
    let until = Instant::now() + Duration::from_millis(100);
    let mut events = Vec::new();
    peer.drive(server, &mut events, "a while", |peer, _| {
        for (slot, &raw) in read.iter_mut().zip(streams) {
            match slot {
                Some(data) => data.extend(peer.raw.read(raw).0),
                None => *slot = server_stream_data(peer, raw),
            }
        }
        Instant::now() >= until
    });
    read.to_vec()
}

/// Opens a server stream carrying `data`.
fn server_stream(server: &mut QuicTransport, id: ConnectionId, data: &'static [u8]) -> u64 {
    let stream = server.open_stream(id).expect("open");
    server
        .send_stream(id, stream, Bytes::from_static(data))
        .expect("send");
    stream.as_u64()
}

#[test]
fn draft14_server_streams_wait_for_the_clients_stream_credit() {
    // Both drafts offered: draft-14 is chosen, and with it flow control.
    let mut settings = DRAFT14.to_vec();
    settings.retain(|&(id, _)| id != setting::WT_INITIAL_MAX_STREAMS_BIDI);
    settings.extend([
        (setting::WT_INITIAL_MAX_STREAMS_BIDI, 1),
        (setting::ENABLE_WEBTRANSPORT, 1),
    ]);
    let (mut server, mut peer, id) = established(&settings);
    let streams = [
        server_stream(&mut server, id, b"a"),
        server_stream(&mut server, id, b"b"),
    ];
    let mut read = [None, None];
    assert_eq!(
        settle(&mut server, &mut peer, &streams, &mut read),
        [Some(b"a".to_vec()), None]
    );

    peer.capsule(&Capsule::MaxStreamsBidi(2));
    assert_eq!(
        settle(&mut server, &mut peer, &streams, &mut read),
        [Some(b"a".to_vec()), Some(b"b".to_vec())]
    );
}

#[test]
fn draft14_server_bytes_wait_for_the_clients_data_credit() {
    let mut settings = DRAFT14.to_vec();
    settings.retain(|&(id, _)| id != setting::WT_INITIAL_MAX_DATA);
    settings.push((setting::WT_INITIAL_MAX_DATA, 4));
    let (mut server, mut peer, id) = established(&settings);
    let streams = [server_stream(&mut server, id, b"0123456789")];
    let mut read = [None];
    assert_eq!(
        settle(&mut server, &mut peer, &streams, &mut read),
        [Some(b"0123".to_vec())]
    );

    peer.capsule(&Capsule::MaxData(10));
    assert_eq!(
        settle(&mut server, &mut peer, &streams, &mut read),
        [Some(b"0123456789".to_vec())]
    );
}

#[test]
fn draft02_has_no_session_flow_control() {
    // The same limits, without draft-14's WT_MAX_SESSIONS, limit nothing.
    let mut settings = DRAFT02.to_vec();
    settings.extend([
        (setting::WT_INITIAL_MAX_STREAMS_BIDI, 1),
        (setting::WT_INITIAL_MAX_DATA, 1),
    ]);
    let (mut server, mut peer, id) = established(&settings);
    let streams = [
        server_stream(&mut server, id, b"a"),
        server_stream(&mut server, id, b"b"),
    ];
    assert_eq!(
        settle(&mut server, &mut peer, &streams, &mut [None, None]),
        [Some(b"a".to_vec()), Some(b"b".to_vec())]
    );
}

#[test]
fn a_retry_before_the_h3_handshake_still_connects() {
    let mut server = server_with(QuicLimits {
        require_address_validation: true,
        ..QuicLimits::default()
    });
    let mut events = Vec::new();
    let mut peer = H3Peer::connect(&mut server, &mut events);
    peer.control(DRAFT02);
    peer.libp2p_connect();
    peer.authenticate(&mut server, &mut events);
}

#[test]
fn a_stream_that_finished_before_noise_completed_is_delivered_whole() {
    let mut server = server();
    let mut events = Vec::new();
    let mut peer = H3Peer::connect(&mut server, &mut events);
    peer.control(DRAFT02);
    peer.libp2p_connect();
    let mut early = 0;
    peer.authenticate_with(&mut server, &mut events, |peer, _, _| {
        early = peer.wt_stream(b"early");
        peer.raw.finish(early);
    });
    peer.drive(&mut server, &mut events, "the early stream", |_, events| {
        events.iter().any(|event| {
            matches!(event, TransportEvent::StreamRemoteWriteClosed { stream_id, .. }
                if stream_id.as_u64() == early)
        })
    });
    assert_eq!(crate::test_peer::stream_bytes(&events, early), b"early");
}

#[test]
fn early_bytes_past_the_stream_window_wait_for_acks() {
    let mut server = server_with(QuicLimits {
        stream_receive_window: 512,
        ..QuicLimits::default()
    });
    let mut events = Vec::new();
    let mut peer = H3Peer::connect(&mut server, &mut events);
    peer.control(DRAFT02);
    peer.libp2p_connect();
    // More than two windows, read while the stream is held.
    let payload: Vec<u8> = (0..=u8::MAX).cycle().take(1200).collect();
    let mut early = 0;
    peer.authenticate_with(&mut server, &mut events, |peer, server, events| {
        early = peer.wt_stream(&[]);
        peer.write_all(server, events, early, &payload);
        peer.raw.finish(early);
    });
    let id = events
        .iter()
        .find_map(|event| match event {
            TransportEvent::Connected { id, .. } => Some(*id),
            _ => None,
        })
        .expect("connected");
    let stream = StreamId::new(early);
    let finished = |events: &[TransportEvent]| {
        events.iter().any(|event| {
            matches!(event, TransportEvent::StreamRemoteWriteClosed { stream_id, .. }
                if *stream_id == stream)
        })
    };
    peer.drive(&mut server, &mut events, "the early stream", |_, events| {
        !crate::test_peer::stream_bytes(events, early).is_empty()
    });
    // Within the window, and nothing more until the reader acknowledges.
    let until = Instant::now() + Duration::from_millis(50);
    peer.drive(&mut server, &mut events, "a while", |_, _| {
        Instant::now() >= until
    });
    assert_eq!(crate::test_peer::stream_bytes(&events, early).len(), 512);
    assert!(!finished(&events));

    // Each acknowledgement releases the next window's worth.
    for delivered in [1024, 1200] {
        server.ack_stream(id, stream, 512).expect("ack");
        let mut acked = Vec::new();
        peer.drive(&mut server, &mut acked, "more early bytes", |_, acked| {
            !crate::test_peer::stream_bytes(acked, early).is_empty()
        });
        events.extend(acked);
        assert_eq!(
            crate::test_peer::stream_bytes(&events, early).len(),
            delivered
        );
    }
    assert_eq!(crate::test_peer::stream_bytes(&events, early), payload);
    assert!(finished(&events));
}

/// A frame header: its type and declared length.
fn frame_header(ty: u64, len: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    minip2p_webtransport::h3::varint::encode(ty, &mut bytes).expect("type");
    minip2p_webtransport::h3::varint::encode(len, &mut bytes).expect("length");
    bytes
}

/// A reserved (GREASE) frame type, which HTTP/3 skips.
const RESERVED_FRAME: u64 = 0x21;

#[test]
fn pre_auth_caps_close_with_their_codes() {
    type Script = fn(&mut H3Peer);
    let rows: &[(&str, Script, u64)] = &[
        (
            "a HEADERS frame over 16 KiB",
            |peer| {
                peer.control(DRAFT02);
                peer.request_block(&vec![0u8; 16 * 1024 + 1]);
            },
            code::H3_EXCESSIVE_LOAD,
        ),
        (
            "a SETTINGS frame over 4 KiB",
            |peer| {
                peer.control_bytes(&frame_header(frame_type::SETTINGS, 4 * 1024 + 1));
            },
            code::H3_EXCESSIVE_LOAD,
        ),
        (
            "a field section past 8 KiB in 64 fields",
            |peer| {
                peer.control(DRAFT02);
                // 63 static references (108 bytes each as counted) and a
                // 2 KiB `:path`.
                let csp: (&[u8], &[u8]) = (
                    b"content-security-policy",
                    b"script-src 'none'; object-src 'none'; base-uri 'none'",
                );
                let path = vec![b'/'; 2 * 1024];
                let mut fields = vec![csp; 63];
                fields.push((b":path", &path));
                peer.request(&fields);
            },
            code::QPACK_DECOMPRESSION_FAILED,
        ),
        (
            "65 fields",
            |peer| {
                peer.control(DRAFT02);
                let mut block = vec![0x00, 0x00];
                // Static index 15, `:method CONNECT`.
                block.resize(2 + 65, 0xcf);
                peer.request_block(&block);
            },
            code::QPACK_DECOMPRESSION_FAILED,
        ),
        (
            "a capsule over 64 KiB",
            |peer| {
                peer.control(DRAFT02);
                let connect = peer.libp2p_connect();
                // An unknown capsule's header alone.
                let capsule = frame_header(RESERVED_FRAME, 64 * 1024 + 1);
                let mut data = frame_header(frame_type::DATA, capsule.len() as u64);
                data.extend(capsule);
                assert_eq!(peer.raw.write(connect, &data), data.len());
            },
            code::H3_EXCESSIVE_LOAD,
        ),
        (
            "a CLOSE capsule with a reason over 1 KiB",
            |peer| {
                peer.control(DRAFT02);
                let connect = peer.libp2p_connect();
                let capsule = frame_header(0x2843, 4 + 1024 + 1);
                let mut data = frame_header(frame_type::DATA, capsule.len() as u64);
                data.extend(capsule);
                assert_eq!(peer.raw.write(connect, &data), data.len());
            },
            code::H3_MESSAGE_ERROR,
        ),
        (
            "five streams before the session",
            |peer| {
                peer.control(DRAFT02);
                // Prefixed streams naming a session not yet requested.
                peer.connect = Some(0);
                for _ in 0..5 {
                    peer.wt_stream(b"early");
                }
            },
            code::H3_EXCESSIVE_LOAD,
        ),
        (
            "the Noise stream and four more before authentication",
            |peer| {
                peer.control(DRAFT02);
                peer.libp2p_connect();
                // The first runs Noise once the session is accepted, and
                // counts as early until Noise completes.
                for _ in 0..5 {
                    peer.wt_stream(&[]);
                }
            },
            code::H3_EXCESSIVE_LOAD,
        ),
        (
            "five unfinished request heads before the session",
            |peer| {
                peer.control(DRAFT02);
                // HEADERS frames that declare 16 KiB and send none of it.
                for _ in 0..5 {
                    let stream = peer.raw.open();
                    let head = frame_header(frame_type::HEADERS, 16 * 1024);
                    assert_eq!(peer.raw.write(stream, &head), head.len());
                }
            },
            code::H3_EXCESSIVE_LOAD,
        ),
        (
            "over 16 KiB on streams before the session",
            |peer| {
                peer.control(DRAFT02);
                peer.connect = Some(0);
                peer.wt_stream(&[0; 9 * 1024]);
                peer.wt_stream(&[0; 9 * 1024]);
            },
            code::H3_EXCESSIVE_LOAD,
        ),
        (
            "over 16 KiB of skipped frames before a request",
            |peer| {
                peer.control(DRAFT02);
                let stream = peer.raw.open();
                let mut data = frame_header(RESERVED_FRAME, 16 * 1024);
                data.resize(data.len() + 16 * 1024, 0);
                data.extend(frame_header(RESERVED_FRAME, 16 * 1024));
                data.resize(data.len() + 16 * 1024, 0);
                assert_eq!(peer.raw.write(stream, &data), data.len());
            },
            code::H3_EXCESSIVE_LOAD,
        ),
    ];
    for &(row, script, expected) in rows {
        let (code, reason) = close_after(script);
        assert_eq!(code, expected, "{row}: closed with {code:#x} ({reason})");
    }
}

#[test]
fn settings_without_a_supported_draft_answer_400_and_close() {
    let settings = [(setting::H3_DATAGRAM, 1)];
    assert_eq!(
        refused_with(&settings, &libp2p_request(b"webtransport")),
        "400"
    );
}

#[test]
fn an_unknown_uni_stream_is_stopped_and_the_session_goes_on() {
    let mut server = server();
    let mut events = Vec::new();
    let mut peer = H3Peer::connect(&mut server, &mut events);
    // A reserved (GREASE) stream type.
    let unknown = peer.uni(&[0x21, 0xff]);
    peer.drive(&mut server, &mut events, "STOP_SENDING", |peer, _| {
        peer.raw.events.iter().any(|event| {
            matches!(event, Event::Stream(StreamEvent::Stopped { id, error_code })
                if u64::from(*id) == unknown
                    && error_code.into_inner() == code::H3_STREAM_CREATION_ERROR)
        })
    });
    peer.control(DRAFT02);
    peer.libp2p_connect();
    peer.authenticate(&mut server, &mut events);
}

#[test]
fn noise_stream_bytes_count_toward_the_pre_auth_byte_cap() {
    let mut server = server();
    let mut events = Vec::new();
    let mut peer = H3Peer::connect(&mut server, &mut events);
    peer.control(DRAFT02);
    peer.libp2p_connect();
    peer.drive(&mut server, &mut events, "the 200", |peer, _| {
        peer.status().is_some()
    });
    // One Noise frame that declares its maximum length and never ends,
    // sent once the session runs Noise on it.
    let mut frame = vec![0xff, 0xff];
    frame.resize(2 + 17 * 1024, 0);
    let noise = peer.wt_stream(&[]);
    peer.drive(&mut server, &mut events, "the Noise stream", |_, _| true);
    assert_eq!(peer.raw.write(noise, &frame), frame.len());
    let (code, reason) = peer.closed_with(&mut server, &mut events);
    assert_eq!(code, code::H3_EXCESSIVE_LOAD, "{reason}");
    assert_ne!(
        close_reason(&events),
        Some(&ConnectionCloseReason::TimedOut)
    );
}

#[test]
fn a_failed_noise_handshake_closes_with_an_error_code() {
    type Script = fn(&mut H3Peer);
    let rows: &[(&str, Script)] = &[
        ("a malformed first message", |peer| {
            peer.control(DRAFT02);
            peer.libp2p_connect();
            // A one-byte Noise message where 32 are due.
            peer.wt_stream(&[0x00, 0x01, 0xff]);
        }),
        ("the Noise stream finished mid-handshake", |peer| {
            peer.control(DRAFT02);
            peer.libp2p_connect();
            let first = outbound(&mut initiator()).0;
            let stream = peer.wt_stream(&first);
            peer.raw.finish(stream);
        }),
    ];
    for &(row, script) in rows {
        let (code, reason) = close_after(script);
        assert_eq!(
            code,
            code::H3_GENERAL_PROTOCOL_ERROR,
            "{row}: closed with {code:#x} ({reason})"
        );
    }
}

#[test]
fn a_stream_reset_before_its_prefix_has_the_servers_side_reset_too() {
    let mut server = server();
    let mut events = Vec::new();
    let mut peer = H3Peer::connect(&mut server, &mut events);
    peer.control(DRAFT02);
    let stream = peer.raw.open();
    // The first byte of the two-byte `0x41` prefix, then a reset.
    assert_eq!(peer.raw.write(stream, &[0x40]), 1);
    peer.raw.reset(stream, 0);
    peer.drive(&mut server, &mut events, "the server's reset", |peer, _| {
        let mut recv = peer.raw.conn().recv_stream(crate::test_peer::sid(stream));
        let Ok(mut chunks) = recv.read(true) else {
            return false;
        };
        let reset = matches!(
            chunks.next(usize::MAX),
            Err(quinn_proto::ReadError::Reset(_))
        );
        let _credit = chunks.finalize();
        reset
    });
    // The session goes on.
    peer.libp2p_connect();
    peer.authenticate(&mut server, &mut events);
}
