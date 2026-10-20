//! A test-only native [`WebTransportIo`]: raw quinn-proto with ALPN `h3`, a
//! verifier that pins the server certificate by certhash, and an HTTP/3
//! client written with `minip2p-webtransport`'s codec.
//!
//! It stands in for a browser, so `WebTransportClient` can be driven against
//! the real `QuicTransport` without one. Not exported anywhere; a real
//! native dialer is a follow-up. Every call is non-blocking: the socket is
//! read and written whenever the queue of events runs dry in
//! [`QuinnIo::poll_event`].

use std::collections::{HashMap, VecDeque};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use minip2p_core::{Bytes, Multihash};
use minip2p_webtransport::h3::{
    Capsule, CapsuleDecoder, Frame, FrameDecoder, Settings, UniStreamHeaderDecoder, UniStreamType,
    encode_frame, encode_uni_stream_type, encode_webtransport_bidi_header, frame_type,
    h3_code_to_webtransport, setting, webtransport_code_to_h3,
};
use minip2p_webtransport::qpack::{QpackDecoder, encode_field_section};
use minip2p_webtransport::{IoError, IoEvent, SessionHandle, StreamHandle, WebTransportIo};
use quinn_proto::crypto::rustls::QuicClientConfig;
use quinn_proto::{
    ClientConfig, Connection, ConnectionHandle, DatagramEvent, Dir, Endpoint, EndpointConfig,
    Event, ReadError, StreamEvent, StreamId, VarInt,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

/// Most bytes in flight per stream, as a browser's writer would hold.
const MAX_IN_FLIGHT: usize = 64 * 1024;

/// How long [`Options::race_noise`] holds the control stream after the
/// first stream went out: long enough for the server to read that stream
/// first.
const CONTROL_DELAY: Duration = Duration::from_millis(30);

/// How long [`Options::split_prefix`] holds a prefix's second half back.
const SPLIT_DELAY: Duration = Duration::from_millis(20);

/// Ways the client can misbehave on purpose.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Sends each stream's `0x41` prefix in two packets.
    pub split_prefix: bool,
    /// Reports the session ready as soon as the CONNECT is sent, and holds
    /// the control stream (so the server's 200) back until a while after the
    /// first stream went out: the Noise stream then reaches the server before
    /// the session is accepted.
    pub race_noise: bool,
    /// The CONNECT `:path`, in place of the libp2p one.
    pub path: Option<String>,
    /// Records what the server put on the wire, for tests to inspect.
    pub wire: Wire,
}

/// What the client saw the server do on the wire, in order. Shared, so a
/// test keeps a clone after handing the options over.
#[derive(Clone, Debug, Default)]
pub struct Wire(Arc<Mutex<Vec<WireEvent>>>);

impl Wire {
    pub fn events(&self) -> Vec<WireEvent> {
        self.0.lock().expect("wire log").clone()
    }

    fn push(&self, event: WireEvent) {
        self.0.lock().expect("wire log").push(event);
    }
}

/// One thing the server did, with the raw HTTP/3 codes it used.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireEvent {
    /// The CONNECT response's `:status`.
    Status(String),
    /// A `CLOSE_WEBTRANSPORT_SESSION` capsule on the CONNECT stream.
    CloseCapsule { code: u32 },
    /// The server finished or reset its side of the CONNECT stream.
    ConnectEnded,
    /// RESET_STREAM on a WebTransport stream.
    Reset { code: u64 },
    /// STOP_SENDING on a WebTransport stream.
    StopSending { code: u64 },
    /// The QUIC connection closed; the application close code, if the
    /// server sent one.
    ConnectionClosed { code: Option<u64> },
}

/// Pins the server certificate by its certhash, then checks the handshake
/// signature with that certificate's key.
#[derive(Debug)]
struct CerthashVerifier {
    certhashes: Vec<Multihash>,
}

fn provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::ring::default_provider()
}

impl ServerCertVerifier for CerthashVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let hash = minip2p_tls::webtransport::certhash(end_entity);
        if self.certhashes.contains(&hash) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "the server certificate matches no dialed certhash".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not offered".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// One in-flight write.
struct Segment {
    bytes: Vec<u8>,
    sent: usize,
    /// Reported as `WriteCompleted` once sent: the caller's bytes, not a
    /// prefix.
    report: bool,
}

/// One WebTransport stream.
struct WtStream {
    session: u64,
    id: StreamId,
    outbox: VecDeque<Segment>,
    /// The second half of a split prefix waits until then, once the first
    /// half went out.
    hold: Option<Instant>,
    split: bool,
    fin: bool,
    granted: usize,
    /// FIN or reset read: nothing more to read.
    done_reading: bool,
}

impl WtStream {
    fn in_flight(&self) -> usize {
        self.outbox
            .iter()
            .filter(|segment| segment.report)
            .map(|segment| segment.bytes.len() - segment.sent)
            .sum()
    }
}

/// One session: one QUIC connection.
struct Session {
    conn: Connection,
    handle: ConnectionHandle,
    authority: String,
    path: String,
    /// The CONNECT stream, once sent.
    connect: Option<StreamId>,
    connect_frames: FrameDecoder,
    connect_capsules: CapsuleDecoder,
    /// The server's side of the CONNECT stream ended.
    connect_ended: bool,
    /// Our side of the CONNECT stream is finished.
    connect_finished: bool,
    /// The control stream went out.
    control_sent: bool,
    /// When a held-back control stream goes out.
    control_at: Option<Instant>,
    ready: bool,
    /// The session is over for the caller: no more events but the wire log.
    closed: bool,
    server_uni: HashMap<StreamId, (UniStreamHeaderDecoder, Option<UniStreamType>, FrameDecoder)>,
    /// Server bidi streams whose prefix is being read.
    heads: HashMap<StreamId, FrameDecoder>,
    by_quinn: HashMap<StreamId, u64>,
}

/// A [`WebTransportIo`] over one loopback UDP socket.
pub struct QuinnIo {
    socket: UdpSocket,
    endpoint: Endpoint,
    by_conn: HashMap<ConnectionHandle, u64>,
    sessions: HashMap<u64, Session>,
    streams: HashMap<u64, WtStream>,
    next_handle: u64,
    events: VecDeque<IoEvent>,
    options: Options,
}

impl QuinnIo {
    pub fn new(options: Options) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind the WebTransport client");
        socket.set_nonblocking(true).expect("nonblocking");
        Self {
            socket,
            endpoint: Endpoint::new(Arc::new(EndpointConfig::default()), None, true, None),
            by_conn: HashMap::new(),
            sessions: HashMap::new(),
            streams: HashMap::new(),
            next_handle: 0,
            events: VecDeque::new(),
            options,
        }
    }

    fn handle(&mut self) -> u64 {
        self.next_handle += 1;
        self.next_handle
    }

    /// Reads the socket, runs every session, and sends what they produce.
    fn pump(&mut self) {
        let now = Instant::now();
        let mut buf = vec![0u8; 65_535];
        let mut reply = Vec::new();
        while let Ok((len, from)) = self.socket.recv_from(&mut buf) {
            reply.clear();
            let data = BytesMut::from(buf.get(..len).unwrap_or_default());
            if let Some(DatagramEvent::ConnectionEvent(handle, event)) = self
                .endpoint
                .handle(now, from, None, None, data, &mut reply)
                && let Some(session) = self
                    .by_conn
                    .get(&handle)
                    .and_then(|s| self.sessions.get_mut(s))
            {
                session.conn.handle_event(event);
            }
        }
        let sessions: Vec<u64> = self.sessions.keys().copied().collect();
        for session in sessions {
            self.service(session, now);
        }
    }

    fn service(&mut self, handle: u64, now: Instant) {
        let Some(session) = self.sessions.get_mut(&handle) else {
            return;
        };
        if session
            .conn
            .poll_timeout()
            .is_some_and(|timeout| timeout <= now)
        {
            session.conn.handle_timeout(now);
        }
        while let Some(event) = session.conn.poll() {
            match event {
                Event::Connected => {
                    let first_stream_out = self.streams.values().any(|s| s.session == handle);
                    start_h3(
                        session,
                        !self.options.race_noise || first_stream_out,
                        self.options.path.as_deref(),
                    );
                    if self.options.race_noise {
                        session.ready = true;
                        self.events.push_back(IoEvent::SessionReady {
                            session: SessionHandle(handle),
                        });
                    }
                }
                Event::ConnectionLost { reason } => {
                    let code = match &reason {
                        quinn_proto::ConnectionError::ApplicationClosed(close) => {
                            Some(close.error_code.into_inner())
                        }
                        _ => None,
                    };
                    self.options.wire.push(WireEvent::ConnectionClosed { code });
                    if !std::mem::replace(&mut session.closed, true) {
                        self.events.push_back(IoEvent::SessionClosed {
                            session: SessionHandle(handle),
                            code: 0,
                            reason: reason.to_string(),
                        });
                    }
                }
                Event::Stream(StreamEvent::Opened { dir }) => {
                    while let Some(stream) = session.conn.streams().accept(dir) {
                        match dir {
                            Dir::Uni => {
                                session.server_uni.insert(
                                    stream,
                                    (UniStreamHeaderDecoder::new(), None, FrameDecoder::new()),
                                );
                            }
                            Dir::Bi => {
                                session.heads.insert(stream, FrameDecoder::new());
                            }
                        }
                    }
                }
                Event::Stream(StreamEvent::Stopped { id, error_code }) => {
                    if let Some(&stream) = session.by_quinn.get(&id) {
                        self.options.wire.push(WireEvent::StopSending {
                            code: error_code.into_inner(),
                        });
                        self.events.push_back(IoEvent::StopSending {
                            stream: StreamHandle(stream),
                            code: wt_code(error_code),
                        });
                    }
                }
                _ => {}
            }
        }
        if session.conn.is_drained() {
            return;
        }
        // A closed session still reads the CONNECT stream, for the log, and
        // sends what the engine has; its streams are gone.
        if session.closed {
            self.read_connect(handle);
            self.transmit(handle, now);
            return;
        }
        // The held control stream goes out a while after a stream has.
        if !session.control_sent {
            match session.control_at {
                Some(at) if at <= now => send_control(session),
                Some(_) => {}
                None => {
                    if self
                        .streams
                        .values()
                        .any(|s| s.session == handle && s.outbox.is_empty())
                    {
                        session.control_at = Some(now + CONTROL_DELAY);
                    }
                }
            }
        }
        self.read_connect(handle);
        self.read_server_streams(handle);
        self.flush(handle);
        self.transmit(handle, now);
    }

    /// Reads the CONNECT stream: the response, then capsules. A refusal, a
    /// close capsule or the server ending the stream closes the session, and
    /// we finish our side as a browser does.
    fn read_connect(&mut self, handle: u64) {
        let Some(session) = self.sessions.get_mut(&handle) else {
            return;
        };
        let Some(connect) = session.connect.filter(|_| !session.connect_ended) else {
            return;
        };
        let (bytes, ended) = read(&mut session.conn, connect, usize::MAX);
        let mut input = &bytes[..];
        let mut closed_with = None;
        while let Ok(Some(frame)) = session.connect_frames.decode(&mut input) {
            match frame {
                Frame::Headers(block) => {
                    let mut decoder = QpackDecoder::new();
                    let status = decoder
                        .decode(&block)
                        .ok()
                        .and_then(|section| section.get(b":status").map(<[u8]>::to_vec))
                        .map(|status| String::from_utf8_lossy(&status).into_owned())
                        .unwrap_or_default();
                    self.options.wire.push(WireEvent::Status(status.clone()));
                    if status == "200" {
                        if !session.closed && !std::mem::replace(&mut session.ready, true) {
                            self.events.push_back(IoEvent::SessionReady {
                                session: SessionHandle(handle),
                            });
                        }
                    } else {
                        closed_with = Some((0, format!("the server answered {status}")));
                    }
                }
                Frame::Data(mut chunk) => {
                    while let Ok(Some(capsule)) = session.connect_capsules.decode(&mut chunk) {
                        if let Capsule::CloseSession { code, reason } = capsule {
                            self.options.wire.push(WireEvent::CloseCapsule { code });
                            closed_with = Some((code, reason));
                        }
                    }
                }
                _ => {}
            }
        }
        if ended {
            session.connect_ended = true;
            self.options.wire.push(WireEvent::ConnectEnded);
            closed_with.get_or_insert((0, "the server ended the session".into()));
        }
        let Some((code, reason)) = closed_with else {
            return;
        };
        if !std::mem::replace(&mut session.closed, true) {
            self.events.push_back(IoEvent::SessionClosed {
                session: SessionHandle(handle),
                code,
                reason,
            });
        }
        finish_connect(session);
    }

    /// Reads the server's uni streams, the CONNECT response, new server
    /// streams' prefixes, and granted bytes of every stream.
    fn read_server_streams(&mut self, handle: u64) {
        let Some(session) = self.sessions.get_mut(&handle) else {
            return;
        };
        for (&id, (header, ty, frames)) in session.server_uni.iter_mut() {
            let (bytes, _) = read(&mut session.conn, id, usize::MAX);
            let mut input = &bytes[..];
            if ty.is_none() {
                *ty = header.decode(&mut input);
            }
            if *ty == Some(UniStreamType::Control) {
                while let Ok(Some(_)) = frames.decode(&mut input) {}
            }
        }
        let heads: Vec<StreamId> = session.heads.keys().copied().collect();
        for id in heads {
            let Some(frames) = session.heads.get_mut(&id) else {
                continue;
            };
            let mut recv = session.conn.recv_stream(id);
            let Ok(mut chunks) = recv.read(true) else {
                continue;
            };
            let mut prefixed = false;
            while let Ok(Some(chunk)) = chunks.next(1) {
                let mut input = &chunk.bytes[..];
                if let Ok(Some(Frame::WebTransportStream { .. })) = frames.decode(&mut input) {
                    prefixed = true;
                    break;
                }
            }
            let _credit = chunks.finalize();
            if prefixed {
                session.heads.remove(&id);
                self.next_handle += 1;
                let stream = self.next_handle;
                session.by_quinn.insert(id, stream);
                self.streams.insert(
                    stream,
                    WtStream {
                        session: handle,
                        id,
                        outbox: VecDeque::new(),
                        hold: None,
                        split: false,
                        fin: false,
                        granted: 0,
                        done_reading: false,
                    },
                );
                self.events.push_back(IoEvent::IncomingStream {
                    session: SessionHandle(handle),
                    stream: StreamHandle(stream),
                });
            }
        }
        for (&stream, state) in self.streams.iter_mut() {
            if state.session != handle || state.done_reading || state.granted == 0 {
                continue;
            }
            let mut recv = session.conn.recv_stream(state.id);
            let Ok(mut chunks) = recv.read(true) else {
                continue;
            };
            let mut data = Vec::new();
            let mut end = None;
            while state.granted > data.len() {
                match chunks.next(state.granted - data.len()) {
                    Ok(Some(chunk)) => data.extend_from_slice(&chunk.bytes),
                    Ok(None) => {
                        end = Some(IoEvent::Fin {
                            stream: StreamHandle(stream),
                        });
                        break;
                    }
                    Err(ReadError::Reset(code)) => {
                        self.options.wire.push(WireEvent::Reset {
                            code: code.into_inner(),
                        });
                        end = Some(IoEvent::Reset {
                            stream: StreamHandle(stream),
                            code: wt_code(code),
                        });
                        break;
                    }
                    Err(ReadError::Blocked) => break,
                }
            }
            let _credit = chunks.finalize();
            state.granted -= data.len();
            if !data.is_empty() {
                self.events.push_back(IoEvent::Data {
                    stream: StreamHandle(stream),
                    bytes: Bytes::from(data),
                });
            }
            if let Some(end) = end {
                state.done_reading = true;
                self.events.push_back(end);
            }
        }
    }

    /// Hands every stream's in-flight writes to the engine.
    fn flush(&mut self, handle: u64) {
        let Some(session) = self.sessions.get_mut(&handle) else {
            return;
        };
        for (&stream, state) in self.streams.iter_mut() {
            if state.session != handle {
                continue;
            }
            let mut send = session.conn.send_stream(state.id);
            while let Some(segment) = state.outbox.front_mut() {
                if std::mem::take(&mut state.split) {
                    // The first half of a split prefix went out last time.
                    state.hold = Some(Instant::now() + SPLIT_DELAY);
                }
                if state.hold.is_some_and(|at| at > Instant::now()) {
                    break;
                }
                let unsent = segment.bytes.get(segment.sent..).unwrap_or_default();
                let Ok(written) = send.write(unsent) else {
                    break;
                };
                segment.sent += written;
                if segment.sent < segment.bytes.len() {
                    break;
                }
                let done = state.outbox.pop_front().expect("front");
                if state.hold.is_none()
                    && self.options.split_prefix
                    && !done.report
                    && state.outbox.front().is_some_and(|next| !next.report)
                {
                    // Only the first half goes in this packet.
                    state.split = true;
                    break;
                }
                if done.report {
                    self.events.push_back(IoEvent::WriteCompleted {
                        stream: StreamHandle(stream),
                        bytes: done.bytes.len(),
                    });
                }
            }
            if state.outbox.is_empty() && std::mem::take(&mut state.fin) {
                match send.finish() {
                    Ok(()) | Err(_) => {}
                }
            }
        }
    }

    fn transmit(&mut self, handle: u64, now: Instant) {
        let Some(session) = self.sessions.get_mut(&handle) else {
            return;
        };
        while let Some(event) = session.conn.poll_endpoint_events() {
            if let Some(event) = self.endpoint.handle_event(session.handle, event) {
                session.conn.handle_event(event);
            }
        }
        let mut buf = Vec::new();
        loop {
            buf.clear();
            let Some(transmit) = session.conn.poll_transmit(now, 1, &mut buf) else {
                break;
            };
            let datagram = buf.get(..transmit.size).unwrap_or_default();
            match self.socket.send_to(datagram, transmit.destination) {
                Ok(_) | Err(_) => {}
            }
        }
    }
}

/// Sends the CONNECT, and the control stream unless it is held back.
fn start_h3(session: &mut Session, send_settings: bool, path: Option<&str>) {
    if send_settings {
        send_control(session);
    }
    let Some(stream) = session.conn.streams().open(Dir::Bi) else {
        return;
    };
    let path = path.unwrap_or(&session.path).to_owned();
    let mut block = Vec::new();
    encode_field_section(
        [
            (&b":method"[..], &b"CONNECT"[..]),
            (b":protocol", b"webtransport"),
            (b":scheme", b"https"),
            (b":authority", session.authority.as_bytes()),
            (b":path", path.as_bytes()),
        ],
        &mut block,
    );
    let mut bytes = Vec::new();
    encode_frame(frame_type::HEADERS, &block, &mut bytes).expect("HEADERS");
    session
        .conn
        .send_stream(stream)
        .write(&bytes)
        .expect("CONNECT fits");
    session.connect = Some(stream);
}

/// Finishes our side of the CONNECT stream, once.
fn finish_connect(session: &mut Session) {
    if let Some(connect) = session.connect
        && !std::mem::replace(&mut session.connect_finished, true)
    {
        match session.conn.send_stream(connect).finish() {
            Ok(()) | Err(_) => {}
        }
    }
}

/// Our control stream: its type, then draft-02 SETTINGS.
fn send_control(session: &mut Session) {
    let Some(stream) = session.conn.streams().open(Dir::Uni) else {
        return;
    };
    let mut bytes = Vec::new();
    encode_uni_stream_type(UniStreamType::Control, &mut bytes).expect("type");
    let mut settings = Settings::new();
    settings
        .set(setting::ENABLE_WEBTRANSPORT, 1)
        .set(setting::H3_DATAGRAM, 1);
    settings.encode_frame(&mut bytes).expect("SETTINGS");
    session
        .conn
        .send_stream(stream)
        .write(&bytes)
        .expect("SETTINGS fit");
    session.control_sent = true;
}

/// Everything readable on a stream, up to `max` bytes, and whether it ended.
fn read(conn: &mut Connection, id: StreamId, max: usize) -> (Vec<u8>, bool) {
    let mut bytes = Vec::new();
    let mut recv = conn.recv_stream(id);
    let Ok(mut chunks) = recv.read(true) else {
        return (bytes, true);
    };
    let ended = loop {
        match chunks.next(max - bytes.len()) {
            Ok(Some(chunk)) => bytes.extend_from_slice(&chunk.bytes),
            Ok(None) | Err(ReadError::Reset(_)) => break true,
            Err(ReadError::Blocked) => break false,
        }
    };
    let _credit = chunks.finalize();
    (bytes, ended)
}

/// The 8-bit WebTransport code a browser would report for an HTTP/3 code.
fn wt_code(code: VarInt) -> u8 {
    h3_code_to_webtransport(code.into_inner()).map_or(0, |code| code as u8)
}

impl WebTransportIo for QuinnIo {
    fn connect(&mut self, url: &str, certhashes: &[Multihash]) -> Result<SessionHandle, IoError> {
        let rest = url
            .strip_prefix("https://")
            .ok_or_else(|| IoError(format!("not an https URL: {url}")))?;
        let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
        let server: SocketAddr = authority
            .parse()
            .map_err(|error| IoError(format!("{authority}: {error}")))?;
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| IoError(error.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(CerthashVerifier {
                certhashes: certhashes.to_vec(),
            }))
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = QuicClientConfig::try_from(tls).map_err(|error| IoError(error.to_string()))?;
        let (handle, conn) = self
            .endpoint
            .connect(
                Instant::now(),
                ClientConfig::new(Arc::new(crypto)),
                server,
                &server.ip().to_string(),
            )
            .map_err(|error| IoError(error.to_string()))?;
        let session = self.handle();
        self.by_conn.insert(handle, session);
        self.sessions.insert(
            session,
            Session {
                conn,
                handle,
                authority: authority.to_owned(),
                path: path.to_owned(),
                connect: None,
                connect_frames: FrameDecoder::new(),
                connect_capsules: CapsuleDecoder::new(),
                connect_ended: false,
                connect_finished: false,
                control_sent: false,
                control_at: None,
                ready: false,
                closed: false,
                server_uni: HashMap::new(),
                heads: HashMap::new(),
                by_quinn: HashMap::new(),
            },
        );
        self.transmit(session, Instant::now());
        Ok(SessionHandle(session))
    }

    fn open_stream(&mut self, session: SessionHandle) -> Result<StreamHandle, IoError> {
        let session_id = session.0;
        let state = self
            .sessions
            .get_mut(&session_id)
            .filter(|s| s.ready && !s.closed)
            .ok_or_else(|| IoError("the session is not ready".into()))?;
        let id = state
            .conn
            .streams()
            .open(Dir::Bi)
            .ok_or_else(|| IoError("no stream credit".into()))?;
        let connect = state.connect.ok_or_else(|| IoError("no CONNECT".into()))?;
        let mut prefix = Vec::new();
        encode_webtransport_bidi_header(u64::from(connect), &mut prefix)
            .map_err(|error| IoError(error.to_string()))?;
        let mut outbox = VecDeque::new();
        if self.options.split_prefix {
            let rest = prefix.split_off(1);
            outbox.push_back(Segment {
                bytes: prefix,
                sent: 0,
                report: false,
            });
            outbox.push_back(Segment {
                bytes: rest,
                sent: 0,
                report: false,
            });
        } else {
            outbox.push_back(Segment {
                bytes: prefix,
                sent: 0,
                report: false,
            });
        }
        let stream = self.handle();
        if let Some(state) = self.sessions.get_mut(&session_id) {
            state.by_quinn.insert(id, stream);
        }
        self.streams.insert(
            stream,
            WtStream {
                session: session_id,
                id,
                outbox,
                hold: None,
                split: false,
                fin: false,
                granted: 0,
                done_reading: false,
            },
        );
        self.events.push_back(IoEvent::StreamOpened {
            stream: StreamHandle(stream),
        });
        Ok(StreamHandle(stream))
    }

    fn write(&mut self, stream: StreamHandle, data: &[u8]) -> Result<usize, IoError> {
        let state = self
            .streams
            .get_mut(&stream.0)
            .ok_or_else(|| IoError(format!("{stream} is gone")))?;
        let accepted = data.len().min(MAX_IN_FLIGHT - state.in_flight());
        if accepted > 0 {
            state.outbox.push_back(Segment {
                bytes: data.get(..accepted).unwrap_or_default().to_vec(),
                sent: 0,
                report: true,
            });
        }
        Ok(accepted)
    }

    fn close_write(&mut self, stream: StreamHandle) {
        if let Some(state) = self.streams.get_mut(&stream.0) {
            state.fin = true;
        }
    }

    fn reset(&mut self, stream: StreamHandle, code: u8) {
        let Some(state) = self.streams.remove(&stream.0) else {
            return;
        };
        let Some(session) = self.sessions.get_mut(&state.session) else {
            return;
        };
        let code = VarInt::from_u64(webtransport_code_to_h3(u32::from(code))).expect("code");
        match session.conn.send_stream(state.id).reset(code) {
            Ok(()) | Err(_) => {}
        }
        match session.conn.recv_stream(state.id).stop(code) {
            Ok(()) | Err(_) => {}
        }
    }

    fn stop(&mut self, stream: StreamHandle, code: u8) {
        let Some(state) = self.streams.get(&stream.0) else {
            return;
        };
        let Some(session) = self.sessions.get_mut(&state.session) else {
            return;
        };
        let code = VarInt::from_u64(webtransport_code_to_h3(u32::from(code))).expect("code");
        match session.conn.recv_stream(state.id).stop(code) {
            Ok(()) | Err(_) => {}
        }
    }

    fn grant_read(&mut self, stream: StreamHandle, bytes: usize) {
        if let Some(state) = self.streams.get_mut(&stream.0) {
            state.granted += bytes;
        }
    }

    /// Closes as a browser does: a close capsule and FIN on the CONNECT
    /// stream, leaving the server to close QUIC.
    fn close(&mut self, session: SessionHandle, code: u32, reason: &str) {
        let Some(state) = self.sessions.get_mut(&session.0) else {
            return;
        };
        state.closed = true;
        if let Some(connect) = state.connect.filter(|_| !state.connect_finished) {
            let mut capsule = Vec::new();
            Capsule::CloseSession {
                code,
                reason: reason.to_owned(),
            }
            .encode(&mut capsule)
            .expect("capsule");
            let mut bytes = Vec::new();
            encode_frame(frame_type::DATA, &capsule, &mut bytes).expect("DATA");
            match state.conn.send_stream(connect).write(&bytes) {
                Ok(_) | Err(_) => {}
            }
            finish_connect(state);
        }
        self.transmit(session.0, Instant::now());
    }

    fn poll_event(&mut self) -> Option<IoEvent> {
        if self.events.is_empty() {
            self.pump();
        }
        self.events.pop_front()
    }
}

impl QuinnIo {
    /// Sends STOP_SENDING with a raw HTTP/3 code, which no browser can.
    pub fn stop_raw(&mut self, stream: StreamHandle, code: u64) {
        let Some(state) = self.streams.get(&stream.0) else {
            return;
        };
        let Some(session) = self.sessions.get_mut(&state.session) else {
            return;
        };
        match session
            .conn
            .recv_stream(state.id)
            .stop(VarInt::from_u64(code).expect("code"))
        {
            Ok(()) | Err(_) => {}
        }
    }
}
