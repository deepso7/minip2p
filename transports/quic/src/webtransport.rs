//! The WebTransport server phase of an `h3` connection (libp2p WebTransport
//! over draft-02 HTTP/3).
//!
//! [`WtSession`] runs beside the connection's stream logic from QUIC
//! `Connected` on. It opens our control stream with SETTINGS, reads the
//! client's control and QPACK streams, answers the CONNECT to
//! [`LIBP2P_WEBTRANSPORT_PATH`] with 200 once the client's SETTINGS offer
//! WebTransport, and runs Noise XX as responder on the first stream with the
//! session's `0x41` prefix. Its output is a list of [`WtEvent`]s for the
//! connection to act on: authenticate, admit a stream, or fail.
//!
//! Stream prefixes never reach the caller: an inbound stream's prefix is
//! read here, a byte at a time so nothing behind it is consumed, and the
//! stream is admitted after it. Prefixed streams that arrive before the
//! session is authenticated (the Noise stream racing the 200, or streams
//! racing Noise) are held with their data still in the engine.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use minip2p_core::platform::{EntropySource, StdEntropy};
use minip2p_core::{Multihash, PeerId};
use minip2p_identity::Ed25519Keypair;
use minip2p_secure_mux::noise::{
    NoiseConfig, NoiseExtensions, NoiseOutput, NoiseRole, NoiseSession,
};
use minip2p_webtransport::LIBP2P_WEBTRANSPORT_PATH;
use minip2p_webtransport::h3::{
    Frame, FrameDecoder, Settings, UniStreamHeaderDecoder, UniStreamType, code, encode_frame,
    encode_uni_stream_type, frame_type, setting,
};
use minip2p_webtransport::qpack::{QpackDecoder, encode_field_section};
use quinn_proto::{Connection, Dir, ReadError, StreamId, VarInt};

/// Prefixed streams held before the session is authenticated; one more
/// fails the connection.
const MAX_EARLY_STREAMS: usize = 4;

/// What every WebTransport connection of one transport shares.
#[derive(Debug)]
pub(crate) struct WebTransportContext {
    /// The host identity Noise proves.
    pub(crate) keypair: Ed25519Keypair,
    /// The certhashes Noise lists, so a client can tell it reached the
    /// server whose certificate it pinned.
    pub(crate) certhashes: Vec<Multihash>,
}

/// What the connection must do after a session step.
#[derive(Debug)]
pub(crate) enum WtEvent {
    /// Noise authenticated the client: the connection is up.
    Established { peer: PeerId, token: [u8; 32] },
    /// A prefixed peer stream is ready to surface, its prefix consumed.
    Admit(u64),
    /// The session cannot go on: close the connection with this HTTP/3
    /// code.
    Fail { code: u64, reason: String },
}

/// One peer unidirectional stream.
enum PeerUni {
    /// Its type is not known yet.
    Header(UniStreamHeaderDecoder),
    /// The client's control stream; `bool` is whether SETTINGS arrived.
    Control(FrameDecoder, bool),
    QpackEncoder,
    QpackDecoder,
}

/// The CONNECT stream once its request was read.
struct Connect {
    id: u64,
    frames: FrameDecoder,
    /// The status the request earns, before the client's SETTINGS weigh in.
    request_status: &'static str,
    /// The response went out: 200 accepts the session.
    replied: bool,
}

/// The Noise stream and its responder session.
struct NoiseStream {
    id: u64,
    /// `None` once the handshake completed.
    session: Option<NoiseSession>,
}

/// The WebTransport session of one `h3` connection.
pub(crate) struct WtSession {
    ctx: Arc<WebTransportContext>,
    /// Our control stream, once opened.
    control: Option<StreamId>,
    /// Peer uni streams being read.
    peer_uni: HashMap<u64, PeerUni>,
    has_control: bool,
    has_encoder: bool,
    has_decoder: bool,
    /// The client's SETTINGS.
    settings: Option<Settings>,
    connect: Option<Connect>,
    /// Peer bidi streams whose first frame or prefix is being read.
    heads: HashMap<u64, FrameDecoder>,
    /// Prefixed streams waiting for the session or for Noise, with the
    /// session id each names, in arrival order.
    held: VecDeque<(u64, u64)>,
    noise: Option<NoiseStream>,
    established: bool,
    /// Bytes per stream the engine has not accepted yet, with whether a FIN
    /// follows them.
    out: HashMap<u64, (Vec<u8>, bool)>,
    events: Vec<WtEvent>,
}

/// How a read of a stream ended.
enum ReadEnd {
    /// More may come.
    Open,
    Finished,
    Reset,
}

impl WtSession {
    pub(crate) fn new(ctx: Arc<WebTransportContext>) -> Self {
        Self {
            ctx,
            control: None,
            peer_uni: HashMap::new(),
            has_control: false,
            has_encoder: false,
            has_decoder: false,
            settings: None,
            connect: None,
            heads: HashMap::new(),
            held: VecDeque::new(),
            noise: None,
            established: false,
            out: HashMap::new(),
            events: Vec::new(),
        }
    }

    /// The session id local streams name in their prefix, once the session
    /// is authenticated.
    pub(crate) fn session_id(&self) -> Option<u64> {
        self.connect
            .as_ref()
            .filter(|_| self.established)
            .map(|connect| connect.id)
    }

    /// Whether the session reads `raw` itself rather than the connection.
    pub(crate) fn owns(&self, raw: u64) -> bool {
        self.peer_uni.contains_key(&raw)
            || self.heads.contains_key(&raw)
            || self.connect.as_ref().is_some_and(|c| c.id == raw)
            || self.noise.as_ref().is_some_and(|n| n.id == raw)
            || self.held.iter().any(|&(id, _)| id == raw)
    }

    /// What the connection must act on since the last call.
    pub(crate) fn take_events(&mut self) -> Vec<WtEvent> {
        std::mem::take(&mut self.events)
    }

    /// Opens our control stream with SETTINGS, once the peer grants a uni
    /// stream. Called on every service until it succeeds.
    pub(crate) fn open_control(&mut self, conn: &mut Connection) {
        if self.control.is_some() {
            return;
        }
        let Some(stream) = conn.streams().open(Dir::Uni) else {
            return;
        };
        self.control = Some(stream);
        let mut bytes = Vec::new();
        let mut settings = Settings::new();
        // Draft-02 (Chrome, Firefox) and draft-13/14 (Safari) together, as
        // webtransport-go sends them. No QPACK settings: the table stays
        // static-only.
        settings
            .set(setting::ENABLE_CONNECT_PROTOCOL, 1)
            .set(setting::H3_DATAGRAM, 1)
            .set(setting::ENABLE_WEBTRANSPORT, 1)
            .set(setting::WT_MAX_SESSIONS, 1)
            .set(setting::WT_INITIAL_MAX_DATA, 1 << 60)
            .set(setting::WT_INITIAL_MAX_STREAMS_UNI, 1 << 60)
            .set(setting::WT_INITIAL_MAX_STREAMS_BIDI, 1 << 60);
        let encoded = encode_uni_stream_type(UniStreamType::Control, &mut bytes)
            .and_then(|()| settings.encode_frame(&mut bytes));
        if encoded.is_err() {
            self.fail(code::H3_INTERNAL_ERROR, "encoding SETTINGS failed".into());
            return;
        }
        self.send(conn, u64::from(stream), bytes, false);
    }

    /// A peer stream the engine just accepted.
    pub(crate) fn on_opened(&mut self, conn: &mut Connection, stream: StreamId) {
        let raw = u64::from(stream);
        match stream.dir() {
            Dir::Uni => {
                self.peer_uni
                    .insert(raw, PeerUni::Header(UniStreamHeaderDecoder::new()));
            }
            Dir::Bi => {
                self.heads.insert(raw, FrameDecoder::new());
            }
        }
        self.on_readable(conn, raw);
    }

    /// New data (or a FIN or reset) on a stream the session owns.
    pub(crate) fn on_readable(&mut self, conn: &mut Connection, raw: u64) {
        if self.peer_uni.contains_key(&raw) {
            self.read_uni(conn, raw);
        } else if self.heads.contains_key(&raw) {
            self.read_head(conn, raw);
        } else if self.connect.as_ref().is_some_and(|c| c.id == raw) {
            self.read_connect(conn);
        } else if self.noise.as_ref().is_some_and(|n| n.id == raw) {
            self.read_noise(conn);
        }
        self.flush(conn);
    }

    /// Hands the engine what it did not take before.
    pub(crate) fn flush(&mut self, conn: &mut Connection) {
        self.out.retain(|&raw, (bytes, fin)| {
            let mut send = conn.send_stream(engine_stream(raw));
            if !bytes.is_empty() {
                match send.write(bytes) {
                    Ok(written) => {
                        bytes.drain(..written);
                    }
                    // Blocked waits for credit; a stopped or closed stream
                    // takes nothing more.
                    Err(quinn_proto::WriteError::Blocked) => return true,
                    Err(_) => return false,
                }
            }
            if !bytes.is_empty() {
                return true;
            }
            if *fin {
                match send.finish() {
                    Ok(()) | Err(_) => {}
                }
            }
            false
        });
    }

    /// Queues `bytes` (and a FIN) on a stream and writes what fits now.
    fn send(&mut self, conn: &mut Connection, raw: u64, bytes: Vec<u8>, fin: bool) {
        let entry = self.out.entry(raw).or_default();
        entry.0.extend_from_slice(&bytes);
        entry.1 |= fin;
        self.flush(conn);
    }

    fn fail(&mut self, code: u64, reason: String) {
        self.events.push(WtEvent::Fail { code, reason });
    }

    fn read_uni(&mut self, conn: &mut Connection, raw: u64) {
        let (bytes, end) = read_available(conn, raw);
        // Out of the map while it is read; put back unless it ended.
        let Some(mut state) = self.peer_uni.remove(&raw) else {
            return;
        };
        let mut input = &bytes[..];
        if let PeerUni::Header(header) = &mut state {
            let Some(ty) = header.decode(&mut input) else {
                if matches!(end, ReadEnd::Open) {
                    self.peer_uni.insert(raw, state);
                }
                return;
            };
            state = match ty {
                UniStreamType::Control if !self.has_control => {
                    self.has_control = true;
                    PeerUni::Control(FrameDecoder::new(), false)
                }
                UniStreamType::QpackEncoder if !self.has_encoder => {
                    self.has_encoder = true;
                    PeerUni::QpackEncoder
                }
                UniStreamType::QpackDecoder if !self.has_decoder => {
                    self.has_decoder = true;
                    PeerUni::QpackDecoder
                }
                UniStreamType::Control
                | UniStreamType::QpackEncoder
                | UniStreamType::QpackDecoder => {
                    self.fail(
                        code::H3_STREAM_CREATION_ERROR,
                        format!("a second {ty:?} stream"),
                    );
                    return;
                }
                // Push, WebTransport uni and unknown streams: refused,
                // never fatal.
                UniStreamType::Push
                | UniStreamType::WebTransport { .. }
                | UniStreamType::Unknown(_) => {
                    stop(conn, raw, code::H3_STREAM_CREATION_ERROR);
                    return;
                }
            };
        }
        let failure = match &mut state {
            PeerUni::Control(frames, saw_settings) => {
                self.read_control(conn, frames, saw_settings, &mut input)
            }
            // The table capacity is 0, so every encoder instruction is
            // illegal.
            PeerUni::QpackEncoder if !input.is_empty() => Some((
                code::QPACK_ENCODER_STREAM_ERROR,
                "QPACK encoder instruction with a zero table capacity".into(),
            )),
            // Decoder instructions only acknowledge a table we never use.
            PeerUni::QpackEncoder | PeerUni::QpackDecoder | PeerUni::Header(_) => None,
        };
        if let Some((code, reason)) = failure {
            self.fail(code, reason);
        } else if matches!(end, ReadEnd::Open) {
            self.peer_uni.insert(raw, state);
        } else {
            self.fail(
                code::H3_CLOSED_CRITICAL_STREAM,
                "the client closed a critical HTTP/3 stream".into(),
            );
        }
    }

    /// Decodes the client's control frames: SETTINGS first, then nothing
    /// but GOAWAY (which ends the session) and frames HTTP/3 skips. Returns
    /// the code and reason of a connection error.
    fn read_control(
        &mut self,
        conn: &mut Connection,
        frames: &mut FrameDecoder,
        saw_settings: &mut bool,
        input: &mut &[u8],
    ) -> Option<(u64, String)> {
        loop {
            match frames.decode(input) {
                Ok(None) => return None,
                Ok(Some(Frame::Settings(settings))) if !*saw_settings => {
                    *saw_settings = true;
                    self.settings = Some(settings);
                    self.reply(conn);
                }
                Ok(Some(_)) if !*saw_settings => {
                    return Some((
                        code::H3_MISSING_SETTINGS,
                        "the client's control stream did not start with SETTINGS".into(),
                    ));
                }
                Ok(Some(Frame::GoAway(_))) => {
                    return Some((code::H3_NO_ERROR, "the client sent GOAWAY".into()));
                }
                Ok(Some(frame)) => {
                    return Some((
                        code::H3_FRAME_UNEXPECTED,
                        format!("unexpected frame on the control stream: {frame:?}"),
                    ));
                }
                Err(error) => return Some((error.code(), format!("control stream: {error}"))),
            }
        }
    }

    /// Reads a peer bidi stream's first frame a byte at a time, so nothing
    /// after a WebTransport prefix is consumed.
    fn read_head(&mut self, conn: &mut Connection, raw: u64) {
        let Some(frames) = self.heads.get_mut(&raw) else {
            return;
        };
        let mut recv = conn.recv_stream(engine_stream(raw));
        let Ok(mut chunks) = recv.read(true) else {
            self.heads.remove(&raw);
            return;
        };
        let head = loop {
            match chunks.next(1) {
                Ok(Some(chunk)) => {
                    let mut input = &chunk.bytes[..];
                    match frames.decode(&mut input) {
                        Ok(None) => {}
                        Ok(Some(Frame::Headers(block))) => break Some(Ok(block)),
                        Ok(Some(Frame::WebTransportStream { session_id })) => {
                            break Some(Err(session_id));
                        }
                        Ok(Some(_)) => {
                            break None;
                        }
                        Err(error) => {
                            let _credit = chunks.finalize();
                            self.heads.remove(&raw);
                            self.fail(error.code(), format!("request stream: {error}"));
                            return;
                        }
                    }
                }
                Ok(None) | Err(ReadError::Reset(_)) => {
                    let _credit = chunks.finalize();
                    // Ended before saying what it is: nothing to keep.
                    self.heads.remove(&raw);
                    return;
                }
                Err(ReadError::Blocked) => {
                    let _credit = chunks.finalize();
                    return;
                }
            }
        };
        let _credit = chunks.finalize();
        let Some(frames) = self.heads.remove(&raw) else {
            return;
        };
        match head {
            Some(Ok(block)) => self.on_request(conn, raw, frames, &block),
            Some(Err(session_id)) => self.on_prefixed(conn, raw, session_id),
            None => {
                self.fail(
                    code::H3_FRAME_UNEXPECTED,
                    "a request stream did not start with HEADERS".into(),
                );
            }
        }
    }

    /// A request on a new bidi stream: the first is the CONNECT, any other
    /// is refused.
    fn on_request(&mut self, conn: &mut Connection, raw: u64, frames: FrameDecoder, block: &[u8]) {
        if self.connect.is_some() {
            refuse(conn, raw, code::H3_REQUEST_REJECTED);
            return;
        }
        let mut decoder = QpackDecoder::new();
        let request_status = match decoder.decode(block) {
            Ok(section) => {
                let field = |name: &[u8]| section.get(name).unwrap_or_default();
                let path = field(b":path");
                if field(b":method") != b"CONNECT" || field(b":protocol") != b"webtransport" {
                    "400"
                } else if path == LIBP2P_WEBTRANSPORT_PATH.as_bytes() {
                    "200"
                } else if path.split(|&byte| byte == b'?').next()
                    == LIBP2P_WEBTRANSPORT_PATH
                        .split('?')
                        .next()
                        .map(str::as_bytes)
                {
                    "400"
                } else {
                    "404"
                }
            }
            Err(error) => {
                self.fail(error.code(), format!("CONNECT request: {error}"));
                return;
            }
        };
        self.connect = Some(Connect {
            id: raw,
            frames,
            request_status,
            replied: false,
        });
        self.reply(conn);
        self.read_connect(conn);
    }

    /// Answers the CONNECT once both it and the client's SETTINGS are in.
    fn reply(&mut self, conn: &mut Connection) {
        let (Some(settings), Some(connect)) = (self.settings.as_ref(), self.connect.as_mut())
        else {
            return;
        };
        if connect.replied {
            return;
        }
        connect.replied = true;
        let offers_webtransport = settings.get(setting::ENABLE_WEBTRANSPORT) == Some(1)
            || settings
                .get(setting::WT_MAX_SESSIONS)
                .is_some_and(|sessions| sessions >= 1);
        let status = if offers_webtransport {
            connect.request_status
        } else {
            "400"
        };
        let id = connect.id;
        let mut block = Vec::new();
        encode_field_section([(&b":status"[..], status.as_bytes())], &mut block);
        let mut bytes = Vec::new();
        if encode_frame(frame_type::HEADERS, &block, &mut bytes).is_err() {
            self.fail(code::H3_INTERNAL_ERROR, "encoding a response failed".into());
            return;
        }
        self.send(conn, id, bytes, false);
        if status != "200" {
            self.fail(
                code::H3_NO_ERROR,
                format!("refused the WebTransport request with {status}"),
            );
            return;
        }
        self.promote_held(conn);
    }

    /// The CONNECT stream after its request: capsules are not read yet,
    /// and its end ends the session.
    fn read_connect(&mut self, conn: &mut Connection) {
        let Some(connect) = self.connect.as_mut() else {
            return;
        };
        let (bytes, end) = read_available(conn, connect.id);
        let mut input = &bytes[..];
        loop {
            match connect.frames.decode(&mut input) {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(error) => {
                    self.fail(error.code(), format!("CONNECT stream: {error}"));
                    return;
                }
            }
        }
        if !matches!(end, ReadEnd::Open) {
            self.fail(
                code::H3_NO_ERROR,
                "the client ended the WebTransport session".into(),
            );
        }
    }

    /// A stream with a WebTransport prefix: admitted once the session is
    /// authenticated, held until then.
    fn on_prefixed(&mut self, conn: &mut Connection, raw: u64, session_id: u64) {
        if self.established {
            if Some(session_id) == self.session_id() {
                self.events.push(WtEvent::Admit(raw));
            } else {
                refuse(conn, raw, code::H3_ID_ERROR);
            }
            return;
        }
        self.held.push_back((raw, session_id));
        if self.held.len() > MAX_EARLY_STREAMS {
            self.fail(
                code::H3_EXCESSIVE_LOAD,
                "too many WebTransport streams before the session was authenticated".into(),
            );
            return;
        }
        self.promote_held(conn);
    }

    /// Once the session is accepted, the first held stream runs Noise; once
    /// Noise is done, every other is admitted.
    fn promote_held(&mut self, conn: &mut Connection) {
        let Some(session) = self
            .connect
            .as_ref()
            .filter(|connect| connect.replied && connect.request_status == "200")
            .map(|connect| connect.id)
        else {
            return;
        };
        while let Some(&(raw, session_id)) = self.held.front() {
            if session_id != session {
                self.held.pop_front();
                refuse(conn, raw, code::H3_ID_ERROR);
            } else if self.noise.is_none() {
                self.held.pop_front();
                self.start_noise(conn, raw);
            } else if self.established {
                self.held.pop_front();
                self.events.push(WtEvent::Admit(raw));
            } else {
                return;
            }
        }
    }

    fn start_noise(&mut self, conn: &mut Connection, raw: u64) {
        let mut entropy = StdEntropy::new();
        let mut secrets = [[0u8; 32]; 2];
        for secret in &mut secrets {
            if let Err(error) = entropy.fill_bytes(secret) {
                self.fail(
                    code::H3_INTERNAL_ERROR,
                    format!("no entropy for Noise keys: {error}"),
                );
                return;
            }
        }
        let [static_secret, ephemeral_secret] = secrets;
        let mut session = NoiseSession::new(NoiseConfig {
            role: NoiseRole::Responder,
            identity: self.ctx.keypair.clone(),
            static_secret,
            ephemeral_secret,
            expected_peer: None,
            local_extensions: Some(NoiseExtensions {
                webtransport_certhashes: self.ctx.certhashes.clone(),
                stream_muxers: Vec::new(),
            }),
        });
        if let Err(error) = session.start() {
            self.fail(
                code::H3_INTERNAL_ERROR,
                format!("Noise start failed: {error}"),
            );
            return;
        }
        self.noise = Some(NoiseStream {
            id: raw,
            session: Some(session),
        });
        self.read_noise(conn);
    }

    /// Feeds the Noise stream to the responder and writes its replies; on
    /// completion the connection is authenticated and the stream finished.
    fn read_noise(&mut self, conn: &mut Connection) {
        let Some(noise) = self.noise.as_mut() else {
            return;
        };
        let raw = noise.id;
        let (bytes, end) = read_available(conn, raw);
        let Some(session) = noise.session.as_mut() else {
            // Done: whatever follows is ignored.
            return;
        };
        if !bytes.is_empty()
            && let Err(error) = session.on_data(bytes)
        {
            self.fail(
                code::H3_NO_ERROR,
                format!("Noise handshake failed: {error}"),
            );
            return;
        }
        let mut outbound = Vec::new();
        let mut peer = None;
        while let Some(output) = session.poll_output() {
            match output {
                NoiseOutput::Outbound(frame) => outbound.extend_from_slice(&frame),
                NoiseOutput::HandshakeComplete { peer: verified, .. } => peer = Some(verified),
                NoiseOutput::Decrypted(_) => {}
            }
        }
        let token = session.handshake_hash();
        if !outbound.is_empty() || peer.is_some() {
            self.send(conn, raw, outbound, peer.is_some());
        }
        if let (Some(peer), Some(token)) = (peer, token) {
            if let Some(noise) = self.noise.as_mut() {
                noise.session = None;
            }
            self.established = true;
            self.events.push(WtEvent::Established { peer, token });
            self.promote_held(conn);
        } else if !matches!(end, ReadEnd::Open) {
            self.fail(
                code::H3_NO_ERROR,
                "the client ended the Noise stream mid-handshake".into(),
            );
        }
    }
}

/// The engine's id for a raw stream id.
fn engine_stream(raw: u64) -> StreamId {
    VarInt::from_u64(raw)
        .expect("stream ids come from the engine")
        .into()
}

/// Reads everything readable on a stream.
fn read_available(conn: &mut Connection, raw: u64) -> (Vec<u8>, ReadEnd) {
    let mut bytes = Vec::new();
    let mut recv = conn.recv_stream(engine_stream(raw));
    let Ok(mut chunks) = recv.read(true) else {
        return (bytes, ReadEnd::Reset);
    };
    let end = loop {
        match chunks.next(usize::MAX) {
            Ok(Some(chunk)) => bytes.extend_from_slice(&chunk.bytes),
            Ok(None) => break ReadEnd::Finished,
            Err(ReadError::Blocked) => break ReadEnd::Open,
            Err(ReadError::Reset(_)) => break ReadEnd::Reset,
        }
    };
    let _credit = chunks.finalize();
    (bytes, end)
}

/// Asks the peer to stop sending on a stream (its only half, for a uni
/// stream).
fn stop(conn: &mut Connection, raw: u64, code: u64) {
    let code = VarInt::from_u64(code).unwrap_or(VarInt::from_u32(0));
    match conn.recv_stream(engine_stream(raw)).stop(code) {
        Ok(()) | Err(_) => {}
    }
}

/// Refuses a peer bidi stream: stop and reset.
fn refuse(conn: &mut Connection, raw: u64, code: u64) {
    stop(conn, raw, code);
    let code = VarInt::from_u64(code).unwrap_or(VarInt::from_u32(0));
    match conn.send_stream(engine_stream(raw)).reset(code) {
        Ok(()) | Err(_) => {}
    }
}
