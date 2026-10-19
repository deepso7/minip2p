//! The WebTransport server phase of an `h3` connection (libp2p WebTransport
//! over HTTP/3, draft-02 or draft-13/14).
//!
//! [`WtSession`] runs beside the connection's stream logic from QUIC
//! `Connected` on. It opens our control stream with SETTINGS, reads the
//! client's control and QPACK streams, answers the CONNECT to
//! [`LIBP2P_WEBTRANSPORT_PATH`] with 200 once the client's SETTINGS offer a
//! draft we speak (draft-13/14 preferred, with its session flow control),
//! and runs Noise XX as responder on the first stream with the
//! session's `0x41` prefix. Its output is a list of [`WtEvent`]s for the
//! connection to act on: authenticate, admit a stream, or fail.
//!
//! Stream prefixes never reach the caller: an inbound stream's prefix is
//! read here, a byte at a time so nothing behind it is consumed, and the
//! stream is admitted after it. Prefixed streams that arrive before the
//! session is authenticated (the Noise stream racing the 200, or streams
//! racing Noise) are held, their data read into a buffer the pre-auth byte
//! cap bounds, and handed over with them.
//!
//! Before authentication every allocation is capped: the codec's frame,
//! capsule and QPACK caps, at most [`MAX_EARLY_STREAMS`] held streams, and
//! [`MAX_EARLY_BYTES`] across request heads and held streams. Past a cap the
//! connection closes with `H3_EXCESSIVE_LOAD`.
//!
//! The session also ends orderly, in either direction: [`WtSession::close`]
//! sends `CLOSE_WEBTRANSPORT_SESSION` and finishes the CONNECT stream, and a
//! peer's capsule, CONNECT FIN or reset, or GOAWAY reports
//! [`WtEvent::PeerClosed`]. The connection then waits for
//! [`WtSession::ended_and_delivered`] (or a deadline) before closing QUIC,
//! so the capsule or a refusal's status, and our FIN, reach the peer.

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
    Capsule, CapsuleDecoder, Frame, FrameDecoder, Settings, UniStreamHeaderDecoder, UniStreamType,
    code, encode_frame, encode_uni_stream_type, frame_type, setting,
};
use minip2p_webtransport::qpack::{FieldSection, QpackDecoder, encode_field_section};
use quinn_proto::{Connection, Dir, ReadError, StreamId, VarInt};

/// Prefixed streams held before the session is authenticated, the Noise
/// stream among them until Noise completes; one more fails the connection.
const MAX_EARLY_STREAMS: usize = 4;

/// Bytes read before the session is authenticated, from request heads (up
/// to their HEADERS or prefix), held streams and the Noise stream; one more
/// fails the connection.
const MAX_EARLY_BYTES: usize = 16 * 1024;

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
    /// A prefixed peer stream is ready to surface, its prefix consumed:
    /// `early` is what was read while it was held, and `end` whether the
    /// peer finished or reset it meanwhile.
    Admit {
        raw: u64,
        early: Vec<u8>,
        end: ReadEnd,
    },
    /// The peer ended the session (close capsule, CONNECT FIN or reset, or
    /// GOAWAY) with this WebTransport code: finish our side and close.
    PeerClosed { code: u32 },
    /// The CONNECT was answered with an error status and finished: close
    /// once the status is through.
    Refused { reason: String },
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
    /// Reassembles capsules from the stream's DATA frames.
    capsules: CapsuleDecoder,
    /// The status the request earns, before the client's SETTINGS weigh in.
    request_status: &'static str,
    /// The response went out: 200 accepts the session.
    replied: bool,
    /// Our side is finished (or queued to finish).
    finished: bool,
    /// The peer finished or reset its side.
    peer_ended: bool,
    /// The peer acknowledged our FIN, or stopped our side: nothing we
    /// sent on it is still in flight.
    delivered: bool,
}

/// The client's session flow-control credit for what we send (draft-13/14,
/// once the client sent any `WT_INITIAL_MAX_*`): server-opened bidi streams,
/// and stream bytes after their prefixes. Noise's handshake bytes are not
/// counted.
#[derive(Debug, Default)]
struct Credit {
    max_streams: u64,
    opened: u64,
    max_data: u64,
    sent: u64,
}

impl Credit {
    /// Applies a credit capsule; limits only ever grow.
    fn raise(&mut self, capsule: &Capsule) {
        match *capsule {
            Capsule::MaxData(max) => self.max_data = self.max_data.max(max),
            Capsule::MaxStreamsBidi(max) => self.max_streams = self.max_streams.max(max),
            // We open no uni streams.
            Capsule::MaxStreamsUni(_) | Capsule::CloseSession { .. } => {}
        }
    }
}

/// A prefixed stream waiting for the session or for Noise.
struct Held {
    id: u64,
    /// The session its prefix names.
    session_id: u64,
    /// What it carried meanwhile.
    data: Vec<u8>,
    end: ReadEnd,
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
    /// Prefixed streams waiting for the session or for Noise, in arrival
    /// order.
    held: VecDeque<Held>,
    /// Bytes read before authentication, against [`MAX_EARLY_BYTES`].
    early_bytes: usize,
    noise: Option<NoiseStream>,
    established: bool,
    /// Session flow control, when the chosen draft and the client enable it.
    credit: Option<Credit>,
    /// The session is ending: only the CONNECT stream is read.
    closing: bool,
    /// Bytes per stream the engine has not accepted yet, with whether a FIN
    /// follows them.
    out: HashMap<u64, (Vec<u8>, bool)>,
    events: Vec<WtEvent>,
}

/// How a read of a stream ended.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ReadEnd {
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
            early_bytes: 0,
            noise: None,
            established: false,
            credit: None,
            closing: false,
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

    /// Whether the client's credit allows opening another stream.
    pub(crate) fn may_open_stream(&self) -> bool {
        self.credit
            .as_ref()
            .is_none_or(|credit| credit.opened < credit.max_streams)
    }

    /// Counts a server-opened stream against the client's credit.
    pub(crate) fn note_opened(&mut self) {
        if let Some(credit) = self.credit.as_mut() {
            credit.opened += 1;
        }
    }

    /// Stream bytes the client's credit still allows.
    pub(crate) fn data_room(&self) -> usize {
        self.credit.as_ref().map_or(usize::MAX, |credit| {
            usize::try_from(credit.max_data.saturating_sub(credit.sent)).unwrap_or(usize::MAX)
        })
    }

    /// Counts stream bytes sent against the client's credit.
    pub(crate) fn note_sent(&mut self, bytes: usize) {
        if let Some(credit) = self.credit.as_mut() {
            credit.sent = credit.sent.saturating_add(bytes as u64);
        }
    }

    /// Whether the session reads `raw` itself rather than the connection.
    pub(crate) fn owns(&self, raw: u64) -> bool {
        self.peer_uni.contains_key(&raw)
            || self.heads.contains_key(&raw)
            || self.connect.as_ref().is_some_and(|c| c.id == raw)
            || self.noise.as_ref().is_some_and(|n| n.id == raw)
            || self.held.iter().any(|held| held.id == raw)
    }

    /// Ends an accepted session from our side: a `CLOSE_WEBTRANSPORT_SESSION`
    /// capsule with `code`, then FIN on the CONNECT stream. Returns whether
    /// there was such a session to close; without one the connection has
    /// nothing to wait for.
    pub(crate) fn close(&mut self, conn: &mut Connection, code: u32) -> bool {
        self.closing = true;
        let Some(connect) = self
            .connect
            .as_mut()
            .filter(|connect| connect.replied && connect.request_status == "200")
        else {
            return false;
        };
        if connect.finished {
            return true;
        }
        connect.finished = true;
        let id = connect.id;
        let mut capsule = Vec::new();
        let mut bytes = Vec::new();
        let encoded = Capsule::CloseSession {
            code,
            reason: String::new(),
        }
        .encode(&mut capsule)
        .and_then(|()| encode_frame(frame_type::DATA, &capsule, &mut bytes));
        if encoded.is_err() {
            bytes.clear();
        }
        self.send(conn, id, bytes, true);
        true
    }

    /// Finishes our side of the CONNECT stream, once.
    pub(crate) fn finish_connect(&mut self, conn: &mut Connection) {
        self.closing = true;
        if let Some(connect) = self.connect.as_mut().filter(|connect| !connect.finished) {
            connect.finished = true;
            let id = connect.id;
            self.send(conn, id, Vec::new(), true);
        }
    }

    /// Whether QUIC may close without discarding the session's end: the peer
    /// finished or reset its side of the CONNECT stream (or never opened
    /// one) and acknowledged our FIN on the
    /// CONNECT stream, or stopped it. Packets the connection queued before
    /// that FIN (its resets) went out with or ahead of it.
    pub(crate) fn ended_and_delivered(&self) -> bool {
        self.connect
            .as_ref()
            .is_none_or(|connect| connect.peer_ended && connect.delivered)
    }

    /// The engine is done sending on `raw`: everything was acknowledged, or
    /// the peer stopped it.
    pub(crate) fn on_send_done(&mut self, raw: u64) {
        if let Some(connect) = self.connect.as_mut().filter(|connect| connect.id == raw) {
            connect.delivered = true;
        }
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

    /// New data (or a FIN or reset) on a stream the session owns. While
    /// closing only the CONNECT stream is read.
    pub(crate) fn on_readable(&mut self, conn: &mut Connection, raw: u64) {
        if self.connect.as_ref().is_some_and(|c| c.id == raw) {
            self.read_connect(conn);
        } else if !self.closing {
            if self.peer_uni.contains_key(&raw) {
                self.read_uni(conn, raw);
            } else if self.heads.contains_key(&raw) {
                self.read_head(conn, raw);
            } else if self.noise.as_ref().is_some_and(|n| n.id == raw) {
                self.read_noise(conn);
            } else {
                self.read_held(raw, conn);
            }
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

    /// Counts bytes read before authentication against the cap.
    fn count_early(&mut self, bytes: usize) {
        if self.established {
            return;
        }
        self.early_bytes += bytes;
        if self.early_bytes > MAX_EARLY_BYTES {
            self.fail(
                code::H3_EXCESSIVE_LOAD,
                "too many bytes before the session was authenticated".into(),
            );
        }
    }

    fn fail(&mut self, code: u64, reason: String) {
        self.events.push(WtEvent::Fail { code, reason });
    }

    /// The peer ended the session; reported once.
    fn peer_closed(&mut self, code: u32) {
        if !std::mem::replace(&mut self.closing, true) {
            self.events.push(WtEvent::PeerClosed { code });
        }
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
                    // Legality comes before any draft is chosen, so a bad
                    // value fails even beside a valid offer.
                    let boolean = [
                        setting::ENABLE_WEBTRANSPORT,
                        setting::ENABLE_CONNECT_PROTOCOL,
                        setting::H3_DATAGRAM,
                    ];
                    if let Some(id) = boolean
                        .into_iter()
                        .find(|&id| settings.get(id).is_some_and(|value| value > 1))
                    {
                        return Some((
                            code::H3_SETTINGS_ERROR,
                            format!("boolean setting {id:#x} is neither 0 nor 1"),
                        ));
                    }
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
                    self.peer_closed(0);
                    return None;
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
        let mut consumed = 0;
        let head = loop {
            match chunks.next(1) {
                Ok(Some(chunk)) => {
                    consumed += chunk.bytes.len();
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
                    self.count_early(consumed);
                    return;
                }
                Err(ReadError::Blocked) => {
                    let _credit = chunks.finalize();
                    self.count_early(consumed);
                    return;
                }
            }
        };
        let _credit = chunks.finalize();
        self.count_early(consumed);
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
            Ok(section) => request_status(&section),
            Err(error) => {
                self.fail(error.code(), format!("CONNECT request: {error}"));
                return;
            }
        };
        self.connect = Some(Connect {
            id: raw,
            frames,
            capsules: CapsuleDecoder::new(),
            request_status,
            replied: false,
            finished: false,
            peer_ended: false,
            delivered: false,
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
        // The highest draft both sides speak: 13/14 (Safari), else 02
        // (Chrome, Firefox).
        let draft14 = settings
            .get(setting::WT_MAX_SESSIONS)
            .is_some_and(|sessions| sessions >= 1);
        let draft02 = settings.get(setting::ENABLE_WEBTRANSPORT) == Some(1);
        let status = if draft14 || draft02 {
            connect.request_status
        } else {
            "400"
        };
        // Draft-13/14 flow control is on once both sides sent a limit; ours
        // are 2^60, so only the client's ever bind.
        let limits = [
            setting::WT_INITIAL_MAX_DATA,
            setting::WT_INITIAL_MAX_STREAMS_BIDI,
            setting::WT_INITIAL_MAX_STREAMS_UNI,
        ];
        if draft14 && limits.iter().any(|&id| settings.get(id).unwrap_or(0) > 0) {
            self.credit = Some(Credit {
                max_streams: settings
                    .get(setting::WT_INITIAL_MAX_STREAMS_BIDI)
                    .unwrap_or(0),
                max_data: settings.get(setting::WT_INITIAL_MAX_DATA).unwrap_or(0),
                ..Credit::default()
            });
        }
        let id = connect.id;
        let mut block = Vec::new();
        encode_field_section([(&b":status"[..], status.as_bytes())], &mut block);
        let mut bytes = Vec::new();
        if encode_frame(frame_type::HEADERS, &block, &mut bytes).is_err() {
            self.fail(code::H3_INTERNAL_ERROR, "encoding a response failed".into());
            return;
        }
        if status != "200" {
            // The refusal ends the stream and the session; the connection
            // closes once the status is through.
            connect.finished = true;
            self.closing = true;
            self.send(conn, id, bytes, true);
            self.events.push(WtEvent::Refused {
                reason: format!("refused the WebTransport request with {status}"),
            });
            return;
        }
        self.send(conn, id, bytes, false);
        self.promote_held(conn);
    }

    /// The CONNECT stream after its request: capsules in its DATA frames,
    /// which raise the client's credit or close the session, as does the
    /// stream's end.
    fn read_connect(&mut self, conn: &mut Connection) {
        let Some(connect) = self.connect.as_mut().filter(|c| !c.peer_ended) else {
            return;
        };
        let (bytes, end) = read_available(conn, connect.id);
        let mut input = &bytes[..];
        let mut closed_with = None;
        let failure = 'frames: loop {
            match connect.frames.decode(&mut input) {
                Ok(Some(Frame::Data(mut chunk))) => loop {
                    match connect.capsules.decode(&mut chunk) {
                        Ok(Some(Capsule::CloseSession { code, .. })) => {
                            closed_with.get_or_insert(code);
                        }
                        Ok(Some(capsule)) => {
                            if let Some(credit) = self.credit.as_mut() {
                                credit.raise(&capsule);
                            }
                        }
                        Ok(None) => break,
                        Err(error) => break 'frames Some(error),
                    }
                },
                Ok(Some(_)) => {}
                Ok(None) => break None,
                Err(error) => break Some(error),
            }
        };
        if !matches!(end, ReadEnd::Open) {
            connect.peer_ended = true;
            closed_with.get_or_insert(0);
        }
        if let Some(error) = failure {
            self.fail(error.code(), format!("CONNECT stream: {error}"));
        } else if let Some(code) = closed_with {
            self.peer_closed(code);
        }
    }

    /// A stream with a WebTransport prefix: admitted once the session is
    /// authenticated, held until then.
    fn on_prefixed(&mut self, conn: &mut Connection, raw: u64, session_id: u64) {
        if self.established {
            if Some(session_id) == self.session_id() {
                self.events.push(WtEvent::Admit {
                    raw,
                    early: Vec::new(),
                    end: ReadEnd::Open,
                });
            } else {
                refuse(conn, raw, code::H3_ID_ERROR);
            }
            return;
        }
        self.held.push_back(Held {
            id: raw,
            session_id,
            data: Vec::new(),
            end: ReadEnd::Open,
        });
        // The Noise stream counts until Noise completes.
        if self.held.len() + usize::from(self.noise.is_some()) > MAX_EARLY_STREAMS {
            self.fail(
                code::H3_EXCESSIVE_LOAD,
                "too many WebTransport streams before the session was authenticated".into(),
            );
            return;
        }
        // What already sits behind the prefix.
        self.read_held(raw, conn);
        self.promote_held(conn);
    }

    /// Reads a held stream's new bytes into its buffer.
    fn read_held(&mut self, raw: u64, conn: &mut Connection) {
        let Some(held) = self
            .held
            .iter_mut()
            .find(|held| held.id == raw && matches!(held.end, ReadEnd::Open))
        else {
            return;
        };
        let (bytes, end) = read_available(conn, raw);
        held.data.extend_from_slice(&bytes);
        held.end = end;
        self.count_early(bytes.len());
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
        while let Some(front) = self.held.front() {
            if front.session_id != session {
                let id = front.id;
                self.held.pop_front();
                refuse(conn, id, code::H3_ID_ERROR);
            } else if self.noise.is_none() {
                if let Some(held) = self.held.pop_front() {
                    self.start_noise(conn, held);
                }
            } else if self.established {
                if let Some(held) = self.held.pop_front() {
                    self.events.push(WtEvent::Admit {
                        raw: held.id,
                        early: held.data,
                        end: held.end,
                    });
                }
            } else {
                return;
            }
        }
    }

    /// Runs Noise as responder on `held`, starting with what it carried.
    fn start_noise(&mut self, conn: &mut Connection, held: Held) {
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
            id: held.id,
            session: Some(session),
        });
        self.feed_noise(conn, held.data, held.end);
    }

    /// Reads the Noise stream into the responder.
    fn read_noise(&mut self, conn: &mut Connection) {
        let Some(noise) = self.noise.as_ref() else {
            return;
        };
        let (bytes, end) = read_available(conn, noise.id);
        self.count_early(bytes.len());
        self.feed_noise(conn, bytes, end);
    }

    /// Feeds the responder what the Noise stream carried and writes its
    /// replies; on completion the connection is authenticated and the stream
    /// finished.
    fn feed_noise(&mut self, conn: &mut Connection, bytes: Vec<u8>, end: ReadEnd) {
        let Some(noise) = self.noise.as_mut() else {
            return;
        };
        let raw = noise.id;
        let Some(session) = noise.session.as_mut() else {
            // Done: whatever follows is ignored.
            return;
        };
        if !bytes.is_empty()
            && let Err(error) = session.on_data(bytes)
        {
            self.fail(
                code::H3_GENERAL_PROTOCOL_ERROR,
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
                code::H3_GENERAL_PROTOCOL_ERROR,
                "the client ended the Noise stream mid-handshake".into(),
            );
        }
    }
}

/// The status a CONNECT request earns on its own: 200 for the libp2p
/// WebTransport request, 404 for another path, 400 for another query or a
/// malformed request.
///
/// Well formed means exactly one each of `:method CONNECT`, `:protocol
/// webtransport` (the token drafts 02 and 13/14 share; draft-15's
/// `webtransport-h3` is not served), `:scheme https`, `:authority` and
/// `:path`, no other pseudo-header, and none after a regular field.
fn request_status(section: &FieldSection<'_>) -> &'static str {
    const PSEUDO: [&[u8]; 5] = [
        b":method",
        b":protocol",
        b":scheme",
        b":authority",
        b":path",
    ];
    let mut values: [Option<&[u8]>; 5] = [None; 5];
    let mut regular = false;
    for field in section.iter() {
        if !field.name.starts_with(b":") {
            regular = true;
            continue;
        }
        let slot = PSEUDO
            .iter()
            .position(|name| *name == field.name)
            .and_then(|index| values.get_mut(index));
        match slot {
            Some(slot @ None) if !regular => *slot = Some(field.value),
            _ => return "400",
        }
    }
    let [
        Some(method),
        Some(protocol),
        Some(scheme),
        Some(_),
        Some(path),
    ] = values
    else {
        return "400";
    };
    if method != b"CONNECT" || protocol != b"webtransport" || scheme != b"https" {
        return "400";
    }
    let (want_path, _) = LIBP2P_WEBTRANSPORT_PATH
        .split_once('?')
        .unwrap_or((LIBP2P_WEBTRANSPORT_PATH, ""));
    if path == LIBP2P_WEBTRANSPORT_PATH.as_bytes() {
        "200"
    } else if path.split(|&byte| byte == b'?').next() == Some(want_path.as_bytes()) {
        "400"
    } else {
        "404"
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
