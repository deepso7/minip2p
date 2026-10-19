//! The WebTransport server phase of an `h3` connection (libp2p WebTransport
//! over HTTP/3, draft-02 or draft-13/14).
//!
//! [`WtSession`] runs beside the connection's stream logic from QUIC
//! `Connected` on. It opens our control stream with SETTINGS, reads the
//! client's control and QPACK streams, answers the CONNECT to
//! [`LIBP2P_WEBTRANSPORT_PATH`] with 200 once the client's SETTINGS offer a
//! draft we speak with HTTP/3 datagrams (draft-13/14 preferred, with its
//! session flow control),
//! and runs Noise XX as responder on the first stream with the
//! session's `0x41` prefix. Its output is a list of [`WtEvent`]s for the
//! connection to act on: authenticate, admit a stream, or fail.
//!
//! Stream prefixes never reach the caller: an inbound stream's prefix is
//! read here, a byte at a time so nothing behind it is consumed, and the
//! stream is admitted after it. Prefixed streams that arrive before the
//! session is authenticated (the Noise stream racing the 200, or streams
//! racing Noise) are held, their data read into a buffer the pre-auth byte
//! cap bounds, and handed over with them. A STOP_SENDING on a stream not
//! yet classified or admitted resets it at once and is kept until its role
//! is known, since quinn forgets the stop once the reset is acknowledged.
//!
//! Before authentication every allocation is capped: the codec's frame,
//! capsule and QPACK caps, at most [`MAX_EARLY_STREAMS`] unfinished heads
//! and held streams, and [`MAX_EARLY_BYTES`] across request heads and held
//! streams. Past a cap the connection closes with the code RFC 9114 and
//! RFC 9204 give it: `H3_EXCESSIVE_LOAD` for all but the codec's field
//! section and CLOSE reason caps.
//!
//! The session also ends orderly, in either direction: [`WtSession::close`]
//! sends `CLOSE_WEBTRANSPORT_SESSION` and finishes the CONNECT stream, and a
//! peer's capsule, CONNECT FIN, reset or STOP_SENDING, or GOAWAY reports
//! [`WtEvent::PeerClosed`]. The connection then waits for a deadline (or,
//! when the peer ended the session, [`WtSession::ended_and_delivered`])
//! before closing QUIC, so the capsule or a refusal's status, and our FIN,
//! reach the peer.

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
use minip2p_webtransport::qpack::{
    DecoderStreamReader, Field, FieldSection, QpackDecoder, encode_field_section,
};
use quinn_proto::{Connection, Dir, ReadError, StreamId, VarInt};

/// Peer bidi streams open before the session is authenticated, other than
/// the CONNECT stream: unfinished request heads, held prefixed streams, and
/// the Noise stream until Noise completes. One more fails the connection.
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
    /// peer finished or reset it meanwhile. `stopped` carries a
    /// STOP_SENDING code the peer sent meanwhile: our side is already reset,
    /// and quinn may have forgotten it once the reset was acknowledged.
    Admit {
        raw: u64,
        early: Vec<u8>,
        end: ReadEnd,
        stopped: Option<VarInt>,
    },
    /// The peer ended the session (close capsule, CONNECT FIN, reset or
    /// STOP_SENDING, or GOAWAY) with this WebTransport code: finish our
    /// side and close.
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
    /// The client's control stream.
    Control(Control),
    QpackEncoder,
    QpackDecoder(DecoderStreamReader),
}

/// What the client's control stream said so far.
#[derive(Default)]
struct Control {
    frames: FrameDecoder,
    saw_settings: bool,
    /// The client's latest MAX_PUSH_ID, which may not shrink (RFC 9114
    /// §7.2.7); we never push.
    max_push_id: Option<u64>,
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
    /// The peer sent its trailer section: nothing may follow.
    trailers: bool,
    /// The peer sent `CLOSE_WEBTRANSPORT_SESSION`: only its FIN may follow.
    close_received: bool,
    /// The peer acknowledged our FIN, or stopped our side: nothing we
    /// sent on it is still in flight.
    delivered: bool,
    /// We reset and stopped it with `H3_MESSAGE_ERROR` for data after the
    /// close capsule. Nothing acknowledges that, so only the Closing
    /// deadline may close QUIC.
    refused: bool,
}

/// The client's session flow-control credit for what we send (draft-13/14,
/// once the client offered more than one session or any nonzero
/// `WT_INITIAL_MAX_*`): server-opened bidi streams, and stream bytes after
/// their prefixes, Noise's replies included.
#[derive(Debug, Default)]
struct Credit {
    max_streams: u64,
    opened: u64,
    max_data: u64,
    sent: u64,
    /// The last WT_MAX_DATA, WT_MAX_STREAMS bidi and uni capsule values
    /// (uni only checked: we open no uni streams).
    last_data: u64,
    last_bidi: u64,
    last_uni: u64,
}

impl Credit {
    /// Applies a credit capsule, so limits only ever grow. Returns false
    /// for a value below the previous capsule's of its kind, which draft-14
    /// §§5.6.2, 5.6.4 make a `WT_FLOW_CONTROL_ERROR`.
    fn raise(&mut self, capsule: &Capsule) -> bool {
        let (last, max) = match *capsule {
            Capsule::MaxData(max) => (&mut self.last_data, max),
            Capsule::MaxStreamsBidi(max) => (&mut self.last_bidi, max),
            Capsule::MaxStreamsUni(max) => (&mut self.last_uni, max),
            Capsule::CloseSession { .. } => return true,
        };
        if max < *last {
            return false;
        }
        *last = max;
        self.max_data = self.max_data.max(self.last_data);
        self.max_streams = self.max_streams.max(self.last_bidi);
        true
    }
}

/// A peer bidi stream whose first frame or prefix is being read.
#[derive(Default)]
struct Head {
    frames: FrameDecoder,
    /// The peer's STOP_SENDING code, if it stopped our side meanwhile.
    stopped: Option<VarInt>,
}

/// A prefixed stream waiting for the session or for Noise.
struct Held {
    id: u64,
    /// The session its prefix names.
    session_id: u64,
    /// What it carried meanwhile.
    data: Vec<u8>,
    end: ReadEnd,
    /// The peer's STOP_SENDING code, if it stopped our side meanwhile.
    stopped: Option<VarInt>,
}

/// The Noise stream and its responder session.
struct NoiseStream {
    id: u64,
    /// `None` once the handshake completed.
    session: Option<NoiseSession>,
    /// Replies the client's data credit does not cover yet.
    pending: Vec<u8>,
    /// A FIN follows `pending`.
    fin: bool,
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
    heads: HashMap<u64, Head>,
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

    /// Ends the session's own streams but CONNECT as the session closes
    /// (draft-14 §6), whichever side closed it: the Noise stream and every
    /// unfinished head and held stream are reset and stopped with `code`,
    /// and Noise replies still waiting for credit are dropped.
    pub(crate) fn end_streams(&mut self, conn: &mut Connection, code: VarInt) {
        self.closing = true;
        let streams: Vec<u64> = self
            .heads
            .drain()
            .map(|(raw, _)| raw)
            .chain(self.held.drain(..).map(|held| held.id))
            .chain(self.noise.take().map(|noise| noise.id))
            .collect();
        for raw in streams {
            self.out.remove(&raw);
            refuse(conn, raw, code.into_inner());
        }
    }

    /// Whether QUIC may close without discarding the session's end: the peer
    /// finished or reset its side of the CONNECT stream (or never opened
    /// one) and acknowledged our FIN on the
    /// CONNECT stream, or stopped it. Packets the connection queued before
    /// that FIN (its resets) went out with or ahead of it. A CONNECT stream
    /// we refused for data after the close capsule never qualifies.
    pub(crate) fn ended_and_delivered(&self) -> bool {
        self.connect.as_ref().is_none_or(|connect| {
            connect.peer_ended && connect.delivered && !connect.refused
        })
    }

    /// The engine is done sending on `raw`: everything was acknowledged, or
    /// the peer stopped it.
    pub(crate) fn on_send_done(&mut self, raw: u64) {
        if let Some(connect) = self.connect.as_mut().filter(|connect| connect.id == raw) {
            connect.delivered = true;
        }
    }

    /// The peer stopped our side of `raw`. Our control stream is critical
    /// (RFC 9114 §6.2.1), so stopping it fails the connection. Any other
    /// stream of the session's own is reset with the peer's code (RFC 9000
    /// §3.5); a stopped CONNECT stream also ends the session (draft-14 §6),
    /// and a stopped Noise stream, before the handshake completed, fails
    /// it. A stream not yet classified or admitted keeps the code, applied
    /// once its role is known. Returns whether `raw` is one of the session's
    /// own streams, which the connection leaves alone.
    pub(crate) fn on_stopped(
        &mut self,
        conn: &mut Connection,
        raw: u64,
        error_code: VarInt,
    ) -> bool {
        if self
            .control
            .is_some_and(|control| u64::from(control) == raw)
        {
            self.fail(
                code::H3_CLOSED_CRITICAL_STREAM,
                "the client stopped our control stream".into(),
            );
            return true;
        }
        if !self.owns(raw) {
            return false;
        }
        match conn.send_stream(engine_stream(raw)).reset(error_code) {
            Ok(()) | Err(_) => {}
        }
        self.out.remove(&raw);
        if self.connect.as_ref().is_some_and(|c| c.id == raw) {
            self.on_send_done(raw);
            // A close capsule already received keeps its code.
            self.read_connect(conn);
            self.peer_closed(0);
        } else if let Some(noise) = self.noise.as_mut().filter(|n| n.id == raw) {
            noise.pending.clear();
            noise.fin = false;
            if noise.session.is_some() {
                self.fail(
                    code::H3_GENERAL_PROTOCOL_ERROR,
                    "the client stopped the Noise stream mid-handshake".into(),
                );
            }
        } else if let Some(head) = self.heads.get_mut(&raw) {
            head.stopped = Some(error_code);
        } else if let Some(held) = self.held.iter_mut().find(|held| held.id == raw) {
            held.stopped = Some(error_code);
        }
        true
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
                self.heads.insert(raw, Head::default());
                if self.too_many_early_streams() {
                    return;
                }
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

    /// Checks the early streams against [`MAX_EARLY_STREAMS`], failing the
    /// connection past it; returns whether it failed.
    fn too_many_early_streams(&mut self) -> bool {
        if self.established {
            return false;
        }
        let early = self.heads.len() + self.held.len() + usize::from(self.noise.is_some());
        if early <= MAX_EARLY_STREAMS {
            return false;
        }
        self.fail(
            code::H3_EXCESSIVE_LOAD,
            "too many streams before the session was authenticated".into(),
        );
        true
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
                    PeerUni::Control(Control::default())
                }
                UniStreamType::QpackEncoder if !self.has_encoder => {
                    self.has_encoder = true;
                    PeerUni::QpackEncoder
                }
                UniStreamType::QpackDecoder if !self.has_decoder => {
                    self.has_decoder = true;
                    PeerUni::QpackDecoder(DecoderStreamReader::new())
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
                // Only a server may open a push stream (RFC 9114 §6.2.2).
                UniStreamType::Push => {
                    self.fail(
                        code::H3_STREAM_CREATION_ERROR,
                        "the client opened a push stream".into(),
                    );
                    return;
                }
                // An id no request stream has, as on bidi streams.
                UniStreamType::WebTransport { session_id } if !session_id.is_multiple_of(4) => {
                    self.fail(
                        code::H3_ID_ERROR,
                        format!("a uni stream named session {session_id}, not a request stream id"),
                    );
                    return;
                }
                // Other WebTransport uni and unknown streams: refused, never
                // fatal.
                UniStreamType::WebTransport { .. } | UniStreamType::Unknown(_) => {
                    stop(conn, raw, code::H3_STREAM_CREATION_ERROR);
                    return;
                }
            };
        }
        let failure = match &mut state {
            PeerUni::Control(control) => self.read_control(conn, control, &mut input),
            // The table capacity is 0, so every encoder instruction is
            // illegal.
            PeerUni::QpackEncoder if !input.is_empty() => Some((
                code::QPACK_ENCODER_STREAM_ERROR,
                "QPACK encoder instruction with a zero table capacity".into(),
            )),
            // Only Stream Cancellation is legal: we never insert.
            PeerUni::QpackDecoder(reader) => reader
                .read(input)
                .err()
                .map(|error| (error.code(), format!("QPACK decoder stream: {error}"))),
            PeerUni::QpackEncoder | PeerUni::Header(_) => None,
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
    /// but GOAWAY (which ends the session), MAX_PUSH_ID (checked, though we
    /// never push) and frames HTTP/3 skips; any CANCEL_PUSH names a push we
    /// never promised. Returns the code and reason of
    /// a connection error.
    fn read_control(
        &mut self,
        conn: &mut Connection,
        control: &mut Control,
        input: &mut &[u8],
    ) -> Option<(u64, String)> {
        let Control {
            frames,
            saw_settings,
            max_push_id,
        } = control;
        loop {
            let frame = match frames.decode(input) {
                Ok(frame) => frame,
                Err(error) => return Some((error.code(), format!("control stream: {error}"))),
            };
            // Checked by type, so a skipped unknown frame before SETTINGS
            // fails too.
            if !*saw_settings
                && frames
                    .first_frame_type()
                    .is_some_and(|ty| ty != frame_type::SETTINGS)
            {
                return Some((
                    code::H3_MISSING_SETTINGS,
                    "the client's control stream did not start with SETTINGS".into(),
                ));
            }
            match frame {
                None => return None,
                Some(Frame::Settings(settings)) if !*saw_settings => {
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
                Some(Frame::GoAway(_)) => {
                    self.peer_closed(0);
                    return None;
                }
                Some(Frame::MaxPushId(id)) if max_push_id.is_none_or(|max| id >= max) => {
                    *max_push_id = Some(id);
                }
                Some(Frame::MaxPushId(_)) => {
                    return Some((code::H3_ID_ERROR, "a smaller MAX_PUSH_ID".into()));
                }
                // We never send PUSH_PROMISE, so no push id was ever
                // promised (RFC 9114 §7.2.3).
                Some(Frame::CancelPush(_)) => {
                    return Some((
                        code::H3_ID_ERROR,
                        "CANCEL_PUSH for a push never promised".into(),
                    ));
                }
                Some(frame) => {
                    return Some((
                        code::H3_FRAME_UNEXPECTED,
                        format!("unexpected frame on the control stream: {frame:?}"),
                    ));
                }
            }
        }
    }

    /// Reads a peer bidi stream's first frame a byte at a time, so nothing
    /// after a WebTransport prefix is consumed.
    fn read_head(&mut self, conn: &mut Connection, raw: u64) {
        let Some(Head { frames, .. }) = self.heads.get_mut(&raw) else {
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
                    // Ended before saying what it is: nothing to keep, and
                    // our unused side is reset so the stream is freed.
                    self.heads.remove(&raw);
                    reset(conn, raw, code::H3_REQUEST_INCOMPLETE);
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
        let Some(Head { frames, stopped }) = self.heads.remove(&raw) else {
            return;
        };
        match head {
            Some(Ok(block)) => self.on_request(conn, raw, frames, &block, stopped),
            Some(Err(session_id)) => self.on_prefixed(conn, raw, session_id, stopped),
            None => {
                self.fail(
                    code::H3_FRAME_UNEXPECTED,
                    "a request stream did not start with HEADERS".into(),
                );
            }
        }
    }

    /// A request on a new bidi stream: the first is the CONNECT, any other
    /// is refused. A CONNECT the peer stopped before its HEADERS were read
    /// ends the session unanswered, as a stop after them would.
    fn on_request(
        &mut self,
        conn: &mut Connection,
        raw: u64,
        frames: FrameDecoder,
        block: &[u8],
        stopped: Option<VarInt>,
    ) {
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
            trailers: false,
            close_received: false,
            delivered: false,
            refused: false,
        });
        if stopped.is_some() {
            // Our side is reset: nothing to answer or finish.
            if let Some(connect) = self.connect.as_mut() {
                connect.finished = true;
                connect.delivered = true;
            }
            self.peer_closed(0);
            return;
        }
        self.reply(conn);
    }

    /// Answers the CONNECT once both it and the client's SETTINGS are in.
    fn reply(&mut self, conn: &mut Connection) {
        let (Some(settings), Some(connect)) = (self.settings.as_ref(), self.connect.as_mut())
        else {
            return;
        };
        if connect.replied || self.closing {
            return;
        }
        connect.replied = true;
        // The highest draft both sides speak: 13/14 (Safari), else 02
        // (Chrome, Firefox). Both need HTTP/3 datagrams, in SETTINGS and as
        // the QUIC transport parameter (draft-14 §3.1, draft-02 §3.1);
        // every browser sends both.
        let datagrams = settings.get(setting::H3_DATAGRAM) == Some(1)
            && conn.datagrams().max_size().is_some_and(|size| size > 0);
        let draft14 = datagrams
            && settings
                .get(setting::WT_MAX_SESSIONS)
                .is_some_and(|sessions| sessions >= 1);
        let draft02 = datagrams && settings.get(setting::ENABLE_WEBTRANSPORT) == Some(1);
        let status = if draft14 || draft02 {
            connect.request_status
        } else {
            "400"
        };
        // Draft-13/14 flow control is on once both sides ask for it, with
        // more than one session or a nonzero initial limit (draft-14 §5.1);
        // ours are 2^60, so only the client's limits ever bind, and an
        // omitted one is 0.
        let limits = [
            setting::WT_INITIAL_MAX_DATA,
            setting::WT_INITIAL_MAX_STREAMS_BIDI,
            setting::WT_INITIAL_MAX_STREAMS_UNI,
        ];
        let flow_control = settings
            .get(setting::WT_MAX_SESSIONS)
            .is_some_and(|sessions| sessions > 1)
            || limits.iter().any(|&id| settings.get(id).unwrap_or(0) > 0);
        if draft14 && flow_control {
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
        } else {
            self.send(conn, id, bytes, false);
            self.promote_held(conn);
        }
        // What waited for the response, and the stream's end.
        self.read_connect(conn);
    }

    /// The CONNECT stream once it was answered: capsules in its DATA frames,
    /// which raise the client's credit or close the session, as does the
    /// stream's end. Until the answer nothing is read, so no capsule acts on
    /// a session not yet accepted (RFC 9297 §3.2); the stream's receive
    /// window bounds what waits.
    ///
    /// Anything but a FIN after the close capsule resets the stream with
    /// `H3_MESSAGE_ERROR` (draft-14 §6); the session still ends with the
    /// capsule's code.
    fn read_connect(&mut self, conn: &mut Connection) {
        let Some(connect) = self.connect.as_mut().filter(|c| c.replied && !c.peer_ended) else {
            return;
        };
        let (bytes, end) = read_available(conn, connect.id);
        let mut input = &bytes[..];
        let mut closed_with = None;
        let mut trailing = connect.close_received && !input.is_empty();
        let unexpected =
            |what: &str| Some((code::H3_FRAME_UNEXPECTED, format!("CONNECT stream: {what}")));
        let mut failure = 'frames: loop {
            if trailing {
                break None;
            }
            match connect.frames.decode(&mut input) {
                // Trailers end the message (RFC 9114 §4.1).
                Ok(Some(Frame::Data(_) | Frame::Headers(_))) if connect.trailers => {
                    break unexpected("a frame after the trailer section");
                }
                Ok(Some(Frame::Data(mut chunk))) => loop {
                    match connect.capsules.decode(&mut chunk) {
                        Ok(Some(Capsule::CloseSession { code, .. })) => {
                            connect.close_received = true;
                            closed_with.get_or_insert(code);
                            trailing = !chunk.is_empty() || !input.is_empty();
                            if trailing {
                                break 'frames None;
                            }
                        }
                        Ok(Some(capsule)) => {
                            // The connection's only session: its flow-control
                            // error closes the connection.
                            if self
                                .credit
                                .as_mut()
                                .is_some_and(|credit| !credit.raise(&capsule))
                            {
                                break 'frames Some((
                                    code::WT_FLOW_CONTROL_ERROR,
                                    format!("{capsule:?} lowers the previous limit"),
                                ));
                            }
                        }
                        Ok(None) => break,
                        Err(error) => {
                            break 'frames Some((error.code(), format!("CONNECT stream: {error}")));
                        }
                    }
                },
                Ok(Some(Frame::Headers(block))) => {
                    connect.trailers = true;
                    let mut decoder = QpackDecoder::new();
                    match decoder.decode(&block) {
                        Ok(section) if section.iter().all(|field| valid_regular_field(&field)) => {}
                        Ok(_) => {
                            break Some((
                                code::H3_MESSAGE_ERROR,
                                "CONNECT stream: a malformed trailer section".into(),
                            ));
                        }
                        Err(error) => {
                            break Some((error.code(), format!("CONNECT trailers: {error}")));
                        }
                    }
                }
                // Control-stream frames.
                Ok(Some(frame)) => break unexpected(&format!("{frame:?}")),
                Ok(None) => break None,
                Err(error) => break Some((error.code(), format!("CONNECT stream: {error}"))),
            }
        };
        if trailing {
            // The reset is in flight, with no acknowledgement to wait
            // for: the Closing phase's deadline lets it out, whatever an
            // acknowledgement of our FIN read in the same poll says.
            connect.peer_ended = true;
            connect.finished = true;
            connect.refused = true;
            let id = connect.id;
            self.out.remove(&id);
            refuse(conn, id, code::H3_MESSAGE_ERROR);
            self.peer_closed(closed_with.unwrap_or(0));
            return;
        }
        if !matches!(end, ReadEnd::Open) {
            connect.peer_ended = true;
            closed_with.get_or_insert(0);
        }
        // A FIN must fall between frames and between capsules; a reset may
        // cut anywhere.
        if matches!(end, ReadEnd::Finished) && failure.is_none() {
            if !connect.frames.is_at_frame_boundary() {
                failure = Some((
                    code::H3_FRAME_ERROR,
                    "the CONNECT stream ended mid-frame".into(),
                ));
            } else if !connect.capsules.is_at_capsule_boundary() {
                failure = Some((
                    code::H3_MESSAGE_ERROR,
                    "the CONNECT stream ended mid-capsule".into(),
                ));
            }
        }
        if let Some((code, reason)) = failure {
            self.fail(code, reason);
        } else if let Some(code) = closed_with {
            self.peer_closed(code);
        } else {
            // New credit may release Noise replies.
            self.release_noise(conn);
        }
    }

    /// A stream with a WebTransport prefix: admitted once the session is
    /// authenticated, held until then.
    fn on_prefixed(
        &mut self,
        conn: &mut Connection,
        raw: u64,
        session_id: u64,
        stopped: Option<VarInt>,
    ) {
        // A session id is a CONNECT stream's: client-initiated bidi, so a
        // multiple of 4. Any other cannot name a session at all (draft-14
        // §4), unlike a valid id that is not ours.
        if !session_id.is_multiple_of(4) {
            self.fail(
                code::H3_ID_ERROR,
                format!("a stream named session {session_id}, not a request stream id"),
            );
            return;
        }
        if self.established {
            if Some(session_id) == self.session_id() {
                self.events.push(WtEvent::Admit {
                    raw,
                    early: Vec::new(),
                    end: ReadEnd::Open,
                    stopped,
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
            stopped,
        });
        if self.too_many_early_streams() {
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
                        stopped: held.stopped,
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
            pending: Vec::new(),
            fin: false,
        });
        if held.stopped.is_some() {
            self.fail(
                code::H3_GENERAL_PROTOCOL_ERROR,
                "the client stopped the Noise stream mid-handshake".into(),
            );
            return;
        }
        self.feed_noise(conn, held.data, held.end);
    }

    /// Writes as much of the Noise replies as the client's data credit
    /// allows (draft-14 §5.4: they are stream data like any other), and
    /// the FIN after the last.
    fn release_noise(&mut self, conn: &mut Connection) {
        let room = self.data_room();
        let Some(noise) = self.noise.as_mut() else {
            return;
        };
        let take = room.min(noise.pending.len());
        let bytes: Vec<u8> = noise.pending.drain(..take).collect();
        let fin = std::mem::take(&mut noise.fin);
        // The FIN waits for the last byte.
        noise.fin = fin && !noise.pending.is_empty();
        let fin = fin && noise.pending.is_empty();
        let raw = noise.id;
        if bytes.is_empty() && !fin {
            return;
        }
        self.note_sent(take);
        self.send(conn, raw, bytes, fin);
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
        noise.pending.extend_from_slice(&outbound);
        noise.fin |= peer.is_some();
        self.release_noise(conn);
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
/// `:path`, no other pseudo-header, and none after a regular field; a
/// nonempty `:authority` without userinfo, which a `host` field, if any,
/// repeats exactly (RFC 9114 §4.3.1); no NUL, CR or LF in any value; and
/// only valid regular fields ([`valid_regular_field`]).
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
            // Pseudo-headers come first, so `:authority` is known here.
            let [.., authority, _] = values;
            if !valid_regular_field(&field)
                || (field.name == b"host" && authority != Some(field.value))
            {
                return "400";
            }
            regular = true;
            continue;
        }
        if !valid_value(field.value) {
            return "400";
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
        Some(authority),
        Some(path),
    ] = values
    else {
        return "400";
    };
    if method != b"CONNECT"
        || protocol != b"webtransport"
        || scheme != b"https"
        || authority.is_empty()
        || authority.contains(&b'@')
    {
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

/// Whether a regular (non-pseudo) field may appear in a request or its
/// trailers (RFC 9114 §4.2, RFC 9110 §5): a lowercase token name, a value
/// without NUL, CR or LF, and none of HTTP/1.1's connection-specific fields
/// (`te` only as `trailers`).
fn valid_regular_field(field: &Field<'_>) -> bool {
    const CONNECTION_SPECIFIC: [&[u8]; 5] = [
        b"connection",
        b"keep-alive",
        b"proxy-connection",
        b"transfer-encoding",
        b"upgrade",
    ];
    let token = |byte: u8| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&byte)
    };
    !field.name.is_empty()
        && field.name.iter().all(|&byte| token(byte))
        && valid_value(field.value)
        && !CONNECTION_SPECIFIC.contains(&field.name)
        && (field.name != b"te" || field.value == b"trailers")
}

/// Whether a field value is free of NUL, CR and LF (RFC 9114 §4.1.2).
fn valid_value(value: &[u8]) -> bool {
    !value
        .iter()
        .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
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

/// Resets our sending half of a peer bidi stream.
fn reset(conn: &mut Connection, raw: u64, code: u64) {
    let code = VarInt::from_u64(code).unwrap_or(VarInt::from_u32(0));
    match conn.send_stream(engine_stream(raw)).reset(code) {
        Ok(()) | Err(_) => {}
    }
}

/// Refuses a peer bidi stream: stop and reset.
fn refuse(conn: &mut Connection, raw: u64, code: u64) {
    stop(conn, raw, code);
    reset(conn, raw, code);
}
