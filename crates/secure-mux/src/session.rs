use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use minip2p_core::SansIoProtocol;
use minip2p_identity::{Ed25519Keypair, PeerId};
use minip2p_multistream_select::{MultistreamInput, MultistreamOutput, MultistreamSelect};
use minip2p_noise::{
    NOISE_PROTOCOL_ID, NoiseConfig, NoiseInput, NoiseOutput, NoiseRole, NoiseSession,
};
use minip2p_platform::{Deadline, Now};
use minip2p_transport::StreamId;
use minip2p_yamux::{YAMUX_PROTOCOL_ID, YamuxInput, YamuxOutput, YamuxRole, YamuxSession};
use thiserror::Error;

pub use minip2p_yamux::{KEEPALIVE_INTERVAL_MS, YamuxConfig, YamuxError};

/// Which end of the session opened the underlying byte stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionRole {
    /// Dials: sends the multistream proposals and drives Noise as initiator.
    Initiator,
    /// Accepts: listens for proposals and drives Noise as responder.
    Responder,
}

/// Everything needed to start one session.
pub struct SessionConfig {
    /// Which end of the byte stream this is.
    pub role: SessionRole,
    /// Local identity, proven to the remote during Noise XX.
    pub identity: Ed25519Keypair,
    /// Noise static key material.
    pub static_secret: [u8; 32],
    /// Noise ephemeral key material.
    pub ephemeral_secret: [u8; 32],
    /// Peer the remote must prove itself to be.
    ///
    /// `None` accepts whichever identity authenticates, which is right for an
    /// inbound connection whose peer is not known in advance.
    pub expected_peer: Option<PeerId>,
    /// Limits applied to the multiplexed session.
    pub yamux: YamuxConfig,
}

/// Something the caller must act on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionOutput {
    /// Bytes to write to the underlying ordered byte stream, in order.
    Write(Vec<u8>),
    /// The upgrade completed and `peer` is cryptographically verified.
    ///
    /// Emitted once, before any stream output.
    Established {
        /// The authenticated remote identity.
        peer: PeerId,
    },
    /// The remote opened a substream.
    IncomingStream {
        /// The new substream.
        stream: StreamId,
    },
    /// Data arrived on a substream.
    StreamData {
        /// Substream the data belongs to.
        stream: StreamId,
        /// Payload.
        data: Vec<u8>,
    },
    /// The remote half-closed its write side of a substream.
    StreamRemoteWriteClosed {
        /// Substream the remote finished writing to.
        stream: StreamId,
    },
    /// A substream closed in both directions.
    StreamClosed {
        /// Substream that closed.
        stream: StreamId,
    },
}

/// Why a session operation failed.
#[derive(Debug, Error)]
pub enum SessionError {
    /// The session failed and cannot continue; tear the connection down.
    #[error("{0}")]
    Protocol(String),
    /// A stream operation was attempted before the upgrade completed.
    #[error("session is still negotiating")]
    NotEstablished,
    /// The stream id does not name a substream of this session.
    #[error("unknown substream {stream}")]
    UnknownStream {
        /// The id that was passed in.
        stream: StreamId,
    },
    /// The remote ended the session with a Yamux `GoAway`.
    ///
    /// Fatal like [`SessionError::Protocol`], but kept separate because a
    /// `code` of 0 is an orderly shutdown rather than a fault: a caller that
    /// surfaces failures to its host can close quietly instead of reporting an
    /// error the remote never made.
    ///
    /// The shutdown takes every open substream with it, so draining outputs
    /// after this error yields a [`SessionOutput::StreamClosed`] for each --
    /// the same lifecycle notification a local
    /// [`go_away`](SecureMuxSession::go_away) produces.
    #[error("remote closed the Yamux session with code {code}")]
    GoAway {
        /// Yamux `GoAway` code; 0 is a normal shutdown.
        code: u32,
    },
    /// Yamux rejected the operation.
    ///
    /// Kept distinct so callers can tell a full send buffer from a fatal
    /// protocol failure.
    #[error(transparent)]
    Yamux(#[from] YamuxError),
}

impl SessionError {
    fn protocol(reason: impl Into<String>) -> Self {
        Self::Protocol(reason.into())
    }
}

enum Phase {
    SelectNoise {
        select: MultistreamSelect,
        noise: Option<NoiseSession>,
    },
    Noise {
        noise: NoiseSession,
    },
    SelectYamux {
        noise: NoiseSession,
        select: MultistreamSelect,
        peer: PeerId,
    },
    Ready {
        noise: NoiseSession,
        yamux: YamuxSession,
        peer: PeerId,
    },
}

/// multistream-select + Noise XX + Yamux over one ordered byte stream.
///
/// See the [crate docs](crate) for the shape of the upgrade and for what the
/// caller is responsible for.
pub struct SecureMuxSession {
    role: SessionRole,
    yamux_config: YamuxConfig,
    phase: Option<Phase>,
    outputs: VecDeque<SessionOutput>,
}

impl SecureMuxSession {
    /// Creates a session in its initial state.
    ///
    /// Nothing is written until [`start`](Self::start) runs.
    pub fn new(config: SessionConfig) -> Self {
        let noise = NoiseSession::new(NoiseConfig {
            role: match config.role {
                SessionRole::Initiator => NoiseRole::Initiator,
                SessionRole::Responder => NoiseRole::Responder,
            },
            identity: config.identity,
            static_secret: config.static_secret,
            ephemeral_secret: config.ephemeral_secret,
            expected_peer: config.expected_peer,
        });
        let select = match config.role {
            SessionRole::Initiator => MultistreamSelect::dialer(NOISE_PROTOCOL_ID),
            SessionRole::Responder => MultistreamSelect::listener([NOISE_PROTOCOL_ID.to_string()]),
        };

        Self {
            role: config.role,
            yamux_config: config.yamux,
            phase: Some(Phase::SelectNoise {
                select,
                noise: Some(noise),
            }),
            outputs: VecDeque::new(),
        }
    }

    /// Begins the upgrade, queueing the first multistream proposal.
    pub fn start(&mut self) -> Result<(), SessionError> {
        let phase = self.take_phase()?;
        let phase = match phase {
            Phase::SelectNoise { mut select, noise } => {
                select
                    .handle_input(MultistreamInput::Start)
                    .map_err(|error| {
                        SessionError::protocol(format!("Noise multistream start failed: {error}"))
                    })?;
                self.drain_raw_select(&mut select)?;
                Phase::SelectNoise { select, noise }
            }
            other => other,
        };
        self.phase = Some(phase);
        Ok(())
    }

    /// Feeds bytes read from the underlying stream.
    pub fn handle_input(&mut self, data: Vec<u8>) -> Result<(), SessionError> {
        if data.is_empty() {
            return Ok(());
        }
        let phase = self.take_phase()?;
        let phase = self.feed_phase(phase, data)?;
        self.phase = Some(phase);
        Ok(())
    }

    /// Takes the next output, if any.
    pub fn poll_output(&mut self) -> Option<SessionOutput> {
        self.outputs.pop_front()
    }

    /// Returns whether the upgrade has completed.
    pub fn is_established(&self) -> bool {
        matches!(self.phase, Some(Phase::Ready { .. }))
    }

    /// Advances Yamux keepalive using the host's time sample.
    ///
    /// A no-op until the upgrade has finished: there is no Yamux session to
    /// ping during negotiation. After that, quiet sessions emit a ping as
    /// [`SessionOutput::Write`].
    pub fn poll(&mut self, now: Now) -> Result<(), SessionError> {
        match self.with_yamux(|yamux| yamux.poll(now)) {
            Ok(()) | Err(SessionError::NotEstablished) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// When this session next wants a [`poll`](Self::poll) for keepalive.
    ///
    /// `None` until Yamux is up, and once the session has failed or gone away.
    pub fn next_deadline(&self) -> Option<Deadline> {
        match self.phase.as_ref()? {
            Phase::Ready { yamux, .. } => yamux.next_deadline(),
            _ => None,
        }
    }

    /// Returns the authenticated peer, once Noise has verified it.
    pub fn peer(&self) -> Option<&PeerId> {
        match self.phase.as_ref()? {
            Phase::SelectYamux { peer, .. } | Phase::Ready { peer, .. } => Some(peer),
            _ => None,
        }
    }

    /// Opens an outbound substream.
    pub fn open_stream(&mut self) -> Result<StreamId, SessionError> {
        let stream = self.with_yamux(|yamux| yamux.open_stream())?;
        Ok(StreamId::new(u64::from(stream)))
    }

    /// Writes to a substream.
    pub fn send(&mut self, stream: StreamId, data: Vec<u8>) -> Result<(), SessionError> {
        let yamux_stream = yamux_stream(stream)?;
        self.with_yamux_stream(stream, move |yamux| yamux.send(yamux_stream, data))
    }

    /// THROWAWAY TCP experiment: borrowed partial write through real Yamux.
    pub fn prototype_try_write(
        &mut self,
        stream: StreamId,
        data: &[u8],
    ) -> Result<usize, SessionError> {
        let id = yamux_stream(stream)?;
        self.with_yamux_stream(stream, |yamux| yamux.prototype_try_write(id, data))
    }

    /// THROWAWAY TCP experiment: consumption-based receive credit.
    pub fn prototype_try_read(
        &mut self,
        stream: StreamId,
        out: &mut [u8],
    ) -> Result<Option<usize>, SessionError> {
        let id = yamux_stream(stream)?;
        self.with_yamux_stream(stream, |yamux| yamux.prototype_try_read(id, out))
    }

    /// THROWAWAY: inspect in-memory readiness, with no socket or clock access.
    pub fn prototype_read_ready(&self, stream: StreamId) -> bool {
        match &self.phase {
            Some(Phase::Ready { yamux, .. }) => {
                u32::try_from(stream.as_u64()).is_ok_and(|id| yamux.prototype_read_ready(id))
            }
            _ => false,
        }
    }

    /// THROWAWAY: payload retained by the pull experiment.
    pub fn prototype_received_bytes(&self) -> usize {
        match &self.phase {
            Some(Phase::Ready { yamux, .. }) => yamux.prototype_received_bytes(),
            _ => 0,
        }
    }

    /// Half-closes the local write side of a substream.
    pub fn close_stream_write(&mut self, stream: StreamId) -> Result<(), SessionError> {
        let yamux_stream = yamux_stream(stream)?;
        self.with_yamux_stream(stream, move |yamux| yamux.close_write(yamux_stream))
    }

    /// Abruptly closes a substream in both directions.
    pub fn reset_stream(&mut self, stream: StreamId) -> Result<(), SessionError> {
        let yamux_stream = yamux_stream(stream)?;
        self.with_yamux_stream(stream, move |yamux| yamux.reset(yamux_stream))
    }

    /// Ends the session cleanly, queueing a Yamux `GoAway` with `code`.
    ///
    /// Every open substream closes, so expect a
    /// [`SessionOutput::StreamClosed`] for each alongside the
    /// [`SessionOutput::Write`] carrying the frame. Draining and writing that
    /// output is the caller's job, as is closing the underlying stream
    /// afterwards; the session neither owns it nor knows when the bytes land.
    ///
    /// [`SessionError::NotEstablished`] means there is no Yamux session to
    /// shut down, so the caller should simply drop the underlying stream.
    pub fn go_away(&mut self, code: u32) -> Result<(), SessionError> {
        self.with_yamux(|yamux| {
            yamux.go_away(code);
            Ok(())
        })
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    /// Runs `operation` against the established Yamux session and drains
    /// whatever it produced.
    ///
    /// The drain runs even when the operation failed, so bytes Yamux already
    /// queued (a reset frame, say) still reach the wire.
    fn with_yamux<R>(
        &mut self,
        operation: impl FnOnce(&mut YamuxSession) -> Result<R, YamuxError>,
    ) -> Result<R, SessionError> {
        // Only `Ready` runs stream operations, but every other phase is still
        // a live session mid-upgrade: put it back, or a stray early call would
        // strand the connection.
        let (mut noise, mut yamux, peer) = match self.phase.take() {
            Some(Phase::Ready { noise, yamux, peer }) => (noise, yamux, peer),
            other => {
                self.phase = other;
                return Err(SessionError::NotEstablished);
            }
        };

        let result = operation(&mut yamux);
        // A failed drain is fatal, exactly as in `handle_input`: leave the
        // phase taken so the session cannot be used again.
        self.drain_yamux(&mut noise, &mut yamux)?;
        self.phase = Some(Phase::Ready { noise, yamux, peer });
        result.map_err(SessionError::Yamux)
    }

    fn with_yamux_stream<R>(
        &mut self,
        stream: StreamId,
        operation: impl FnOnce(&mut YamuxSession) -> Result<R, YamuxError>,
    ) -> Result<R, SessionError> {
        self.with_yamux(operation).map_err(|error| match error {
            SessionError::Yamux(YamuxError::UnknownStream(_)) => {
                SessionError::UnknownStream { stream }
            }
            other => other,
        })
    }

    fn take_phase(&mut self) -> Result<Phase, SessionError> {
        self.phase
            .take()
            .ok_or_else(|| SessionError::protocol("session already failed"))
    }

    fn feed_phase(&mut self, phase: Phase, data: Vec<u8>) -> Result<Phase, SessionError> {
        match phase {
            Phase::SelectNoise {
                mut select,
                mut noise,
            } => {
                select
                    .handle_input(MultistreamInput::Data(data))
                    .map_err(|error| {
                        SessionError::protocol(format!("Noise multistream failed: {error}"))
                    })?;
                let mut negotiated = false;
                while let Some(output) = select.poll_output() {
                    match output {
                        MultistreamOutput::OutboundData(bytes) => self.write(bytes),
                        MultistreamOutput::Negotiated { protocol }
                            if protocol == NOISE_PROTOCOL_ID =>
                        {
                            negotiated = true;
                        }
                        MultistreamOutput::NotAvailable if self.role == SessionRole::Responder => {}
                        MultistreamOutput::Negotiated { .. } | MultistreamOutput::NotAvailable => {
                            return Err(SessionError::protocol("remote did not negotiate Noise"));
                        }
                        MultistreamOutput::ProtocolError { reason } => {
                            return Err(SessionError::protocol(format!(
                                "Noise multistream protocol error: {reason}"
                            )));
                        }
                    }
                }
                if !negotiated {
                    return Ok(Phase::SelectNoise { select, noise });
                }
                let remaining = select.take_remaining_buffer();
                let mut noise = noise
                    .take()
                    .ok_or_else(|| SessionError::protocol("Noise session unavailable"))?;
                noise.handle_input(NoiseInput::Start).map_err(|error| {
                    SessionError::protocol(format!("Noise start failed: {error}"))
                })?;
                let (peer, decrypted) = self.drain_noise(&mut noise)?;
                if peer.is_some() || !decrypted.is_empty() {
                    return Err(SessionError::protocol(
                        "Noise produced transport data before input",
                    ));
                }
                if remaining.is_empty() {
                    Ok(Phase::Noise { noise })
                } else {
                    self.feed_phase(Phase::Noise { noise }, remaining)
                }
            }
            Phase::Noise { mut noise } => {
                noise
                    .handle_input(NoiseInput::Data(data))
                    .map_err(|error| {
                        SessionError::protocol(format!("Noise handshake failed: {error}"))
                    })?;
                let (peer, decrypted) = self.drain_noise(&mut noise)?;
                let Some(peer) = peer else {
                    if !decrypted.is_empty() {
                        return Err(SessionError::protocol(
                            "Noise decrypted data before authentication",
                        ));
                    }
                    return Ok(Phase::Noise { noise });
                };
                let mut select = match self.role {
                    SessionRole::Initiator => MultistreamSelect::dialer(YAMUX_PROTOCOL_ID),
                    SessionRole::Responder => {
                        MultistreamSelect::listener([YAMUX_PROTOCOL_ID.to_string()])
                    }
                };
                select
                    .handle_input(MultistreamInput::Start)
                    .map_err(|error| {
                        SessionError::protocol(format!("Yamux multistream start failed: {error}"))
                    })?;
                self.drain_encrypted_select(&mut noise, &mut select)?;
                let mut phase = Phase::SelectYamux {
                    noise,
                    select,
                    peer,
                };
                for plaintext in decrypted {
                    phase = self.feed_decrypted_transport(phase, plaintext)?;
                }
                Ok(phase)
            }
            Phase::SelectYamux {
                mut noise,
                select,
                peer,
            } => {
                noise
                    .handle_input(NoiseInput::Data(data))
                    .map_err(|error| {
                        SessionError::protocol(format!("Noise transport failed: {error}"))
                    })?;
                let (unexpected_peer, decrypted) = self.drain_noise(&mut noise)?;
                if unexpected_peer.is_some() {
                    return Err(SessionError::protocol("Noise authenticated twice"));
                }
                let mut phase = Phase::SelectYamux {
                    noise,
                    select,
                    peer,
                };
                for plaintext in decrypted {
                    phase = self.feed_decrypted_transport(phase, plaintext)?;
                }
                Ok(phase)
            }
            Phase::Ready {
                mut noise,
                mut yamux,
                peer,
            } => {
                noise
                    .handle_input(NoiseInput::Data(data))
                    .map_err(|error| {
                        SessionError::protocol(format!("Noise transport failed: {error}"))
                    })?;
                let (unexpected_peer, decrypted) = self.drain_noise(&mut noise)?;
                if unexpected_peer.is_some() {
                    return Err(SessionError::protocol("Noise authenticated twice"));
                }
                for plaintext in decrypted {
                    let result = yamux.handle_input(YamuxInput::Data(plaintext));
                    self.drain_yamux(&mut noise, &mut yamux)?;
                    result.map_err(|error| {
                        SessionError::protocol(format!("Yamux protocol failed: {error}"))
                    })?;
                }
                Ok(Phase::Ready { noise, yamux, peer })
            }
        }
    }

    /// Routes plaintext Noise transport messages across the exact Yamux phase
    /// boundary. One read may decrypt both the selection reply and
    /// immediately-pipelined Yamux frames, so later plaintexts must use the
    /// `Ready` state produced by an earlier one in the same batch.
    fn feed_decrypted_transport(
        &mut self,
        phase: Phase,
        plaintext: Vec<u8>,
    ) -> Result<Phase, SessionError> {
        match phase {
            phase @ Phase::SelectYamux { .. } => self.feed_decrypted_yamux_select(phase, plaintext),
            Phase::Ready {
                mut noise,
                mut yamux,
                peer,
            } => {
                let result = yamux.handle_input(YamuxInput::Data(plaintext));
                self.drain_yamux(&mut noise, &mut yamux)?;
                result.map_err(|error| {
                    SessionError::protocol(format!("Yamux protocol failed: {error}"))
                })?;
                Ok(Phase::Ready { noise, yamux, peer })
            }
            _ => Err(SessionError::protocol(
                "decrypted transport data arrived before Yamux selection",
            )),
        }
    }

    fn feed_decrypted_yamux_select(
        &mut self,
        phase: Phase,
        plaintext: Vec<u8>,
    ) -> Result<Phase, SessionError> {
        let Phase::SelectYamux {
            mut noise,
            mut select,
            peer,
        } = phase
        else {
            return Err(SessionError::protocol(
                "Yamux selection completed before pipelined data",
            ));
        };
        select
            .handle_input(MultistreamInput::Data(plaintext))
            .map_err(|error| {
                SessionError::protocol(format!("Yamux multistream failed: {error}"))
            })?;
        let mut negotiated = false;
        while let Some(output) = select.poll_output() {
            match output {
                MultistreamOutput::OutboundData(bytes) => {
                    self.encrypt(&mut noise, bytes)?;
                }
                MultistreamOutput::Negotiated { protocol } if protocol == YAMUX_PROTOCOL_ID => {
                    negotiated = true;
                }
                MultistreamOutput::NotAvailable if self.role == SessionRole::Responder => {}
                MultistreamOutput::Negotiated { .. } | MultistreamOutput::NotAvailable => {
                    return Err(SessionError::protocol("remote did not negotiate Yamux"));
                }
                MultistreamOutput::ProtocolError { reason } => {
                    return Err(SessionError::protocol(format!(
                        "Yamux multistream protocol error: {reason}"
                    )));
                }
            }
        }
        if !negotiated {
            return Ok(Phase::SelectYamux {
                noise,
                select,
                peer,
            });
        }
        let remaining = select.take_remaining_buffer();
        let mut yamux = YamuxSession::with_config(
            match self.role {
                SessionRole::Initiator => YamuxRole::Client,
                SessionRole::Responder => YamuxRole::Server,
            },
            self.yamux_config.clone(),
        )
        .map_err(|error| SessionError::protocol(format!("invalid Yamux configuration: {error}")))?;

        // Handle the pipelined remainder first, then insert `Established`
        // ahead of whatever it produced. Announcing up front would leave a
        // pollable `Established` behind when the remainder fails, and a host
        // that drains outputs after an error would treat a dead session as up.
        let established_at = self.outputs.len();
        if !remaining.is_empty() {
            let handled = yamux.handle_input(YamuxInput::Data(remaining));
            let drained = self.drain_yamux(&mut noise, &mut yamux);
            let outcome = drained.and_then(|()| {
                handled.map_err(|error| {
                    SessionError::protocol(format!("Yamux protocol failed: {error}"))
                })
            });
            if let Err(error) = outcome {
                // The upgrade never completed, so nothing the remainder
                // produced may be published either. Callers drain outputs even
                // when the input failed, to flush bytes the session had already
                // queued; without this they would also see substream traffic on
                // a connection they were never told came up.
                self.outputs.truncate(established_at);
                return Err(error);
            }
        }
        self.outputs.insert(
            established_at,
            SessionOutput::Established { peer: peer.clone() },
        );
        Ok(Phase::Ready { noise, yamux, peer })
    }

    fn drain_raw_select(&mut self, select: &mut MultistreamSelect) -> Result<(), SessionError> {
        while let Some(output) = select.poll_output() {
            if let MultistreamOutput::OutboundData(bytes) = output {
                self.write(bytes);
            }
        }
        Ok(())
    }

    fn drain_encrypted_select(
        &mut self,
        noise: &mut NoiseSession,
        select: &mut MultistreamSelect,
    ) -> Result<(), SessionError> {
        while let Some(output) = select.poll_output() {
            if let MultistreamOutput::OutboundData(bytes) = output {
                self.encrypt(noise, bytes)?;
            }
        }
        Ok(())
    }

    fn drain_noise(
        &mut self,
        noise: &mut NoiseSession,
    ) -> Result<(Option<PeerId>, Vec<Vec<u8>>), SessionError> {
        let mut peer = None;
        let mut decrypted = Vec::new();
        while let Some(output) = noise.poll_output() {
            match output {
                NoiseOutput::Outbound(bytes) => self.write(bytes),
                NoiseOutput::HandshakeComplete {
                    peer: authenticated,
                    ..
                } => peer = Some(authenticated),
                NoiseOutput::Decrypted(bytes) => decrypted.push(bytes),
            }
        }
        Ok((peer, decrypted))
    }

    /// Publishes everything Yamux has queued, then reports a remote `GoAway`.
    ///
    /// A `GoAway` is followed by the terminal events for the substreams it
    /// closed, so failing on sight would swallow them: the phase stays taken
    /// after the error, and nothing would ever drain the rest. The error is
    /// held back until the queue is empty instead, which both keeps the
    /// lifecycle notifications and still kills the session.
    fn drain_yamux(
        &mut self,
        noise: &mut NoiseSession,
        yamux: &mut YamuxSession,
    ) -> Result<(), SessionError> {
        let mut go_away = None;
        while let Some(output) = yamux.poll_output() {
            match output {
                YamuxOutput::Outbound(bytes) => self.encrypt(noise, bytes)?,
                YamuxOutput::IncomingStream { stream } => {
                    self.outputs.push_back(SessionOutput::IncomingStream {
                        stream: StreamId::new(u64::from(stream)),
                    });
                }
                YamuxOutput::Data { stream, data } => {
                    self.outputs.push_back(SessionOutput::StreamData {
                        stream: StreamId::new(u64::from(stream)),
                        data,
                    });
                }
                YamuxOutput::RemoteWriteClosed { stream } => {
                    self.outputs
                        .push_back(SessionOutput::StreamRemoteWriteClosed {
                            stream: StreamId::new(u64::from(stream)),
                        });
                }
                YamuxOutput::StreamClosed { stream } => {
                    self.outputs.push_back(SessionOutput::StreamClosed {
                        stream: StreamId::new(u64::from(stream)),
                    });
                }
                YamuxOutput::GoAwayReceived { code } => {
                    // Keep the first code: it is the one that ended the session.
                    go_away.get_or_insert(code);
                }
            }
        }
        match go_away {
            Some(code) => Err(SessionError::GoAway { code }),
            None => Ok(()),
        }
    }

    fn encrypt(
        &mut self,
        noise: &mut NoiseSession,
        plaintext: Vec<u8>,
    ) -> Result<(), SessionError> {
        noise
            .handle_input(NoiseInput::Encrypt(plaintext))
            .map_err(|error| SessionError::protocol(format!("Noise encryption failed: {error}")))?;
        let (peer, decrypted) = self.drain_noise(noise)?;
        if peer.is_some() || !decrypted.is_empty() {
            return Err(SessionError::protocol(
                "unexpected Noise output while encrypting",
            ));
        }
        Ok(())
    }

    fn write(&mut self, bytes: Vec<u8>) {
        self.outputs.push_back(SessionOutput::Write(bytes));
    }
}

/// Narrows a transport stream id to Yamux's 32-bit stream id.
///
/// Rejects anything that does not fit rather than truncating: a fabricated id
/// congruent to a live stream modulo 2^32 would otherwise alias onto it and
/// operate on somebody else's substream.
fn yamux_stream(stream: StreamId) -> Result<u32, SessionError> {
    #[expect(
        clippy::map_err_ignore,
        reason = "SessionError preserves the caller's stream id while intentionally hiding conversion details."
    )]
    u32::try_from(stream.as_u64()).map_err(|_| SessionError::UnknownStream { stream })
}

#[cfg(test)]
mod tests {
    use super::*;
    use minip2p_yamux::{FLAG_SYN, Frame};

    #[test]
    fn responder_allows_fallback_before_noise() {
        let mut responder = SecureMuxSession::new(SessionConfig {
            role: SessionRole::Responder,
            identity: Ed25519Keypair::generate(),
            static_secret: [1; 32],
            ephemeral_secret: [2; 32],
            expected_peer: None,
            yamux: YamuxConfig::default(),
        });
        responder.start().expect("start responder");
        while responder.poll_output().is_some() {}

        let mut proposals = b"\x13/multistream/1.0.0\n\x0b/tls/1.0.0\n\x07/noise\n".to_vec();
        responder
            .handle_input(core::mem::take(&mut proposals))
            .expect("reject TLS and accept Noise on the same negotiation");

        assert!(matches!(responder.phase, Some(Phase::Noise { .. })));
        let writes = core::iter::from_fn(|| responder.poll_output())
            .filter_map(|output| match output {
                SessionOutput::Write(bytes) => Some(bytes),
                _ => None,
            })
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(writes, b"\x03na\n\x07/noise\n");
    }

    /// Runs two raw Noise sessions through their handshake, returning both in
    /// transport mode with their nonces in step.
    ///
    /// Driving Noise directly, rather than through two `SecureMuxSession`s,
    /// is what lets the test encrypt a message the peer never sent: a session
    /// auto-sends its Yamux confirmation, and dropping that ciphertext would
    /// desync the nonces.
    fn noise_pair(
        initiator_key: Ed25519Keypair,
        responder_key: Ed25519Keypair,
    ) -> (NoiseSession, NoiseSession) {
        let responder_peer = responder_key.peer_id();
        let mut initiator = NoiseSession::new(NoiseConfig {
            role: NoiseRole::Initiator,
            identity: initiator_key,
            static_secret: [1; 32],
            ephemeral_secret: [2; 32],
            expected_peer: Some(responder_peer),
        });
        let mut responder = NoiseSession::new(NoiseConfig {
            role: NoiseRole::Responder,
            identity: responder_key,
            static_secret: [3; 32],
            ephemeral_secret: [4; 32],
            expected_peer: None,
        });
        initiator.handle_input(NoiseInput::Start).expect("start");
        responder.handle_input(NoiseInput::Start).expect("start");

        // Takes everything `from` has queued and delivers it to `to`, reporting
        // whether anything moved and whether `to` finished its handshake.
        fn shuttle(from: &mut NoiseSession, to: &mut NoiseSession) -> (bool, bool) {
            let mut batch = Vec::new();
            while let Some(output) = from.poll_output() {
                match output {
                    NoiseOutput::Outbound(bytes) => batch.extend_from_slice(&bytes),
                    NoiseOutput::HandshakeComplete { .. } => {}
                    NoiseOutput::Decrypted(_) => panic!("no data during handshake"),
                }
            }
            if batch.is_empty() {
                return (false, false);
            }
            to.handle_input(NoiseInput::Data(batch)).expect("handshake");
            (true, false)
        }

        fn completed(session: &mut NoiseSession) -> bool {
            // Peeking for completion would consume queued outbound bytes, so
            // ask the session instead of draining it.
            session.is_handshake_complete()
        }

        for _ in 0..16 {
            let (moved_forward, _) = shuttle(&mut initiator, &mut responder);
            let (moved_back, _) = shuttle(&mut responder, &mut initiator);
            if !moved_forward && !moved_back {
                break;
            }
        }
        assert!(
            completed(&mut initiator) && completed(&mut responder),
            "handshake must complete"
        );

        (initiator, responder)
    }

    #[test]
    fn responder_allows_fallback_before_yamux() {
        let initiator_key = Ed25519Keypair::generate();
        let initiator_peer = initiator_key.peer_id();
        let (mut initiator_noise, responder_noise) =
            noise_pair(initiator_key, Ed25519Keypair::generate());
        let mut select = MultistreamSelect::listener([YAMUX_PROTOCOL_ID.to_string()]);
        select.handle_input(MultistreamInput::Start).expect("start");
        while select.poll_output().is_some() {}

        let mut responder = SecureMuxSession {
            role: SessionRole::Responder,
            yamux_config: YamuxConfig::default(),
            phase: Some(Phase::SelectYamux {
                noise: responder_noise,
                select,
                peer: initiator_peer,
            }),
            outputs: VecDeque::new(),
        };
        let proposals = b"\x13/multistream/1.0.0\n\x0d/mplex/6.7.0\n\x0d/yamux/1.0.0\n".to_vec();
        initiator_noise
            .handle_input(NoiseInput::Encrypt(proposals))
            .expect("encrypt proposals");
        let ciphertext = core::iter::from_fn(|| initiator_noise.poll_output())
            .filter_map(|output| match output {
                NoiseOutput::Outbound(bytes) => Some(bytes),
                NoiseOutput::HandshakeComplete { .. } | NoiseOutput::Decrypted(_) => None,
            })
            .flatten()
            .collect::<Vec<_>>();

        responder
            .handle_input(ciphertext)
            .expect("reject mplex and accept Yamux on the same negotiation");

        assert!(matches!(responder.phase, Some(Phase::Ready { .. })));
        assert!(matches!(
            responder.poll_output(),
            Some(SessionOutput::Write(_))
        ));
        assert!(matches!(
            responder.poll_output(),
            Some(SessionOutput::Write(_))
        ));
        assert!(matches!(
            responder.poll_output(),
            Some(SessionOutput::Established { .. })
        ));
    }

    /// Builds a dialer select that has exchanged multistream headers and sent
    /// its `/yamux/1.0.0` proposal, plus the exact echo the peer replies with.
    ///
    /// The echo is the message that completes negotiation, so anything a peer
    /// packs after it in the same write is what
    /// `take_remaining_buffer` hands to Yamux.
    fn dialer_awaiting_echo() -> (MultistreamSelect, Vec<u8>) {
        const MULTISTREAM_HEADER: &[u8] = b"\x13/multistream/1.0.0\n";

        let mut select = MultistreamSelect::dialer(YAMUX_PROTOCOL_ID);
        select.handle_input(MultistreamInput::Start).expect("start");
        while select.poll_output().is_some() {}

        // The header echo makes the dialer send its protocol proposal; the
        // peer echoes that same line back to confirm.
        select
            .handle_input(MultistreamInput::Data(MULTISTREAM_HEADER.to_vec()))
            .expect("header echo");
        let mut echo = Vec::new();
        while let Some(output) = select.poll_output() {
            if let MultistreamOutput::OutboundData(bytes) = output {
                echo.extend_from_slice(&bytes);
            }
        }
        assert!(!echo.is_empty(), "dialer must propose a protocol");

        (select, echo)
    }

    /// A peer that writes its Yamux confirmation and its first frames in one
    /// socket write lands both in a single Noise plaintext, so the
    /// confirmation's `take_remaining_buffer` carries those frames. If they
    /// are fatal the upgrade never completed, and nothing the remainder
    /// produced may be left pollable -- neither `Established` nor the
    /// substream traffic that preceded the failure. Callers drain outputs even
    /// after an error, to flush bytes the session had already queued, so
    /// anything left behind is something they will act on.
    ///
    /// A `SecureMuxSession` emits the two as separate plaintexts, so this
    /// packs them by hand. That needs crate internals, which is why the test
    /// lives here rather than in `tests/`.
    /// Builds a dialer awaiting its Yamux confirmation, and hands it one Noise
    /// plaintext holding that confirmation followed by `trailing` frames.
    ///
    /// Packing them by hand is the point: a real peer usually sends them as
    /// separate Noise messages, and those are handled after the phase is
    /// already `Ready`, so they never race the announcement. Only a single
    /// packed plaintext reaches `take_remaining_buffer`.
    fn feed_packed_remainder(trailing: Vec<u8>) -> (SecureMuxSession, Result<(), SessionError>) {
        let dialer_key = Ed25519Keypair::generate();
        let listener_key = Ed25519Keypair::generate();
        let listener_peer = listener_key.peer_id();
        let (dialer_noise, mut listener_noise) = noise_pair(dialer_key, listener_key);
        let (select, echo) = dialer_awaiting_echo();

        let mut dialer = SecureMuxSession {
            role: SessionRole::Initiator,
            yamux_config: YamuxConfig::default(),
            phase: Some(Phase::SelectYamux {
                noise: dialer_noise,
                select,
                peer: listener_peer,
            }),
            outputs: VecDeque::new(),
        };

        let mut packed = echo;
        packed.extend_from_slice(&trailing);
        listener_noise
            .handle_input(NoiseInput::Encrypt(packed))
            .expect("encrypt the packed plaintext");
        let mut ciphertext = Vec::new();
        while let Some(output) = listener_noise.poll_output() {
            if let NoiseOutput::Outbound(bytes) = output {
                ciphertext.extend_from_slice(&bytes);
            }
        }
        assert!(!ciphertext.is_empty(), "packed plaintext must encrypt");

        let result = dialer.handle_input(ciphertext);
        (dialer, result)
    }

    fn syn_with_data() -> Vec<u8> {
        Frame::data(2, FLAG_SYN, b"pipelined".to_vec())
            .expect("well-formed frame")
            .encode()
    }

    /// The sound twin of the test below: substream traffic packed alongside the
    /// confirmation must still queue behind `Established`, so a host applying
    /// connection policy sees the peer before it has to decide anything about a
    /// stream.
    #[test]
    fn a_sound_pipelined_remainder_queues_behind_establishment() {
        let (mut dialer, result) = feed_packed_remainder(syn_with_data());
        result.expect("a sound remainder must complete the upgrade");
        assert!(dialer.is_established());

        let outputs: Vec<SessionOutput> = core::iter::from_fn(|| dialer.poll_output()).collect();
        let established = outputs
            .iter()
            .position(|output| matches!(output, SessionOutput::Established { .. }))
            .expect("the upgrade completed");
        let first_stream = outputs
            .iter()
            .position(|output| {
                matches!(
                    output,
                    SessionOutput::IncomingStream { .. } | SessionOutput::StreamData { .. }
                )
            })
            .expect("the packed frames must surface, or this proves nothing");
        assert!(
            established < first_stream,
            "Established must precede the remainder's stream output: {outputs:?}"
        );
    }

    #[test]
    fn a_fatal_pipelined_remainder_publishes_nothing_at_all() {
        // The confirming echo, then a substream carrying data, then a fatal
        // GoAway. The frames before the GoAway are what the drain turns into
        // pollable stream outputs before it fails.
        let mut trailing = syn_with_data();
        trailing.extend_from_slice(&Frame::go_away(1).encode());
        let (mut dialer, result) = feed_packed_remainder(trailing);

        assert!(
            matches!(result, Err(SessionError::GoAway { code: 1 })),
            "a fatal remainder must fail the upgrade: {result:?}"
        );
        assert!(!dialer.is_established());

        let outputs: Vec<SessionOutput> = core::iter::from_fn(|| dialer.poll_output()).collect();
        assert!(
            outputs
                .iter()
                .all(|output| matches!(output, SessionOutput::Write(_))),
            "a failed upgrade may leave only queued writes behind: {outputs:?}"
        );
    }

    #[test]
    fn unknown_yamux_streams_preserve_the_transport_error_contract() {
        let initiator_key = Ed25519Keypair::generate();
        let responder_key = Ed25519Keypair::generate();
        let peer = responder_key.peer_id();
        let (noise, _) = noise_pair(initiator_key, responder_key);
        let mut session = SecureMuxSession {
            role: SessionRole::Initiator,
            yamux_config: YamuxConfig::default(),
            phase: Some(Phase::Ready {
                noise,
                yamux: YamuxSession::new(YamuxRole::Client),
                peer,
            }),
            outputs: VecDeque::new(),
        };
        let stream = StreamId::new(77);

        for result in [
            session.send(stream, b"data".to_vec()),
            session.close_stream_write(stream),
            session.reset_stream(stream),
        ] {
            assert!(
                matches!(result, Err(SessionError::UnknownStream { stream: id }) if id == stream),
                "unknown stream must remain distinguishable: {result:?}"
            );
        }
    }
}
