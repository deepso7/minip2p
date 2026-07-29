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
use minip2p_transport::StreamId;
use minip2p_yamux::{YAMUX_PROTOCOL_ID, YamuxInput, YamuxOutput, YamuxRole, YamuxSession};
use thiserror::Error;

pub use minip2p_yamux::{YamuxConfig, YamuxError};

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
        let stream = yamux_stream(stream);
        self.with_yamux(move |yamux| yamux.send(stream, data))
    }

    /// Half-closes the local write side of a substream.
    pub fn close_stream_write(&mut self, stream: StreamId) -> Result<(), SessionError> {
        let stream = yamux_stream(stream);
        self.with_yamux(move |yamux| yamux.close_write(stream))
    }

    /// Abruptly closes a substream in both directions.
    pub fn reset_stream(&mut self, stream: StreamId) -> Result<(), SessionError> {
        let stream = yamux_stream(stream);
        self.with_yamux(move |yamux| yamux.reset(stream))
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
        let Some(Phase::Ready {
            mut noise,
            mut yamux,
            peer,
        }) = self.phase.take()
        else {
            // Put back whatever phase we found; the session is still usable.
            return Err(SessionError::NotEstablished);
        };

        let result = operation(&mut yamux);
        let drain = self.drain_yamux(&mut noise, &mut yamux);
        self.phase = Some(Phase::Ready { noise, yamux, peer });
        drain?;
        result.map_err(SessionError::Yamux)
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

        // Ordered before any stream output from the pipelined remainder, so a
        // caller applying connection policy sees the peer first.
        self.outputs
            .push_back(SessionOutput::Established { peer: peer.clone() });

        if !remaining.is_empty() {
            let result = yamux.handle_input(YamuxInput::Data(remaining));
            self.drain_yamux(&mut noise, &mut yamux)?;
            result.map_err(|error| {
                SessionError::protocol(format!("Yamux protocol failed: {error}"))
            })?;
        }
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

    fn drain_yamux(
        &mut self,
        noise: &mut NoiseSession,
        yamux: &mut YamuxSession,
    ) -> Result<(), SessionError> {
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
                YamuxOutput::GoAwayReceived { code: 0 } => {
                    return Err(SessionError::protocol("remote closed the Yamux session"));
                }
                YamuxOutput::GoAwayReceived { code } => {
                    return Err(SessionError::protocol(format!(
                        "remote closed Yamux with error code {code}"
                    )));
                }
            }
        }
        Ok(())
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
/// Ids only ever originate from Yamux itself (widened in `drain_yamux`), so
/// the value always fits; a caller passing a fabricated id gets a truncated
/// one that Yamux rejects as unknown.
fn yamux_stream(stream: StreamId) -> u32 {
    stream.as_u64() as u32
}
