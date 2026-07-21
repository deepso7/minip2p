//! Relay-circuit transport built from an existing ordered bridge stream.
//!
//! The wrapper performs multistream-select, Noise XX, and Yamux without
//! owning sockets, clocks, or an executor. Wrapped transport connection IDs
//! pass through unchanged; circuit IDs have [`CIRCUIT_ID_BIT`] set.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use minip2p_core::{Multiaddr, Protocol, SansIoProtocol};
use minip2p_identity::{Ed25519Keypair, PeerId};
use minip2p_multistream_select::{MultistreamInput, MultistreamOutput, MultistreamSelect};
use minip2p_noise::{
    NOISE_PROTOCOL_ID, NoiseConfig, NoiseInput, NoiseOutput, NoiseRole, NoiseSession,
};
use minip2p_transport::{
    ConnectionEndpoint, ConnectionId, StreamId, Transport, TransportError, TransportEvent,
    WaitOutcome,
};
use minip2p_yamux::{
    YAMUX_PROTOCOL_ID, YamuxConfig, YamuxError, YamuxInput, YamuxOutput, YamuxRole, YamuxSession,
};
use thiserror::Error;

/// Marker bit reserved for circuit connection identifiers.
pub const CIRCUIT_ID_BIT: u64 = 1 << 63;

// A retired bridge suppresses late inner-transport events after the circuit's
// public `Closed`. Keep this finite because a peer may never finish closing
// its half of a gracefully closed bridge.
const MAX_RETIRED_BRIDGES: usize = 1024;

fn is_circuit_id(id: ConnectionId) -> bool {
    id.as_u64() & CIRCUIT_ID_BIT != 0
}

/// Supplies fresh cryptographic entropy for one circuit adoption.
pub trait EntropySource {
    /// Fills `destination` with unpredictable bytes.
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyError>;
}

/// Failure to obtain cryptographic entropy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("entropy source failed: {0}")]
pub struct EntropyError(&'static str);

impl EntropyError {
    /// Creates an entropy failure with source-specific diagnostic context.
    pub const fn new(message: &'static str) -> Self {
        Self(message)
    }
}

/// Entropy source backed by the operating system.
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, Default)]
pub struct OsEntropy;

#[cfg(feature = "std")]
impl EntropySource for OsEntropy {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::fill(destination).map_err(|_| EntropyError("OS randomness unavailable"))
    }
}

/// Which endpoint initiated the relayed connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircuitRole {
    /// Sent the relay HOP CONNECT request.
    Initiator,
    /// Accepted the relay STOP CONNECT request.
    Responder,
}

/// Description of a relay stream that has become a transparent byte bridge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeAdoption {
    /// Wrapped transport connection to the relay.
    pub inner_conn: ConnectionId,
    /// Stream carrying the relayed byte bridge.
    pub bridge_stream: StreamId,
    /// Relay peer used to form the circuit endpoint address.
    pub relay: PeerId,
    /// Expected peer at the other end of the bridge.
    pub remote_peer: PeerId,
    /// Local role in the end-to-end circuit handshake.
    pub role: CircuitRole,
    /// Bytes already read beyond the relay CONNECT response.
    pub pending_data: Vec<u8>,
    /// Whether the bridge's remote write side was already closed.
    pub remote_write_closed: bool,
}

/// Synchronous errors from adopting a relay bridge.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AdoptError {
    /// The bridge is already adopted with different immutable metadata.
    #[error("bridge is already adopted with conflicting parameters")]
    ConflictingAdoption,
    /// A verified direct connection to the peer already exists.
    #[error("peer already has a direct connection")]
    PeerAlreadyDirect,
    /// The bridge cannot carry a handshake because its remote write side closed.
    #[error("bridge remote write side is closed")]
    RemoteWriteClosed,
    /// The wrapped relay connection is not active.
    #[error("wrapped relay connection is unknown")]
    UnknownConnection,
    /// Fresh Noise key material could not be generated.
    #[error(transparent)]
    Entropy(#[from] EntropyError),
    /// All circuit connection identifiers have been allocated.
    #[error("circuit connection IDs exhausted")]
    IdsExhausted,
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

struct Circuit {
    id: ConnectionId,
    inner_conn: ConnectionId,
    bridge_stream: StreamId,
    relay: PeerId,
    remote_peer: PeerId,
    role: CircuitRole,
    phase: Option<Phase>,
}

impl Circuit {
    fn bridge_key(&self) -> (ConnectionId, StreamId) {
        (self.inner_conn, self.bridge_stream)
    }

    fn endpoint(&self, peer: Option<PeerId>) -> ConnectionEndpoint {
        let address = Multiaddr::from_protocols(vec![
            Protocol::P2p(self.relay.clone()),
            Protocol::P2pCircuit,
        ]);
        match peer {
            Some(peer) => ConnectionEndpoint::with_peer_id(address, peer),
            None => ConnectionEndpoint::new(address),
        }
    }

    fn is_ready(&self) -> bool {
        matches!(self.phase, Some(Phase::Ready { .. }))
    }
}

/// A transport wrapper that promotes relay bridge streams into connections.
pub struct CircuitTransport<T, E> {
    inner: T,
    entropy: E,
    identity: Ed25519Keypair,
    yamux_config: YamuxConfig,
    circuits: BTreeMap<ConnectionId, Circuit>,
    bridge_index: BTreeMap<(ConnectionId, StreamId), ConnectionId>,
    retired_bridges: BTreeSet<(ConnectionId, StreamId)>,
    retired_bridge_order: VecDeque<(ConnectionId, StreamId)>,
    active_inner: BTreeSet<ConnectionId>,
    direct_by_peer: BTreeMap<PeerId, BTreeSet<ConnectionId>>,
    direct_by_conn: BTreeMap<ConnectionId, PeerId>,
    pending: VecDeque<TransportEvent>,
    next_circuit_id: Option<u64>,
}

impl<T, E> CircuitTransport<T, E> {
    /// Wraps a transport with an explicit entropy source and local identity.
    pub fn new(inner: T, identity: Ed25519Keypair, entropy: E) -> Self {
        Self {
            inner,
            entropy,
            identity,
            yamux_config: YamuxConfig::default(),
            circuits: BTreeMap::new(),
            bridge_index: BTreeMap::new(),
            retired_bridges: BTreeSet::new(),
            retired_bridge_order: VecDeque::new(),
            active_inner: BTreeSet::new(),
            direct_by_peer: BTreeMap::new(),
            direct_by_conn: BTreeMap::new(),
            pending: VecDeque::new(),
            next_circuit_id: Some(1),
        }
    }

    /// Replaces the Yamux limits used by subsequently adopted circuits.
    pub fn set_yamux_config(&mut self, config: YamuxConfig) {
        self.yamux_config = config;
    }

    /// Returns whether an identifier belongs to a circuit connection.
    pub fn is_circuit(id: ConnectionId) -> bool {
        is_circuit_id(id)
    }

    /// Returns the active circuit connection identifiers.
    pub fn circuit_ids(&self) -> Vec<ConnectionId> {
        self.circuits.keys().copied().collect()
    }

    /// Borrows the wrapped transport.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Mutably borrows the wrapped transport.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: Transport, E: EntropySource> CircuitTransport<T, E> {
    /// Promotes an already-negotiated relay bridge into a circuit connection.
    ///
    /// Repeating the same `(inner_conn, bridge_stream)` adoption is
    /// idempotent and returns the existing circuit identifier when its relay,
    /// remote peer, role, and remote-write state agree. Conflicting immutable
    /// metadata returns [`AdoptError::ConflictingAdoption`].
    pub fn adopt_bridge(&mut self, adoption: BridgeAdoption) -> Result<ConnectionId, AdoptError> {
        let key = (adoption.inner_conn, adoption.bridge_stream);
        if let Some(id) = self.bridge_index.get(&key).copied() {
            let circuit = self
                .circuits
                .get(&id)
                .expect("bridge index must reference an active circuit");
            if adoption.remote_write_closed
                || adoption.relay != circuit.relay
                || adoption.remote_peer != circuit.remote_peer
                || adoption.role != circuit.role
            {
                return Err(AdoptError::ConflictingAdoption);
            }
            return Ok(id);
        }
        if adoption.remote_write_closed {
            return Err(AdoptError::RemoteWriteClosed);
        }
        if !self.active_inner.contains(&adoption.inner_conn) {
            return Err(AdoptError::UnknownConnection);
        }
        if self
            .direct_by_peer
            .get(&adoption.remote_peer)
            .is_some_and(|connections| !connections.is_empty())
        {
            return Err(AdoptError::PeerAlreadyDirect);
        }

        let sequence = self.next_circuit_id.ok_or(AdoptError::IdsExhausted)?;
        let next = sequence
            .checked_add(1)
            .filter(|value| *value < CIRCUIT_ID_BIT);

        let mut static_secret = [0u8; 32];
        let mut ephemeral_secret = [0u8; 32];
        self.entropy.fill(&mut static_secret)?;
        self.entropy.fill(&mut ephemeral_secret)?;

        let id = ConnectionId::new(CIRCUIT_ID_BIT | sequence);
        let noise = NoiseSession::new(NoiseConfig {
            role: match adoption.role {
                CircuitRole::Initiator => NoiseRole::Initiator,
                CircuitRole::Responder => NoiseRole::Responder,
            },
            identity: self.identity.clone(),
            static_secret,
            ephemeral_secret,
            expected_peer: Some(adoption.remote_peer.clone()),
        });
        let select = match adoption.role {
            CircuitRole::Initiator => MultistreamSelect::dialer(NOISE_PROTOCOL_ID),
            CircuitRole::Responder => MultistreamSelect::listener([NOISE_PROTOCOL_ID.to_string()]),
        };
        let circuit = Circuit {
            id,
            inner_conn: adoption.inner_conn,
            bridge_stream: adoption.bridge_stream,
            relay: adoption.relay,
            remote_peer: adoption.remote_peer,
            role: adoption.role,
            phase: Some(Phase::SelectNoise {
                select,
                noise: Some(noise),
            }),
        };

        self.next_circuit_id = next;
        self.bridge_index.insert(key, id);
        if adoption.role == CircuitRole::Responder {
            self.pending.push_back(TransportEvent::IncomingConnection {
                id,
                endpoint: circuit.endpoint(None),
            });
        }
        self.circuits.insert(id, circuit);

        let start_result = self.with_circuit(id, |this, circuit| {
            let phase = circuit
                .phase
                .take()
                .ok_or_else(|| "circuit phase unavailable".to_string())?;
            let phase = this.start_phase(circuit, phase)?;
            circuit.phase = Some(phase);
            Ok(())
        });
        if let Err(message) = start_result {
            self.fail_circuit(id, message, true);
            return Ok(id);
        }
        if !adoption.pending_data.is_empty() {
            self.inject_bridge_data(
                adoption.inner_conn,
                adoption.bridge_stream,
                adoption.pending_data,
            );
        }
        Ok(id)
    }

    /// Injects bytes read from a bridge outside the wrapped transport poll.
    pub fn inject_bridge_data(
        &mut self,
        inner_conn: ConnectionId,
        bridge_stream: StreamId,
        data: Vec<u8>,
    ) {
        let key = (inner_conn, bridge_stream);
        let Some(id) = self.bridge_index.get(&key).copied() else {
            return;
        };
        // `feed_phase` temporarily takes the phase and leaves it absent on
        // error, so capture readiness before entering it. In particular, a
        // normal Yamux GoAway from a Ready circuit must close without being
        // misclassified as a pre-handshake protocol failure.
        let pre_ready = self.circuits.get(&id).is_some_and(|c| !c.is_ready());
        let result = self.with_circuit(id, |this, circuit| {
            let phase = circuit
                .phase
                .take()
                .ok_or_else(|| "circuit phase unavailable".to_string())?;
            let phase = this.feed_phase(circuit, phase, data)?;
            circuit.phase = Some(phase);
            Ok(())
        });
        if let Err(message) = &result {
            let normal_go_away = message == "remote closed the Yamux session";
            self.fail_circuit(id, message.clone(), pre_ready || !normal_go_away);
        }
    }

    /// Reports that a bridge received its remote FIN.
    pub fn inject_bridge_remote_write_closed(
        &mut self,
        inner_conn: ConnectionId,
        bridge_stream: StreamId,
    ) {
        let key = (inner_conn, bridge_stream);
        if let Some(id) = self.bridge_index.get(&key).copied() {
            let pre_ready = self.circuits.get(&id).is_some_and(|c| !c.is_ready());
            self.fail_circuit(
                id,
                "relay bridge remote write side closed".to_string(),
                pre_ready,
            );
        }
    }

    /// Reports that a bridge stream fully closed or reset.
    pub fn inject_bridge_closed(&mut self, inner_conn: ConnectionId, bridge_stream: StreamId) {
        let key = (inner_conn, bridge_stream);
        self.release_retired_bridge(key);
        if let Some(id) = self.bridge_index.get(&key).copied() {
            let pre_ready = self.circuits.get(&id).is_some_and(|c| !c.is_ready());
            self.fail_circuit(id, "relay bridge closed".to_string(), pre_ready);
        }
    }

    fn with_circuit<R>(
        &mut self,
        id: ConnectionId,
        operation: impl FnOnce(&mut Self, &mut Circuit) -> Result<R, String>,
    ) -> Result<R, String> {
        let mut circuit = self
            .circuits
            .remove(&id)
            .ok_or_else(|| format!("circuit {id} is unknown"))?;
        let result = operation(self, &mut circuit);
        self.circuits.insert(id, circuit);
        result
    }

    fn retire_bridge(&mut self, key: (ConnectionId, StreamId)) {
        if !self.retired_bridges.insert(key) {
            return;
        }
        self.retired_bridge_order.push_back(key);
        if self.retired_bridge_order.len() > MAX_RETIRED_BRIDGES
            && let Some(expired) = self.retired_bridge_order.pop_front()
        {
            self.retired_bridges.remove(&expired);
        }
    }

    fn release_retired_bridge(&mut self, key: (ConnectionId, StreamId)) {
        if self.retired_bridges.remove(&key) {
            self.retired_bridge_order
                .retain(|candidate| *candidate != key);
        }
    }

    fn release_retired_bridges_for_connection(&mut self, id: ConnectionId) {
        self.retired_bridges.retain(|(conn, _)| *conn != id);
        self.retired_bridge_order.retain(|(conn, _)| *conn != id);
    }

    fn start_phase(&mut self, circuit: &Circuit, phase: Phase) -> Result<Phase, String> {
        match phase {
            Phase::SelectNoise { mut select, noise } => {
                select
                    .handle_input(MultistreamInput::Start)
                    .map_err(|error| format!("Noise multistream start failed: {error}"))?;
                self.drain_raw_select(circuit, &mut select)?;
                Ok(Phase::SelectNoise { select, noise })
            }
            other => Ok(other),
        }
    }

    fn feed_phase(
        &mut self,
        circuit: &Circuit,
        phase: Phase,
        data: Vec<u8>,
    ) -> Result<Phase, String> {
        match phase {
            Phase::SelectNoise {
                mut select,
                mut noise,
            } => {
                select
                    .handle_input(MultistreamInput::Data(data))
                    .map_err(|error| format!("Noise multistream failed: {error}"))?;
                let mut negotiated = false;
                while let Some(output) = select.poll_output() {
                    match output {
                        MultistreamOutput::OutboundData(bytes) => {
                            self.send_bridge(circuit, bytes)?;
                        }
                        MultistreamOutput::Negotiated { protocol }
                            if protocol == NOISE_PROTOCOL_ID =>
                        {
                            negotiated = true;
                        }
                        MultistreamOutput::Negotiated { .. } | MultistreamOutput::NotAvailable => {
                            return Err("remote did not negotiate Noise".to_string());
                        }
                        MultistreamOutput::ProtocolError { reason } => {
                            return Err(format!("Noise multistream protocol error: {reason}"));
                        }
                    }
                }
                if !negotiated {
                    return Ok(Phase::SelectNoise { select, noise });
                }
                let remaining = select.take_remaining_buffer();
                let mut noise = noise
                    .take()
                    .ok_or_else(|| "Noise session unavailable".to_string())?;
                noise
                    .handle_input(NoiseInput::Start)
                    .map_err(|error| format!("Noise start failed: {error}"))?;
                let (peer, decrypted) = self.drain_noise(circuit, &mut noise)?;
                if peer.is_some() || !decrypted.is_empty() {
                    return Err("Noise produced transport data before input".to_string());
                }
                if remaining.is_empty() {
                    Ok(Phase::Noise { noise })
                } else {
                    self.feed_phase(circuit, Phase::Noise { noise }, remaining)
                }
            }
            Phase::Noise { mut noise } => {
                noise
                    .handle_input(NoiseInput::Data(data))
                    .map_err(|error| format!("Noise handshake failed: {error}"))?;
                let (peer, decrypted) = self.drain_noise(circuit, &mut noise)?;
                let Some(peer) = peer else {
                    if !decrypted.is_empty() {
                        return Err("Noise decrypted data before authentication".to_string());
                    }
                    return Ok(Phase::Noise { noise });
                };
                let mut select = match circuit.role {
                    CircuitRole::Initiator => MultistreamSelect::dialer(YAMUX_PROTOCOL_ID),
                    CircuitRole::Responder => {
                        MultistreamSelect::listener([YAMUX_PROTOCOL_ID.to_string()])
                    }
                };
                select
                    .handle_input(MultistreamInput::Start)
                    .map_err(|error| format!("Yamux multistream start failed: {error}"))?;
                self.drain_encrypted_select(circuit, &mut noise, &mut select)?;
                let mut phase = Phase::SelectYamux {
                    noise,
                    select,
                    peer,
                };
                for plaintext in decrypted {
                    phase = self.feed_decrypted_transport(circuit, phase, plaintext)?;
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
                    .map_err(|error| format!("Noise transport failed: {error}"))?;
                let (unexpected_peer, decrypted) = self.drain_noise(circuit, &mut noise)?;
                if unexpected_peer.is_some() {
                    return Err("Noise authenticated twice".to_string());
                }
                let mut phase = Phase::SelectYamux {
                    noise,
                    select,
                    peer,
                };
                for plaintext in decrypted {
                    phase = self.feed_decrypted_transport(circuit, phase, plaintext)?;
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
                    .map_err(|error| format!("Noise transport failed: {error}"))?;
                let (unexpected_peer, decrypted) = self.drain_noise(circuit, &mut noise)?;
                if unexpected_peer.is_some() {
                    return Err("Noise authenticated twice".to_string());
                }
                for plaintext in decrypted {
                    let result = yamux.handle_input(YamuxInput::Data(plaintext));
                    self.drain_yamux(circuit, &mut noise, &mut yamux)?;
                    result.map_err(|error| format!("Yamux protocol failed: {error}"))?;
                }
                Ok(Phase::Ready { noise, yamux, peer })
            }
        }
    }

    /// Routes plaintext Noise transport messages across the exact Yamux
    /// phase boundary. One bridge read may decrypt both the selection reply
    /// and immediately-pipelined Yamux frames, so later plaintexts must use
    /// the `Ready` state produced by an earlier one in the same batch.
    fn feed_decrypted_transport(
        &mut self,
        circuit: &Circuit,
        phase: Phase,
        plaintext: Vec<u8>,
    ) -> Result<Phase, String> {
        match phase {
            phase @ Phase::SelectYamux { .. } => {
                self.feed_decrypted_yamux_select(circuit, phase, plaintext)
            }
            Phase::Ready {
                mut noise,
                mut yamux,
                peer,
            } => {
                let result = yamux.handle_input(YamuxInput::Data(plaintext));
                self.drain_yamux(circuit, &mut noise, &mut yamux)?;
                result.map_err(|error| format!("Yamux protocol failed: {error}"))?;
                Ok(Phase::Ready { noise, yamux, peer })
            }
            _ => Err("decrypted transport data arrived before Yamux selection".to_string()),
        }
    }

    fn feed_decrypted_yamux_select(
        &mut self,
        circuit: &Circuit,
        phase: Phase,
        plaintext: Vec<u8>,
    ) -> Result<Phase, String> {
        let Phase::SelectYamux {
            mut noise,
            mut select,
            peer,
        } = phase
        else {
            return Err("Yamux selection completed before pipelined data".to_string());
        };
        select
            .handle_input(MultistreamInput::Data(plaintext))
            .map_err(|error| format!("Yamux multistream failed: {error}"))?;
        let mut negotiated = false;
        while let Some(output) = select.poll_output() {
            match output {
                MultistreamOutput::OutboundData(bytes) => {
                    self.encrypt_bridge(circuit, &mut noise, bytes)?;
                }
                MultistreamOutput::Negotiated { protocol } if protocol == YAMUX_PROTOCOL_ID => {
                    negotiated = true;
                }
                MultistreamOutput::Negotiated { .. } | MultistreamOutput::NotAvailable => {
                    return Err("remote did not negotiate Yamux".to_string());
                }
                MultistreamOutput::ProtocolError { reason } => {
                    return Err(format!("Yamux multistream protocol error: {reason}"));
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
        if self
            .direct_by_peer
            .get(&peer)
            .is_some_and(|connections| !connections.is_empty())
        {
            return Err("direct connection won circuit arbitration".to_string());
        }
        let remaining = select.take_remaining_buffer();
        let mut yamux = YamuxSession::with_config(
            match circuit.role {
                CircuitRole::Initiator => YamuxRole::Client,
                CircuitRole::Responder => YamuxRole::Server,
            },
            self.yamux_config.clone(),
        )
        .map_err(|error| format!("invalid Yamux configuration: {error}"))?;
        self.pending.push_back(TransportEvent::Connected {
            id: circuit.id,
            endpoint: circuit.endpoint(Some(peer.clone())),
        });
        if !remaining.is_empty() {
            let result = yamux.handle_input(YamuxInput::Data(remaining));
            self.drain_yamux(circuit, &mut noise, &mut yamux)?;
            result.map_err(|error| format!("Yamux protocol failed: {error}"))?;
        }
        Ok(Phase::Ready { noise, yamux, peer })
    }

    fn drain_raw_select(
        &mut self,
        circuit: &Circuit,
        select: &mut MultistreamSelect,
    ) -> Result<(), String> {
        while let Some(output) = select.poll_output() {
            if let MultistreamOutput::OutboundData(bytes) = output {
                self.send_bridge(circuit, bytes)?;
            }
        }
        Ok(())
    }

    fn drain_encrypted_select(
        &mut self,
        circuit: &Circuit,
        noise: &mut NoiseSession,
        select: &mut MultistreamSelect,
    ) -> Result<(), String> {
        while let Some(output) = select.poll_output() {
            if let MultistreamOutput::OutboundData(bytes) = output {
                self.encrypt_bridge(circuit, noise, bytes)?;
            }
        }
        Ok(())
    }

    fn drain_noise(
        &mut self,
        circuit: &Circuit,
        noise: &mut NoiseSession,
    ) -> Result<(Option<PeerId>, Vec<Vec<u8>>), String> {
        let mut peer = None;
        let mut decrypted = Vec::new();
        while let Some(output) = noise.poll_output() {
            match output {
                NoiseOutput::Outbound(bytes) => self.send_bridge(circuit, bytes)?,
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
        circuit: &Circuit,
        noise: &mut NoiseSession,
        yamux: &mut YamuxSession,
    ) -> Result<(), String> {
        while let Some(output) = yamux.poll_output() {
            match output {
                YamuxOutput::Outbound(bytes) => self.encrypt_bridge(circuit, noise, bytes)?,
                YamuxOutput::IncomingStream { stream } => {
                    self.pending.push_back(TransportEvent::IncomingStream {
                        id: circuit.id,
                        stream_id: StreamId::new(u64::from(stream)),
                    });
                }
                YamuxOutput::Data { stream, data } => {
                    self.pending.push_back(TransportEvent::StreamData {
                        id: circuit.id,
                        stream_id: StreamId::new(u64::from(stream)),
                        data,
                    });
                }
                YamuxOutput::RemoteWriteClosed { stream } => {
                    self.pending
                        .push_back(TransportEvent::StreamRemoteWriteClosed {
                            id: circuit.id,
                            stream_id: StreamId::new(u64::from(stream)),
                        });
                }
                YamuxOutput::StreamClosed { stream } => {
                    self.pending.push_back(TransportEvent::StreamClosed {
                        id: circuit.id,
                        stream_id: StreamId::new(u64::from(stream)),
                    });
                }
                YamuxOutput::GoAwayReceived { code: 0 } => {
                    return Err("remote closed the Yamux session".to_string());
                }
                YamuxOutput::GoAwayReceived { code } => {
                    return Err(format!("remote closed Yamux with error code {code}"));
                }
            }
        }
        Ok(())
    }

    fn send_bridge(&mut self, circuit: &Circuit, bytes: Vec<u8>) -> Result<(), String> {
        self.inner
            .send_stream(circuit.inner_conn, circuit.bridge_stream, bytes)
            .map_err(|error| format!("relay bridge send failed: {error}"))
    }

    fn encrypt_bridge(
        &mut self,
        circuit: &Circuit,
        noise: &mut NoiseSession,
        plaintext: Vec<u8>,
    ) -> Result<(), String> {
        noise
            .handle_input(NoiseInput::Encrypt(plaintext))
            .map_err(|error| format!("Noise encryption failed: {error}"))?;
        let (peer, decrypted) = self.drain_noise(circuit, noise)?;
        if peer.is_some() || !decrypted.is_empty() {
            return Err("unexpected Noise output while encrypting".to_string());
        }
        Ok(())
    }

    fn fail_circuit(&mut self, id: ConnectionId, message: String, emit_error: bool) {
        let Some(circuit) = self.circuits.remove(&id) else {
            return;
        };
        let key = circuit.bridge_key();
        self.bridge_index.remove(&key);
        self.retire_bridge(key);
        let _ = self
            .inner
            .reset_stream(circuit.inner_conn, circuit.bridge_stream);
        if emit_error {
            self.pending
                .push_back(TransportEvent::Error { id, message });
        }
        self.pending.push_back(TransportEvent::Closed { id });
    }

    fn record_direct(&mut self, id: ConnectionId, peer: PeerId) {
        if let Some(previous) = self.direct_by_conn.insert(id, peer.clone())
            && previous != peer
            && let Some(ids) = self.direct_by_peer.get_mut(&previous)
        {
            ids.remove(&id);
            if ids.is_empty() {
                self.direct_by_peer.remove(&previous);
            }
        }
        self.direct_by_peer
            .entry(peer.clone())
            .or_default()
            .insert(id);
        let losers: Vec<_> = self
            .circuits
            .iter()
            .filter_map(|(circuit_id, circuit)| {
                (!circuit.is_ready() && circuit.remote_peer == peer).then_some(*circuit_id)
            })
            .collect();
        for circuit_id in losers {
            self.fail_circuit(
                circuit_id,
                "direct connection won circuit arbitration".to_string(),
                true,
            );
        }
    }

    fn remove_direct(&mut self, id: ConnectionId) {
        let Some(peer) = self.direct_by_conn.remove(&id) else {
            return;
        };
        if let Some(ids) = self.direct_by_peer.get_mut(&peer) {
            ids.remove(&id);
            if ids.is_empty() {
                self.direct_by_peer.remove(&peer);
            }
        }
    }

    fn reject_inner_collision(&mut self, id: ConnectionId) {
        self.active_inner.remove(&id);
        self.remove_direct(id);
        let _ = self.inner.close(id);
        self.pending.push_back(TransportEvent::Error {
            id,
            message: "wrapped transport used the circuit connection-ID bit".to_string(),
        });
    }

    fn handle_inner_event(&mut self, event: TransportEvent) {
        let event_id = match &event {
            TransportEvent::Connected { id, .. }
            | TransportEvent::StreamOpened { id, .. }
            | TransportEvent::IncomingStream { id, .. }
            | TransportEvent::StreamData { id, .. }
            | TransportEvent::StreamRemoteWriteClosed { id, .. }
            | TransportEvent::StreamClosed { id, .. }
            | TransportEvent::Closed { id }
            | TransportEvent::Error { id, .. }
            | TransportEvent::IncomingConnection { id, .. }
            | TransportEvent::PeerIdentityVerified { id, .. } => Some(*id),
            TransportEvent::Listening { .. } => None,
        };
        if event_id.is_some_and(is_circuit_id) {
            self.reject_inner_collision(event_id.expect("checked above"));
            return;
        }

        match event {
            TransportEvent::IncomingConnection { id, endpoint } => {
                self.active_inner.insert(id);
                self.pending
                    .push_back(TransportEvent::IncomingConnection { id, endpoint });
            }
            TransportEvent::Connected { id, endpoint } => {
                self.active_inner.insert(id);
                if let Some(peer) = endpoint.peer_id().cloned() {
                    self.record_direct(id, peer);
                }
                self.pending
                    .push_back(TransportEvent::Connected { id, endpoint });
            }
            TransportEvent::PeerIdentityVerified {
                id,
                endpoint,
                previous_peer_id,
            } => {
                if let Some(peer) = endpoint.peer_id().cloned() {
                    self.record_direct(id, peer);
                }
                self.pending
                    .push_back(TransportEvent::PeerIdentityVerified {
                        id,
                        endpoint,
                        previous_peer_id,
                    });
            }
            TransportEvent::StreamData {
                id,
                stream_id,
                data,
            } => {
                let key = (id, stream_id);
                if self.bridge_index.contains_key(&key) {
                    self.inject_bridge_data(id, stream_id, data);
                } else if !self.retired_bridges.contains(&key) {
                    self.pending.push_back(TransportEvent::StreamData {
                        id,
                        stream_id,
                        data,
                    });
                }
            }
            TransportEvent::StreamRemoteWriteClosed { id, stream_id } => {
                let key = (id, stream_id);
                if self.bridge_index.contains_key(&key) {
                    self.inject_bridge_remote_write_closed(id, stream_id);
                } else if !self.retired_bridges.contains(&key) {
                    self.pending
                        .push_back(TransportEvent::StreamRemoteWriteClosed { id, stream_id });
                }
            }
            TransportEvent::StreamClosed { id, stream_id } => {
                let key = (id, stream_id);
                if self.bridge_index.contains_key(&key) || self.retired_bridges.contains(&key) {
                    self.inject_bridge_closed(id, stream_id);
                } else {
                    self.pending
                        .push_back(TransportEvent::StreamClosed { id, stream_id });
                }
            }
            TransportEvent::Closed { id } => {
                self.active_inner.remove(&id);
                self.remove_direct(id);
                let riding: Vec<_> = self
                    .circuits
                    .iter()
                    .filter_map(|(circuit_id, circuit)| {
                        (circuit.inner_conn == id).then_some(*circuit_id)
                    })
                    .collect();
                for circuit_id in riding {
                    let pre_ready = self
                        .circuits
                        .get(&circuit_id)
                        .is_some_and(|circuit| !circuit.is_ready());
                    self.fail_circuit(circuit_id, "relay connection closed".to_string(), pre_ready);
                }
                self.release_retired_bridges_for_connection(id);
                self.pending.push_back(TransportEvent::Closed { id });
            }
            other => self.pending.push_back(other),
        }
    }

    fn circuit_stream(&self, id: ConnectionId, stream_id: StreamId) -> Result<u32, TransportError> {
        if !self.circuits.contains_key(&id) {
            return Err(TransportError::ConnectionNotFound { id });
        }
        u32::try_from(stream_id.as_u64())
            .map_err(|_| TransportError::StreamNotFound { id, stream_id })
    }

    fn operate_ready<R>(
        &mut self,
        id: ConnectionId,
        operation: impl FnOnce(&mut YamuxSession) -> Result<R, YamuxError>,
    ) -> Result<R, TransportError> {
        let mut circuit = self
            .circuits
            .remove(&id)
            .ok_or(TransportError::ConnectionNotFound { id })?;
        let Some(Phase::Ready {
            mut noise,
            mut yamux,
            peer,
        }) = circuit.phase.take()
        else {
            self.circuits.insert(id, circuit);
            return Err(TransportError::InvalidState {
                id,
                state: minip2p_transport::ConnectionState::Connecting,
                expected: minip2p_transport::ConnectionState::Connected,
            });
        };
        let result = operation(&mut yamux);
        let drain = self.drain_yamux(&circuit, &mut noise, &mut yamux);
        circuit.phase = Some(Phase::Ready { noise, yamux, peer });
        self.circuits.insert(id, circuit);
        if let Err(message) = drain {
            self.fail_circuit(id, message.clone(), false);
            return Err(TransportError::PollError { reason: message });
        }
        result.map_err(|error| TransportError::PollError {
            reason: error.to_string(),
        })
    }

    fn send_circuit(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Vec<u8>,
    ) -> Result<(), TransportError> {
        let stream = self.circuit_stream(id, stream_id)?;
        let mut circuit = self
            .circuits
            .remove(&id)
            .ok_or(TransportError::ConnectionNotFound { id })?;
        let Some(Phase::Ready {
            mut noise,
            mut yamux,
            peer,
        }) = circuit.phase.take()
        else {
            self.circuits.insert(id, circuit);
            return Err(TransportError::InvalidState {
                id,
                state: minip2p_transport::ConnectionState::Connecting,
                expected: minip2p_transport::ConnectionState::Connected,
            });
        };
        let result = yamux.send(stream, data);
        let drain = self.drain_yamux(&circuit, &mut noise, &mut yamux);
        circuit.phase = Some(Phase::Ready { noise, yamux, peer });
        self.circuits.insert(id, circuit);
        if let Err(message) = drain {
            self.fail_circuit(id, message.clone(), false);
            return Err(TransportError::StreamSendFailed {
                id,
                stream_id,
                reason: message,
            });
        }
        match result {
            Ok(()) => Ok(()),
            Err(YamuxError::SendBufferFull { .. }) => Err(TransportError::StreamSendFailed {
                id,
                stream_id,
                reason: "Yamux send buffer is full".to_string(),
            }),
            Err(error) => Err(TransportError::StreamSendFailed {
                id,
                stream_id,
                reason: error.to_string(),
            }),
        }
    }

    fn drain_pending_events(&mut self) -> Vec<TransportEvent> {
        self.pending.drain(..).collect()
    }
}

impl<T: Transport, E: EntropySource> Transport for CircuitTransport<T, E> {
    fn dial(&mut self, address: &minip2p_core::PeerAddr) -> Result<ConnectionId, TransportError> {
        let id = self.inner.dial(address)?;
        if is_circuit_id(id) {
            let _ = self.inner.close(id);
            return Err(TransportError::DialFailed {
                id,
                reason: "wrapped transport used the circuit connection-ID bit".to_string(),
            });
        }
        Ok(id)
    }

    fn listen(&mut self, address: &Multiaddr) -> Result<Multiaddr, TransportError> {
        self.inner.listen(address)
    }

    fn open_stream(&mut self, id: ConnectionId) -> Result<StreamId, TransportError> {
        if !is_circuit_id(id) {
            return self.inner.open_stream(id);
        }
        let stream = self.operate_ready(id, YamuxSession::open_stream)?;
        let stream_id = StreamId::new(u64::from(stream));
        self.pending
            .push_back(TransportEvent::StreamOpened { id, stream_id });
        Ok(stream_id)
    }

    fn send_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Vec<u8>,
    ) -> Result<(), TransportError> {
        if !is_circuit_id(id) {
            return self.inner.send_stream(id, stream_id, data);
        }
        self.send_circuit(id, stream_id, data)
    }

    fn close_stream_write(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        if !is_circuit_id(id) {
            return self.inner.close_stream_write(id, stream_id);
        }
        let stream = self.circuit_stream(id, stream_id)?;
        match self.operate_ready(id, |yamux| yamux.close_write(stream)) {
            Ok(()) => Ok(()),
            Err(error @ TransportError::ConnectionNotFound { .. })
            | Err(error @ TransportError::InvalidState { .. }) => Err(error),
            Err(error) => Err(TransportError::StreamCloseWriteFailed {
                id,
                stream_id,
                reason: error.to_string(),
            }),
        }
    }

    fn reset_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        if !is_circuit_id(id) {
            return self.inner.reset_stream(id, stream_id);
        }
        let stream = self.circuit_stream(id, stream_id)?;
        match self.operate_ready(id, |yamux| yamux.reset(stream)) {
            Ok(()) => Ok(()),
            Err(error @ TransportError::ConnectionNotFound { .. })
            | Err(error @ TransportError::InvalidState { .. }) => Err(error),
            Err(error) => Err(TransportError::StreamResetFailed {
                id,
                stream_id,
                reason: error.to_string(),
            }),
        }
    }

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        if !is_circuit_id(id) {
            return self.inner.close(id);
        }
        let mut circuit = self
            .circuits
            .remove(&id)
            .ok_or(TransportError::ConnectionNotFound { id })?;
        let key = circuit.bridge_key();
        self.bridge_index.remove(&key);
        self.retire_bridge(key);
        let ready = circuit.is_ready();
        let mut graceful = false;
        if let Some(Phase::Ready {
            mut noise,
            mut yamux,
            ..
        }) = circuit.phase.take()
        {
            yamux.go_away(0);
            graceful = self.drain_yamux(&circuit, &mut noise, &mut yamux).is_ok()
                && self
                    .inner
                    .close_stream_write(circuit.inner_conn, circuit.bridge_stream)
                    .is_ok();
        }
        if !ready || !graceful {
            let _ = self
                .inner
                .reset_stream(circuit.inner_conn, circuit.bridge_stream);
        }
        self.pending.push_back(TransportEvent::Closed { id });
        Ok(())
    }

    fn poll(&mut self) -> Result<Vec<TransportEvent>, TransportError> {
        if !self.pending.is_empty() {
            return Ok(self.drain_pending_events());
        }
        for event in self.inner.poll()? {
            self.handle_inner_event(event);
        }
        Ok(self.drain_pending_events())
    }

    fn next_timeout(&self) -> Option<Duration> {
        if self.pending.is_empty() {
            self.inner.next_timeout()
        } else {
            Some(Duration::ZERO)
        }
    }

    fn wait_for_input(&mut self, timeout: Duration) -> WaitOutcome {
        if self.pending.is_empty() {
            self.inner.wait_for_input(timeout)
        } else {
            WaitOutcome::Ready
        }
    }

    fn local_addresses(&self) -> Vec<Multiaddr> {
        self.inner.local_addresses()
    }

    fn active_inbound_connection_sources(&self) -> Vec<Multiaddr> {
        self.inner.active_inbound_connection_sources()
    }
}

#[cfg(feature = "std")]
impl<T> CircuitTransport<T, OsEntropy> {
    /// Wraps a transport using operating-system entropy.
    pub fn new_os(inner: T, identity: Ed25519Keypair) -> Self {
        Self::new(inner, identity, OsEntropy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use minip2p_test_support::InMemoryTransport;

    #[derive(Clone, Debug)]
    struct CounterEntropy(u8);

    impl EntropySource for CounterEntropy {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            self.0 = self.0.wrapping_add(1);
            destination.fill(self.0);
            Ok(())
        }
    }

    struct FailingEntropy;

    impl EntropySource for FailingEntropy {
        fn fill(&mut self, _destination: &mut [u8]) -> Result<(), EntropyError> {
            Err(EntropyError("injected failure"))
        }
    }

    struct CloseObservingTransport<T> {
        inner: T,
        fail_close_write: bool,
        close_write_calls: usize,
        reset_calls: usize,
    }

    impl<T> CloseObservingTransport<T> {
        fn new(inner: T) -> Self {
            Self {
                inner,
                fail_close_write: false,
                close_write_calls: 0,
                reset_calls: 0,
            }
        }
    }

    impl<T: Transport> Transport for CloseObservingTransport<T> {
        fn dial(
            &mut self,
            address: &minip2p_core::PeerAddr,
        ) -> Result<ConnectionId, TransportError> {
            self.inner.dial(address)
        }

        fn listen(&mut self, address: &Multiaddr) -> Result<Multiaddr, TransportError> {
            self.inner.listen(address)
        }

        fn open_stream(&mut self, id: ConnectionId) -> Result<StreamId, TransportError> {
            self.inner.open_stream(id)
        }

        fn send_stream(
            &mut self,
            id: ConnectionId,
            stream_id: StreamId,
            data: Vec<u8>,
        ) -> Result<(), TransportError> {
            self.inner.send_stream(id, stream_id, data)
        }

        fn close_stream_write(
            &mut self,
            id: ConnectionId,
            stream_id: StreamId,
        ) -> Result<(), TransportError> {
            self.close_write_calls += 1;
            if self.fail_close_write {
                return Err(TransportError::StreamCloseWriteFailed {
                    id,
                    stream_id,
                    reason: "injected FIN failure".to_string(),
                });
            }
            self.inner.close_stream_write(id, stream_id)
        }

        fn reset_stream(
            &mut self,
            id: ConnectionId,
            stream_id: StreamId,
        ) -> Result<(), TransportError> {
            self.reset_calls += 1;
            self.inner.reset_stream(id, stream_id)
        }

        fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
            self.inner.close(id)
        }

        fn poll(&mut self) -> Result<Vec<TransportEvent>, TransportError> {
            self.inner.poll()
        }

        fn next_timeout(&self) -> Option<Duration> {
            self.inner.next_timeout()
        }

        fn wait_for_input(&mut self, timeout: Duration) -> WaitOutcome {
            self.inner.wait_for_input(timeout)
        }

        fn local_addresses(&self) -> Vec<Multiaddr> {
            self.inner.local_addresses()
        }

        fn active_inbound_connection_sources(&self) -> Vec<Multiaddr> {
            self.inner.active_inbound_connection_sources()
        }
    }

    type CloseObservedCircuit =
        CircuitTransport<CloseObservingTransport<InMemoryTransport>, CounterEntropy>;
    type TestCircuit = CircuitTransport<InMemoryTransport, CounterEntropy>;
    type CloseObservedPair = (
        CloseObservedCircuit,
        TestCircuit,
        ConnectionId,
        StreamId,
        PeerId,
        PeerId,
    );

    fn identity(seed: u8) -> Ed25519Keypair {
        Ed25519Keypair::from_secret_key_bytes([seed; 32])
    }

    fn setup_pair_with_yamux_config(
        yamux_config: Option<YamuxConfig>,
    ) -> (
        CircuitTransport<InMemoryTransport, CounterEntropy>,
        CircuitTransport<InMemoryTransport, CounterEntropy>,
        ConnectionId,
        StreamId,
        PeerId,
        PeerId,
    ) {
        let relay = identity(9).peer_id();
        let a_identity = identity(1);
        let b_identity = identity(2);
        let a_peer = a_identity.peer_id();
        let b_peer = b_identity.peer_id();
        let (inner_a, inner_b) = InMemoryTransport::pair(relay.clone(), relay.clone());
        let inner_conn = inner_a.connection_id();
        let mut a = CircuitTransport::new(inner_a, a_identity, CounterEntropy(10));
        let mut b = CircuitTransport::new(inner_b, b_identity, CounterEntropy(20));
        if let Some(config) = yamux_config {
            a.set_yamux_config(config.clone());
            b.set_yamux_config(config);
        }

        let _ = a.poll().expect("initial A events");
        let _ = b.poll().expect("initial B events");
        let bridge = a.inner_mut().open_stream(inner_conn).expect("bridge open");
        let _ = a.poll().expect("local bridge event");
        let _ = b.poll().expect("remote bridge event");

        let a_id = a
            .adopt_bridge(BridgeAdoption {
                inner_conn,
                bridge_stream: bridge,
                relay: relay.clone(),
                remote_peer: b_peer.clone(),
                role: CircuitRole::Initiator,
                pending_data: Vec::new(),
                remote_write_closed: false,
            })
            .expect("initiator adoption");
        let b_id = b
            .adopt_bridge(BridgeAdoption {
                inner_conn,
                bridge_stream: bridge,
                relay,
                remote_peer: a_peer.clone(),
                role: CircuitRole::Responder,
                pending_data: Vec::new(),
                remote_write_closed: false,
            })
            .expect("responder adoption");
        // Circuit IDs are endpoint-local; synchronized test counters let the
        // pair helpers refer to both deterministic IDs with one value.
        assert_eq!(a_id, b_id);
        assert!(CircuitTransport::<InMemoryTransport, CounterEntropy>::is_circuit(a_id));
        let incoming = b.poll().expect("responder incoming");
        assert!(matches!(
            incoming.as_slice(),
            [TransportEvent::IncomingConnection { id, endpoint }]
                if *id == b_id && endpoint.peer_id().is_none()
        ));
        (a, b, a_id, bridge, a_peer, b_peer)
    }

    fn setup_pair() -> (
        CircuitTransport<InMemoryTransport, CounterEntropy>,
        CircuitTransport<InMemoryTransport, CounterEntropy>,
        ConnectionId,
        StreamId,
        PeerId,
        PeerId,
    ) {
        setup_pair_with_yamux_config(None)
    }

    fn setup_close_observed_pair() -> CloseObservedPair {
        let relay = identity(9).peer_id();
        let a_identity = identity(1);
        let b_identity = identity(2);
        let a_peer = a_identity.peer_id();
        let b_peer = b_identity.peer_id();
        let (inner_a, inner_b) = InMemoryTransport::pair(relay.clone(), relay.clone());
        let inner_conn = inner_a.connection_id();
        let mut a = CircuitTransport::new(
            CloseObservingTransport::new(inner_a),
            a_identity,
            CounterEntropy(10),
        );
        let mut b = CircuitTransport::new(inner_b, b_identity, CounterEntropy(20));
        let _ = a.poll().expect("initial A events");
        let _ = b.poll().expect("initial B events");
        let bridge = a.inner_mut().open_stream(inner_conn).expect("bridge open");
        let _ = a.poll().expect("local bridge event");
        let _ = b.poll().expect("remote bridge event");
        let a_id = a
            .adopt_bridge(BridgeAdoption {
                inner_conn,
                bridge_stream: bridge,
                relay: relay.clone(),
                remote_peer: b_peer.clone(),
                role: CircuitRole::Initiator,
                pending_data: Vec::new(),
                remote_write_closed: false,
            })
            .expect("initiator adoption");
        let b_id = b
            .adopt_bridge(BridgeAdoption {
                inner_conn,
                bridge_stream: bridge,
                relay,
                remote_peer: a_peer.clone(),
                role: CircuitRole::Responder,
                pending_data: Vec::new(),
                remote_write_closed: false,
            })
            .expect("responder adoption");
        // Circuit IDs are endpoint-local; synchronized test counters let the
        // pair helpers refer to both deterministic IDs with one value.
        assert_eq!(a_id, b_id);
        assert!(matches!(
            b.poll().expect("responder incoming").as_slice(),
            [TransportEvent::IncomingConnection { id, .. }] if *id == b_id
        ));
        (a, b, a_id, bridge, a_peer, b_peer)
    }

    fn complete_handshake<TA, EA, TB, EB>(
        a: &mut CircuitTransport<TA, EA>,
        b: &mut CircuitTransport<TB, EB>,
        circuit_id: ConnectionId,
        a_peer: &PeerId,
        b_peer: &PeerId,
    ) where
        TA: Transport,
        EA: EntropySource,
        TB: Transport,
        EB: EntropySource,
    {
        let mut a_connected = false;
        let mut b_connected = false;
        for _ in 0..32 {
            for event in a.poll().expect("drive initiator") {
                if let TransportEvent::Connected { id, endpoint } = event
                    && id == circuit_id
                {
                    assert_eq!(endpoint.peer_id(), Some(b_peer));
                    a_connected = true;
                }
            }
            for event in b.poll().expect("drive responder") {
                if let TransportEvent::Connected { id, endpoint } = event
                    && id == circuit_id
                {
                    assert_eq!(endpoint.peer_id(), Some(a_peer));
                    b_connected = true;
                }
            }
            if a_connected && b_connected {
                return;
            }
        }
        panic!("circuit handshake did not complete");
    }

    #[test]
    fn circuit_runs_noise_yamux_and_stream_contract() {
        let (mut a, mut b, circuit_id, _bridge, a_peer, b_peer) = setup_pair();
        complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);

        let stream = a.open_stream(circuit_id).expect("open circuit stream");
        assert_eq!(stream.as_u64() % 2, 1, "initiator streams are odd");
        assert!(a
            .poll()
            .expect("opened")
            .iter()
            .any(|event| matches!(event, TransportEvent::StreamOpened { id, stream_id } if *id == circuit_id && *stream_id == stream)));
        let incoming = b.poll().expect("incoming stream");
        assert!(incoming.iter().any(|event| matches!(event,
            TransportEvent::IncomingStream { id, stream_id }
                if *id == circuit_id && *stream_id == stream
        )));

        a.send_stream(circuit_id, stream, b"hello".to_vec())
            .expect("send");
        let data = b.poll().expect("data");
        assert!(data.iter().any(|event| matches!(event,
            TransportEvent::StreamData { id, stream_id, data }
                if *id == circuit_id && *stream_id == stream && data == b"hello"
        )));

        a.close_stream_write(circuit_id, stream).expect("FIN");
        let eof = b.poll().expect("remote FIN");
        assert!(eof.iter().any(|event| matches!(event,
            TransportEvent::StreamRemoteWriteClosed { id, stream_id }
                if *id == circuit_id && *stream_id == stream
        )));
        b.send_stream(circuit_id, stream, b"reply".to_vec())
            .expect("reverse send remains open");
        let reply = a.poll().expect("reply");
        assert!(reply.iter().any(|event| matches!(event,
            TransportEvent::StreamData { data, .. } if data == b"reply"
        )));

        b.reset_stream(circuit_id, stream).expect("reset");
        let local_closed = b.poll().expect("local reset close");
        assert_eq!(
            local_closed
                .iter()
                .filter(|event| matches!(event, TransportEvent::StreamClosed { id, stream_id } if *id == circuit_id && *stream_id == stream))
                .count(),
            1
        );
        let remote_closed = a.poll().expect("remote reset close");
        assert!(remote_closed.iter().any(|event| matches!(event,
            TransportEvent::StreamClosed { id, stream_id }
                if *id == circuit_id && *stream_id == stream
        )));
    }

    #[test]
    fn wrapper_transport_contract_orders_connection_and_stream_events() {
        let (mut a, mut b, circuit_id, _bridge, a_peer, b_peer) = setup_pair();
        let mut a_events = Vec::new();
        let mut b_events = Vec::new();
        for _ in 0..32 {
            a_events.extend(a.poll().expect("drive initiator"));
            b_events.extend(b.poll().expect("drive responder"));
            let a_connected = a_events.iter().any(
                |event| matches!(event, TransportEvent::Connected { id, .. } if *id == circuit_id),
            );
            let b_connected = b_events.iter().any(
                |event| matches!(event, TransportEvent::Connected { id, .. } if *id == circuit_id),
            );
            if a_connected && b_connected {
                break;
            }
        }
        for (events, expected_peer) in [(&a_events, &b_peer), (&b_events, &a_peer)] {
            assert_eq!(
                events
                    .iter()
                    .filter(|event| matches!(event, TransportEvent::Connected { id, .. } if *id == circuit_id))
                    .count(),
                1,
                "Connected must be emitted exactly once"
            );
            let connected = events
                .iter()
                .position(|event| {
                    matches!(event,
                        TransportEvent::Connected { id, endpoint }
                            if *id == circuit_id && endpoint.peer_id() == Some(expected_peer)
                    )
                })
                .expect("authenticated Connected event");
            assert!(!events[..connected].iter().any(|event| matches!(
                event,
                TransportEvent::StreamOpened { id, .. }
                    | TransportEvent::IncomingStream { id, .. }
                    | TransportEvent::StreamData { id, .. }
                    | TransportEvent::StreamRemoteWriteClosed { id, .. }
                    | TransportEvent::StreamClosed { id, .. }
                    if *id == circuit_id
            )));
        }
        assert!(a.poll().expect("idle initiator").is_empty());
        assert!(b.poll().expect("idle responder").is_empty());

        let stream = a.open_stream(circuit_id).expect("open stream");
        a.send_stream(circuit_id, stream, b"ordered".to_vec())
            .expect("send immediately after open");
        assert_eq!(
            a.poll().expect("local stream event"),
            [TransportEvent::StreamOpened {
                id: circuit_id,
                stream_id: stream,
            }]
        );
        let inbound = b.poll().expect("coalesced stream open and data");
        let incoming = inbound
            .iter()
            .position(|event| {
                matches!(event,
                    TransportEvent::IncomingStream { id, stream_id }
                        if *id == circuit_id && *stream_id == stream
                )
            })
            .expect("IncomingStream event");
        let data = inbound
            .iter()
            .position(|event| {
                matches!(event,
                    TransportEvent::StreamData { id, stream_id, data }
                        if *id == circuit_id && *stream_id == stream && data == b"ordered"
                )
            })
            .expect("StreamData event");
        assert!(incoming < data, "IncomingStream must precede StreamData");

        a.reset_stream(circuit_id, stream).expect("reset stream");
        assert_eq!(
            a.poll().expect("immediate local terminal event"),
            [TransportEvent::StreamClosed {
                id: circuit_id,
                stream_id: stream,
            }]
        );
        assert_eq!(
            b.poll().expect("remote terminal event"),
            [TransportEvent::StreamClosed {
                id: circuit_id,
                stream_id: stream,
            }]
        );
        assert!(a.poll().expect("no events after local terminal").is_empty());
        assert!(
            b.poll()
                .expect("no events after remote terminal")
                .is_empty()
        );
    }

    #[test]
    fn wrapper_transport_contract_rejects_unknown_connection_and_stream_ids() {
        let (mut a, mut b, circuit_id, _bridge, a_peer, b_peer) = setup_pair();
        complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
        let unknown_connection = ConnectionId::new(CIRCUIT_ID_BIT | 999);
        let stream = StreamId::new(99);

        assert!(matches!(
            a.open_stream(unknown_connection),
            Err(TransportError::ConnectionNotFound { id }) if id == unknown_connection
        ));
        assert!(matches!(
            a.send_stream(unknown_connection, stream, vec![1]),
            Err(TransportError::ConnectionNotFound { id }) if id == unknown_connection
        ));
        assert!(matches!(
            a.close_stream_write(unknown_connection, stream),
            Err(TransportError::ConnectionNotFound { id }) if id == unknown_connection
        ));
        assert!(matches!(
            a.reset_stream(unknown_connection, stream),
            Err(TransportError::ConnectionNotFound { id }) if id == unknown_connection
        ));
        assert_eq!(
            a.close(unknown_connection),
            Err(TransportError::ConnectionNotFound {
                id: unknown_connection,
            })
        );

        let oversized_stream = StreamId::new(u64::from(u32::MAX) + 1);
        assert_eq!(
            a.send_stream(unknown_connection, oversized_stream, vec![1]),
            Err(TransportError::ConnectionNotFound {
                id: unknown_connection,
            })
        );
        assert_eq!(
            a.close_stream_write(unknown_connection, oversized_stream),
            Err(TransportError::ConnectionNotFound {
                id: unknown_connection,
            })
        );
        assert_eq!(
            a.reset_stream(unknown_connection, oversized_stream),
            Err(TransportError::ConnectionNotFound {
                id: unknown_connection,
            })
        );

        assert!(matches!(
            a.send_stream(circuit_id, stream, vec![1]),
            Err(TransportError::StreamSendFailed { id, stream_id, .. })
                if id == circuit_id && stream_id == stream
        ));
        assert!(matches!(
            a.close_stream_write(circuit_id, stream),
            Err(TransportError::StreamCloseWriteFailed { id, stream_id, .. })
                if id == circuit_id && stream_id == stream
        ));
        assert!(matches!(
            a.reset_stream(circuit_id, stream),
            Err(TransportError::StreamResetFailed { id, stream_id, .. })
                if id == circuit_id && stream_id == stream
        ));
    }

    #[test]
    fn adoption_processes_pending_bridge_bytes_before_live_input() {
        let relay = identity(9).peer_id();
        let a_identity = identity(1);
        let b_identity = identity(2);
        let a_peer = a_identity.peer_id();
        let b_peer = b_identity.peer_id();
        let (inner_a, inner_b) = InMemoryTransport::pair(relay.clone(), relay.clone());
        let inner_conn = inner_a.connection_id();
        let mut a = CircuitTransport::new(inner_a, a_identity, CounterEntropy(10));
        let mut b = CircuitTransport::new(inner_b, b_identity, CounterEntropy(20));
        let _ = a.poll().expect("initial A events");
        let _ = b.poll().expect("initial B events");
        let bridge = a.inner_mut().open_stream(inner_conn).expect("bridge open");
        let _ = a.poll().expect("local bridge event");
        let _ = b.poll().expect("remote bridge event");
        let circuit_id = a
            .adopt_bridge(BridgeAdoption {
                inner_conn,
                bridge_stream: bridge,
                relay: relay.clone(),
                remote_peer: b_peer.clone(),
                role: CircuitRole::Initiator,
                pending_data: Vec::new(),
                remote_write_closed: false,
            })
            .expect("initiator adoption");
        let header = b
            .inner_mut()
            .poll()
            .expect("read pipelined header")
            .into_iter()
            .find_map(|event| match event {
                TransportEvent::StreamData { data, .. } => Some(data),
                _ => None,
            })
            .expect("initiator multistream header");
        let split = header.len() / 2;
        b.adopt_bridge(BridgeAdoption {
            inner_conn,
            bridge_stream: bridge,
            relay,
            remote_peer: a_peer.clone(),
            role: CircuitRole::Responder,
            pending_data: header[..split].to_vec(),
            remote_write_closed: false,
        })
        .expect("responder adoption with partial pending data");
        assert!(matches!(
            b.poll().expect("incoming event").as_slice(),
            [TransportEvent::IncomingConnection { .. }]
        ));
        b.inject_bridge_data(inner_conn, bridge, header[split..].to_vec());
        complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
    }

    #[test]
    fn adoption_processes_pipelined_selection_and_noise_message() {
        let relay = identity(9).peer_id();
        let a_identity = identity(1);
        let b_identity = identity(2);
        let a_peer = a_identity.peer_id();
        let b_peer = b_identity.peer_id();
        let (inner_a, inner_b) = InMemoryTransport::pair(relay.clone(), relay.clone());
        let inner_conn = inner_a.connection_id();
        let mut a = CircuitTransport::new(inner_a, a_identity.clone(), CounterEntropy(10));
        let mut b = CircuitTransport::new(inner_b, b_identity, CounterEntropy(20));
        let _ = a.poll().expect("initial A events");
        let _ = b.poll().expect("initial B events");
        let bridge = a.inner_mut().open_stream(inner_conn).expect("bridge open");
        let _ = a.poll().expect("local bridge event");
        let _ = b.poll().expect("remote bridge event");

        let mut select = MultistreamSelect::dialer(NOISE_PROTOCOL_ID);
        select
            .handle_input(MultistreamInput::Start)
            .expect("scripted multistream start");
        let mut pending_data = Vec::new();
        while let Some(output) = select.poll_output() {
            if let MultistreamOutput::OutboundData(bytes) = output {
                pending_data.extend(bytes);
            }
        }
        let mut scripted_listener = MultistreamSelect::listener([NOISE_PROTOCOL_ID.to_string()]);
        scripted_listener
            .handle_input(MultistreamInput::Start)
            .expect("scripted listener start");
        let listener_header = match scripted_listener.poll_output() {
            Some(MultistreamOutput::OutboundData(bytes)) => bytes,
            other => panic!("expected listener header, got {other:?}"),
        };
        select
            .handle_input(MultistreamInput::Data(listener_header))
            .expect("scripted dialer receives listener header");
        while let Some(output) = select.poll_output() {
            if let MultistreamOutput::OutboundData(bytes) = output {
                pending_data.extend(bytes);
            }
        }
        let selection_len = pending_data.len();
        let mut scripted_noise = NoiseSession::new(NoiseConfig {
            role: NoiseRole::Initiator,
            identity: a_identity,
            static_secret: [11; 32],
            ephemeral_secret: [12; 32],
            expected_peer: Some(b_peer.clone()),
        });
        scripted_noise
            .handle_input(NoiseInput::Start)
            .expect("scripted Noise start");
        while let Some(output) = scripted_noise.poll_output() {
            if let NoiseOutput::Outbound(bytes) = output {
                pending_data.extend(bytes);
            }
        }
        assert!(selection_len > 0 && pending_data.len() > selection_len);

        let circuit_id = b
            .adopt_bridge(BridgeAdoption {
                inner_conn,
                bridge_stream: bridge,
                relay: relay.clone(),
                remote_peer: a_peer.clone(),
                role: CircuitRole::Responder,
                pending_data,
                remote_write_closed: false,
            })
            .expect("responder adopts pipelined selection and Noise msg1");
        let responder_events = b.poll().expect("responder incoming event");
        assert!(
            matches!(
                responder_events.as_slice(),
                [TransportEvent::IncomingConnection { id, .. }] if *id == circuit_id
            ),
            "unexpected pipelined adoption events: {responder_events:?}"
        );

        let a_id = a
            .adopt_bridge(BridgeAdoption {
                inner_conn,
                bridge_stream: bridge,
                relay,
                remote_peer: b_peer.clone(),
                role: CircuitRole::Initiator,
                pending_data: Vec::new(),
                remote_write_closed: false,
            })
            .expect("real initiator adoption");
        assert_eq!(a_id, circuit_id);

        // The responder already consumed the scripted copy of the dialer's
        // selection and msg1, so discard the identical selection emitted by
        // the real initiator before letting it consume the responder reply.
        let duplicate_selection = b.inner_mut().poll().expect("duplicate selection");
        assert!(
            duplicate_selection
                .iter()
                .any(|event| matches!(event, TransportEvent::StreamData { .. }))
        );
        let _ = a.poll().expect("initiator consumes pipelined response");

        // Receiving the real selection reply emits the duplicate protocol
        // proposal and Noise msg1 before msg3 and the encrypted Yamux
        // selection. Drop those first two data events, then route the
        // remaining bridge events through the wrapper.
        let mut real_followup = b.inner_mut().poll().expect("real Noise follow-up");
        for expected in ["protocol proposal", "Noise msg1"] {
            let duplicate = real_followup
                .iter()
                .position(|event| matches!(event, TransportEvent::StreamData { .. }))
                .unwrap_or_else(|| panic!("duplicate {expected}"));
            real_followup.remove(duplicate);
        }
        for event in real_followup {
            b.handle_inner_event(event);
        }

        complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
    }

    #[test]
    fn decrypt_batch_crosses_yamux_selection_into_ready_frames() {
        let (mut a, mut b, circuit_id, bridge, _a_peer, _b_peer) = setup_pair();

        // Stop immediately after B reaches Ready. Its encrypted Yamux
        // selection confirmation is now queued for A, which is still in
        // SelectYamux and has not consumed that ciphertext yet.
        for _ in 0..32 {
            let _ = a.poll().expect("drive initiator toward Yamux selection");
            let _ = b.poll().expect("drive responder toward Yamux selection");
            let a_selecting = matches!(
                a.circuits.get(&circuit_id).and_then(|c| c.phase.as_ref()),
                Some(Phase::SelectYamux { .. })
            );
            let b_ready = matches!(
                b.circuits.get(&circuit_id).and_then(|c| c.phase.as_ref()),
                Some(Phase::Ready { .. })
            );
            if a_selecting && b_ready {
                break;
            }
        }
        assert!(matches!(
            a.circuits.get(&circuit_id).and_then(|c| c.phase.as_ref()),
            Some(Phase::SelectYamux { .. })
        ));
        assert!(matches!(
            b.circuits.get(&circuit_id).and_then(|c| c.phase.as_ref()),
            Some(Phase::Ready { .. })
        ));

        // Queue a Yamux SYN behind the already-encrypted selection reply,
        // then combine both Noise transport frames into one bridge read.
        // Noise decrypts them as two plaintexts in one output batch: the
        // first transitions A to Ready and the second must be routed through
        // that newly-created Ready state.
        let opened = b.open_stream(circuit_id).expect("open responder stream");
        let raw = a.inner_mut().poll().expect("read encrypted bridge batch");
        let chunks: Vec<_> = raw
            .into_iter()
            .filter_map(|event| match event {
                TransportEvent::StreamData {
                    stream_id, data, ..
                } if stream_id == bridge => Some(data),
                _ => None,
            })
            .collect();
        assert!(chunks.len() >= 2, "expected selection and Yamux frames");
        let coalesced = chunks.into_iter().flatten().collect();
        let inner_conn = a
            .circuits
            .get(&circuit_id)
            .expect("initiator circuit")
            .inner_conn;
        a.inject_bridge_data(inner_conn, bridge, coalesced);

        let events = a.poll().expect("drain cross-boundary outputs");
        assert!(events.iter().any(
            |event| matches!(event, TransportEvent::Connected { id, .. } if *id == circuit_id)
        ));
        assert!(events.iter().any(|event| matches!(
            event,
            TransportEvent::IncomingStream { id, stream_id }
                if *id == circuit_id && *stream_id == opened
        )));
    }

    fn assert_pre_ready_bridge_failure(events: &[TransportEvent], circuit_id: ConnectionId) {
        assert!(matches!(
            events,
            [
                TransportEvent::Error { id: error_id, .. },
                TransportEvent::Closed { id: closed_id },
            ] if *error_id == circuit_id && *closed_id == circuit_id
        ));
        assert!(!events.iter().any(|event| matches!(
            event,
            TransportEvent::Connected { id, .. } if *id == circuit_id
        )));
    }

    #[test]
    fn bridge_reset_mid_handshake_is_terminal() {
        let (mut a, _b, circuit_id, bridge, _a_peer, _b_peer) = setup_pair();
        let inner_conn = ConnectionId::new(1);

        a.inject_bridge_closed(inner_conn, bridge);
        let events = a.poll().expect("pre-ready bridge reset");
        assert_pre_ready_bridge_failure(&events, circuit_id);
        assert!(a.poll().expect("consume reset acknowledgement").is_empty());

        a.inject_bridge_data(inner_conn, bridge, b"late".to_vec());
        a.inject_bridge_remote_write_closed(inner_conn, bridge);
        a.inject_bridge_closed(inner_conn, bridge);
        assert!(a.poll().expect("nothing follows terminal close").is_empty());
    }

    #[test]
    fn bridge_remote_fin_mid_handshake_is_terminal() {
        let (mut a, _b, circuit_id, bridge, _a_peer, _b_peer) = setup_pair();
        let inner_conn = ConnectionId::new(1);

        a.inject_bridge_remote_write_closed(inner_conn, bridge);
        let events = a.poll().expect("pre-ready bridge FIN");
        assert_pre_ready_bridge_failure(&events, circuit_id);
        assert!(a.poll().expect("consume reset acknowledgement").is_empty());

        a.inject_bridge_data(inner_conn, bridge, b"late".to_vec());
        assert!(a.poll().expect("post-close data is ignored").is_empty());
    }

    #[test]
    fn adoption_is_idempotent_and_close_is_terminal() {
        let (mut a, mut b, circuit_id, bridge, a_peer, b_peer) = setup_pair();
        let relay = identity(9).peer_id();
        let duplicate = a
            .adopt_bridge(BridgeAdoption {
                inner_conn: ConnectionId::new(1),
                bridge_stream: bridge,
                relay: relay.clone(),
                remote_peer: b_peer.clone(),
                role: CircuitRole::Initiator,
                pending_data: Vec::new(),
                remote_write_closed: false,
            })
            .expect("identical duplicate is idempotent");
        assert_eq!(duplicate, circuit_id);
        assert_eq!(
            a.adopt_bridge(BridgeAdoption {
                inner_conn: ConnectionId::new(1),
                bridge_stream: bridge,
                relay: identity(8).peer_id(),
                remote_peer: b_peer.clone(),
                role: CircuitRole::Initiator,
                pending_data: Vec::new(),
                remote_write_closed: false,
            }),
            Err(AdoptError::ConflictingAdoption)
        );
        assert_eq!(
            a.adopt_bridge(BridgeAdoption {
                inner_conn: ConnectionId::new(1),
                bridge_stream: bridge,
                relay,
                remote_peer: b_peer.clone(),
                role: CircuitRole::Initiator,
                pending_data: Vec::new(),
                remote_write_closed: true,
            }),
            Err(AdoptError::ConflictingAdoption)
        );
        complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
        a.close(circuit_id).expect("graceful close");
        let events = a.poll().expect("closed event");
        assert_eq!(events, vec![TransportEvent::Closed { id: circuit_id }]);
        assert!(matches!(
            a.open_stream(circuit_id),
            Err(TransportError::ConnectionNotFound { .. })
        ));
        a.inject_bridge_data(ConnectionId::new(1), bridge, b"late".to_vec());
        a.inject_bridge_remote_write_closed(ConnectionId::new(1), bridge);
        a.inject_bridge_closed(ConnectionId::new(1), bridge);
        assert!(a.poll().expect("late bridge events are dropped").is_empty());
    }

    #[test]
    fn ready_close_sends_go_away_then_bridge_fin_without_reset() {
        let (mut a, mut b, circuit_id, _bridge, a_peer, b_peer) = setup_close_observed_pair();
        complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
        let stream = a.open_stream(circuit_id).expect("open stream before close");
        let _ = a.poll().expect("local stream open");
        let _ = b.poll().expect("remote stream open");
        let _ = a.poll().expect("stream acknowledgement");
        a.send_stream(circuit_id, stream, b"queued-before-close".to_vec())
            .expect("queue application data before close");

        a.close(circuit_id).expect("graceful circuit close");
        assert_eq!(a.inner().close_write_calls, 1);
        assert_eq!(a.inner().reset_calls, 0);
        assert_eq!(
            a.poll().expect("local close event"),
            [
                TransportEvent::StreamClosed {
                    id: circuit_id,
                    stream_id: stream,
                },
                TransportEvent::Closed { id: circuit_id },
            ]
        );

        let peer_wire = b.inner_mut().poll().expect("peer bridge events");
        let data_positions: Vec<_> = peer_wire
            .iter()
            .enumerate()
            .filter_map(|(index, event)| {
                matches!(event, TransportEvent::StreamData { .. }).then_some(index)
            })
            .collect();
        assert_eq!(
            data_positions.len(),
            2,
            "application data and encrypted GoAway must both reach the peer"
        );
        let go_away = data_positions[1];
        let fin = peer_wire
            .iter()
            .position(|event| matches!(event, TransportEvent::StreamRemoteWriteClosed { .. }))
            .expect("bridge FIN reaches the peer");
        assert!(go_away < fin, "GoAway must be queued before bridge FIN");
        assert!(
            !peer_wire
                .iter()
                .any(|event| matches!(event, TransportEvent::StreamClosed { .. }))
        );
        for event in peer_wire {
            b.handle_inner_event(event);
        }
        let peer_events = b.poll().expect("peer observes data then GoAway");
        assert!(
            matches!(
                peer_events.as_slice(),
                [
                    TransportEvent::StreamData { id, stream_id, data },
                    TransportEvent::Closed { id: closed_id },
                ] if *id == circuit_id
                    && *stream_id == stream
                    && data == b"queued-before-close"
                    && *closed_id == circuit_id
            ),
            "unexpected peer close events: {peer_events:?}"
        );
        assert!(b.poll().expect("terminal peer state").is_empty());
    }

    #[test]
    fn gracefully_closed_bridge_tombstones_are_bounded() {
        let (mut a, mut b, circuit_id, bridge, a_peer, b_peer) = setup_close_observed_pair();
        complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
        let inner_conn = ConnectionId::new(1);

        a.close(circuit_id).expect("graceful circuit close");
        let _ = a.poll().expect("local close event");
        assert!(a.retired_bridges.contains(&(inner_conn, bridge)));

        for index in 0..MAX_RETIRED_BRIDGES {
            a.retire_bridge((
                inner_conn,
                StreamId::new(10_000 + u64::try_from(index).expect("usize fits u64")),
            ));
        }

        assert_eq!(a.retired_bridges.len(), MAX_RETIRED_BRIDGES);
        assert_eq!(a.retired_bridge_order.len(), MAX_RETIRED_BRIDGES);
        assert!(!a.retired_bridges.contains(&(inner_conn, bridge)));
    }

    #[test]
    fn ready_close_resets_bridge_when_fin_fails() {
        let (mut a, mut b, circuit_id, _bridge, a_peer, b_peer) = setup_close_observed_pair();
        complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
        a.inner_mut().fail_close_write = true;

        a.close(circuit_id).expect("fallback circuit close");
        assert_eq!(a.inner().close_write_calls, 1);
        assert_eq!(a.inner().reset_calls, 1);
        assert_eq!(
            a.poll().expect("local close event"),
            [TransportEvent::Closed { id: circuit_id }]
        );

        let peer_wire = b.inner_mut().poll().expect("peer bridge events");
        assert!(
            peer_wire
                .iter()
                .any(|event| matches!(event, TransportEvent::StreamData { .. }))
        );
        assert!(
            peer_wire
                .iter()
                .any(|event| matches!(event, TransportEvent::StreamClosed { .. }))
        );
        assert!(
            !peer_wire
                .iter()
                .any(|event| matches!(event, TransportEvent::StreamRemoteWriteClosed { .. }))
        );
        for event in peer_wire {
            b.handle_inner_event(event);
        }
        assert_eq!(
            b.poll().expect("peer observes terminal close"),
            [TransportEvent::Closed { id: circuit_id }]
        );
    }

    #[test]
    fn close_before_ready_resets_bridge_and_is_terminal() {
        let (mut a, _b, circuit_id, bridge, _a_peer, _b_peer) = setup_close_observed_pair();
        let inner_conn = ConnectionId::new(1);

        a.close(circuit_id).expect("pre-ready close");
        assert_eq!(a.inner().close_write_calls, 0);
        assert_eq!(a.inner().reset_calls, 1);
        assert_eq!(
            a.poll().expect("pre-ready close event"),
            [TransportEvent::Closed { id: circuit_id }]
        );
        assert_eq!(
            a.close(circuit_id),
            Err(TransportError::ConnectionNotFound { id: circuit_id })
        );
        assert!(a.poll().expect("consume reset acknowledgement").is_empty());
        a.inject_bridge_data(inner_conn, bridge, b"late".to_vec());
        assert!(a.poll().expect("post-close data is ignored").is_empty());
    }

    #[test]
    fn relay_connection_close_closes_each_ready_circuit_once() {
        let (mut a, mut b, circuit_id, _bridge, a_peer, b_peer) = setup_pair();
        complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);
        let stream = a
            .open_stream(circuit_id)
            .expect("open stream before relay loss");
        let _ = a.poll().expect("local stream open");
        let _ = b.poll().expect("remote stream open");

        a.inner_mut()
            .close(ConnectionId::new(1))
            .expect("relay connection closes");
        let events = a.poll().expect("relay close mapping");
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, TransportEvent::Closed { id } if *id == circuit_id))
                .count(),
            1
        );
        assert!(events.iter().any(|event| matches!(
            event,
            TransportEvent::Closed { id } if *id == ConnectionId::new(1)
        )));
        assert!(!events.iter().any(|event| matches!(
            event,
            TransportEvent::StreamClosed { id, stream_id }
                if *id == circuit_id && *stream_id == stream
        )));
        assert!(a.poll().expect("relay close is terminal").is_empty());
    }

    #[test]
    fn yamux_backpressure_is_stream_scoped_and_session_survives() {
        let receive_window = 256 * 1024;
        let max_buffered_send = 64;
        let config = YamuxConfig {
            receive_window,
            max_frame_len: 64 * 1024,
            max_streams: 8,
            max_buffered_send,
            max_total_buffered_send: 128,
        };
        let (mut a, mut b, circuit_id, _bridge, a_peer, b_peer) =
            setup_pair_with_yamux_config(Some(config));
        complete_handshake(&mut a, &mut b, circuit_id, &a_peer, &b_peer);

        let initiator_stream = a.open_stream(circuit_id).expect("initiator stream");
        assert_eq!(initiator_stream.as_u64() % 2, 1);
        let _ = a.poll().expect("local open");
        let _ = b.poll().expect("remote open");

        let error = a
            .send_stream(
                circuit_id,
                initiator_stream,
                vec![0; receive_window as usize + max_buffered_send + 1],
            )
            .expect_err("send beyond the Yamux queue cap");
        assert!(matches!(error, TransportError::StreamSendFailed { .. }));
        a.send_stream(circuit_id, initiator_stream, b"still-alive".to_vec())
            .expect("backpressure must not poison the stream");
        assert!(b.poll().expect("small data").iter().any(|event| matches!(
            event,
            TransportEvent::StreamData { data, .. } if data == b"still-alive"
        )));

        let responder_stream = b.open_stream(circuit_id).expect("responder stream");
        assert_eq!(responder_stream.as_u64() % 2, 0);
    }

    #[test]
    fn adoption_rejects_invalid_preconditions_without_consuming_ids() {
        let relay = identity(9).peer_id();
        let local = identity(1);
        let remote = identity(2).peer_id();
        let (inner, _) = InMemoryTransport::pair(local.peer_id(), relay.clone());
        let mut transport = CircuitTransport::new(inner, local, CounterEntropy(1));
        assert_eq!(
            transport.adopt_bridge(BridgeAdoption {
                inner_conn: ConnectionId::new(99),
                bridge_stream: StreamId::new(1),
                relay,
                remote_peer: remote,
                role: CircuitRole::Initiator,
                pending_data: Vec::new(),
                remote_write_closed: false,
            }),
            Err(AdoptError::UnknownConnection)
        );
        assert!(transport.circuit_ids().is_empty());
    }

    #[test]
    fn direct_connection_wins_before_and_during_circuit_handshake() {
        let local = identity(1);
        let remote = identity(2).peer_id();
        let relay = identity(9).peer_id();
        let (inner, _) = InMemoryTransport::pair(local.peer_id(), remote.clone());
        let mut direct_first = CircuitTransport::new(inner, local, CounterEntropy(1));
        let _ = direct_first.poll().expect("record direct connection");
        assert_eq!(
            direct_first.adopt_bridge(BridgeAdoption {
                inner_conn: ConnectionId::new(1),
                bridge_stream: StreamId::new(1),
                relay: relay.clone(),
                remote_peer: remote.clone(),
                role: CircuitRole::Initiator,
                pending_data: Vec::new(),
                remote_write_closed: false,
            }),
            Err(AdoptError::PeerAlreadyDirect)
        );

        let (mut a, _b, circuit_id, _bridge, _a_peer, b_peer) = setup_pair();
        a.inner_mut().push_event(TransportEvent::Connected {
            id: ConnectionId::new(2),
            endpoint: ConnectionEndpoint::with_peer_id(
                "/ip4/198.51.100.1/udp/5001/quic-v1"
                    .parse()
                    .expect("direct endpoint"),
                b_peer,
            ),
        });
        let events = a.poll().expect("direct connection arrives");
        assert!(events.iter().any(|event| matches!(
            event,
            TransportEvent::Error { id, .. } if *id == circuit_id
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            TransportEvent::Closed { id } if *id == circuit_id
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            TransportEvent::Connected { id, .. } if *id == ConnectionId::new(2)
        )));
    }

    #[test]
    fn adoption_failures_leave_bridge_and_identifier_ownership_with_caller() {
        let local = identity(1);
        let remote = identity(2).peer_id();
        let relay = identity(9).peer_id();
        let (inner, _) = InMemoryTransport::pair(local.peer_id(), relay.clone());
        let mut transport = CircuitTransport::new(inner, local, FailingEntropy);
        let _ = transport.poll().expect("activate wrapped connection");
        let adoption = BridgeAdoption {
            inner_conn: ConnectionId::new(1),
            bridge_stream: StreamId::new(7),
            relay,
            remote_peer: remote,
            role: CircuitRole::Initiator,
            pending_data: Vec::new(),
            remote_write_closed: false,
        };
        assert!(matches!(
            transport.adopt_bridge(adoption.clone()),
            Err(AdoptError::Entropy(_))
        ));
        assert!(transport.circuit_ids().is_empty());
        assert_eq!(
            transport.adopt_bridge(BridgeAdoption {
                remote_write_closed: true,
                ..adoption.clone()
            }),
            Err(AdoptError::RemoteWriteClosed)
        );
        assert!(transport.circuit_ids().is_empty());
        transport.next_circuit_id = None;
        assert_eq!(
            transport.adopt_bridge(BridgeAdoption {
                remote_write_closed: false,
                ..adoption
            }),
            Err(AdoptError::IdsExhausted)
        );
    }

    #[test]
    fn wrapped_high_bit_ids_are_rejected_without_becoming_circuits() {
        let local = identity(1);
        let relay = identity(9).peer_id();
        let (inner, _) = InMemoryTransport::pair(local.peer_id(), relay);
        let mut transport = CircuitTransport::new(inner, local, CounterEntropy(1));
        let _ = transport.poll().expect("initial direct event");
        // InMemoryTransport::dial is intentionally stubbed, so this fixture
        // covers polled collisions; dial-return collisions need a dial fake.
        let collision = ConnectionId::new(CIRCUIT_ID_BIT | 77);
        transport
            .inner_mut()
            .push_event(TransportEvent::IncomingConnection {
                id: collision,
                endpoint: ConnectionEndpoint::new(
                    "/ip4/203.0.113.7/udp/7007/quic-v1"
                        .parse()
                        .expect("collision endpoint"),
                ),
            });
        let events = transport.poll().expect("collision event");
        assert_eq!(
            events,
            vec![TransportEvent::Error {
                id: collision,
                message: "wrapped transport used the circuit connection-ID bit".to_string(),
            }]
        );
        assert!(transport.circuit_ids().is_empty());
    }
}
