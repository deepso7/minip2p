//! Runtime-only helpers for the demo CLI.

use std::error::Error;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use minip2p_core::{Multiaddr, PeerAddr, Protocol};
use minip2p_identity::{ED25519_SECRET_KEY_LENGTH, Ed25519Keypair};
use minip2p_quic::{QuicNodeConfig, QuicTransport};
use minip2p_transport::{ConnectionId, StreamId, Transport, TransportError, TransportEvent};

use crate::cli::RunOptions;

const DEFAULT_IPV4_BIND: &str = "0.0.0.0:0";
const DEFAULT_IPV6_BIND: &str = "[::]:0";

/// Loads a persistent key from `--key`, or generates and writes one when missing.
pub fn load_keypair(options: &RunOptions, role: &str) -> Result<Ed25519Keypair, Box<dyn Error>> {
    let Some(path) = &options.key_path else {
        let keypair = Ed25519Keypair::generate();
        println!("[{role}] peer={} identity=ephemeral", keypair.peer_id());
        return Ok(keypair);
    };

    if path.exists() {
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("failed to read key file {}: {e}", path.display()))?;
        let secret = decode_secret(raw.trim())
            .map_err(|e| format!("invalid key file {}: {e}", path.display()))?;
        let keypair = Ed25519Keypair::from_secret_key_bytes(secret);
        println!(
            "[{role}] peer={} identity={} persisted=loaded",
            keypair.peer_id(),
            path.display()
        );
        return Ok(keypair);
    }

    let keypair = Ed25519Keypair::generate();
    write_secret(path, &keypair.secret_key_bytes())?;
    println!(
        "[{role}] peer={} identity={} persisted=created",
        keypair.peer_id(),
        path.display()
    );
    Ok(keypair)
}

/// Builds the peer CLI's QUIC transport.
///
/// With an explicit `--listen`, bind exactly that address. With no explicit
/// listen address, bind IPv4 and IPv6 sockets so the demo is reachable on both
/// address families by default.
pub fn build_peer_transport(
    options: &RunOptions,
    keypair: &Ed25519Keypair,
) -> Result<PeerTransport, Box<dyn Error>> {
    let config = QuicNodeConfig::new(keypair.clone());
    if let Some(addr) = &options.listen_addr {
        let bind = multiaddr_to_socket_addr(addr)?.to_string();
        let transport =
            QuicTransport::new(config, &bind).map_err(|e| format!("quic bind {bind}: {e}"))?;
        return Ok(PeerTransport::Single(transport));
    }

    let ipv4 = QuicTransport::new(config.clone(), DEFAULT_IPV4_BIND)
        .map_err(|e| format!("quic bind {DEFAULT_IPV4_BIND}: {e}"))?;
    let ipv6 = QuicTransport::new(config, DEFAULT_IPV6_BIND)
        .map_err(|e| format!("quic bind {DEFAULT_IPV6_BIND}: {e}"))?;
    Ok(PeerTransport::Dual(DualQuicTransport { ipv4, ipv6 }))
}

pub enum PeerTransport {
    Single(QuicTransport),
    Dual(DualQuicTransport),
}

impl PeerTransport {
    pub fn send_raw_udp(&self, target: &Multiaddr, payload: &[u8]) -> Result<(), TransportError> {
        match self {
            Self::Single(transport) => transport.send_raw_udp(target, payload),
            Self::Dual(transport) => transport.send_raw_udp(target, payload),
        }
    }
}

pub struct DualQuicTransport {
    ipv4: QuicTransport,
    ipv6: QuicTransport,
}

#[derive(Clone, Copy)]
enum Family {
    Ipv4,
    Ipv6,
}

impl DualQuicTransport {
    fn transport(&self, family: Family) -> &QuicTransport {
        match family {
            Family::Ipv4 => &self.ipv4,
            Family::Ipv6 => &self.ipv6,
        }
    }

    fn family_for_addr(addr: &Multiaddr) -> Family {
        match addr.protocols().first() {
            Some(Protocol::Ip6(_) | Protocol::Dns6(_)) => Family::Ipv6,
            _ => Family::Ipv4,
        }
    }

    fn transport_mut(&mut self, family: Family) -> &mut QuicTransport {
        match family {
            Family::Ipv4 => &mut self.ipv4,
            Family::Ipv6 => &mut self.ipv6,
        }
    }

    fn external_id(family: Family, id: ConnectionId) -> ConnectionId {
        let raw = id.as_u64();
        match family {
            Family::Ipv4 => ConnectionId::new(raw.saturating_mul(2).saturating_sub(1)),
            Family::Ipv6 => ConnectionId::new(raw.saturating_mul(2)),
        }
    }

    fn internal_id(id: ConnectionId) -> (Family, ConnectionId) {
        let raw = id.as_u64();
        if raw % 2 == 0 {
            (Family::Ipv6, ConnectionId::new(raw / 2))
        } else {
            (Family::Ipv4, ConnectionId::new(raw.div_ceil(2)))
        }
    }

    fn map_event(family: Family, event: TransportEvent) -> TransportEvent {
        let map = |id| Self::external_id(family, id);
        match event {
            TransportEvent::Connected { id, endpoint } => TransportEvent::Connected {
                id: map(id),
                endpoint,
            },
            TransportEvent::StreamOpened { id, stream_id } => TransportEvent::StreamOpened {
                id: map(id),
                stream_id,
            },
            TransportEvent::IncomingStream { id, stream_id } => TransportEvent::IncomingStream {
                id: map(id),
                stream_id,
            },
            TransportEvent::StreamData {
                id,
                stream_id,
                data,
            } => TransportEvent::StreamData {
                id: map(id),
                stream_id,
                data,
            },
            TransportEvent::StreamRemoteWriteClosed { id, stream_id } => {
                TransportEvent::StreamRemoteWriteClosed {
                    id: map(id),
                    stream_id,
                }
            }
            TransportEvent::StreamClosed { id, stream_id } => TransportEvent::StreamClosed {
                id: map(id),
                stream_id,
            },
            TransportEvent::Closed { id } => TransportEvent::Closed { id: map(id) },
            TransportEvent::Error { id, message } => TransportEvent::Error {
                id: map(id),
                message,
            },
            TransportEvent::IncomingConnection { id, endpoint } => {
                TransportEvent::IncomingConnection {
                    id: map(id),
                    endpoint,
                }
            }
            TransportEvent::PeerIdentityVerified {
                id,
                endpoint,
                previous_peer_id,
            } => TransportEvent::PeerIdentityVerified {
                id: map(id),
                endpoint,
                previous_peer_id,
            },
            TransportEvent::Listening { addr } => TransportEvent::Listening { addr },
        }
    }

    pub fn send_raw_udp(&self, target: &Multiaddr, payload: &[u8]) -> Result<(), TransportError> {
        let family = Self::family_for_addr(target);
        self.transport(family).send_raw_udp(target, payload)
    }
}

impl Transport for PeerTransport {
    fn dial(&mut self, addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        match self {
            Self::Single(transport) => transport.dial(addr),
            Self::Dual(transport) => transport.dial(addr),
        }
    }

    fn listen(&mut self, addr: &Multiaddr) -> Result<Multiaddr, TransportError> {
        match self {
            Self::Single(transport) => transport.listen(addr),
            Self::Dual(transport) => transport.listen(addr),
        }
    }

    fn open_stream(&mut self, id: ConnectionId) -> Result<StreamId, TransportError> {
        match self {
            Self::Single(transport) => transport.open_stream(id),
            Self::Dual(transport) => transport.open_stream(id),
        }
    }

    fn send_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Vec<u8>,
    ) -> Result<(), TransportError> {
        match self {
            Self::Single(transport) => transport.send_stream(id, stream_id, data),
            Self::Dual(transport) => transport.send_stream(id, stream_id, data),
        }
    }

    fn close_stream_write(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        match self {
            Self::Single(transport) => transport.close_stream_write(id, stream_id),
            Self::Dual(transport) => transport.close_stream_write(id, stream_id),
        }
    }

    fn reset_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        match self {
            Self::Single(transport) => transport.reset_stream(id, stream_id),
            Self::Dual(transport) => transport.reset_stream(id, stream_id),
        }
    }

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        match self {
            Self::Single(transport) => transport.close(id),
            Self::Dual(transport) => transport.close(id),
        }
    }

    fn poll(&mut self) -> Result<Vec<TransportEvent>, TransportError> {
        match self {
            Self::Single(transport) => transport.poll(),
            Self::Dual(transport) => transport.poll(),
        }
    }

    fn local_addresses(&self) -> Vec<Multiaddr> {
        match self {
            Self::Single(transport) => transport.local_addresses(),
            Self::Dual(transport) => transport.local_addresses(),
        }
    }

    fn active_connection_count(&self) -> usize {
        match self {
            Self::Single(transport) => transport.active_connection_count(),
            Self::Dual(transport) => transport.active_connection_count(),
        }
    }

    fn active_connection_sources(&self) -> Vec<Multiaddr> {
        match self {
            Self::Single(transport) => transport.active_connection_sources(),
            Self::Dual(transport) => transport.active_connection_sources(),
        }
    }

    fn active_inbound_connection_sources(&self) -> Vec<Multiaddr> {
        match self {
            Self::Single(transport) => transport.active_inbound_connection_sources(),
            Self::Dual(transport) => transport.active_inbound_connection_sources(),
        }
    }
}

impl Transport for DualQuicTransport {
    fn dial(&mut self, addr: &PeerAddr) -> Result<ConnectionId, TransportError> {
        let family = Self::family_for_addr(addr.transport());
        let id = self.transport_mut(family).dial(addr)?;
        Ok(Self::external_id(family, id))
    }

    fn listen(&mut self, _addr: &Multiaddr) -> Result<Multiaddr, TransportError> {
        let ipv4 = self.ipv4.listen_on_bound_addr()?;
        let _ipv6 = self.ipv6.listen_on_bound_addr()?;
        Ok(ipv4)
    }

    fn open_stream(&mut self, id: ConnectionId) -> Result<StreamId, TransportError> {
        let (family, id) = Self::internal_id(id);
        self.transport_mut(family).open_stream(id)
    }

    fn send_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        data: Vec<u8>,
    ) -> Result<(), TransportError> {
        let (family, id) = Self::internal_id(id);
        self.transport_mut(family).send_stream(id, stream_id, data)
    }

    fn close_stream_write(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        let (family, id) = Self::internal_id(id);
        self.transport_mut(family).close_stream_write(id, stream_id)
    }

    fn reset_stream(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), TransportError> {
        let (family, id) = Self::internal_id(id);
        self.transport_mut(family).reset_stream(id, stream_id)
    }

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        let (family, id) = Self::internal_id(id);
        self.transport_mut(family).close(id)
    }

    fn poll(&mut self) -> Result<Vec<TransportEvent>, TransportError> {
        let mut events = Vec::new();
        events.extend(
            self.ipv4
                .poll()?
                .into_iter()
                .map(|event| Self::map_event(Family::Ipv4, event)),
        );
        events.extend(
            self.ipv6
                .poll()?
                .into_iter()
                .map(|event| Self::map_event(Family::Ipv6, event)),
        );
        Ok(events)
    }

    fn local_addresses(&self) -> Vec<Multiaddr> {
        let mut addrs = self.ipv4.local_addresses();
        addrs.extend(self.ipv6.local_addresses());
        addrs
    }

    fn active_connection_count(&self) -> usize {
        self.ipv4.active_connection_count() + self.ipv6.active_connection_count()
    }

    fn active_connection_sources(&self) -> Vec<Multiaddr> {
        let mut addrs = self.ipv4.active_connection_sources();
        addrs.extend(self.ipv6.active_connection_sources());
        addrs
    }

    fn active_inbound_connection_sources(&self) -> Vec<Multiaddr> {
        let mut addrs = self.ipv4.active_inbound_connection_sources();
        addrs.extend(self.ipv6.active_inbound_connection_sources());
        addrs
    }
}

fn write_secret(
    path: &Path,
    secret: &[u8; ED25519_SECRET_KEY_LENGTH],
) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create key directory {}: {e}", parent.display()))?;
    }

    let data = format!("{}\n", encode_hex(secret));
    fs::write(path, data)
        .map_err(|e| format!("failed to write key file {}: {e}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, permissions)
            .map_err(|e| format!("failed to chmod key file {}: {e}", path.display()))?;
    }

    Ok(())
}

fn multiaddr_to_socket_addr(addr: &Multiaddr) -> Result<SocketAddr, Box<dyn Error>> {
    let protocols = addr.protocols();
    if protocols.len() != 3 || !addr.is_quic_transport() {
        return Err(
            format!("--listen must be /ip4|ip6/<addr>/udp/<port>/quic-v1, got {addr}").into(),
        );
    }

    let ip = match &protocols[0] {
        Protocol::Ip4(bytes) => IpAddr::from(*bytes),
        Protocol::Ip6(bytes) => IpAddr::from(*bytes),
        _ => return Err(format!("--listen requires /ip4 or /ip6 host, got {addr}").into()),
    };
    let port = match &protocols[1] {
        Protocol::Udp(port) => *port,
        _ => unreachable!("is_quic_transport already checked udp"),
    };
    Ok(SocketAddr::new(ip, port))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_secret(input: &str) -> Result<[u8; ED25519_SECRET_KEY_LENGTH], String> {
    if input.len() != ED25519_SECRET_KEY_LENGTH * 2 {
        return Err(format!(
            "expected {} hex chars, got {}",
            ED25519_SECRET_KEY_LENGTH * 2,
            input.len()
        ));
    }

    let mut out = [0u8; ED25519_SECRET_KEY_LENGTH];
    let bytes = input.as_bytes();
    for idx in 0..ED25519_SECRET_KEY_LENGTH {
        let hi = hex_value(bytes[idx * 2])?;
        let lo = hex_value(bytes[idx * 2 + 1])?;
        out[idx] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("non-hex byte 0x{byte:02x}")),
    }
}
