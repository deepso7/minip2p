use alloc::{string::ToString, vec::Vec};
use core::{fmt, net::Ipv6Addr, str::FromStr};

use minip2p_identity::PeerId;

use crate::{MultiaddrError, Protocol};

/// An ordered sequence of protocol components representing a network address.
///
/// Parse from a string with [`FromStr`] or build programmatically with
/// [`from_protocols`](Multiaddr::from_protocols).
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Multiaddr {
    protocols: Vec<Protocol>,
}

impl Multiaddr {
    /// Creates an empty multiaddr.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a multiaddr from a pre-built protocol list.
    pub fn from_protocols(protocols: Vec<Protocol>) -> Self {
        Self { protocols }
    }

    /// Returns the protocol components as a slice.
    pub fn protocols(&self) -> &[Protocol] {
        &self.protocols
    }

    /// Returns an iterator over the protocol components.
    pub fn iter(&self) -> core::slice::Iter<'_, Protocol> {
        self.protocols.iter()
    }

    /// Appends a protocol component.
    pub fn push(&mut self, protocol: Protocol) {
        self.protocols.push(protocol);
    }

    /// Returns the number of protocol components.
    pub fn len(&self) -> usize {
        self.protocols.len()
    }

    /// Returns `true` if this multiaddr has no components.
    pub fn is_empty(&self) -> bool {
        self.protocols.is_empty()
    }

    /// Returns `true` if any component is `/quic-v1`.
    pub fn has_quic_v1(&self) -> bool {
        self.protocols
            .iter()
            .any(|protocol| matches!(protocol, Protocol::QuicV1))
    }

    /// Returns the first `/p2p` peer id, if present.
    pub fn peer_id(&self) -> Option<&PeerId> {
        self.protocols.iter().find_map(|protocol| match protocol {
            Protocol::P2p(peer_id) => Some(peer_id),
            _ => None,
        })
    }

    /// Returns a new multiaddr with `other` appended.
    pub fn encapsulate(&self, other: &Self) -> Self {
        let mut protocols = Vec::with_capacity(self.protocols.len() + other.protocols.len());
        protocols.extend(self.protocols.iter().cloned());
        protocols.extend(other.protocols.iter().cloned());
        Self { protocols }
    }

    /// Removes the last occurrence of `suffix` and returns the prefix.
    pub fn decapsulate(&self, suffix: &Self) -> Option<Self> {
        if suffix.protocols.is_empty() {
            return Some(self.clone());
        }

        if suffix.protocols.len() > self.protocols.len() {
            return None;
        }

        for idx in (0..=self.protocols.len() - suffix.protocols.len()).rev() {
            if self.protocols[idx..idx + suffix.protocols.len()] == suffix.protocols {
                return Some(Self::from_protocols(self.protocols[..idx].to_vec()));
            }
        }

        None
    }

    /// Returns `true` if this is a valid QUIC transport address (host + udp + quic-v1).
    pub fn is_quic_transport(&self) -> bool {
        is_quic_transport_slice(&self.protocols)
    }

    /// Encodes this multiaddr to its binary multicodec wire form.
    ///
    /// Shape: for each component, a varint multicodec code followed by
    /// the value (fixed-size, length-prefixed, or absent depending on
    /// the protocol). See the multiformats multiaddr specification at
    /// <https://github.com/multiformats/multiaddr>.
    ///
    /// This is the on-wire encoding used by interoperable libp2p
    /// components (Identify's `listen_addrs` / `observed_addr`, DCUtR
    /// observed addresses, etc.).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for protocol in &self.protocols {
            protocol.write_binary(&mut out);
        }
        out
    }

    /// Decodes a multiaddr from its binary multicodec wire form.
    ///
    /// Errors:
    /// - `Varint` — a multicodec code or length prefix is malformed.
    /// - `UnknownProtocolCode` — a component uses a code we don't
    ///   implement.
    /// - `TruncatedBinaryValue` — a component declared more bytes than
    ///   the buffer contains.
    /// - `InvalidBinaryValue` — a component's body failed validation
    ///   (e.g. non-UTF-8 DNS name, malformed `/p2p/` multihash).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MultiaddrError> {
        let mut protocols = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            let (protocol, consumed) = Protocol::read_binary(&bytes[offset..])?;
            offset += consumed;
            protocols.push(protocol);
        }
        Ok(Self { protocols })
    }
}

impl fmt::Display for Multiaddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for protocol in &self.protocols {
            match protocol {
                Protocol::Ip4(bytes) => write!(
                    f,
                    "/ip4/{}.{}.{}.{}",
                    bytes[0], bytes[1], bytes[2], bytes[3]
                )?,
                Protocol::Ip6(bytes) => write!(f, "/ip6/{}", Ipv6Addr::from(*bytes))?,
                Protocol::Dns(value) => write!(f, "/dns/{value}")?,
                Protocol::Dns4(value) => write!(f, "/dns4/{value}")?,
                Protocol::Dns6(value) => write!(f, "/dns6/{value}")?,
                Protocol::Udp(port) => write!(f, "/udp/{port}")?,
                Protocol::QuicV1 => f.write_str("/quic-v1")?,
                Protocol::P2p(peer_id) => write!(f, "/p2p/{peer_id}")?,
            }
        }
        Ok(())
    }
}

impl FromStr for Multiaddr {
    type Err = MultiaddrError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_multiaddr(input)
    }
}

impl<'a> IntoIterator for &'a Multiaddr {
    type Item = &'a Protocol;
    type IntoIter = core::slice::Iter<'a, Protocol>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Checks if a protocol slice forms a valid QUIC transport (host + udp + quic-v1).
pub(crate) fn is_quic_transport_slice(protocols: &[Protocol]) -> bool {
    protocols.len() == 3
        && protocols[0].is_host()
        && matches!(protocols[1], Protocol::Udp(_))
        && matches!(protocols[2], Protocol::QuicV1)
}

/// Parses a `/`-delimited multiaddr string into protocol components.
fn parse_multiaddr(input: &str) -> Result<Multiaddr, MultiaddrError> {
    if input.is_empty() {
        return Err(MultiaddrError::EmptyInput);
    }
    if !input.starts_with('/') {
        return Err(MultiaddrError::MissingLeadingSlash);
    }

    let segments: Vec<&str> = input.split('/').collect();
    let mut protocols = Vec::new();
    let mut idx = 1usize;

    while idx < segments.len() {
        let protocol = segments[idx];
        if protocol.is_empty() {
            return Err(MultiaddrError::EmptyProtocol);
        }

        match protocol {
            "ip4" => {
                let value = require_value(&segments, idx, "ip4")?;
                let parsed = parse_ip4(value).ok_or_else(|| MultiaddrError::InvalidIp4 {
                    value: value.to_string(),
                })?;
                protocols.push(Protocol::Ip4(parsed));
                idx += 2;
            }
            "ip6" => {
                let value = require_value(&segments, idx, "ip6")?;
                let parsed = value
                    .parse::<Ipv6Addr>()
                    .map_err(|_| MultiaddrError::InvalidIp6 {
                        value: value.to_string(),
                    })?
                    .octets();
                protocols.push(Protocol::Ip6(parsed));
                idx += 2;
            }
            "dns" | "dns4" | "dns6" => {
                let value = require_value(&segments, idx, protocol)?;
                if !is_valid_dns(value) {
                    return Err(MultiaddrError::InvalidDnsName {
                        value: value.to_string(),
                    });
                }

                let value = value.to_string();
                let parsed = match protocol {
                    "dns" => Protocol::Dns(value),
                    "dns4" => Protocol::Dns4(value),
                    _ => Protocol::Dns6(value),
                };
                protocols.push(parsed);
                idx += 2;
            }
            "udp" => {
                let value = require_value(&segments, idx, "udp")?;
                let parsed = value
                    .parse::<u16>()
                    .map_err(|_| MultiaddrError::InvalidPort {
                        value: value.to_string(),
                    })?;
                protocols.push(Protocol::Udp(parsed));
                idx += 2;
            }
            "quic-v1" => {
                protocols.push(Protocol::QuicV1);
                idx += 1;
            }
            "p2p" => {
                let value = require_value(&segments, idx, "p2p")?;
                let parsed =
                    value
                        .parse::<PeerId>()
                        .map_err(|source| MultiaddrError::InvalidPeerId {
                            value: value.to_string(),
                            source,
                        })?;
                protocols.push(Protocol::P2p(parsed));
                idx += 2;
            }
            _ => {
                return Err(MultiaddrError::UnknownProtocol {
                    protocol: protocol.to_string(),
                });
            }
        }
    }

    Ok(Multiaddr::from_protocols(protocols))
}

/// Returns the next segment as a value for the given protocol, or an error.
fn require_value<'a>(
    segments: &'a [&str],
    idx: usize,
    protocol: &str,
) -> Result<&'a str, MultiaddrError> {
    match segments.get(idx + 1) {
        Some(value) if !value.is_empty() => Ok(value),
        _ => Err(MultiaddrError::MissingValue {
            protocol: protocol.to_string(),
        }),
    }
}

/// Basic DNS name validation: non-empty, no slashes, no whitespace/control chars.
fn is_valid_dns(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('/')
        && !value
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
}

/// Parses a dotted-quad IPv4 string into 4 bytes.
fn parse_ip4(value: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut parts = value.split('.');

    for slot in &mut out {
        *slot = parts.next()?.parse::<u8>().ok()?;
    }

    if parts.next().is_some() {
        return None;
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;

    const PEER_ID: &str = "QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N";

    #[test]
    fn parses_and_formats_quic_ip4_multiaddr() {
        let input = "/ip4/127.0.0.1/udp/4001/quic-v1";
        let parsed = Multiaddr::from_str(input).expect("must parse");

        assert_eq!(parsed.to_string(), input);
        assert!(parsed.is_quic_transport());
    }

    #[test]
    fn parses_dns_multiaddr_with_peer_id() {
        let input = format!("/dns4/example.com/udp/9000/quic-v1/p2p/{PEER_ID}");
        let parsed = Multiaddr::from_str(&input).expect("must parse");

        assert_eq!(parsed.to_string(), input);
        assert_eq!(
            parsed.peer_id().expect("peer id should exist").to_string(),
            PEER_ID
        );
    }

    #[test]
    fn rejects_unknown_protocol() {
        let err = Multiaddr::from_str("/ip4/127.0.0.1/tcp/1234").expect_err("must fail");
        assert!(matches!(err, MultiaddrError::UnknownProtocol { .. }));
    }

    #[test]
    fn rejects_missing_value() {
        let err = Multiaddr::from_str("/ip4/127.0.0.1/udp").expect_err("must fail");
        assert!(matches!(
            err,
            MultiaddrError::MissingValue { protocol, .. } if protocol == "udp"
        ));
    }

    #[test]
    fn decapsulates_last_matching_suffix() {
        let base = Multiaddr::from_str("/ip4/127.0.0.1/udp/4001/quic-v1").expect("must parse");
        let peer = Multiaddr::from_str(&format!("/p2p/{PEER_ID}")).expect("must parse");
        let full = base.encapsulate(&peer);

        let decapsulated = full.decapsulate(&peer).expect("suffix should be found");
        assert_eq!(decapsulated, base);
    }

    // ---------------------------------------------------------------------
    // Binary codec
    // ---------------------------------------------------------------------

    /// Hand-derived reference vector for `/ip4/127.0.0.1/udp/4001/quic-v1`.
    ///
    /// - `/ip4`: varint code 0x04, value 127.0.0.1 = 7F 00 00 01
    /// - `/udp`: varint code 0x0111 -> 91 02, value 4001 (big-endian) = 0F A1
    /// - `/quic-v1`: varint code 0x01cc -> CC 03, no value
    #[test]
    fn binary_codec_reference_vector_ip4_quic() {
        let addr = Multiaddr::from_str("/ip4/127.0.0.1/udp/4001/quic-v1").unwrap();
        let expected: Vec<u8> = vec![
            0x04, 0x7F, 0x00, 0x00, 0x01, // ip4 127.0.0.1
            0x91, 0x02, 0x0F, 0xA1, // udp 4001
            0xCC, 0x03, // quic-v1
        ];
        assert_eq!(addr.to_bytes(), expected);
        assert_eq!(Multiaddr::from_bytes(&expected).unwrap(), addr);
    }

    #[test]
    fn binary_codec_round_trips_ip6() {
        let input = "/ip6/2001:db8::1/udp/9000/quic-v1";
        let addr = Multiaddr::from_str(input).unwrap();
        let bytes = addr.to_bytes();
        let decoded = Multiaddr::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.to_string(), input);
    }

    #[test]
    fn binary_codec_round_trips_dns_variants() {
        for proto in ["dns", "dns4", "dns6"] {
            let input = alloc::format!("/{proto}/example.com/udp/443/quic-v1");
            let addr = Multiaddr::from_str(&input).unwrap();
            let bytes = addr.to_bytes();
            let decoded = Multiaddr::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_string(), input);
        }
    }

    #[test]
    fn binary_codec_round_trips_p2p_suffix() {
        let input = format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{PEER_ID}");
        let addr = Multiaddr::from_str(&input).unwrap();
        let bytes = addr.to_bytes();
        let decoded = Multiaddr::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.to_string(), input);
    }

    #[test]
    fn binary_codec_round_trips_empty_multiaddr() {
        let addr = Multiaddr::new();
        assert_eq!(addr.to_bytes(), Vec::<u8>::new());
        assert_eq!(Multiaddr::from_bytes(&[]).unwrap(), addr);
    }

    #[test]
    fn binary_codec_rejects_unknown_code() {
        // 0xC1 0x01 is varint for 193; not a code we implement.
        let err = Multiaddr::from_bytes(&[0xC1, 0x01, 0xFF]).unwrap_err();
        assert!(matches!(
            err,
            MultiaddrError::UnknownProtocolCode { code: 193 }
        ));
    }

    #[test]
    fn binary_codec_rejects_truncated_ip4() {
        // ip4 code (0x04) followed by only 2 bytes of value.
        let err = Multiaddr::from_bytes(&[0x04, 0x7F, 0x00]).unwrap_err();
        assert!(matches!(
            err,
            MultiaddrError::TruncatedBinaryValue { protocol: "ip4" }
        ));
    }

    #[test]
    fn binary_codec_rejects_truncated_length_prefix() {
        // dns code (0x35) + length 10 + only 3 body bytes.
        let err = Multiaddr::from_bytes(&[0x35, 0x0A, b'a', b'b', b'c']).unwrap_err();
        assert!(matches!(
            err,
            MultiaddrError::TruncatedBinaryValue { protocol: "dns" }
        ));
    }

    #[test]
    fn binary_codec_rejects_invalid_dns_utf8() {
        // dns code (0x35) + length 2 + invalid utf-8 bytes (0xFF 0xFE).
        let err = Multiaddr::from_bytes(&[0x35, 0x02, 0xFF, 0xFE]).unwrap_err();
        assert!(matches!(
            err,
            MultiaddrError::InvalidBinaryValue { protocol: "dns", .. }
        ));
    }
}
