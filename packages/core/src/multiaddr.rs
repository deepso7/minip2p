use alloc::{string::ToString, vec::Vec};
use core::{fmt, net::Ipv6Addr, str::FromStr};

use minip2p_identity::PeerId;

use crate::{MultiaddrError, Protocol};

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Multiaddr {
    protocols: Vec<Protocol>,
}

impl Multiaddr {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_protocols(protocols: Vec<Protocol>) -> Self {
        Self { protocols }
    }

    pub fn protocols(&self) -> &[Protocol] {
        &self.protocols
    }

    pub fn iter(&self) -> core::slice::Iter<'_, Protocol> {
        self.protocols.iter()
    }

    pub fn push(&mut self, protocol: Protocol) {
        self.protocols.push(protocol);
    }

    pub fn len(&self) -> usize {
        self.protocols.len()
    }

    pub fn is_empty(&self) -> bool {
        self.protocols.is_empty()
    }

    pub fn has_quic_v1(&self) -> bool {
        self.protocols
            .iter()
            .any(|protocol| matches!(protocol, Protocol::QuicV1))
    }

    pub fn peer_id(&self) -> Option<&PeerId> {
        self.protocols.iter().find_map(|protocol| match protocol {
            Protocol::P2p(peer_id) => Some(peer_id),
            _ => None,
        })
    }

    pub fn encapsulate(&self, other: &Self) -> Self {
        let mut protocols = Vec::with_capacity(self.protocols.len() + other.protocols.len());
        protocols.extend(self.protocols.iter().cloned());
        protocols.extend(other.protocols.iter().cloned());
        Self { protocols }
    }

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

    pub fn is_quic_transport(&self) -> bool {
        is_quic_transport_slice(&self.protocols)
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

pub(crate) fn is_quic_transport_slice(protocols: &[Protocol]) -> bool {
    protocols.len() == 3
        && protocols[0].is_host()
        && matches!(protocols[1], Protocol::Udp(_))
        && matches!(protocols[2], Protocol::QuicV1)
}

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

fn is_valid_dns(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('/')
        && !value
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
}

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
}
