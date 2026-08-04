use alloc::{string::ToString, vec::Vec};
use core::{fmt, net::Ipv6Addr, str::FromStr};

use minip2p_identity::PeerId;

use crate::{MultiaddrError, Protocol};

/// An ordered sequence of protocol components representing a network address.
///
/// Parse from a string with [`FromStr`] or build programmatically with
/// [`from_protocols`](Multiaddr::from_protocols).
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
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

    /// Returns `true` if this is a valid TCP transport address (host + tcp).
    pub fn is_tcp_transport(&self) -> bool {
        is_tcp_transport_slice(&self.protocols)
    }

    /// Returns which transport can dial this address, if any.
    ///
    /// This is the classification a multi-transport host routes on: `/tcp`
    /// addresses go to TCP, `/udp/.../quic-v1` addresses to QUIC. Anything
    /// else -- a bare host, a circuit address, a trailing `/p2p` -- is not a
    /// dialable transport address and returns `None`.
    pub fn transport_kind(&self) -> Option<TransportKind> {
        transport_kind_of(&self.protocols)
    }

    /// Returns `true` if the first component is a wildcard IP host
    /// (`/ip4/0.0.0.0` or `/ip6/::`).
    ///
    /// Wildcard hosts are valid bind addresses but are not dialable, so
    /// address candidates and advertisements typically filter them out.
    pub fn is_wildcard_host(&self) -> bool {
        match self.protocols.first() {
            Some(Protocol::Ip4(bytes)) => *bytes == [0; 4],
            Some(Protocol::Ip6(bytes)) => *bytes == [0; 16],
            _ => false,
        }
    }

    /// Returns `true` if this is a relay circuit transport address: a
    /// dialable address for the relay, then `/p2p/<relay>` and
    /// `/p2p-circuit`.
    ///
    /// This is the shape produced by relay reservations, and the leg that
    /// reaches the relay is an ordinary transport address -- whichever
    /// transport that is. A circuit is carried over an established connection
    /// to the relay, so how that connection was made is the relay's business
    /// and not the circuit's.
    ///
    /// Anything longer or shorter (including a direct address, or one with a
    /// trailing `/p2p/<target>`) returns `false`.
    pub fn is_relay_circuit_transport(&self) -> bool {
        let Some((Protocol::P2pCircuit, head)) = self.protocols.split_last() else {
            return false;
        };
        let Some((Protocol::P2p(_), leg)) = head.split_last() else {
            return false;
        };
        transport_kind_of(leg).is_some()
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
                Protocol::Tcp(port) => write!(f, "/tcp/{port}")?,
                Protocol::Udp(port) => write!(f, "/udp/{port}")?,
                Protocol::QuicV1 => f.write_str("/quic-v1")?,
                Protocol::P2p(peer_id) => write!(f, "/p2p/{peer_id}")?,
                Protocol::P2pCircuit => f.write_str("/p2p-circuit")?,
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

/// Checks if a protocol slice forms a valid TCP transport (host + tcp).
pub(crate) fn is_tcp_transport_slice(protocols: &[Protocol]) -> bool {
    protocols.len() == 2 && protocols[0].is_host() && matches!(protocols[1], Protocol::Tcp(_))
}

/// Returns which transport can dial a protocol slice, if any.
pub(crate) fn transport_kind_of(protocols: &[Protocol]) -> Option<TransportKind> {
    if is_tcp_transport_slice(protocols) {
        Some(TransportKind::Tcp)
    } else if is_quic_transport_slice(protocols) {
        Some(TransportKind::Quic)
    } else {
        None
    }
}

/// Which base transport dials a given address shape.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TransportKind {
    /// `/<host>/tcp/<port>`
    Tcp,
    /// `/<host>/udp/<port>/quic-v1`
    Quic,
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
            "tcp" | "udp" => {
                let value = require_value(&segments, idx, protocol)?;
                let parsed = value
                    .parse::<u16>()
                    .map_err(|_| MultiaddrError::InvalidPort {
                        value: value.to_string(),
                    })?;
                protocols.push(if protocol == "tcp" {
                    Protocol::Tcp(parsed)
                } else {
                    Protocol::Udp(parsed)
                });
                idx += 2;
            }
            "quic-v1" => {
                protocols.push(Protocol::QuicV1);
                idx += 1;
            }
            "p2p-circuit" => {
                protocols.push(Protocol::P2pCircuit);
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
///
/// Applied by both codecs. A name containing `/` would print as several
/// components and re-parse into a *different* address; whitespace and control
/// characters would likewise not survive a text round trip.
pub(crate) fn is_valid_dns(value: &str) -> bool {
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
    fn detects_relay_circuit_transport_shape() {
        for host in [
            "/ip4/203.0.113.7",
            "/ip6/2001:db8::1",
            "/dns4/relay.example.com",
        ] {
            // Either leg: a circuit rides an established connection to the
            // relay, so how that connection was made is the relay's business.
            // A TCP-only device has no other kind to offer.
            for leg in ["/udp/4001/quic-v1", "/tcp/4001"] {
                let input = format!("{host}{leg}/p2p/{PEER_ID}/p2p-circuit");
                let parsed = Multiaddr::from_str(&input).expect("must parse");
                assert!(parsed.is_relay_circuit_transport(), "{input}");
            }
        }
    }

    #[test]
    fn rejects_non_circuit_transport_shapes() {
        let near_misses = [
            // Direct QUIC address, no relay suffix.
            "/ip4/203.0.113.7/udp/4001/quic-v1".to_string(),
            // Relay address without the circuit marker.
            format!("/ip4/203.0.113.7/udp/4001/quic-v1/p2p/{PEER_ID}"),
            // Circuit marker without the relay peer id (four components).
            "/ip4/203.0.113.7/udp/4001/quic-v1/p2p-circuit".to_string(),
            // Circuit marker before the relay peer id (five components, wrong order).
            format!("/ip4/203.0.113.7/udp/4001/quic-v1/p2p-circuit/p2p/{PEER_ID}"),
            // Destination peer appended after the circuit marker (six components).
            format!("/ip4/203.0.113.7/udp/4001/quic-v1/p2p/{PEER_ID}/p2p-circuit/p2p/{PEER_ID}"),
            // The leg has to be a whole transport address, not a bare host or
            // half of one: a circuit is reached by dialing the relay, and
            // there is no dialing this.
            format!("/ip4/203.0.113.7/p2p/{PEER_ID}/p2p-circuit"),
            format!("/ip4/203.0.113.7/udp/4001/p2p/{PEER_ID}/p2p-circuit"),
        ];
        for input in near_misses {
            let parsed = Multiaddr::from_str(&input).expect("must parse");
            assert!(!parsed.is_relay_circuit_transport(), "{input}");
        }
        assert!(!Multiaddr::default().is_relay_circuit_transport());
    }

    #[test]
    fn parses_and_formats_tcp_multiaddrs() {
        // Every strict form the TCP transport accepts, round-tripped through
        // text to catch a Display that disagrees with the parser.
        let inputs = [
            "/ip4/192.0.2.1/tcp/4001".to_string(),
            "/ip6/2001:db8::1/tcp/4001".to_string(),
            "/dns4/example.test/tcp/4001".to_string(),
            "/dns6/example.test/tcp/4001".to_string(),
            "/dns/example.test/tcp/4001".to_string(),
            format!("/ip4/192.0.2.1/tcp/4001/p2p/{PEER_ID}"),
        ];

        for input in inputs {
            let parsed = Multiaddr::from_str(&input).expect("must parse");
            assert_eq!(parsed.to_string(), input, "canonical formatting");
            assert_eq!(
                Multiaddr::from_bytes(&parsed.to_bytes()).expect("must decode"),
                parsed,
                "binary round trip for {input}"
            );
        }
    }

    /// Hand-derived reference vector for `/ip4/192.0.2.1/tcp/4001`.
    ///
    /// - `/ip4`: varint code 0x04 -> 04, value 192.0.2.1 = C0 00 02 01
    /// - `/tcp`: varint code 0x06 -> 06, value 4001 (big-endian) = 0F A1
    ///
    /// `/tcp` is a single-byte varint, unlike `/udp`'s two-byte 0x0111, so
    /// this pins the code rather than trusting the encoder round-tripping
    /// against itself.
    #[test]
    fn binary_codec_reference_vector_ip4_tcp() {
        let addr = Multiaddr::from_str("/ip4/192.0.2.1/tcp/4001").unwrap();
        let expected: Vec<u8> = vec![
            0x04, 0xC0, 0x00, 0x02, 0x01, // ip4 192.0.2.1
            0x06, 0x0F, 0xA1, // tcp 4001
        ];
        assert_eq!(addr.to_bytes(), expected);
        assert_eq!(Multiaddr::from_bytes(&expected).unwrap(), addr);
    }

    #[test]
    fn tcp_and_udp_ports_are_distinct_on_the_wire() {
        let tcp = Multiaddr::from_str("/ip4/192.0.2.1/tcp/4001").unwrap();
        let udp = Multiaddr::from_str("/ip4/192.0.2.1/udp/4001").unwrap();

        assert_ne!(tcp, udp);
        assert_ne!(tcp.to_bytes(), udp.to_bytes());
        // Decoding must not confuse the two codes.
        assert_eq!(Multiaddr::from_bytes(&tcp.to_bytes()).unwrap(), tcp);
        assert_eq!(Multiaddr::from_bytes(&udp.to_bytes()).unwrap(), udp);
    }

    #[test]
    fn classifies_dialable_transport_addresses() {
        let tcp = Multiaddr::from_str("/ip4/192.0.2.1/tcp/4001").unwrap();
        assert!(tcp.is_tcp_transport());
        assert!(!tcp.is_quic_transport());
        assert_eq!(tcp.transport_kind(), Some(TransportKind::Tcp));

        let quic = Multiaddr::from_str("/ip4/192.0.2.1/udp/4001/quic-v1").unwrap();
        assert!(quic.is_quic_transport());
        assert!(!quic.is_tcp_transport());
        assert_eq!(quic.transport_kind(), Some(TransportKind::Quic));

        // Shapes a router must not treat as dialable.
        let not_transports = [
            "/ip4/192.0.2.1".to_string(),
            "/tcp/4001".to_string(),
            "/ip4/192.0.2.1/udp/4001".to_string(),
            "/ip4/192.0.2.1/tcp/4001/quic-v1".to_string(),
            format!("/ip4/192.0.2.1/tcp/4001/p2p/{PEER_ID}"),
            format!("/ip4/192.0.2.1/udp/4001/quic-v1/p2p/{PEER_ID}"),
        ];
        for input in not_transports {
            let parsed = Multiaddr::from_str(&input).expect("must parse");
            assert_eq!(parsed.transport_kind(), None, "{input}");
            assert!(!parsed.is_tcp_transport(), "{input}");
            assert!(!parsed.is_quic_transport(), "{input}");
        }
        assert_eq!(Multiaddr::default().transport_kind(), None);
    }

    #[test]
    fn rejects_malformed_tcp_ports() {
        let err = Multiaddr::from_str("/ip4/127.0.0.1/tcp").expect_err("must fail");
        assert!(matches!(
            err,
            MultiaddrError::MissingValue { protocol, .. } if protocol == "tcp"
        ));

        for bad in [
            "/ip4/127.0.0.1/tcp/65536",
            "/ip4/127.0.0.1/tcp/-1",
            "/ip4/127.0.0.1/tcp/x",
        ] {
            let err = Multiaddr::from_str(bad).expect_err("must fail");
            assert!(matches!(err, MultiaddrError::InvalidPort { .. }), "{bad}");
        }

        // Port 0 is a legal bind wildcard, so it must parse.
        assert!(Multiaddr::from_str("/ip4/0.0.0.0/tcp/0").is_ok());
    }

    #[test]
    fn truncated_tcp_port_is_rejected() {
        // Code present, only one of the two port bytes.
        let err = Multiaddr::from_bytes(&[0x04, 0x7F, 0x00, 0x00, 0x01, 0x06, 0x0F])
            .expect_err("must fail");
        assert!(matches!(
            err,
            MultiaddrError::TruncatedBinaryValue { protocol } if protocol == "tcp"
        ));
    }

    #[test]
    fn binary_decoder_rejects_dns_names_the_text_parser_would_reject() {
        // Found by the wire_inputs fuzzer. `/dns` with a body containing `/`
        // decoded to one component but printed as several, so re-parsing the
        // text produced a *different* address -- one binary value with two
        // meanings, from peer-supplied Identify/beacon addresses.
        let mut confusable = vec![0x35, 8];
        confusable.extend_from_slice(b"x/tcp/80");
        let err = Multiaddr::from_bytes(&confusable).expect_err("must reject");
        assert!(matches!(
            err,
            MultiaddrError::InvalidBinaryValue { protocol, .. } if protocol == "dns"
        ));

        // Control characters and whitespace likewise cannot survive a text
        // round trip, for every dns variant.
        for (code, label) in [(0x35u8, "dns"), (0x36, "dns4"), (0x37, "dns6")] {
            for body in [&b"\0"[..], b" ", b"a b", b"", b"a/b"] {
                let mut bytes = vec![code, body.len() as u8];
                bytes.extend_from_slice(body);
                let err = Multiaddr::from_bytes(&bytes)
                    .expect_err(&alloc::format!("{label} {body:?} must be rejected"));
                assert!(
                    matches!(err, MultiaddrError::InvalidBinaryValue { .. }),
                    "{label} {body:?} gave {err:?}"
                );
            }
        }
    }

    #[test]
    fn binary_and_text_decoders_agree_on_dns_names() {
        // Parity in both directions: the codecs must accept the same names and
        // reject the same names, or a name means one thing on the wire and
        // another in text.
        for name in ["example.test", "a.b.c.d", "xn--bcher-kva.example", "host-1"] {
            let text = alloc::format!("/dns4/{name}/tcp/4001");
            let parsed = Multiaddr::from_str(&text).expect("text must parse");
            let decoded = Multiaddr::from_bytes(&parsed.to_bytes()).expect("binary must decode");
            assert_eq!(decoded, parsed);
            assert_eq!(decoded.to_string(), text);
        }

        for name in ["a/b", "a b", "a\u{7f}b", "\u{0}", ""] {
            // Text side.
            let text = alloc::format!("/dns4/{name}");
            assert!(
                Multiaddr::from_str(&text).is_err(),
                "text parser accepted {name:?}"
            );

            // Binary side, hand-built so the encoder cannot launder it.
            let body = name.as_bytes();
            let mut bytes = alloc::vec![0x36u8, body.len() as u8];
            bytes.extend_from_slice(body);
            assert!(
                Multiaddr::from_bytes(&bytes).is_err(),
                "binary decoder accepted {name:?}"
            );
        }
    }

    #[test]
    fn rejects_unknown_protocol() {
        let err = Multiaddr::from_str("/ip4/127.0.0.1/sctp/1234").expect_err("must fail");
        assert!(matches!(
            err,
            MultiaddrError::UnknownProtocol { protocol } if protocol == "sctp"
        ));
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
    /// - `/quic-v1`: varint code 0x01cd -> CD 03, no value
    #[test]
    fn binary_codec_reference_vector_ip4_quic() {
        let addr = Multiaddr::from_str("/ip4/127.0.0.1/udp/4001/quic-v1").unwrap();
        let expected: Vec<u8> = vec![
            0x04, 0x7F, 0x00, 0x00, 0x01, // ip4 127.0.0.1
            0x91, 0x02, 0x0F, 0xA1, // udp 4001
            0xCD, 0x03, // quic-v1
        ];
        assert_eq!(addr.to_bytes(), expected);
        assert_eq!(Multiaddr::from_bytes(&expected).unwrap(), addr);
    }

    #[test]
    fn rejects_legacy_quic_protocol() {
        let err = Multiaddr::from_str("/ip4/127.0.0.1/udp/4001/quic").unwrap_err();
        assert!(matches!(err, MultiaddrError::UnknownProtocol { protocol } if protocol == "quic"));

        // 0x01cc is legacy `/quic`; minip2p intentionally supports only `/quic-v1`.
        let err = Multiaddr::from_bytes(&[
            0x04, 0x7F, 0x00, 0x00, 0x01, // ip4 127.0.0.1
            0x91, 0x02, 0x0F, 0xA1, // udp 4001
            0xCC, 0x03, // quic
        ])
        .unwrap_err();
        assert!(matches!(
            err,
            MultiaddrError::UnknownProtocolCode { code: 0x01cc }
        ));
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
    fn parses_and_formats_circuit_multiaddr() {
        let input = format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{PEER_ID}/p2p-circuit");
        let parsed = Multiaddr::from_str(&input).expect("must parse");

        assert_eq!(parsed.to_string(), input);
        // A circuit address is not a direct QUIC transport address.
        assert!(!parsed.is_quic_transport());
    }

    /// Hand-derived reference vector for `/p2p-circuit`: varint code
    /// 0x0122 -> A2 02, no value.
    #[test]
    fn binary_codec_reference_vector_p2p_circuit() {
        let addr = Multiaddr::from_protocols(vec![Protocol::P2pCircuit]);
        let expected: Vec<u8> = vec![0xA2, 0x02];
        assert_eq!(addr.to_bytes(), expected);
        assert_eq!(Multiaddr::from_bytes(&expected).unwrap(), addr);
    }

    #[test]
    fn binary_codec_round_trips_circuit_suffix() {
        let input = format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{PEER_ID}/p2p-circuit");
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
    fn binary_codec_rejects_length_prefix_beyond_usize() {
        // dns code (0x35) + a 10-byte uvarint declaring u64::MAX bytes of
        // body. Must fail cleanly on 32-bit and 64-bit targets alike.
        let mut bytes = vec![0x35];
        bytes.extend_from_slice(&[0xFF; 9]);
        bytes.push(0x01);
        let err = Multiaddr::from_bytes(&bytes).unwrap_err();
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
            MultiaddrError::InvalidBinaryValue {
                protocol: "dns",
                ..
            }
        ));
    }
}
