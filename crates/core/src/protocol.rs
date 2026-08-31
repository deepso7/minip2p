use alloc::string::{String, ToString};
use alloc::vec::Vec;

use minip2p_identity::{PeerId, read_uvarint_with_remainder, write_uvarint};

use crate::MultiaddrError;
use crate::multiaddr::is_valid_dns;

// ---------------------------------------------------------------------------
// Multicodec codes
// ---------------------------------------------------------------------------
//
// Per the multiformats/multicodec table at
// <https://github.com/multiformats/multicodec/blob/master/table.csv>. Each
// component of a binary multiaddr is `<varint(code)><value>`; the shape of
// `<value>` depends on the code (fixed-size bytes, length-prefixed bytes,
// or absent).

/// Multicodec code for `/ip4/<a.b.c.d>`. 4 raw bytes.
const IP4_CODE: u64 = 0x04;
/// Multicodec code for `/ip6/<address>`. 16 raw bytes.
const IP6_CODE: u64 = 0x29;
/// Multicodec code for `/dns/<name>`. Varint-length-prefixed UTF-8.
const DNS_CODE: u64 = 0x35;
/// Multicodec code for `/dns4/<name>`. Varint-length-prefixed UTF-8.
const DNS4_CODE: u64 = 0x36;
/// Multicodec code for `/dns6/<name>`. Varint-length-prefixed UTF-8.
const DNS6_CODE: u64 = 0x37;
/// Multicodec code for `/tcp/<port>`. 2 raw bytes (big-endian).
const TCP_CODE: u64 = 0x06;
/// Multicodec code for `/udp/<port>`. 2 raw bytes (big-endian).
const UDP_CODE: u64 = 0x0111;
/// Multicodec code for `/quic-v1`. No value.
const QUIC_V1_CODE: u64 = 0x01cd;
/// Multicodec code for `/p2p/<peer-id>`. Varint-length-prefixed multihash.
const P2P_CODE: u64 = 0x01a5;
/// Multicodec code for `/p2p-circuit`. No value.
const P2P_CIRCUIT_CODE: u64 = 0x0122;

/// A single component of a multiaddr.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Protocol {
    Ip4([u8; 4]),
    Ip6([u8; 16]),
    Dns(String),
    Dns4(String),
    Dns6(String),
    Tcp(u16),
    Udp(u16),
    QuicV1,
    P2p(PeerId),
    P2pCircuit,
}

impl Protocol {
    /// Returns `true` if this protocol represents a network host (IP or DNS).
    pub fn is_host(&self) -> bool {
        matches!(
            self,
            Self::Ip4(_) | Self::Ip6(_) | Self::Dns(_) | Self::Dns4(_) | Self::Dns6(_)
        )
    }

    /// Returns the multicodec code for this protocol.
    pub fn code(&self) -> u64 {
        match self {
            Self::Ip4(_) => IP4_CODE,
            Self::Ip6(_) => IP6_CODE,
            Self::Dns(_) => DNS_CODE,
            Self::Dns4(_) => DNS4_CODE,
            Self::Dns6(_) => DNS6_CODE,
            Self::Tcp(_) => TCP_CODE,
            Self::Udp(_) => UDP_CODE,
            Self::QuicV1 => QUIC_V1_CODE,
            Self::P2p(_) => P2P_CODE,
            Self::P2pCircuit => P2P_CIRCUIT_CODE,
        }
    }

    /// Writes the binary multicodec encoding for this protocol into `out`.
    ///
    /// Shape: `<varint(code)><value>` where the value layout is determined
    /// by the protocol. Length-prefixed protocols prepend another varint
    /// before their body.
    pub(crate) fn write_binary(&self, out: &mut Vec<u8>) {
        write_uvarint(self.code(), out);
        match self {
            Self::Ip4(bytes) => out.extend_from_slice(bytes),
            Self::Ip6(bytes) => out.extend_from_slice(bytes),
            Self::Dns(name) | Self::Dns4(name) | Self::Dns6(name) => {
                let body = name.as_bytes();
                write_uvarint(body.len() as u64, out);
                out.extend_from_slice(body);
            }
            Self::Tcp(port) | Self::Udp(port) => out.extend_from_slice(&port.to_be_bytes()),
            Self::QuicV1 | Self::P2pCircuit => {}
            Self::P2p(peer_id) => {
                let body = peer_id.to_bytes();
                write_uvarint(body.len() as u64, out);
                out.extend_from_slice(&body);
            }
        }
    }

    /// Reads a single protocol component from the front of `bytes`.
    ///
    /// Returns the decoded protocol and the unconsumed input.
    pub(crate) fn read_binary(bytes: &[u8]) -> Result<(Self, &[u8]), MultiaddrError> {
        let (code, rest) = read_uvarint_with_remainder(bytes)?;

        match code {
            IP4_CODE => {
                let (value, rest) = fixed::<4>(rest, "ip4")?;
                Ok((Self::Ip4(value), rest))
            }
            IP6_CODE => {
                let (value, rest) = fixed::<16>(rest, "ip6")?;
                Ok((Self::Ip6(value), rest))
            }
            TCP_CODE => {
                let (value, rest) = fixed::<2>(rest, "tcp")?;
                Ok((Self::Tcp(u16::from_be_bytes(value)), rest))
            }
            UDP_CODE => {
                let (value, rest) = fixed::<2>(rest, "udp")?;
                Ok((Self::Udp(u16::from_be_bytes(value)), rest))
            }
            QUIC_V1_CODE => Ok((Self::QuicV1, rest)),
            P2P_CIRCUIT_CODE => Ok((Self::P2pCircuit, rest)),
            DNS_CODE | DNS4_CODE | DNS6_CODE => {
                let label = match code {
                    DNS_CODE => "dns",
                    DNS4_CODE => "dns4",
                    _ => "dns6",
                };
                let (body, rest) = length_prefixed(rest, label)?;
                let name = core::str::from_utf8(body)
                    .map_err(|e| MultiaddrError::InvalidBinaryValue {
                        protocol: label,
                        reason: e.to_string(),
                    })?
                    .to_string();
                // Same validation the text parser applies. Without it the
                // binary decoder accepts names the text form cannot represent:
                // a name containing `/` re-parses as different components
                // entirely, so one address would have two meanings depending
                // on which representation a check looked at.
                if !is_valid_dns(&name) {
                    return Err(MultiaddrError::InvalidBinaryValue {
                        protocol: label,
                        reason: "invalid dns name".to_string(),
                    });
                }
                let protocol = match code {
                    DNS_CODE => Self::Dns(name),
                    DNS4_CODE => Self::Dns4(name),
                    _ => Self::Dns6(name),
                };
                Ok((protocol, rest))
            }
            P2P_CODE => {
                let (body, rest) = length_prefixed(rest, "p2p")?;
                let peer_id =
                    PeerId::from_bytes(body).map_err(|e| MultiaddrError::InvalidBinaryValue {
                        protocol: "p2p",
                        reason: e.to_string(),
                    })?;
                Ok((Self::P2p(peer_id), rest))
            }
            _ => Err(MultiaddrError::UnknownProtocolCode { code }),
        }
    }
}

/// Reads `N` bytes from the front of `bytes` as a fixed-size value.
fn fixed<'a, const N: usize>(
    bytes: &'a [u8],
    protocol: &'static str,
) -> Result<([u8; N], &'a [u8]), MultiaddrError> {
    let (value, rest) = bytes
        .split_first_chunk::<N>()
        .ok_or(MultiaddrError::TruncatedBinaryValue { protocol })?;
    Ok((*value, rest))
}

/// Reads a varint length prefix and returns a slice of that many bytes
/// and the input following the body.
fn length_prefixed<'a>(
    bytes: &'a [u8],
    protocol: &'static str,
) -> Result<(&'a [u8], &'a [u8]), MultiaddrError> {
    let (len, rest) = read_uvarint_with_remainder(bytes)?;
    // Compare in u64 so an absurd declared length errs identically on
    // 32-bit and 64-bit targets.
    if len > rest.len() as u64 {
        return Err(MultiaddrError::TruncatedBinaryValue { protocol });
    }
    let len = len as usize;
    Ok(rest.split_at(len))
}
