//! Protobuf wire codec compatible with js-libp2p pubsub peer discovery.

use alloc::vec::Vec;

/// Default js-libp2p-compatible discovery topic.
pub const DISCOVERY_TOPIC: &str = "_peer-discovery._p2p._pubsub";
/// Maximum topic length, deliberately equal to minip2p-pubsub's bound.
pub const MAX_TOPIC_LEN: usize = 1024;
/// Maximum encoded beacon payload.
pub const MAX_BEACON_SIZE: usize = 8192;
/// Maximum address fields in a beacon.
pub const MAX_BEACON_ADDRS: usize = 64;
/// Maximum bytes in one encoded multiaddr.
pub const MAX_ADDR_LEN: usize = 1024;
/// Maximum bytes in the protobuf-encoded public key.
pub const MAX_PUBLIC_KEY_LEN: usize = 128;

const WIRE_VARINT: u64 = 0;
const WIRE_64: u64 = 1;
const WIRE_LEN: u64 = 2;
const WIRE_32: u64 = 5;
const MAX_FIELD_NUMBER: u64 = (1 << 29) - 1;

/// Presence payload: protobuf `Peer { bytes publicKey = 1; repeated bytes addrs = 2; }`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Beacon {
    /// Deterministic libp2p public-key protobuf bytes.
    pub public_key: Vec<u8>,
    /// Binary multiaddrs, normally suffixed with `/p2p/<publisher>`.
    pub addrs: Vec<Vec<u8>>,
}

impl Beacon {
    /// Returns the exact number of bytes produced by [`Self::encode`].
    pub fn encoded_len(&self) -> usize {
        let mut len = 0usize;
        if !self.public_key.is_empty() {
            len = len.saturating_add(len_field_size(self.public_key.len()));
        }
        for addr in &self.addrs {
            len = len.saturating_add(len_field_size(addr.len()));
        }
        len
    }

    /// Encodes the beacon using canonical proto3 field ordering.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        if !self.public_key.is_empty() {
            write_len_field(1, &self.public_key, &mut out);
        }
        for addr in &self.addrs {
            write_len_field(2, addr, &mut out);
        }
        out
    }

    /// Decodes a bounded beacon, skipping protobuf-compatible unknown fields.
    pub fn decode(input: &[u8]) -> Result<Self, DiscoveryWireError> {
        if input.len() > MAX_BEACON_SIZE {
            return Err(DiscoveryWireError::BeaconTooLarge);
        }
        let mut beacon = Self::default();
        let mut idx = 0;
        while idx < input.len() {
            let tag = read_varint(input, &mut idx)?;
            let field = tag >> 3;
            let wire = tag & 7;
            if field == 0 {
                return Err(DiscoveryWireError::FieldZero);
            }
            if field > MAX_FIELD_NUMBER {
                return Err(DiscoveryWireError::InvalidFieldNumber);
            }
            match (field, wire) {
                (1, WIRE_LEN) => {
                    let value = read_len(input, &mut idx)?;
                    if value.len() > MAX_PUBLIC_KEY_LEN {
                        return Err(DiscoveryWireError::PublicKeyTooLarge);
                    }
                    beacon.public_key = value.to_vec();
                }
                (2, WIRE_LEN) => {
                    if beacon.addrs.len() == MAX_BEACON_ADDRS {
                        return Err(DiscoveryWireError::TooManyAddresses);
                    }
                    let value = read_len(input, &mut idx)?;
                    if value.len() > MAX_ADDR_LEN {
                        return Err(DiscoveryWireError::AddressTooLarge);
                    }
                    beacon.addrs.push(value.to_vec());
                }
                (_, wire) => skip_field(input, &mut idx, wire)?,
            }
        }
        Ok(beacon)
    }
}

/// Why a beacon payload could not be decoded safely.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DiscoveryWireError {
    /// The top-level payload exceeds [`MAX_BEACON_SIZE`].
    #[error("discovery beacon exceeds the maximum size")]
    BeaconTooLarge,
    /// A protobuf varint is truncated, too long, or overflows.
    #[error("invalid protobuf varint")]
    InvalidVarint,
    /// Protobuf field zero is forbidden.
    #[error("protobuf field number zero is invalid")]
    FieldZero,
    /// The field number exceeds protobuf's 29-bit range.
    #[error("protobuf field number exceeds the supported range")]
    InvalidFieldNumber,
    /// A length-delimited value extends beyond the input.
    #[error("truncated length-delimited protobuf field")]
    Truncated,
    /// Groups and reserved wire types are unsupported.
    #[error("unsupported protobuf wire type {0}")]
    UnsupportedWireType(u64),
    /// The public-key field exceeds its bound.
    #[error("discovery public key exceeds the maximum length")]
    PublicKeyTooLarge,
    /// An address field exceeds its bound.
    #[error("discovery address exceeds the maximum length")]
    AddressTooLarge,
    /// More than [`MAX_BEACON_ADDRS`] address fields were present.
    #[error("discovery beacon contains too many addresses")]
    TooManyAddresses,
}

fn write_len_field(field: u64, value: &[u8], out: &mut Vec<u8>) {
    write_varint((field << 3) | WIRE_LEN, out);
    write_varint(value.len() as u64, out);
    out.extend_from_slice(value);
}

fn len_field_size(value_len: usize) -> usize {
    1usize
        .saturating_add(varint_size(value_len))
        .saturating_add(value_len)
}

fn varint_size(mut value: usize) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

fn write_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn read_varint(input: &[u8], idx: &mut usize) -> Result<u64, DiscoveryWireError> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *input.get(*idx).ok_or(DiscoveryWireError::InvalidVarint)?;
        *idx += 1;
        if shift == 63 && byte > 1 {
            return Err(DiscoveryWireError::InvalidVarint);
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(DiscoveryWireError::InvalidVarint)
}

fn read_len<'a>(input: &'a [u8], idx: &mut usize) -> Result<&'a [u8], DiscoveryWireError> {
    let len: usize = read_varint(input, idx)?
        .try_into()
        .map_err(|_| DiscoveryWireError::Truncated)?;
    let end = idx.checked_add(len).ok_or(DiscoveryWireError::Truncated)?;
    let value = input.get(*idx..end).ok_or(DiscoveryWireError::Truncated)?;
    *idx = end;
    Ok(value)
}

fn skip_field(input: &[u8], idx: &mut usize, wire: u64) -> Result<(), DiscoveryWireError> {
    match wire {
        WIRE_VARINT => {
            read_varint(input, idx)?;
        }
        WIRE_64 => {
            *idx = idx.checked_add(8).ok_or(DiscoveryWireError::Truncated)?;
            if *idx > input.len() {
                return Err(DiscoveryWireError::Truncated);
            }
        }
        WIRE_LEN => {
            let _ = read_len(input, idx)?;
        }
        WIRE_32 => {
            *idx = idx.checked_add(4).ok_or(DiscoveryWireError::Truncated)?;
            if *idx > input.len() {
                return Err(DiscoveryWireError::Truncated);
            }
        }
        other => return Err(DiscoveryWireError::UnsupportedWireType(other)),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_vector_and_empty_round_trip() {
        let beacon = Beacon {
            public_key: vec![1, 2, 3],
            addrs: vec![vec![4, 5], vec![]],
        };
        assert_eq!(
            beacon.encode(),
            vec![0x0a, 3, 1, 2, 3, 0x12, 2, 4, 5, 0x12, 0]
        );
        assert_eq!(Beacon::decode(&beacon.encode()).unwrap(), beacon);
        assert_eq!(beacon.encoded_len(), beacon.encode().len());
        assert_eq!(Beacon::decode(&[]).unwrap(), Beacon::default());
    }

    #[test]
    fn rejects_malformed_and_skips_unknown_fields() {
        assert_eq!(Beacon::decode(&[0]), Err(DiscoveryWireError::FieldZero));
        assert_eq!(
            Beacon::decode(&[0x0b]),
            Err(DiscoveryWireError::UnsupportedWireType(3))
        );
        assert_eq!(
            Beacon::decode(&[0x0a, 2, 1]),
            Err(DiscoveryWireError::Truncated)
        );
        let input = [0x18, 0x96, 1, 0x0a, 1, 7];
        assert_eq!(Beacon::decode(&input).unwrap().public_key, vec![7]);
    }

    #[test]
    fn enforces_each_cap() {
        assert_eq!(
            Beacon::decode(&vec![0; MAX_BEACON_SIZE + 1]),
            Err(DiscoveryWireError::BeaconTooLarge)
        );
        let key = Beacon {
            public_key: vec![0; MAX_PUBLIC_KEY_LEN],
            addrs: vec![],
        }
        .encode();
        assert!(Beacon::decode(&key).is_ok());
        let key = Beacon {
            public_key: vec![0; MAX_PUBLIC_KEY_LEN + 1],
            addrs: vec![],
        }
        .encode();
        assert_eq!(
            Beacon::decode(&key),
            Err(DiscoveryWireError::PublicKeyTooLarge)
        );
        let addr = Beacon {
            public_key: vec![],
            addrs: vec![vec![0; MAX_ADDR_LEN + 1]],
        }
        .encode();
        assert_eq!(
            Beacon::decode(&addr),
            Err(DiscoveryWireError::AddressTooLarge)
        );
        let many = Beacon {
            public_key: vec![],
            addrs: vec![vec![]; MAX_BEACON_ADDRS + 1],
        }
        .encode();
        assert_eq!(
            Beacon::decode(&many),
            Err(DiscoveryWireError::TooManyAddresses)
        );
    }
}
