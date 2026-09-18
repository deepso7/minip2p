//! Protobuf wire codec compatible with js-libp2p pubsub peer discovery.
//!
//! Field framing uses the shared protobuf vocabulary in [`minip2p_core`];
//! this module keeps beacon layout, size caps, and contextual
//! [`DiscoveryWireError`] values (including field-number policy).

use alloc::vec::Vec;

use minip2p_core::{
    WIRE_LEN, WireError, encode_bytes_field, read_len_delimited, read_tag, skip_field, uvarint_len,
};

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
/// Maximum bytes in a protobuf-encoded public key that can fill a beacon by itself.
///
/// The three remaining bytes encode the field tag and its two-byte length prefix.
pub const MAX_PUBLIC_KEY_LEN: usize = MAX_BEACON_SIZE - 3;

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
            encode_bytes_field(&mut out, 1, &self.public_key);
        }
        for addr in &self.addrs {
            encode_bytes_field(&mut out, 2, addr);
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
        while let Some((field, wire)) = read_tag(input, &mut idx)? {
            if field == 0 {
                return Err(DiscoveryWireError::FieldZero);
            }
            if field > MAX_FIELD_NUMBER {
                return Err(DiscoveryWireError::InvalidFieldNumber);
            }
            match (field, wire) {
                (1, WIRE_LEN) => {
                    let value = read_len_delimited(input, &mut idx)?;
                    if value.len() > MAX_PUBLIC_KEY_LEN {
                        return Err(DiscoveryWireError::PublicKeyTooLarge);
                    }
                    beacon.public_key = value.to_vec();
                }
                (2, WIRE_LEN) => {
                    if beacon.addrs.len() == MAX_BEACON_ADDRS {
                        return Err(DiscoveryWireError::TooManyAddresses);
                    }
                    let value = read_len_delimited(input, &mut idx)?;
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
///
/// Shared framing failures are wrapped as [`Self::Wire`] so callers retain
/// discovery context while reusing the core protobuf vocabulary.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DiscoveryWireError {
    /// A shared protobuf framing failure.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// The top-level payload exceeds [`MAX_BEACON_SIZE`].
    #[error("discovery beacon exceeds the maximum size")]
    BeaconTooLarge,
    /// Protobuf field zero is forbidden.
    #[error("protobuf field number zero is invalid")]
    FieldZero,
    /// The field number exceeds protobuf's 29-bit range.
    #[error("protobuf field number exceeds the supported range")]
    InvalidFieldNumber,
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

fn len_field_size(value_len: usize) -> usize {
    // Beacon fields 1 and 2 always use a single-byte tag.
    1usize
        .saturating_add(uvarint_len(value_len as u64))
        .saturating_add(value_len)
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
        // Discovery-specific field-number policy plus unknown-field skip.
        assert_eq!(Beacon::decode(&[0]), Err(DiscoveryWireError::FieldZero));
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
        Beacon::decode(&key).expect("a beacon at the public-key size limit must decode");
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

    #[test]
    fn accepts_variable_length_public_keys_within_the_beacon_budget() {
        let key = Beacon {
            // Large enough to cover ordinary RSA public-key protobufs and to
            // regress the former 128-byte wire limit.
            public_key: vec![7; 1_024],
            addrs: vec![],
        };

        assert_eq!(Beacon::decode(&key.encode()).unwrap(), key);
    }
}
