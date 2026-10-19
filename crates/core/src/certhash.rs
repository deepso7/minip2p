use alloc::{string::ToString, vec::Vec};
use core::{fmt, str::FromStr};

use base64ct::{Base64UrlUnpadded, Encoding};
use minip2p_identity::{multibase, read_uvarint_with_remainder};

use crate::CerthashError;

/// Multihash code for sha2-256, the only certhash function WebTransport uses.
const SHA256_CODE: u8 = 0x12;
/// Length of a sha2-256 digest.
const SHA256_LEN: u8 = 32;
/// A certhash multihash: code, length, then the digest.
const MULTIHASH_LEN: usize = 2 + SHA256_LEN as usize;
/// Unpadded base64url text of a [`MULTIHASH_LEN`]-byte multihash.
const BASE64URL_LEN: usize = (MULTIHASH_LEN * 4).div_ceil(3);

/// The sha2-256 hash of a WebTransport server certificate, as carried by a
/// `/certhash` multiaddr component.
///
/// Browsers verify a self-signed WebTransport certificate against these
/// hashes (`serverCertificateHashes`), and libp2p carries them in Noise
/// extensions as multihash bytes. Only sha2-256 with a 32-byte digest is
/// accepted, so every value is a valid hash for that check.
///
/// Text form is a multibase string. Parsing accepts base58btc (`z`),
/// base64url (`u`), base32 (`b`/`B`) and base16 (`f`/`F`); printing always
/// uses base64url, as rust-libp2p and js-libp2p do.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Certhash([u8; SHA256_LEN as usize]);

impl Certhash {
    /// Wraps a sha2-256 digest, typically `sha256(certificate DER)`.
    pub const fn from_sha256_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// The sha2-256 digest.
    pub const fn digest(&self) -> &[u8; 32] {
        &self.0
    }

    /// Decodes multihash bytes (`0x12 0x20 <32-byte digest>`), the form used
    /// in binary multiaddrs and Noise extensions.
    pub fn from_multihash_bytes(bytes: &[u8]) -> Result<Self, CerthashError> {
        let (code, rest) = read_uvarint_with_remainder(bytes)?;
        if code != u64::from(SHA256_CODE) {
            return Err(CerthashError::UnsupportedHashCode { code });
        }
        let (declared, digest) = read_uvarint_with_remainder(rest)?;
        match digest.try_into() {
            Ok(digest) if declared == u64::from(SHA256_LEN) => Ok(Self(digest)),
            _ => Err(CerthashError::InvalidDigestLength {
                declared,
                actual: digest.len(),
            }),
        }
    }

    /// Encodes the multihash bytes: `0x12 0x20 <32-byte digest>`.
    pub fn to_multihash_bytes(&self) -> [u8; MULTIHASH_LEN] {
        let mut out = [0u8; MULTIHASH_LEN];
        let (head, digest) = out.split_at_mut(2);
        head.copy_from_slice(&[SHA256_CODE, SHA256_LEN]);
        digest.copy_from_slice(&self.0);
        out
    }
}

impl fmt::Display for Certhash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; BASE64URL_LEN];
        // The buffer is sized for a certhash multihash, so this cannot fail.
        let text = Base64UrlUnpadded::encode(&self.to_multihash_bytes(), &mut buf)
            .map_err(|_too_small| fmt::Error)?;
        write!(f, "u{text}")
    }
}

impl FromStr for Certhash {
    type Err = CerthashError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut chars = input.chars();
        let prefix = chars.next().ok_or(CerthashError::EmptyInput)?;
        let payload = chars.as_str();
        let invalid = |reason: &dyn ToString| CerthashError::InvalidMultibase {
            reason: reason.to_string(),
        };
        let bytes: Vec<u8> = match prefix {
            'u' => Base64UrlUnpadded::decode_vec(payload).map_err(|e| invalid(&e))?,
            'z' => multibase::decode_base58btc(payload).map_err(|e| invalid(&e))?,
            'b' | 'B' => multibase::decode_base32(payload).map_err(|e| invalid(&e))?,
            'f' | 'F' => multibase::decode_base16(payload).map_err(|e| invalid(&e))?,
            other => return Err(CerthashError::UnsupportedMultibase(other)),
        };
        Self::from_multihash_bytes(&bytes)
    }
}
