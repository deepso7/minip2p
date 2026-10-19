//! Codecs for `/certhash` values: WebTransport certificate hashes.
//!
//! A certhash is a sha2-256 multihash with a 32-byte digest. Binary form is
//! the raw multihash. Text form is a multibase string: parsing accepts
//! base58btc (`z`), base64url (`u`), base32 (`b`/`B`) and base16 (`f`/`F`);
//! printing always uses base64url, as rust-libp2p and js-libp2p do.

use alloc::{string::ToString, vec::Vec};
use core::fmt;

use base64ct::{Base64UrlUnpadded, Encoding};
use minip2p_identity::{Multihash, multibase};

use crate::CerthashError;

/// Multihash code for sha2-256, the only certhash function WebTransport uses.
const SHA256_CODE: u64 = 0x12;
/// Length of a sha2-256 digest.
const SHA256_LEN: usize = 32;

/// Decodes multihash bytes, accepting only a 32-byte sha2-256 digest.
pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Multihash, CerthashError> {
    let hash = Multihash::from_bytes(bytes).map_err(|e| CerthashError::InvalidMultihash {
        reason: e.to_string(),
    })?;
    if hash.code() != SHA256_CODE {
        return Err(CerthashError::UnsupportedHashCode { code: hash.code() });
    }
    if hash.digest().len() != SHA256_LEN {
        return Err(CerthashError::InvalidDigestLength {
            actual: hash.digest().len(),
        });
    }
    Ok(hash)
}

/// Parses multibase text into a certhash.
pub(crate) fn parse(input: &str) -> Result<Multihash, CerthashError> {
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
    from_bytes(&bytes)
}

/// Writes the canonical text form: `u` and unpadded base64url.
pub(crate) fn write(hash: &Multihash, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "u{}", Base64UrlUnpadded::encode_string(&hash.to_bytes()))
}
