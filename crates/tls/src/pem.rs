//! PEM encoding helpers for certificate and private key DER bytes.
//!
//! `no_std + alloc` compatible. When the `std` feature is enabled,
//! `cert_to_pem` uses `der::EncodePem` for X.509-aware PEM output;
//! without `std` it falls back to a hand-written base64 encoder that
//! produces identical RFC 7468 PEM.

use alloc::string::String;

/// Encodes DER-encoded certificate bytes as a PEM string.
///
/// With the `std` feature, uses `der::EncodePem` for proper X.509-aware
/// encoding. Without `std`, uses a hand-written base64 encoder.
#[cfg(feature = "std")]
pub fn cert_to_pem(cert_der: &[u8]) -> String {
    use der::pem::LineEnding;
    use der::{Decode, EncodePem};
    use x509_cert::Certificate;

    match Certificate::from_der(cert_der) {
        Ok(cert) => cert
            .to_pem(LineEnding::LF)
            .unwrap_or_else(|_| manual_pem("CERTIFICATE", cert_der)),
        Err(_) => manual_pem("CERTIFICATE", cert_der),
    }
}

/// Encodes DER-encoded certificate bytes as a PEM string.
///
/// Uses a hand-written base64 encoder producing RFC 7468 compliant PEM.
#[cfg(not(feature = "std"))]
pub fn cert_to_pem(cert_der: &[u8]) -> String {
    manual_pem("CERTIFICATE", cert_der)
}

/// Encodes DER-encoded PKCS#8 private key bytes as a PEM string.
///
/// Wraps the DER bytes in `-----BEGIN PRIVATE KEY-----` /
/// `-----END PRIVATE KEY-----` headers with base64 content.
pub fn private_key_to_pem(key_der: &[u8]) -> String {
    manual_pem("PRIVATE KEY", key_der)
}

/// Manual PEM encoding: base64 with 64-char line wrapping and header/footer.
fn manual_pem(label: &str, der: &[u8]) -> String {
    use alloc::format;

    let b64 = base64_encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(core::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

/// Minimal base64 encoder (standard alphabet, with padding).
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity(((input.len() + 2) / 3) * 4);

    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[((triple >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3f) as usize] as char);

        if chunk.len() > 1 {
            out.push(ALPHABET[((triple >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }

        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_encodes_empty() {
        assert_eq!(base64_encode(b""), "");
    }

    #[test]
    fn base64_encodes_hello() {
        assert_eq!(base64_encode(b"Hello"), "SGVsbG8=");
    }

    #[test]
    fn base64_encodes_three_byte_boundary() {
        assert_eq!(base64_encode(b"abc"), "YWJj");
    }

    #[test]
    fn pem_wraps_correctly() {
        let pem = manual_pem("TEST", b"hello");
        assert!(pem.starts_with("-----BEGIN TEST-----\n"));
        assert!(pem.ends_with("-----END TEST-----\n"));
    }
}
