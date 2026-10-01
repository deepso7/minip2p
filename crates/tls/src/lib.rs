//! libp2p TLS certificate generation and verification for minip2p.
//!
//! Implements the [libp2p TLS spec](https://github.com/libp2p/specs/blob/master/tls/tls.md)
//! for peer authentication over TLS 1.3. Transport-agnostic: reusable by
//! QUIC, TCP, WebSocket, and future transport adapters.
//!
//! Both verification and generation are `no_std + alloc` compatible. The
//! `std` feature adds a convenience wrapper ([`generate_certificate`]) that
//! uses OS randomness and a default validity window.
//!
//! Certificate generation uses Ed25519 host identities. Verification accepts
//! Ed25519 and ECDSA P-256 host keys; secp256k1 and RSA are deliberately
//! unsupported for now. Verification takes the current time from the caller,
//! so the crate stays sans-I/O.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod error;
mod generate;
mod verify;

#[cfg(test)]
mod test_rng;

pub use error::TlsError;
#[cfg(feature = "std")]
pub use generate::generate_certificate;
pub use generate::generate_certificate_with_rng;
pub use verify::verify_libp2p_certificate;
pub use x509_cert::time::Validity;

/// OID for the libp2p Public Key Extension: `1.3.6.1.4.1.53594.1.1`.
///
/// Allocated by IANA to the libp2p project at Protocol Labs.
pub(crate) const LIBP2P_EXTENSION_OID: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.53594.1.1");

/// Prefix prepended to the SubjectPublicKeyInfo before signing with the host key.
pub(crate) const SIGNATURE_PREFIX: &[u8] = b"libp2p-tls-handshake:";
