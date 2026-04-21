//! libp2p TLS certificate generation and verification for minip2p.
//!
//! Implements the [libp2p TLS spec](https://github.com/libp2p/specs/blob/master/tls/tls.md)
//! for peer authentication over TLS 1.3. Transport-agnostic: reusable by
//! QUIC, TCP, WebSocket, and future transport adapters.
//!
//! Both verification and generation are `no_std + alloc` compatible. The
//! `std` feature adds a convenience wrapper ([`generate_certificate`]) that
//! uses OS randomness and a default validity window, plus PEM encoding helpers.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod error;
mod generate;
mod pem;
mod verify;

pub use error::TlsError;
#[cfg(feature = "std")]
pub use generate::generate_certificate;
pub use generate::generate_certificate_with_rng;
pub use pem::{cert_to_pem, private_key_to_pem};
pub use verify::verify_libp2p_certificate;
pub use x509_cert::time::Validity;

/// OID for the libp2p Public Key Extension: `1.3.6.1.4.1.53594.1.1`.
///
/// Allocated by IANA to the libp2p project at Protocol Labs.
pub const LIBP2P_EXTENSION_OID: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.53594.1.1");

/// Prefix prepended to the SubjectPublicKeyInfo before signing with the host key.
pub const SIGNATURE_PREFIX: &[u8] = b"libp2p-tls-handshake:";
