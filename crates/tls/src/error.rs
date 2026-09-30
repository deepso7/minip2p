use alloc::string::String;
use thiserror::Error;

/// Errors from libp2p TLS certificate generation and verification.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TlsError {
    /// The certificate is missing the libp2p Public Key Extension.
    #[error("missing libp2p TLS extension (OID 1.3.6.1.4.1.53594.1.1)")]
    MissingExtension,

    /// The certificate carries the libp2p extension more than once.
    #[error("certificate repeats the libp2p TLS extension (OID 1.3.6.1.4.1.53594.1.1)")]
    DuplicateExtension,

    /// The certificate carries a critical extension other than the libp2p
    /// extension, which the libp2p TLS spec requires rejecting.
    #[error("unsupported critical certificate extension: {0}")]
    UnsupportedCriticalExtension(String),

    /// The libp2p TLS extension value could not be decoded.
    #[error("invalid libp2p TLS extension: {0}")]
    InvalidExtension(String),

    /// The extension's host-key signature failed verification.
    #[error("extension signature verification failed: {0}")]
    SignatureVerification(String),

    /// The public key in the extension is malformed.
    #[error("invalid public key in certificate extension: {0}")]
    InvalidPublicKey(String),

    /// The host key in the extension is a type minip2p doesn't verify:
    /// secp256k1, RSA, or ECDSA on a curve other than P-256.
    #[error("unsupported host key type: {0} (minip2p verifies Ed25519 and ECDSA P-256 host keys)")]
    UnsupportedKeyType(String),

    /// The certificate's self-signature (over TBSCertificate) is invalid.
    #[error("certificate self-signature verification failed")]
    InvalidSelfSignature,

    /// The certificate uses an unsupported signature algorithm for its self-signature.
    #[error("unsupported certificate signature algorithm: {0}")]
    UnsupportedSignatureAlgorithm(String),

    /// The certificate is expired or not yet valid at the caller's `now`.
    /// All values are seconds since the Unix epoch.
    #[error(
        "certificate is not valid at {now_unix_secs}: valid from {not_before_unix_secs} to {not_after_unix_secs} (Unix seconds); check the local clock"
    )]
    OutsideValidityPeriod {
        /// The time the certificate was checked at.
        now_unix_secs: u64,
        /// The certificate's NotBefore bound.
        not_before_unix_secs: u64,
        /// The certificate's NotAfter bound.
        not_after_unix_secs: u64,
    },

    /// DER encoding or decoding failed.
    #[error("DER encoding/decoding error: {0}")]
    Der(String),

    /// Certificate generation failed.
    #[error("certificate generation failed: {0}")]
    CertificateGeneration(String),
}
