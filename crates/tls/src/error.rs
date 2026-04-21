use alloc::string::String;
use thiserror::Error;

/// Errors from libp2p TLS certificate generation and verification.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TlsError {
    /// The certificate is missing the libp2p Public Key Extension.
    #[error("missing libp2p TLS extension (OID 1.3.6.1.4.1.53594.1.1)")]
    MissingExtension,

    /// The libp2p TLS extension value could not be decoded.
    #[error("invalid libp2p TLS extension: {0}")]
    InvalidExtension(String),

    /// The extension's host-key signature failed verification.
    #[error("extension signature verification failed: {0}")]
    SignatureVerification(String),

    /// The public key in the extension is malformed or uses an unsupported type.
    #[error("invalid public key in certificate extension: {0}")]
    InvalidPublicKey(String),

    /// The certificate's self-signature (over TBSCertificate) is invalid.
    #[error("certificate self-signature verification failed")]
    InvalidSelfSignature,

    /// The certificate uses an unsupported signature algorithm for its self-signature.
    #[error("unsupported certificate signature algorithm: {0}")]
    UnsupportedSignatureAlgorithm(String),

    /// DER encoding or decoding failed.
    #[error("DER encoding/decoding error: {0}")]
    Der(String),

    /// The expected PeerId does not match the one derived from the certificate.
    #[error("peer id mismatch: expected {expected}, got {actual}")]
    PeerIdMismatch { expected: String, actual: String },

    /// Certificate generation failed.
    #[error("certificate generation failed: {0}")]
    CertificateGeneration(String),
}
