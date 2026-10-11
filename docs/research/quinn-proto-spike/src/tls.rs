//! libp2p TLS (rustls + ring) for quinn-proto.
//!
//! The rustls verifiers only check what the handshake needs: exactly one
//! certificate, a structurally valid libp2p certificate, and the TLS 1.3
//! CertificateVerify signature against that certificate's key. The expected
//! peer id is checked after the handshake, as the quiche adapter does today.

use std::sync::Arc;
use std::time::Duration;

use der::{Decode, Encode};
use minip2p_identity::Ed25519Keypair;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};

pub const ALPN: &[u8] = b"libp2p";

#[derive(Debug)]
pub struct Libp2pVerifier {
    algs: WebPkiSupportedAlgorithms,
}

impl Libp2pVerifier {
    fn new(provider: &CryptoProvider) -> Self {
        Self { algs: provider.signature_verification_algorithms }
    }

    fn verify_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], now: UnixTime) -> Result<(), Error> {
        if !intermediates.is_empty() {
            return Err(Error::General("libp2p TLS requires exactly one certificate".into()));
        }
        minip2p_tls::verify_libp2p_certificate(end_entity, Duration::from_secs(now.as_secs()))
            .map(|_| ())
            .map_err(|e| Error::General(format!("libp2p certificate rejected: {e}")))
    }

    fn verify_sig(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        let parsed = x509_cert::Certificate::from_der(cert)
            .map_err(|e| Error::General(format!("bad certificate: {e}")))?;
        let spki = parsed
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .map_err(|e| Error::General(format!("bad spki: {e}")))?;
        rustls::crypto::verify_tls13_signature_with_raw_key(message, &SubjectPublicKeyInfoDer::from(spki), dss, &self.algs)
    }
}

impl ServerCertVerifier for Libp2pVerifier {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], _server_name: &ServerName<'_>, _ocsp: &[u8], now: UnixTime) -> Result<ServerCertVerified, Error> {
        self.verify_cert(end_entity, intermediates, now)?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::PeerIncompatible(rustls::PeerIncompatible::Tls12NotOffered))
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        self.verify_sig(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

impl ClientCertVerifier for Libp2pVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], now: UnixTime) -> Result<ClientCertVerified, Error> {
        self.verify_cert(end_entity, intermediates, now)?;
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::PeerIncompatible(rustls::PeerIncompatible::Tls12NotOffered))
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        self.verify_sig(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

fn identity(keypair: &Ed25519Keypair) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let (cert, key) = minip2p_tls::generate_certificate(keypair).expect("cert");
    (vec![CertificateDer::from(cert)], PrivateKeyDer::try_from(key).expect("pkcs8 key"))
}

pub fn client_config(keypair: &Ed25519Keypair) -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(Libp2pVerifier::new(&provider));
    let (certs, key) = identity(keypair);
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls13")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(certs, key)
        .expect("client cert");
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    cfg
}

pub fn server_config(keypair: &Ed25519Keypair) -> rustls::ServerConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(Libp2pVerifier::new(&provider));
    let (certs, key) = identity(keypair);
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls13")
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .expect("server cert");
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    cfg
}
