use der_parser::oid::Oid;
use minip2p_identity::{KeyType, Keypair, PeerId, PublicKey};
use rcgen::{
    CertificateParams, CustomExtension, DistinguishedName, KeyPair, PKCS_ECDSA_P256_SHA256,
    PublicKeyData,
};
use thiserror::Error;
use x509_parser::prelude::{FromDer, X509Certificate};

const P2P_EXT_OID: [u64; 9] = [1, 3, 6, 1, 4, 1, 53594, 1, 1];
const BASIC_CONSTRAINTS_OID: [u64; 4] = [2, 5, 29, 19];
const KEY_USAGE_OID: [u64; 4] = [2, 5, 29, 15];
const EXTENDED_KEY_USAGE_OID: [u64; 4] = [2, 5, 29, 37];
const P2P_SIGNING_PREFIX: [u8; 21] = *b"libp2p-tls-handshake:";

#[derive(Clone, Debug)]
pub struct GeneratedCertificate {
    pub certificate_pem: String,
    pub private_key_pem: String,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("failed to generate certificate: {0}")]
    CertificateGeneration(String),
    #[error("failed to parse certificate: {0}")]
    CertificateParse(String),
    #[error("certificate chain must contain exactly one certificate")]
    InvalidCertificateChain,
    #[error("peer certificate is missing")]
    MissingPeerCertificate,
    #[error("peer certificate is not currently valid")]
    InvalidCertificateValidity,
    #[error("peer certificate self-signature is invalid")]
    InvalidSelfSignature,
    #[error("peer certificate has unsupported critical extension")]
    UnsupportedCriticalExtension,
    #[error("peer certificate is missing libp2p extension")]
    MissingLibp2pExtension,
    #[error("peer certificate libp2p extension is malformed")]
    InvalidLibp2pExtension,
    #[error("peer certificate contains unsupported host key type {0:?}")]
    UnsupportedHostKeyType(KeyType),
    #[error("peer certificate libp2p extension signature is invalid")]
    ExtensionSignatureInvalid,
    #[error("peer id mismatch: expected {expected}, got {actual}")]
    PeerIdMismatch { expected: PeerId, actual: PeerId },
}

pub fn generate_certificate(host_keypair: &Keypair) -> Result<GeneratedCertificate, AuthError> {
    let cert_keypair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|err| AuthError::CertificateGeneration(err.to_string()))?;

    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .custom_extensions
        .push(make_libp2p_extension(host_keypair, &cert_keypair)?);

    let cert = params
        .self_signed(&cert_keypair)
        .map_err(|err| AuthError::CertificateGeneration(err.to_string()))?;

    let certificate_pem = cert.pem();
    let private_key_pem = cert_keypair.serialize_pem();
    Ok(GeneratedCertificate {
        certificate_pem,
        private_key_pem,
    })
}

pub fn verify_peer_certificate(
    peer_cert_chain: Option<Vec<&[u8]>>,
    peer_cert: Option<&[u8]>,
    expected_peer: Option<&PeerId>,
) -> Result<PeerId, AuthError> {
    let cert_der = match (peer_cert_chain, peer_cert) {
        (Some(chain), _) => {
            if chain.len() != 1 {
                return Err(AuthError::InvalidCertificateChain);
            }
            chain[0]
        }
        (None, Some(leaf)) => leaf,
        (None, None) => return Err(AuthError::MissingPeerCertificate),
    };

    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|err| AuthError::CertificateParse(err.to_string()))?;

    if !cert.validity().is_valid() {
        return Err(AuthError::InvalidCertificateValidity);
    }

    cert.verify_signature(None)
        .map_err(|_| AuthError::InvalidSelfSignature)?;

    let oid =
        Oid::from(&P2P_EXT_OID).map_err(|err| AuthError::CertificateParse(err.to_string()))?;

    for ext in cert.extensions() {
        if ext.critical && ext.oid != oid && !is_known_critical_extension(&ext.oid) {
            return Err(AuthError::UnsupportedCriticalExtension);
        }
    }

    let extension = cert
        .get_extension_unique(&oid)
        .map_err(|err| AuthError::CertificateParse(err.to_string()))?
        .ok_or(AuthError::MissingLibp2pExtension)?;

    let (public_key, signature): (Vec<u8>, Vec<u8>) =
        yasna::decode_der(extension.value).map_err(|_| AuthError::InvalidLibp2pExtension)?;

    let public_key =
        PublicKey::decode_protobuf(&public_key).map_err(|_| AuthError::InvalidLibp2pExtension)?;

    if public_key.key_type() != KeyType::Ed25519 {
        return Err(AuthError::UnsupportedHostKeyType(public_key.key_type()));
    }

    let mut message = Vec::with_capacity(P2P_SIGNING_PREFIX.len() + cert.public_key().raw.len());
    message.extend_from_slice(&P2P_SIGNING_PREFIX);
    message.extend_from_slice(cert.public_key().raw);

    if !public_key.verify(&message, &signature) {
        return Err(AuthError::ExtensionSignatureInvalid);
    }

    let peer_id = PeerId::from_public_key(&public_key);

    if let Some(expected_peer) = expected_peer {
        if expected_peer != &peer_id {
            return Err(AuthError::PeerIdMismatch {
                expected: expected_peer.clone(),
                actual: peer_id,
            });
        }
    }

    Ok(peer_id)
}

fn make_libp2p_extension(
    host_keypair: &Keypair,
    cert_keypair: &KeyPair,
) -> Result<CustomExtension, AuthError> {
    let mut message = Vec::new();
    message.extend_from_slice(&P2P_SIGNING_PREFIX);
    let subject_public_key_info = cert_keypair.subject_public_key_info();
    message.extend_from_slice(&subject_public_key_info);

    let signature = host_keypair.sign(&message);
    let encoded_public_key = host_keypair.public().encode_protobuf();
    let extension_content = yasna::encode_der(&(encoded_public_key, signature));

    let mut extension = CustomExtension::from_oid_content(&P2P_EXT_OID, extension_content);
    extension.set_criticality(true);
    Ok(extension)
}

fn is_known_critical_extension(oid: &Oid<'_>) -> bool {
    let basic_constraints = Oid::from(&BASIC_CONSTRAINTS_OID).expect("valid OID");
    let key_usage = Oid::from(&KEY_USAGE_OID).expect("valid OID");
    let extended_key_usage = Oid::from(&EXTENDED_KEY_USAGE_OID).expect("valid OID");

    oid == &basic_constraints || oid == &key_usage || oid == &extended_key_usage
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex(input: &str) -> Vec<u8> {
        assert_eq!(input.len() % 2, 0);
        let mut out = Vec::with_capacity(input.len() / 2);
        let bytes = input.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let hi = (bytes[i] as char).to_digit(16).expect("invalid hex") as u8;
            let lo = (bytes[i + 1] as char).to_digit(16).expect("invalid hex") as u8;
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    #[test]
    fn parses_valid_ed25519_spec_certificate() {
        let cert = decode_hex(
            "308201773082011ea003020102020900f5bd0debaa597f52300a06082a8648ce3d04030230003020170d3735303130313030303030305a180f34303936303130313030303030305a30003059301306072a8648ce3d020106082a8648ce3d030107034200046bf9871220d71dcb3483ecdfcbfcc7c103f8509d0974b3c18ab1f1be1302d643103a08f7a7722c1b247ba3876fe2c59e26526f479d7718a85202ddbe47562358a37f307d307b060a2b0601040183a25a01010101ff046a30680424080112207fda21856709c5ae12fd6e8450623f15f11955d384212b89f56e7e136d2e17280440aaa6bffabe91b6f30c35e3aa4f94b1188fed96b0ffdd393f4c58c1c047854120e674ce64c788406d1c2c4b116581fd7411b309881c3c7f20b46e54c7e6fe7f0f300a06082a8648ce3d040302034700304402207d1a1dbd2bda235ff2ec87daf006f9b04ba076a5a5530180cd9c2e8f6399e09d0220458527178c7e77024601dbb1b256593e9b96d961b96349d1f560114f61a87595",
        );

        let peer_id = verify_peer_certificate(None, Some(&cert), None).expect("must verify");
        assert_eq!(
            peer_id.to_string(),
            "12D3KooWJRSrypvnpHgc6ZAgyCni4KcSmbV7uGRaMw5LgMKT18fq"
        );
    }

    #[test]
    fn rejects_invalid_extension_signature() {
        let cert = decode_hex(
            "308201773082011da003020102020830a73c5d896a1109300a06082a8648ce3d04030230003020170d3735303130313030303030305a180f34303936303130313030303030305a30003059301306072a8648ce3d020106082a8648ce3d03010703420004bbe62df9a7c1c46b7f1f21d556deec5382a36df146fb29c7f1240e60d7d5328570e3b71d99602b77a65c9b3655f62837f8d66b59f1763b8c9beba3be07778043a37f307d307b060a2b0601040183a25a01010101ff046a3068042408011220ec8094573afb9728088860864f7bcea2d4fd412fef09a8e2d24d482377c20db60440ecabae8354afa2f0af4b8d2ad871e865cb5a7c0c8d3dbdbf42de577f92461a0ebb0a28703e33581af7d2a4f2270fc37aec6261fcc95f8af08f3f4806581c730a300a06082a8648ce3d040302034800304502202dfb17a6fa0f94ee0e2e6a3b9fb6e986f311dee27392058016464bd130930a61022100ba4b937a11c8d3172b81e7cd04aedb79b978c4379c2b5b24d565dd5d67d3cb3c",
        );

        let err = verify_peer_certificate(None, Some(&cert), None).expect_err("must fail");
        assert!(matches!(err, AuthError::ExtensionSignatureInvalid));
    }
}
