//! Certificate generation per the libp2p TLS spec.
//!
//! Generates a self-signed X.509 certificate with an embedded libp2p Public
//! Key Extension. The certificate uses an ephemeral ECDSA P-256 key for
//! signing, while the libp2p host identity (Ed25519) is carried in the
//! extension.
//!
//! The core function [`generate_certificate_with_rng`] is `no_std + alloc`
//! compatible — the caller provides the validity period and CSPRNG. The
//! [`generate_certificate`] convenience wrapper (requires `std`) fills in
//! OS randomness and a 100-year validity window.

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use der::Encode;
use minip2p_identity::Ed25519Keypair;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::Generate;
use rand_core::CryptoRng;
use spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::certificate::TbsCertificate;
use x509_cert::ext::{Criticality, Extension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

use crate::{SIGNATURE_PREFIX, TlsError};

/// Generates a libp2p TLS certificate from an Ed25519 host keypair using OS
/// randomness and a 100-year validity window.
///
/// This is a convenience wrapper around [`generate_certificate_with_rng`].
///
/// Returns `(cert_der, private_key_der)` where `cert_der` is the DER-encoded
/// X.509 certificate and `private_key_der` is the DER-encoded PKCS#8
/// ephemeral private key.
#[cfg(feature = "std")]
pub fn generate_certificate(
    keypair: &Ed25519Keypair,
) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    let validity = Validity::from_now(core::time::Duration::from_secs(100 * 365 * 24 * 60 * 60))
        .map_err(|e| TlsError::CertificateGeneration(format!("{e}")))?;
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    generate_certificate_with_rng(keypair, validity, &mut rng)
}

/// Generates a libp2p TLS certificate from an Ed25519 host keypair.
///
/// `no_std + alloc` compatible — the caller provides the certificate validity
/// period and a CSPRNG source.
///
/// Returns `(cert_der, private_key_der)` where `cert_der` is the DER-encoded
/// X.509 certificate and `private_key_der` is the DER-encoded PKCS#8
/// ephemeral private key.
pub fn generate_certificate_with_rng(
    keypair: &Ed25519Keypair,
    validity: Validity,
    rng: &mut (impl CryptoRng + ?Sized),
) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    use p256::pkcs8::EncodePrivateKey;

    fn gen_err(e: impl core::fmt::Display) -> TlsError {
        TlsError::CertificateGeneration(format!("{e}"))
    }

    // 1. Generate an ephemeral ECDSA P-256 signing key.
    let ephemeral_signing_key = SigningKey::generate_from_rng(rng);
    let ephemeral_verifying_key = ephemeral_signing_key.verifying_key();

    // 2. Get the SubjectPublicKeyInfo DER of the ephemeral key.
    let spki_doc = ephemeral_verifying_key
        .to_public_key_der()
        .map_err(gen_err)?;
    let spki_der = spki_doc.as_bytes();

    // 3. Sign "libp2p-tls-handshake:" || SPKI_DER with the Ed25519 host key.
    let mut sign_message = Vec::with_capacity(SIGNATURE_PREFIX.len() + spki_der.len());
    sign_message.extend_from_slice(SIGNATURE_PREFIX);
    sign_message.extend_from_slice(spki_der);
    let host_signature = keypair.sign(&sign_message);

    // 4. Build the SignedKey extension value (DER-encoded ASN.1 SEQUENCE).
    let public_key_protobuf = keypair.public_key().encode_protobuf();
    let signed_key_der = encode_signed_key(&public_key_protobuf, &host_signature)
        .map_err(gen_err)?;

    // 5. Build the self-signed X.509 certificate.
    let serial_number = SerialNumber::new(&[0x49, 0x96, 0x02, 0xd2])
        .map_err(gen_err)?;

    let spki_owned = SubjectPublicKeyInfoOwned::from_key(ephemeral_verifying_key)
        .map_err(gen_err)?;

    let libp2p_ext = Libp2pExtension(signed_key_der);

    let mut builder = CertificateBuilder::new(
        Libp2pProfile,
        serial_number,
        validity,
        spki_owned,
    )
    .map_err(gen_err)?;

    builder
        .add_extension(&libp2p_ext)
        .map_err(gen_err)?;

    let cert = builder
        .build::<_, ecdsa::der::Signature<p256::NistP256>>(&ephemeral_signing_key)
        .map_err(gen_err)?;

    let cert_der = cert
        .to_der()
        .map_err(gen_err)?;

    // 6. Encode the ephemeral private key as PKCS#8 DER.
    let key_doc = ephemeral_signing_key
        .to_pkcs8_der()
        .map_err(gen_err)?;

    Ok((cert_der, key_doc.as_bytes().to_vec()))
}

/// DER-encodes the `SignedKey` ASN.1 structure.
///
/// ```text
/// SignedKey ::= SEQUENCE {
///   publicKey  OCTET STRING,
///   signature  OCTET STRING
/// }
/// ```
fn encode_signed_key(public_key: &[u8], signature: &[u8]) -> Result<Vec<u8>, der::Error> {
    use der::asn1::OctetStringRef;

    let pk = OctetStringRef::new(public_key)?;
    let sig = OctetStringRef::new(signature)?;

    // Calculate the total encoded length of the SEQUENCE contents.
    let pk_encoded_len = pk.encoded_len()?;
    let sig_encoded_len = sig.encoded_len()?;
    let content_len = (pk_encoded_len + sig_encoded_len)?;

    let mut buf = Vec::new();
    // SEQUENCE tag + length (DER encoding)
    buf.push(0x30);
    let len_val = usize::try_from(content_len)
        .map_err(|_| der::Tag::Sequence.value_error())?;
    if len_val < 128 {
        buf.push(len_val as u8);
    } else if len_val < 256 {
        buf.push(0x81);
        buf.push(len_val as u8);
    } else {
        buf.push(0x82);
        buf.push((len_val >> 8) as u8);
        buf.push((len_val & 0xff) as u8);
    }

    // Encode the two OCTET STRINGs into the remaining space.
    let offset = buf.len();
    buf.resize(offset + len_val, 0);
    let mut writer = der::SliceWriter::new(&mut buf[offset..]);
    pk.encode(&mut writer)?;
    sig.encode(&mut writer)?;
    writer.finish()?;

    Ok(buf)
}

// -- Custom builder profile for libp2p certificates --

/// Builder profile for libp2p TLS certificates.
///
/// Produces self-signed certs with `O=libp2p.io, serialNumber=1`.
struct Libp2pProfile;

impl x509_cert::builder::profile::BuilderProfile for Libp2pProfile {
    fn get_issuer(&self, subject: &Name) -> Name {
        subject.clone()
    }

    fn get_subject(&self) -> Name {
        "O=libp2p.io,serialNumber=1"
            .parse()
            .expect("hardcoded libp2p subject name must parse")
    }

    fn build_extensions(
        &self,
        _spk: spki::SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: spki::SubjectPublicKeyInfoRef<'_>,
        _tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<vec::Vec<Extension>> {
        Ok(vec![])
    }
}

// -- Custom extension type for the libp2p Public Key Extension --

/// Wrapper for the libp2p extension value.
struct Libp2pExtension(Vec<u8>);

impl Criticality for Libp2pExtension {
    fn criticality(&self, _subject: &Name, _extensions: &[Extension]) -> bool {
        false
    }
}

impl const_oid::AssociatedOid for Libp2pExtension {
    const OID: const_oid::ObjectIdentifier = crate::LIBP2P_EXTENSION_OID;
}

impl der::Encode for Libp2pExtension {
    fn encoded_len(&self) -> Result<der::Length, der::Error> {
        Ok(der::Length::try_from(self.0.len())?)
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> Result<(), der::Error> {
        encoder.write(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::verify_libp2p_certificate;

    #[test]
    fn round_trip_generate_and_verify() {
        let keypair = Ed25519Keypair::generate();
        let (cert_der, _key_der) = generate_certificate(&keypair).expect("must generate");

        let peer_id = verify_libp2p_certificate(&cert_der).expect("must verify");
        assert_eq!(peer_id, keypair.peer_id());
    }

    #[test]
    fn different_keypairs_produce_different_peer_ids() {
        let kp1 = Ed25519Keypair::generate();
        let kp2 = Ed25519Keypair::generate();

        let (cert1, _) = generate_certificate(&kp1).unwrap();
        let (cert2, _) = generate_certificate(&kp2).unwrap();

        let pid1 = verify_libp2p_certificate(&cert1).unwrap();
        let pid2 = verify_libp2p_certificate(&cert2).unwrap();

        assert_ne!(pid1, pid2);
        assert_eq!(pid1, kp1.peer_id());
        assert_eq!(pid2, kp2.peer_id());
    }
}
