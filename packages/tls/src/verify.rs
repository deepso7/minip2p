//! Certificate verification per the libp2p TLS spec.
//!
//! Parses a DER-encoded X.509 certificate, extracts the libp2p Public Key
//! Extension, verifies the host-key signature over the certificate's
//! SubjectPublicKeyInfo, and derives the remote peer's `PeerId`.

use alloc::format;
use alloc::vec::Vec;

use der::{Decode, Encode, Reader, SliceReader};
use minip2p_identity::{KeyType, PeerId, PublicKey};
use x509_cert::Certificate;

use crate::{LIBP2P_EXTENSION_OID, SIGNATURE_PREFIX, TlsError};

/// Verifies a DER-encoded X.509 certificate per the libp2p TLS spec and
/// returns the remote peer's `PeerId`.
///
/// Performs the following checks:
/// 1. Parses the X.509 certificate from DER bytes.
/// 2. Verifies the certificate's self-signature (ECDSA P-256 over TBSCertificate).
/// 3. Locates the libp2p Public Key Extension (OID `1.3.6.1.4.1.53594.1.1`).
/// 4. Decodes the `SignedKey` ASN.1 structure from the extension value.
/// 5. Verifies the host-key signature over `"libp2p-tls-handshake:" || SPKI_DER`.
/// 6. Derives and returns the `PeerId` from the verified host public key.
///
/// Currently supports Ed25519 host keys only.
pub fn verify_libp2p_certificate(cert_der: &[u8]) -> Result<PeerId, TlsError> {
    // Step 1: Parse the X.509 certificate.
    let cert =
        Certificate::from_der(cert_der).map_err(|e| TlsError::Der(format!("{e}")))?;

    // Step 2: Verify the certificate's self-signature.
    verify_self_signature(cert_der, &cert)?;

    // Step 3: Find the libp2p extension.
    let tbs = cert.tbs_certificate();
    let extensions = tbs
        .extensions()
        .ok_or(TlsError::MissingExtension)?;

    let libp2p_ext = extensions
        .iter()
        .find(|ext| ext.extn_id == LIBP2P_EXTENSION_OID)
        .ok_or(TlsError::MissingExtension)?;

    // Step 4: Decode SignedKey from the extension value.
    let ext_bytes = libp2p_ext.extn_value.as_bytes();
    let (public_key_bytes, signature_bytes) =
        decode_signed_key(ext_bytes).map_err(|e| TlsError::InvalidExtension(format!("{e}")))?;

    // Step 5a: Decode the protobuf-encoded libp2p PublicKey.
    let libp2p_public_key = PublicKey::decode_protobuf(&public_key_bytes)
        .map_err(|e| TlsError::InvalidPublicKey(format!("{e}")))?;

    // Step 5b: Get the certificate's SubjectPublicKeyInfo DER.
    let spki_der = tbs
        .subject_public_key_info()
        .to_der()
        .map_err(|e| TlsError::Der(format!("{e}")))?;

    // Step 5c: Build the signed message and verify.
    let mut message = Vec::with_capacity(SIGNATURE_PREFIX.len() + spki_der.len());
    message.extend_from_slice(SIGNATURE_PREFIX);
    message.extend_from_slice(&spki_der);

    verify_host_signature(&libp2p_public_key, &message, &signature_bytes)?;

    // Step 6: Derive PeerId from the verified public key.
    Ok(PeerId::from_public_key(&libp2p_public_key))
}

/// Verifies the certificate's ECDSA P-256 self-signature over the TBSCertificate.
///
/// Extracts the raw TBS bytes from the original DER encoding (rather than
/// re-encoding) to guarantee byte-exact matching for signature verification.
fn verify_self_signature(cert_der: &[u8], cert: &Certificate) -> Result<(), TlsError> {
    use ecdsa::signature::Verifier;
    use p256::ecdsa::{DerSignature, VerifyingKey};

    // Check that the signature algorithm is ECDSA with SHA-256.
    let sig_alg_oid = cert.signature_algorithm().oid;
    // ecdsa-with-SHA256: 1.2.840.10045.4.3.2
    let ecdsa_sha256_oid =
        const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    if sig_alg_oid != ecdsa_sha256_oid {
        return Err(TlsError::UnsupportedSignatureAlgorithm(format!(
            "{sig_alg_oid}"
        )));
    }

    // RFC 5280 Section 4.1.1.2: the outer signatureAlgorithm and the TBS
    // signature field MUST be identical.
    let tbs_sig_oid = cert.tbs_certificate().signature().oid;
    if tbs_sig_oid != sig_alg_oid {
        return Err(TlsError::InvalidSelfSignature);
    }

    // Extract the raw TBS DER bytes from the original certificate encoding.
    let tbs_der = extract_tbs_der(cert_der)?;

    // Extract the P-256 public key from SubjectPublicKeyInfo.
    let tbs = cert.tbs_certificate();
    let spki = tbs.subject_public_key_info();
    let pk_bytes = spki.subject_public_key.raw_bytes();
    let verifying_key = VerifyingKey::from_sec1_bytes(pk_bytes)
        .map_err(|_| TlsError::InvalidSelfSignature)?;

    // Extract and verify the signature.
    let sig_bytes = cert.signature().raw_bytes();
    let signature =
        DerSignature::from_der(sig_bytes).map_err(|_| TlsError::InvalidSelfSignature)?;

    verifying_key
        .verify(tbs_der, &signature)
        .map_err(|_| TlsError::InvalidSelfSignature)
}

/// Extracts the raw TBSCertificate DER bytes from the certificate's outer
/// SEQUENCE without re-encoding, so signature verification uses the exact
/// original bytes.
fn extract_tbs_der(cert_der: &[u8]) -> Result<&[u8], TlsError> {
    let map_err = |e: der::Error| TlsError::Der(format!("{e}"));

    let mut reader = SliceReader::new(cert_der).map_err(map_err)?;

    // Parse the outer Certificate SEQUENCE header.
    let _outer_header = der::Header::decode(&mut reader).map_err(map_err)?;

    // Record where the TBSCertificate starts (right after outer header).
    let remaining_before = usize::try_from(reader.remaining_len()).map_err(map_err)?;
    let tbs_start = cert_der.len() - remaining_before;

    // Parse the TBSCertificate header to determine its total encoded length.
    let tbs_header = der::Header::decode(&mut reader).map_err(map_err)?;
    let remaining_after = usize::try_from(reader.remaining_len()).map_err(map_err)?;
    let tbs_header_len = remaining_before - remaining_after;
    let tbs_value_len =
        usize::try_from(tbs_header.length()).map_err(|_| TlsError::Der("TBS length overflow".into()))?;

    let tbs_end = tbs_start + tbs_header_len + tbs_value_len;
    if tbs_end > cert_der.len() {
        return Err(TlsError::Der("TBS extends beyond certificate".into()));
    }

    Ok(&cert_der[tbs_start..tbs_end])
}

/// Decodes the `SignedKey` ASN.1 structure from DER bytes.
///
/// ```text
/// SignedKey ::= SEQUENCE {
///   publicKey  OCTET STRING,
///   signature  OCTET STRING
/// }
/// ```
///
/// Returns `(public_key_bytes, signature_bytes)`.
fn decode_signed_key(der_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), der::Error> {
    let mut reader = SliceReader::new(der_bytes)?;
    let result = reader.sequence(|seq| -> Result<_, der::Error> {
        let public_key = der::asn1::OctetString::decode(seq)?;
        let signature = der::asn1::OctetString::decode(seq)?;
        Ok((
            public_key.as_bytes().to_vec(),
            signature.as_bytes().to_vec(),
        ))
    })?;
    // Reject trailing data after the SEQUENCE — strict DER parsing for this
    // security-critical path.
    reader.finish()?;
    Ok(result)
}

/// Verifies the host-key signature from the libp2p extension.
///
/// Currently supports Ed25519 host keys only. Returns an error for other key
/// types (ECDSA, secp256k1, RSA).
fn verify_host_signature(
    public_key: &PublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    match public_key.key_type() {
        KeyType::Ed25519 => {
            let sig_array: [u8; 64] = signature.try_into().map_err(|_| {
                TlsError::SignatureVerification(format!(
                    "invalid Ed25519 signature length: expected 64, got {}",
                    signature.len()
                ))
            })?;

            public_key
                .verify(message, &sig_array)
                .map_err(|e| TlsError::SignatureVerification(format!("{e}")))
        }
        other => Err(TlsError::SignatureVerification(format!(
            "unsupported host key type for verification: {other:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Decodes a hex string into bytes.
    fn decode_hex(input: &str) -> Vec<u8> {
        assert_eq!(input.len() % 2, 0);
        let mut out = Vec::with_capacity(input.len() / 2);
        let bytes = input.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let hi = (bytes[i] as char).to_digit(16).expect("invalid hex") as u8;
            let lo = (bytes[i + 1] as char)
                .to_digit(16)
                .expect("invalid hex") as u8;
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    // -- Spec test vectors from https://github.com/libp2p/specs/blob/master/tls/tls.md --

    const ED25519_CERT_HEX: &str = "308201ae30820156a0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea37c307a3078060a2b0601040183a25a0101046a3068042408011220a77f1d92fedb59dddaea5a1c4abd1ac2fbde7d7b879ed364501809923d7c11b90440d90d2769db992d5e6195dbb08e706b6651e024fda6cfb8846694a435519941cac215a8207792e42849cccc6cd8136c6e4bde92a58c5e08cfd4206eb5fe0bf909300a06082a8648ce3d0403020346003043021f50f6b6c52711a881778718238f650c9fb48943ae6ee6d28427dc6071ae55e702203625f116a7a454db9c56986c82a25682f7248ea1cb764d322ea983ed36a31b77";
    const ED25519_PEER_ID: &str = "12D3KooWM6CgA9iBFZmcYAHA6A2qvbAxqfkmrYiRQuz3XEsk4Ksv";

    const ECDSA_CERT_HEX: &str = "308201f63082019da0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea381c23081bf3081bc060a2b0601040183a25a01010481ad3081aa045f0803125b3059301306072a8648ce3d020106082a8648ce3d03010703420004bf30511f909414ebdd3242178fd290f093a551cf75c973155de0bb5a96fedf6cb5d52da7563e794b512f66e60c7f55ba8a3acf3dd72a801980d205e8a1ad29f2044730450220064ea8124774caf8f50e57f436aa62350ce652418c019df5d98a3ac666c9386a022100aa59d704a931b5f72fb9222cb6cc51f954d04a4e2e5450f8805fe8918f71eaae300a06082a8648ce3d04030203470030440220799395b0b6c1e940a7e4484705f610ab51ed376f19ff9d7c16757cfbf61b8d4302206205c03fbb0f95205c779be86581d3e31c01871ad5d1f3435bcf375cb0e5088a";
    const ECDSA_PEER_ID: &str = "QmfXbAwNjJLXfesgztEHe8HwgVDCMMpZ9Eax1HYq6hn9uE";

    const SECP256K1_CERT_HEX: &str = "308201ba3082015fa0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea38184308181307f060a2b0601040183a25a01010471306f0425080212210206dc6968726765b820f050263ececf7f71e4955892776c0970542efd689d2382044630440220145e15a991961f0d08cd15425bb95ec93f6ffa03c5a385eedc34ecf464c7a8ab022026b3109b8a3f40ef833169777eb2aa337cfb6282f188de0666d1bcec2a4690dd300a06082a8648ce3d0403020349003046022100e1a217eeef9ec9204b3f774a08b70849646b6a1e6b8b27f93dc00ed58545d9fe022100b00dafa549d0f03547878338c7b15e7502888f6d45db387e5ae6b5d46899cef0";
    const SECP256K1_PEER_ID: &str = "16Uiu2HAkutTMoTzDw1tCvSRtu6YoixJwS46S1ZFxW8hSx9fWHiPs";

    const INVALID_CERT_HEX: &str = "308201f73082019da0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea381c23081bf3081bc060a2b0601040183a25a01010481ad3081aa045f0803125b3059301306072a8648ce3d020106082a8648ce3d03010703420004bf30511f909414ebdd3242178fd290f093a551cf75c973155de0bb5a96fedf6cb5d52da7563e794b512f66e60c7f55ba8a3acf3dd72a801980d205e8a1ad29f204473045022100bb6e03577b7cc7a3cd1558df0da2b117dfdcc0399bc2504ebe7de6f65cade72802206de96e2a5be9b6202adba24ee0362e490641ac45c240db71fe955f2c5cf8df6e300a06082a8648ce3d0403020348003045022100e847f267f43717358f850355bdcabbefb2cfbf8a3c043b203a14788a092fe8db022027c1d04a2d41fd6b57a7e8b3989e470325de4406e52e084e34a3fd56eef0d0df";

    #[test]
    fn verifies_ed25519_test_vector() {
        let cert_der = decode_hex(ED25519_CERT_HEX);
        let peer_id = verify_libp2p_certificate(&cert_der).expect("must verify");
        assert_eq!(peer_id.to_base58(), ED25519_PEER_ID);
    }

    #[test]
    fn rejects_invalid_cert_signature_mismatch() {
        // This cert has a valid structure but the extension signature does not
        // match the host key that supposedly signed it.
        let cert_der = decode_hex(INVALID_CERT_HEX);
        let result = verify_libp2p_certificate(&cert_der);
        assert!(result.is_err(), "invalid cert must fail verification");
    }

    #[test]
    fn extracts_peer_id_from_extension_only_ed25519() {
        let cert_der = decode_hex(ED25519_CERT_HEX);
        let cert = Certificate::from_der(&cert_der).unwrap();

        let tbs = cert.tbs_certificate();
        let extensions = tbs.extensions().unwrap();
        let libp2p_ext = extensions
            .iter()
            .find(|ext| ext.extn_id == LIBP2P_EXTENSION_OID)
            .expect("extension must exist");

        let (pk_bytes, _sig_bytes) = decode_signed_key(libp2p_ext.extn_value.as_bytes())
            .expect("signed key must decode");

        let public_key = PublicKey::decode_protobuf(&pk_bytes).expect("protobuf must decode");
        assert_eq!(public_key.key_type(), KeyType::Ed25519);

        let peer_id = PeerId::from_public_key(&public_key);
        assert_eq!(peer_id.to_base58(), ED25519_PEER_ID);
    }

    #[test]
    fn parses_ecdsa_cert_extension() {
        let cert_der = decode_hex(ECDSA_CERT_HEX);
        let cert = Certificate::from_der(&cert_der).unwrap();

        let tbs = cert.tbs_certificate();
        let extensions = tbs.extensions().unwrap();
        let libp2p_ext = extensions
            .iter()
            .find(|ext| ext.extn_id == LIBP2P_EXTENSION_OID)
            .expect("extension must exist");

        let (pk_bytes, _sig_bytes) = decode_signed_key(libp2p_ext.extn_value.as_bytes())
            .expect("signed key must decode");

        let public_key = PublicKey::decode_protobuf(&pk_bytes).expect("protobuf must decode");
        assert_eq!(public_key.key_type(), KeyType::Ecdsa);

        let peer_id = PeerId::from_public_key(&public_key);
        assert_eq!(peer_id.to_base58(), ECDSA_PEER_ID);
    }

    #[test]
    fn parses_secp256k1_cert_extension() {
        let cert_der = decode_hex(SECP256K1_CERT_HEX);
        let cert = Certificate::from_der(&cert_der).unwrap();

        let tbs = cert.tbs_certificate();
        let extensions = tbs.extensions().unwrap();
        let libp2p_ext = extensions
            .iter()
            .find(|ext| ext.extn_id == LIBP2P_EXTENSION_OID)
            .expect("extension must exist");

        let (pk_bytes, _sig_bytes) = decode_signed_key(libp2p_ext.extn_value.as_bytes())
            .expect("signed key must decode");

        let public_key = PublicKey::decode_protobuf(&pk_bytes).expect("protobuf must decode");
        assert_eq!(public_key.key_type(), KeyType::Secp256k1);

        let peer_id = PeerId::from_public_key(&public_key);
        assert_eq!(peer_id.to_base58(), SECP256K1_PEER_ID);
    }

    #[test]
    fn rejects_cert_without_extension() {
        let result = verify_libp2p_certificate(&[0x30, 0x00]);
        assert!(result.is_err());
    }
}
