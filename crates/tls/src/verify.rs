//! Certificate verification per the libp2p TLS spec.
//!
//! Parses a DER-encoded X.509 certificate, checks its validity period and
//! extensions, extracts the libp2p Public Key Extension, verifies the
//! host-key signature over the certificate's SubjectPublicKeyInfo, and
//! derives the remote peer's `PeerId`.

use alloc::format;
use alloc::vec::Vec;
use core::time::Duration;

use der::{Decode, Encode, Reader, SliceReader};
use minip2p_identity::{KeyType, PeerId, PublicKey};
use x509_cert::Certificate;
use x509_cert::ext::Extension;

use crate::{LIBP2P_EXTENSION_OID, SIGNATURE_PREFIX, TlsError};

/// Verifies a DER-encoded X.509 certificate per the libp2p TLS spec and
/// returns the remote peer's `PeerId`.
///
/// `now` is the current wall-clock time as a duration since the Unix epoch.
/// The crate reads no clock itself, so the transport adapter samples the time.
///
/// Performs the following checks:
/// 1. Parses the X.509 certificate from DER bytes.
/// 2. Verifies the certificate's self-signature (ECDSA P-256 over TBSCertificate).
/// 3. Checks that `now` lies within the certificate's validity period
///    (NotBefore and NotAfter, inclusive).
/// 4. Locates exactly one libp2p Public Key Extension (OID
///    `1.3.6.1.4.1.53594.1.1`), rejecting any other critical extension.
///    Unknown non-critical extensions are ignored.
/// 5. Decodes the `SignedKey` ASN.1 structure from the extension value.
/// 6. Verifies the host-key signature over `"libp2p-tls-handshake:" || SPKI_DER`.
/// 7. Derives and returns the `PeerId` from the verified host public key.
///
/// Ed25519 and ECDSA P-256 host keys are supported. secp256k1 and RSA (which
/// the spec makes optional) are deliberately deferred and fail with
/// [`TlsError::UnsupportedKeyType`], as does ECDSA on any other curve.
///
/// This verifies one certificate. The spec also requires rejecting a peer
/// that presents a chain of more than one certificate; the transport, which
/// sees the whole chain, enforces that.
pub fn verify_libp2p_certificate(cert_der: &[u8], now: Duration) -> Result<PeerId, TlsError> {
    // Step 1: Parse the X.509 certificate.
    let cert = Certificate::from_der(cert_der).map_err(|e| TlsError::Der(format!("{e}")))?;

    // Step 2: Verify the certificate's self-signature.
    verify_self_signature(cert_der, &cert)?;

    // Step 3: Check the validity period.
    check_validity(&cert, now)?;

    // Step 4: Find the single libp2p extension.
    let tbs = cert.tbs_certificate();
    let libp2p_ext = find_libp2p_extension(tbs.extensions().map_or(&[], |exts| exts))?;

    // Step 5: Decode SignedKey from the extension value.
    let ext_bytes = libp2p_ext.extn_value.as_bytes();
    let (public_key_bytes, signature_bytes) =
        decode_signed_key(ext_bytes).map_err(|e| TlsError::InvalidExtension(format!("{e}")))?;

    // Step 6a: Decode the protobuf-encoded libp2p PublicKey.
    let libp2p_public_key = PublicKey::decode_protobuf(&public_key_bytes)
        .map_err(|e| TlsError::InvalidPublicKey(format!("{e}")))?;

    // Step 6b: Get the certificate's SubjectPublicKeyInfo DER.
    let spki_der = tbs
        .subject_public_key_info()
        .to_der()
        .map_err(|e| TlsError::Der(format!("{e}")))?;

    // Step 6c: Build the signed message and verify.
    let mut message = Vec::with_capacity(SIGNATURE_PREFIX.len() + spki_der.len());
    message.extend_from_slice(SIGNATURE_PREFIX);
    message.extend_from_slice(&spki_der);

    verify_host_signature(&libp2p_public_key, &message, &signature_bytes)?;

    // Step 7: Derive PeerId from the verified public key.
    Ok(PeerId::from_public_key(&libp2p_public_key))
}

/// Rejects a certificate whose validity period does not contain `now`.
/// Both bounds are inclusive, per RFC 5280 Section 4.1.2.5.
fn check_validity(cert: &Certificate, now: Duration) -> Result<(), TlsError> {
    let validity = cert.tbs_certificate().validity();
    let not_before = validity.not_before.to_unix_duration();
    let not_after = validity.not_after.to_unix_duration();
    if now < not_before || now > not_after {
        return Err(TlsError::OutsideValidityPeriod {
            now_unix_secs: now.as_secs(),
            not_before_unix_secs: not_before.as_secs(),
            not_after_unix_secs: not_after.as_secs(),
        });
    }
    Ok(())
}

/// Returns the one libp2p extension, rejecting a certificate that lacks it,
/// repeats it (RFC 5280 forbids duplicate extension OIDs), or carries any
/// other critical extension (the libp2p extension is the only one we
/// understand; unknown non-critical extensions are ignored).
fn find_libp2p_extension(extensions: &[Extension]) -> Result<&Extension, TlsError> {
    let mut libp2p_ext = None;
    for ext in extensions {
        if ext.extn_id == LIBP2P_EXTENSION_OID {
            if libp2p_ext.replace(ext).is_some() {
                return Err(TlsError::DuplicateExtension);
            }
        } else if ext.critical {
            return Err(TlsError::UnsupportedCriticalExtension(format!(
                "{}",
                ext.extn_id
            )));
        }
    }
    libp2p_ext.ok_or(TlsError::MissingExtension)
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
    let ecdsa_sha256_oid = const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
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
    #[expect(
        clippy::map_err_ignore,
        reason = "invalid self-signatures intentionally have one public error"
    )]
    let verifying_key =
        VerifyingKey::from_sec1_bytes(pk_bytes).map_err(|_| TlsError::InvalidSelfSignature)?;

    // Extract and verify the signature.
    let sig_bytes = cert.signature().raw_bytes();
    #[expect(
        clippy::map_err_ignore,
        reason = "invalid self-signatures intentionally have one public error"
    )]
    let signature =
        DerSignature::from_der(sig_bytes).map_err(|_| TlsError::InvalidSelfSignature)?;

    #[expect(
        clippy::map_err_ignore,
        reason = "invalid self-signatures intentionally have one public error"
    )]
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
    let tbs_start = cert_der
        .len()
        .checked_sub(remaining_before)
        .ok_or(TlsError::Der("TBS starts beyond certificate".into()))?;

    // Parse the TBSCertificate header to determine its total encoded length.
    let tbs_header = der::Header::decode(&mut reader).map_err(map_err)?;
    let remaining_after = usize::try_from(reader.remaining_len()).map_err(map_err)?;
    let tbs_header_len = remaining_before
        .checked_sub(remaining_after)
        .ok_or(TlsError::Der("TBS header exceeds certificate".into()))?;
    #[expect(
        clippy::map_err_ignore,
        reason = "a length conversion failure has one compact TLS error"
    )]
    let tbs_value_len = usize::try_from(tbs_header.length())
        .map_err(|_| TlsError::Der("TBS length overflow".into()))?;

    let tbs_end = tbs_start
        .checked_add(tbs_header_len)
        .and_then(|offset| offset.checked_add(tbs_value_len))
        .ok_or(TlsError::Der("TBS length overflow".into()))?;

    cert_der
        .get(tbs_start..tbs_end)
        .ok_or(TlsError::Der("TBS extends beyond certificate".into()))
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
/// Supports Ed25519 and ECDSA P-256 host keys. secp256k1 and RSA (optional in
/// the spec) are deliberately unsupported for now, as is ECDSA on any other
/// curve; they fail with [`TlsError::UnsupportedKeyType`].
fn verify_host_signature(
    public_key: &PublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    match public_key.key_type() {
        KeyType::Ed25519 => {
            #[expect(
                clippy::map_err_ignore,
                reason = "signature conversion errors are represented by the reported length"
            )]
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
        KeyType::Ecdsa => verify_ecdsa_p256(public_key.data(), message, signature),
        other => Err(TlsError::UnsupportedKeyType(format!("{other:?}"))),
    }
}

/// Verifies an ECDSA host-key signature. Per the libp2p peer-id spec, the key
/// is a DER-encoded SubjectPublicKeyInfo and the signature is a DER-encoded
/// ECDSA signature over the SHA-256 digest of `message`.
fn verify_ecdsa_p256(spki_der: &[u8], message: &[u8], signature: &[u8]) -> Result<(), TlsError> {
    use ecdsa::signature::Verifier;
    use p256::ecdsa::{DerSignature, VerifyingKey};

    // id-ecPublicKey and the P-256 (secp256r1) named curve.
    const ID_EC_PUBLIC_KEY: const_oid::ObjectIdentifier =
        const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    const SECP256R1: const_oid::ObjectIdentifier =
        const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

    let spki = spki::SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| TlsError::InvalidPublicKey(format!("ECDSA key: {e}")))?;
    if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
        return Err(TlsError::InvalidPublicKey(format!(
            "ECDSA key has algorithm {}, expected id-ecPublicKey",
            spki.algorithm.oid
        )));
    }
    let curve = spki
        .algorithm
        .parameters_oid()
        .map_err(|e| TlsError::InvalidPublicKey(format!("ECDSA curve: {e}")))?;
    if curve != SECP256R1 {
        return Err(TlsError::UnsupportedKeyType(format!(
            "ECDSA on curve {curve}"
        )));
    }

    let verifying_key = VerifyingKey::from_sec1_bytes(spki.subject_public_key.raw_bytes())
        .map_err(|e| TlsError::InvalidPublicKey(format!("ECDSA P-256 key: {e}")))?;
    let signature = DerSignature::from_der(signature)
        .map_err(|e| TlsError::SignatureVerification(format!("ECDSA signature: {e}")))?;
    verifying_key
        .verify(message, &signature)
        .map_err(|e| TlsError::SignatureVerification(format!("{e}")))
}

#[cfg(test)]
mod tests {
    use minip2p_identity::Ed25519Keypair;
    use x509_cert::time::{Time, Validity};

    use super::*;
    use crate::generate::build_certificate;
    use crate::test_rng::TestRng;
    /// Decodes a hex string into bytes.
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

    // -- Spec test vectors from https://github.com/libp2p/specs/blob/master/tls/tls.md --

    const ED25519_CERT_HEX: &str = "308201ae30820156a0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea37c307a3078060a2b0601040183a25a0101046a3068042408011220a77f1d92fedb59dddaea5a1c4abd1ac2fbde7d7b879ed364501809923d7c11b90440d90d2769db992d5e6195dbb08e706b6651e024fda6cfb8846694a435519941cac215a8207792e42849cccc6cd8136c6e4bde92a58c5e08cfd4206eb5fe0bf909300a06082a8648ce3d0403020346003043021f50f6b6c52711a881778718238f650c9fb48943ae6ee6d28427dc6071ae55e702203625f116a7a454db9c56986c82a25682f7248ea1cb764d322ea983ed36a31b77";
    const ED25519_PEER_ID: &str = "12D3KooWM6CgA9iBFZmcYAHA6A2qvbAxqfkmrYiRQuz3XEsk4Ksv";

    const ECDSA_CERT_HEX: &str = "308201f63082019da0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea381c23081bf3081bc060a2b0601040183a25a01010481ad3081aa045f0803125b3059301306072a8648ce3d020106082a8648ce3d03010703420004bf30511f909414ebdd3242178fd290f093a551cf75c973155de0bb5a96fedf6cb5d52da7563e794b512f66e60c7f55ba8a3acf3dd72a801980d205e8a1ad29f2044730450220064ea8124774caf8f50e57f436aa62350ce652418c019df5d98a3ac666c9386a022100aa59d704a931b5f72fb9222cb6cc51f954d04a4e2e5450f8805fe8918f71eaae300a06082a8648ce3d04030203470030440220799395b0b6c1e940a7e4484705f610ab51ed376f19ff9d7c16757cfbf61b8d4302206205c03fbb0f95205c779be86581d3e31c01871ad5d1f3435bcf375cb0e5088a";
    const ECDSA_PEER_ID: &str = "QmfXbAwNjJLXfesgztEHe8HwgVDCMMpZ9Eax1HYq6hn9uE";

    const SECP256K1_CERT_HEX: &str = "308201ba3082015fa0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea38184308181307f060a2b0601040183a25a01010471306f0425080212210206dc6968726765b820f050263ececf7f71e4955892776c0970542efd689d2382044630440220145e15a991961f0d08cd15425bb95ec93f6ffa03c5a385eedc34ecf464c7a8ab022026b3109b8a3f40ef833169777eb2aa337cfb6282f188de0666d1bcec2a4690dd300a06082a8648ce3d0403020349003046022100e1a217eeef9ec9204b3f774a08b70849646b6a1e6b8b27f93dc00ed58545d9fe022100b00dafa549d0f03547878338c7b15e7502888f6d45db387e5ae6b5d46899cef0";

    /// Unix time inside the spec vectors' validity window (1975..4096).
    const VECTOR_NOW: Duration = Duration::from_secs(1_700_000_000);

    const INVALID_CERT_HEX: &str = "308201f73082019da0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea381c23081bf3081bc060a2b0601040183a25a01010481ad3081aa045f0803125b3059301306072a8648ce3d020106082a8648ce3d03010703420004bf30511f909414ebdd3242178fd290f093a551cf75c973155de0bb5a96fedf6cb5d52da7563e794b512f66e60c7f55ba8a3acf3dd72a801980d205e8a1ad29f204473045022100bb6e03577b7cc7a3cd1558df0da2b117dfdcc0399bc2504ebe7de6f65cade72802206de96e2a5be9b6202adba24ee0362e490641ac45c240db71fe955f2c5cf8df6e300a06082a8648ce3d0403020348003045022100e847f267f43717358f850355bdcabbefb2cfbf8a3c043b203a14788a092fe8db022027c1d04a2d41fd6b57a7e8b3989e470325de4406e52e084e34a3fd56eef0d0df";

    #[test]
    fn verifies_ed25519_test_vector() {
        let cert_der = decode_hex(ED25519_CERT_HEX);
        let peer_id = verify_libp2p_certificate(&cert_der, VECTOR_NOW).expect("must verify");
        assert_eq!(peer_id.to_base58(), ED25519_PEER_ID);
    }

    #[test]
    fn rejects_invalid_cert_signature_mismatch() {
        // This cert has a valid structure but the extension signature does not
        // match the host key that supposedly signed it.
        let cert_der = decode_hex(INVALID_CERT_HEX);
        let result = verify_libp2p_certificate(&cert_der, VECTOR_NOW);
        assert!(
            matches!(result, Err(TlsError::SignatureVerification(_))),
            "invalid cert must fail host-key verification, got {result:?}"
        );
    }

    #[test]
    fn verifies_ecdsa_test_vector() {
        let cert_der = decode_hex(ECDSA_CERT_HEX);
        let peer_id = verify_libp2p_certificate(&cert_der, VECTOR_NOW).expect("must verify");
        assert_eq!(peer_id.to_base58(), ECDSA_PEER_ID);
    }

    #[test]
    fn rejects_secp256k1_test_vector_as_unsupported() {
        let cert_der = decode_hex(SECP256K1_CERT_HEX);
        assert_eq!(
            verify_libp2p_certificate(&cert_der, VECTOR_NOW),
            Err(TlsError::UnsupportedKeyType("Secp256k1".into()))
        );
    }

    const NOT_BEFORE: u64 = 1_600_000_000;
    const NOT_AFTER: u64 = 1_700_000_000;

    /// Generates an Ed25519-identity certificate valid from `NOT_BEFORE` to
    /// `NOT_AFTER` (Unix seconds), with `extra` extensions appended.
    fn test_certificate(extra: &[Extension]) -> (Vec<u8>, PeerId) {
        let keypair = Ed25519Keypair::from_secret_key_bytes([9u8; 32]);
        let validity = Validity::new(
            Time::from(der::DateTime::from_unix_duration(Duration::from_secs(NOT_BEFORE)).unwrap()),
            Time::from(der::DateTime::from_unix_duration(Duration::from_secs(NOT_AFTER)).unwrap()),
        );
        let (cert_der, _key_der) =
            build_certificate(&keypair, validity, &mut TestRng(3), extra).expect("must generate");
        (cert_der, keypair.peer_id())
    }

    #[test]
    fn accepts_certificate_inside_validity_period() {
        let (cert_der, peer_id) = test_certificate(&[]);
        for now in [NOT_BEFORE, NOT_AFTER] {
            let verified = verify_libp2p_certificate(&cert_der, Duration::from_secs(now))
                .expect("validity bounds are inclusive");
            assert_eq!(verified, peer_id);
        }
    }

    #[test]
    fn rejects_certificate_before_not_before() {
        let (cert_der, _) = test_certificate(&[]);
        let now = Duration::from_secs(NOT_BEFORE - 1);
        assert_eq!(
            verify_libp2p_certificate(&cert_der, now),
            Err(TlsError::OutsideValidityPeriod {
                now_unix_secs: NOT_BEFORE - 1,
                not_before_unix_secs: NOT_BEFORE,
                not_after_unix_secs: NOT_AFTER,
            })
        );
    }

    #[test]
    fn rejects_expired_certificate() {
        let (cert_der, _) = test_certificate(&[]);
        let now = Duration::from_secs(NOT_AFTER + 1);
        assert!(matches!(
            verify_libp2p_certificate(&cert_der, now),
            Err(TlsError::OutsideValidityPeriod { now_unix_secs, .. }) if now_unix_secs == NOT_AFTER + 1
        ));
    }

    /// An extension with an OID the verifier doesn't know about.
    fn unknown_extension(critical: bool) -> Extension {
        Extension {
            extn_id: const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1"),
            critical,
            extn_value: der::asn1::OctetString::new([0x05, 0x00]).unwrap(),
        }
    }

    #[test]
    fn rejects_unknown_critical_extension() {
        let (cert_der, _) = test_certificate(&[unknown_extension(true)]);
        assert_eq!(
            verify_libp2p_certificate(&cert_der, Duration::from_secs(NOT_BEFORE)),
            Err(TlsError::UnsupportedCriticalExtension(
                "1.3.6.1.4.1.99999.1".into()
            ))
        );
    }

    #[test]
    fn ignores_unknown_non_critical_extension() {
        let (cert_der, peer_id) = test_certificate(&[unknown_extension(false)]);
        let verified = verify_libp2p_certificate(&cert_der, Duration::from_secs(NOT_BEFORE))
            .expect("non-critical unknown extensions are ignored");
        assert_eq!(verified, peer_id);
    }

    #[test]
    fn rejects_duplicate_libp2p_extension() {
        let duplicate = Extension {
            extn_id: LIBP2P_EXTENSION_OID,
            critical: false,
            extn_value: der::asn1::OctetString::new([0x30, 0x00]).unwrap(),
        };
        let (cert_der, _) = test_certificate(&[duplicate]);
        assert_eq!(
            verify_libp2p_certificate(&cert_der, Duration::from_secs(NOT_BEFORE)),
            Err(TlsError::DuplicateExtension)
        );
    }

    #[test]
    fn rejects_cert_without_extension() {
        verify_libp2p_certificate(&[0x30, 0x00], VECTOR_NOW)
            .expect_err("certificate without the libp2p extension must fail");
    }
}
