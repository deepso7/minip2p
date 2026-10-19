//! Deterministic WebTransport certificates.
//!
//! A browser dialing `/webtransport/certhash/<hash>` accepts a self-signed
//! certificate only if its SHA-256 matches a pinned hash, it is X.509v3 and
//! ECDSA P-256, and it is valid for at most 14 days. These certificates are
//! plain TLS server leaves (basic constraints, key usage, extended key
//! usage) with no libp2p extension: the peer identity is proven over Noise
//! instead, which also carries the certhashes.
//!
//! Time is split into certificate periods of [`PERIOD_SECS`] (13 days);
//! period `k` starts at `k · PERIOD_SECS` Unix seconds. Certificate `k` is
//! valid from one hour before its period starts for exactly
//! [`CERTIFICATE_VALIDITY_SECS`] (14 days), leaving a 1 h margin for client
//! clock skew at the start and 23 h after the period ends.
//!
//! The certificate is a pure function of the host key and the period: the
//! P-256 key is derived with HKDF-SHA256 and the signature is RFC 6979
//! deterministic. A restarted node therefore serves the same certificate,
//! and addresses it published before the restart stay valid.

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use const_oid::db::rfc5280::{ID_KP_CLIENT_AUTH, ID_KP_SERVER_AUTH};
use der::Encode;
use hkdf::Hkdf;
use minip2p_identity::{Ed25519Keypair, Multihash};
use p256::ecdsa::SigningKey;
use p256::pkcs8::EncodePrivateKey;
use sha2::{Digest, Sha256};
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::certificate::TbsCertificate;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages};
use x509_cert::ext::{Extension, ToExtension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};

use crate::TlsError;

/// HKDF `info` for the certificate key; a retry appends its counter.
const KEY_DERIVATION_INFO: &[u8] = b"minip2p webtransport certificate";

/// Multihash code for sha2-256.
const SHA2_256: u64 = 0x12;

/// Length of one certificate period: 13 days, in seconds.
pub const PERIOD_SECS: u64 = 13 * 24 * 60 * 60;

/// How long before its period starts a certificate becomes valid: 1 h.
pub const CLOCK_SKEW_MARGIN_SECS: u64 = 60 * 60;

/// Total validity of one certificate: 14 days, the browser maximum.
pub const CERTIFICATE_VALIDITY_SECS: u64 = 14 * 24 * 60 * 60;

/// Returns the certificate period containing `unix_secs`.
pub fn period_at(unix_secs: u64) -> u64 {
    unix_secs / PERIOD_SECS
}

/// Returns the Unix second at which the next period after `unix_secs` starts:
/// the time a rotating listener must switch certificates. Saturates at
/// `u64::MAX`.
pub fn next_boundary(unix_secs: u64) -> u64 {
    (period_at(unix_secs) + 1).saturating_mul(PERIOD_SECS)
}

/// Builds the WebTransport certificate for `period`, deterministically from
/// the host key.
///
/// Returns `(cert_der, pkcs8_key_der)`: the self-signed X.509v3 ECDSA P-256
/// certificate and its private key as PKCS#8 DER, loadable with rustls's
/// checked `CertifiedKey::from_der`. Fails only for a period
/// whose validity cannot be expressed in X.509 (after year 9999).
pub fn webtransport_certificate(
    host: &Ed25519Keypair,
    period: u64,
) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    fn gen_err(e: impl core::fmt::Display) -> TlsError {
        TlsError::CertificateGeneration(format!("{e}"))
    }

    let signing_key = derive_signing_key(host, period);
    let out_of_range = || gen_err("certificate period is out of range");
    let not_before = period
        .checked_mul(PERIOD_SECS)
        // Period 0 starts at the epoch, so its margin is clamped there.
        .map(|start| start.saturating_sub(CLOCK_SKEW_MARGIN_SECS))
        .ok_or_else(out_of_range)?;
    let not_after = not_before
        .checked_add(CERTIFICATE_VALIDITY_SECS)
        .ok_or_else(out_of_range)?;
    let time = |secs| {
        der::DateTime::from_unix_duration(Duration::from_secs(secs))
            .map(Time::from)
            .map_err(gen_err)
    };
    let validity = Validity::new(time(not_before)?, time(not_after)?);

    let spki = SubjectPublicKeyInfoOwned::from_key(signing_key.verifying_key()).map_err(gen_err)?;
    // Every certificate has the same self-issued name, so the serial tells
    // them apart: NSS (Firefox) refuses a certificate whose issuer and serial
    // match one it already holds. A positive 16-byte serial, 0x01 followed
    // by 15 bytes of SHA-256 over the period's public key, differs per node
    // and per period yet stays deterministic.
    let mut serial = [0x01; 16];
    let digest = Sha256::digest(spki.subject_public_key.raw_bytes());
    for (byte, hashed) in serial.iter_mut().skip(1).zip(digest) {
        *byte = hashed;
    }
    let serial = SerialNumber::new(&serial).map_err(gen_err)?;

    let builder =
        CertificateBuilder::new(WebTransportProfile, serial, validity, spki).map_err(gen_err)?;
    // ECDSA signing in `p256` is RFC 6979 deterministic.
    let cert = builder
        .build::<_, ecdsa::der::Signature<p256::NistP256>>(&signing_key)
        .map_err(gen_err)?;
    let cert_der = cert.to_der().map_err(gen_err)?;
    let key_der = signing_key.to_pkcs8_der().map_err(gen_err)?;
    Ok((cert_der, key_der.as_bytes().to_vec()))
}

/// Returns the certhash of a DER certificate: its sha2-256 multihash, as
/// carried in `/certhash` addresses and Noise extensions.
pub fn certhash(cert_der: &[u8]) -> Multihash {
    Multihash::wrap(SHA2_256, &Sha256::digest(cert_der))
        .expect("a 32-byte digest fits a 64-byte multihash")
}

/// Derives the period's P-256 key: HKDF-SHA256 over the host secret, salted
/// with the big-endian period. A candidate outside the scalar range (zero or
/// at least the group order, probability about 2^-32) retries with a counter
/// appended to the info.
fn derive_signing_key(host: &Ed25519Keypair, period: u64) -> SigningKey {
    let hkdf = Hkdf::<Sha256>::new(Some(&period.to_be_bytes()), &host.secret_key_bytes());
    let mut counter: u32 = 0;
    loop {
        let mut candidate = [0u8; 32];
        let counter_bytes = counter.to_be_bytes();
        let info: &[&[u8]] = if counter == 0 {
            &[KEY_DERIVATION_INFO]
        } else {
            &[KEY_DERIVATION_INFO, &counter_bytes]
        };
        hkdf.expand_multi_info(info, &mut candidate)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        if let Ok(key) = SigningKey::from_bytes(&candidate.into()) {
            return key;
        }
        counter += 1;
    }
}

/// Builder profile for WebTransport certificates: a fixed self-issued
/// subject and the X.509v3 extensions of a TLS server leaf. Browsers require
/// v3 for `serverCertificateHashes`, and webpki (rustls) refuses v1.
///
/// go-libp2p marks its certificate as a CA (with `keyCertSign`); this one is
/// a plain end entity instead, which is what it is used as. Browsers
/// matching a pinned hash check neither.
struct WebTransportProfile;

impl x509_cert::builder::profile::BuilderProfile for WebTransportProfile {
    fn get_issuer(&self, subject: &Name) -> Name {
        subject.clone()
    }

    fn get_subject(&self) -> Name {
        "O=minip2p,CN=webtransport"
            .parse()
            .expect("hardcoded WebTransport subject name must parse")
    }

    fn build_extensions(
        &self,
        _spk: spki::SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: spki::SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let subject = tbs.subject();
        let mut extensions = Vec::new();
        let basic = BasicConstraints {
            ca: false,
            path_len_constraint: None,
        };
        extensions.push(basic.to_extension(subject, &extensions)?);
        let usage = KeyUsage(KeyUsages::DigitalSignature.into());
        extensions.push(usage.to_extension(subject, &extensions)?);
        let extended = ExtendedKeyUsage(vec![ID_KP_SERVER_AUTH, ID_KP_CLIENT_AUTH]);
        extensions.push(extended.to_extension(subject, &extensions)?);
        Ok(extensions)
    }
}

#[cfg(test)]
mod tests {
    use der::Decode;
    use x509_cert::Certificate;

    use super::*;

    const DAY: u64 = 24 * 60 * 60;

    fn host(byte: u8) -> Ed25519Keypair {
        Ed25519Keypair::from_secret_key_bytes([byte; 32])
    }

    fn parse(cert_der: &[u8]) -> Certificate {
        Certificate::from_der(cert_der).expect("certificate must parse")
    }

    /// `(not_before, not_after)` of host 1's certificate for `period`, in Unix seconds.
    fn validity_secs(period: u64) -> (u64, u64) {
        let (cert_der, _) = webtransport_certificate(&host(1), period).unwrap();
        let validity = *parse(&cert_der).tbs_certificate().validity();
        (
            validity.not_before.to_unix_duration().as_secs(),
            validity.not_after.to_unix_duration().as_secs(),
        )
    }

    #[test]
    fn same_key_and_period_give_identical_der() {
        let first = webtransport_certificate(&host(1), 2_000).unwrap();
        let second = webtransport_certificate(&host(1), 2_000).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn different_periods_or_keys_give_different_hashes() {
        let base = certhash(&webtransport_certificate(&host(1), 2_000).unwrap().0);
        let next_period = certhash(&webtransport_certificate(&host(1), 2_001).unwrap().0);
        let other_key = certhash(&webtransport_certificate(&host(2), 2_000).unwrap().0);
        assert_ne!(base, next_period);
        assert_ne!(base, other_key);
    }

    /// Every certificate has the same self-issued name, so the serial must
    /// tell nodes apart: Firefox (NSS) refuses a second certificate with an
    /// issuer and serial it already holds (`SEC_ERROR_REUSED_ISSUER_AND_SERIAL`),
    /// which breaks a page connected to two nodes at once.
    #[test]
    fn different_keys_or_periods_give_different_serials() {
        let serial = |host_byte, period| {
            let (cert_der, _) = webtransport_certificate(&host(host_byte), period).unwrap();
            parse(&cert_der).tbs_certificate().serial_number().clone()
        };
        assert_ne!(serial(1, 2_000), serial(2, 2_000));
        assert_ne!(serial(1, 2_000), serial(1, 2_001));
    }

    #[test]
    fn validity_is_fourteen_days_from_an_hour_before_the_period() {
        // Period 2000 starts at 2000 · 13 days = 2_246_400_000.
        let (not_before, not_after) = validity_secs(2_000);
        assert_eq!(not_before, 2_246_400_000 - 3_600);
        assert_eq!(not_after - not_before, 14 * DAY);
    }

    #[test]
    fn certificate_is_ecdsa_p256_without_libp2p_extension() {
        let (cert_der, key_der) = webtransport_certificate(&host(1), 2_000).unwrap();
        let cert = parse(&cert_der);
        let tbs = cert.tbs_certificate();

        let spki = tbs.subject_public_key_info();
        assert_eq!(spki.algorithm.oid.to_string(), "1.2.840.10045.2.1"); // id-ecPublicKey
        let curve = spki.algorithm.parameters.as_ref().unwrap();
        assert_eq!(
            curve
                .decode_as::<const_oid::ObjectIdentifier>()
                .unwrap()
                .to_string(),
            "1.2.840.10045.3.1.7" // prime256v1
        );
        // ecdsa-with-SHA256, so no RSA signature either.
        assert_eq!(
            cert.signature_algorithm().oid.to_string(),
            "1.2.840.10045.4.3.2"
        );
        assert!(
            tbs.extensions()
                .into_iter()
                .flatten()
                .all(|ext| ext.extn_id != crate::LIBP2P_EXTENSION_OID)
        );

        // The returned PKCS#8 key is the certificate's P-256 key.
        use p256::pkcs8::DecodePrivateKey;
        use spki::EncodePublicKey;
        let key = p256::ecdsa::SigningKey::from_pkcs8_der(&key_der).unwrap();
        assert_eq!(
            key.verifying_key().to_public_key_der().unwrap().as_bytes(),
            der::Encode::to_der(spki).unwrap()
        );
    }

    #[test]
    fn certificate_is_x509_v3_end_entity_for_tls() {
        use x509_cert::certificate::Version;
        use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};

        let (cert_der, _) = webtransport_certificate(&host(1), 2_000).unwrap();
        let cert = parse(&cert_der);
        let tbs = cert.tbs_certificate();
        assert_eq!(tbs.version(), Version::V3);

        let (_, basic) = tbs.get_extension::<BasicConstraints>().unwrap().unwrap();
        assert!(!basic.ca);
        let (critical, usage) = tbs.get_extension::<KeyUsage>().unwrap().unwrap();
        assert!(critical && usage.digital_signature() && !usage.key_cert_sign());
        let (_, extended) = tbs.get_extension::<ExtendedKeyUsage>().unwrap().unwrap();
        let server_auth = const_oid::db::rfc5280::ID_KP_SERVER_AUTH;
        assert!(extended.0.contains(&server_auth));
    }

    #[test]
    fn certhash_is_the_sha256_multihash_of_the_der() {
        let (cert_der, _) = webtransport_certificate(&host(1), 2_000).unwrap();
        let hash = certhash(&cert_der);
        assert_eq!(hash.code(), 0x12);
        assert_eq!(hash.digest(), Sha256::digest(&cert_der).as_slice());
    }

    #[test]
    fn period_arithmetic_at_exact_boundaries() {
        let length = 13 * DAY;
        assert_eq!(period_at(0), 0);
        assert_eq!(period_at(length - 1), 0);
        assert_eq!(period_at(length), 1);
        assert_eq!(period_at(5 * length + 7), 5);

        assert_eq!(next_boundary(0), length);
        assert_eq!(next_boundary(length - 1), length);
        assert_eq!(next_boundary(length), 2 * length);
        assert_eq!(next_boundary(u64::MAX), u64::MAX);
    }

    #[test]
    fn current_and_next_certificates_overlap_across_the_boundary() {
        // Certificate k+1 is already valid an hour before period k+1 starts,
        // and certificate k is still valid 23 h after period k ends.
        let boundary = next_boundary(2_000 * 13 * DAY);
        assert_eq!(validity_secs(2_001).0, boundary - 3_600);
        assert_eq!(validity_secs(2_000).1, boundary + 23 * 3_600);
    }

    #[test]
    fn periods_past_the_x509_range_are_errors() {
        // Year 10000 cannot be encoded, and the last period's validity end
        // overflows `u64`; both are generation errors, not panics.
        for period in [period_at(253_402_300_800), period_at(u64::MAX)] {
            assert!(matches!(
                webtransport_certificate(&host(1), period),
                Err(TlsError::CertificateGeneration(_))
            ));
        }
    }
}
