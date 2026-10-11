//! libp2p TLS on rustls (ring), as the QUIC engine's crypto.
//!
//! Peers are authenticated inside the handshake. The verifiers here require
//! exactly one certificate, verify it as a libp2p certificate at the host's
//! wall-clock time, check the TLS 1.3 CertificateVerify signature against the
//! certificate's own key, and, on a dial, require the `PeerId` the caller
//! named. Any rejection aborts the handshake with a TLS alert, so neither end
//! reports the connection as established.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use minip2p_core::PeerId;
use minip2p_identity::Ed25519Keypair;
use rustls::client::Resumption;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime,
};
use rustls::server::NoServerSessionStorage;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::time_provider::TimeProvider;
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, OtherError, SignatureScheme,
};

/// The ALPN protocol id libp2p uses for QUIC.
pub(crate) const ALPN: &[u8] = b"libp2p";

/// Wall-clock time since the Unix epoch, or zero if the clock reads earlier.
pub(crate) fn system_time() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

/// The host's wall-clock time, as rustls sees it when checking certificates.
///
/// The transport stores each poll's `Now::unix_seconds` here; while the host
/// has supplied none, the system clock answers instead.
#[derive(Debug)]
pub(crate) struct HostTime(AtomicU64);

/// Stored while the host has supplied no sample. Zero can't be the marker:
/// the Unix epoch is a valid (if unlikely) sample.
const NO_SAMPLE: u64 = u64::MAX;

impl Default for HostTime {
    fn default() -> Self {
        Self(AtomicU64::new(NO_SAMPLE))
    }
}

impl HostTime {
    /// Records the host's latest sample; `None` falls back to the system clock.
    pub(crate) fn set(&self, unix_seconds: Option<u64>) {
        self.0.store(unix_seconds.unwrap_or(NO_SAMPLE), Relaxed);
    }

    /// The current wall-clock time on the host's timeline.
    pub(crate) fn now(&self) -> Duration {
        match self.0.load(Relaxed) {
            NO_SAMPLE => system_time(),
            seconds => Duration::from_secs(seconds),
        }
    }
}

impl TimeProvider for HostTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(self.now()))
    }
}

/// Why a peer's certificate was rejected; carried in the rustls error.
#[derive(Debug)]
struct Rejection(String);

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Rejection {}

fn reject(message: String) -> rustls::Error {
    rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(Rejection(
        message,
    )))))
}

/// Verifies a peer's libp2p certificate, for either side of the handshake.
#[derive(Debug)]
struct Libp2pVerifier {
    algorithms: WebPkiSupportedAlgorithms,
    /// The peer a dial named; the listener side expects anyone.
    expected: Option<PeerId>,
}

impl Libp2pVerifier {
    fn verify_certificate(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<(), rustls::Error> {
        if !intermediates.is_empty() {
            return Err(reject(format!(
                "peer presented {} certificates; libp2p TLS requires exactly one",
                intermediates.len() + 1
            )));
        }
        let verified =
            minip2p_tls::verify_libp2p_certificate(end_entity, Duration::from_secs(now.as_secs()))
                .map_err(|e| reject(format!("peer TLS certificate verification failed: {e}")))?;
        match &self.expected {
            Some(expected) if *expected != verified => Err(reject(format!(
                "peer id mismatch: dialed {expected} but the certificate proves {verified}"
            ))),
            _ => Ok(()),
        }
    }

    /// Checks CertificateVerify against the certificate's own key, so webpki
    /// never parses libp2p's critical extension.
    fn verify_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let spki = minip2p_tls::certificate_spki(cert)
            .map_err(|e| reject(format!("peer TLS certificate verification failed: {e}")))?;
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(spki),
            dss,
            &self.algorithms,
        )
    }
}

impl ServerCertVerifier for Libp2pVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.verify_certificate(end_entity, intermediates, now)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::PeerIncompatible::Tls12NotOffered.into())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

impl ClientCertVerifier for Libp2pVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.verify_certificate(end_entity, intermediates, now)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::PeerIncompatible::Tls12NotOffered.into())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// A node's TLS identity: its libp2p certificate and key, the crypto
/// provider, and the host clock its verifiers read. Shared by every config it
/// builds, so a per-dial client config costs a few `Arc` clones.
pub(crate) struct TlsIdentity {
    provider: Arc<CryptoProvider>,
    key: Arc<CertifiedKey>,
    time: Arc<HostTime>,
}

impl TlsIdentity {
    /// Generates a libp2p certificate for `keypair`; `time` is the clock the
    /// verifiers check certificate validity against.
    pub(crate) fn new(keypair: &Ed25519Keypair, time: Arc<HostTime>) -> Result<Self, String> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let (cert, key) = minip2p_tls::generate_certificate(keypair)
            .map_err(|e| format!("failed to generate libp2p TLS certificate: {e}"))?;
        let key = PrivateKeyDer::try_from(key)
            .map_err(|e| format!("failed to parse generated TLS private key: {e}"))?;
        let key = CertifiedKey::from_der(vec![CertificateDer::from(cert)], key, &provider)
            .map_err(|e| format!("failed to load generated TLS certificate: {e}"))?;
        Ok(Self {
            provider,
            key: Arc::new(key),
            time,
        })
    }

    fn verifier(&self, expected: Option<PeerId>) -> Arc<Libp2pVerifier> {
        Arc::new(Libp2pVerifier {
            algorithms: self.provider.signature_verification_algorithms,
            expected,
        })
    }

    /// The listener's config: TLS 1.3, ALPN `libp2p`, a mandatory client
    /// certificate, and no session resumption (a resumed session would skip
    /// the peer's certificate).
    pub(crate) fn server_config(&self) -> Result<rustls::ServerConfig, rustls::Error> {
        let mut config = rustls::ServerConfig::builder_with_details(
            Arc::clone(&self.provider),
            Arc::clone(&self.time) as Arc<dyn TimeProvider>,
        )
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(self.verifier(None))
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(Arc::clone(&self.key))));
        config.alpn_protocols = vec![ALPN.to_vec()];
        config.session_storage = Arc::new(NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        Ok(config)
    }

    /// A dialer's config, rejecting any listener that does not prove
    /// `expected`.
    pub(crate) fn client_config(
        &self,
        expected: Option<PeerId>,
    ) -> Result<rustls::ClientConfig, rustls::Error> {
        let mut config = rustls::ClientConfig::builder_with_details(
            Arc::clone(&self.provider),
            Arc::clone(&self.time) as Arc<dyn TimeProvider>,
        )
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(self.verifier(expected))
        .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(Arc::clone(&self.key))));
        config.alpn_protocols = vec![ALPN.to_vec()];
        config.resumption = Resumption::disabled();
        Ok(config)
    }
}

/// The `PeerId` a completed handshake's peer certificate proves.
///
/// The handshake only completed because [`Libp2pVerifier`] accepted exactly
/// this certificate, so the peer id is read from it rather than verified a
/// second time (a full verification costs a few hundred microseconds).
pub(crate) fn peer_id_from_identity(identity: Option<Box<dyn std::any::Any>>) -> Option<PeerId> {
    let certs = identity?.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    let [leaf] = certs.as_slice() else {
        return None;
    };
    minip2p_tls::certificate_peer_id(leaf).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{ClientConnection, ServerConnection};

    #[test]
    fn host_time_distinguishes_the_epoch_from_no_sample() {
        let time = HostTime::default();
        assert!(
            time.now() > Duration::from_secs(1),
            "no sample: system clock"
        );
        time.set(Some(0));
        assert_eq!(time.now(), Duration::ZERO, "the epoch is a real sample");
        time.set(None);
        assert!(time.now() > Duration::from_secs(1));
    }

    /// A certificate and key that are not a valid libp2p identity pair.
    fn certified(cert: Vec<u8>, key: Vec<u8>) -> Arc<CertifiedKey> {
        let provider = rustls::crypto::ring::default_provider();
        let key = provider
            .key_provider
            .load_private_key(PrivateKeyDer::try_from(key).expect("pkcs8"))
            .expect("signing key");
        Arc::new(CertifiedKey::new(vec![CertificateDer::from(cert)], key))
    }

    fn identity(time: &Arc<HostTime>) -> (TlsIdentity, PeerId) {
        let keypair = Ed25519Keypair::generate();
        let identity = TlsIdentity::new(&keypair, Arc::clone(time)).expect("identity");
        (identity, keypair.peer_id())
    }

    /// Runs a TLS handshake in memory; the first error either side hits.
    fn handshake(
        client: rustls::ClientConfig,
        server: rustls::ServerConfig,
    ) -> Result<(), rustls::Error> {
        let name = ServerName::try_from("l").map_err(|e| rustls::Error::General(e.to_string()))?;
        let mut client = ClientConnection::new(Arc::new(client), name)?;
        let mut server = ServerConnection::new(Arc::new(server))?;
        for _ in 0..10 {
            transfer(&mut *client, &mut *server)?;
            transfer(&mut *server, &mut *client)?;
            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok(());
            }
        }
        Err(rustls::Error::General("handshake did not finish".into()))
    }

    /// Moves everything `from` wants to write into `to`.
    fn transfer(
        from: &mut rustls::ConnectionCommon<impl rustls::SideData>,
        to: &mut rustls::ConnectionCommon<impl rustls::SideData>,
    ) -> Result<(), rustls::Error> {
        let io = |e: std::io::Error| rustls::Error::General(e.to_string());
        let mut buf = Vec::new();
        while from.wants_write() {
            from.write_tls(&mut buf).map_err(io)?;
        }
        let mut read = &buf[..];
        while !read.is_empty() {
            to.read_tls(&mut read).map_err(io)?;
            to.process_new_packets()?;
        }
        Ok(())
    }

    fn rejection(result: Result<(), rustls::Error>) -> String {
        match result {
            Err(rustls::Error::InvalidCertificate(error)) => error.to_string(),
            other => panic!("expected a certificate rejection, got {other:?}"),
        }
    }

    #[test]
    fn mutual_libp2p_identities_complete_the_handshake() {
        let time = Arc::new(HostTime::default());
        let (dialer, _) = identity(&time);
        let (listener, listener_id) = identity(&time);
        handshake(
            dialer.client_config(Some(listener_id)).expect("client"),
            listener.server_config().expect("server"),
        )
        .expect("handshake");
    }

    #[test]
    fn a_listener_requires_a_client_certificate() {
        let time = Arc::new(HostTime::default());
        let (listener, _) = identity(&time);
        let anonymous = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls13")
        .dangerous()
        .with_custom_certificate_verifier(listener.verifier(None))
        .with_no_client_auth();
        let result = handshake(anonymous, listener.server_config().expect("server"));
        assert!(
            matches!(result, Err(rustls::Error::NoCertificatesPresented)),
            "{result:?}"
        );
    }

    #[test]
    fn a_certificate_chain_is_rejected() {
        let time = Arc::new(HostTime::default());
        let (dialer, _) = identity(&time);
        let (listener, _) = identity(&time);
        let (extra, _) =
            minip2p_tls::generate_certificate(&Ed25519Keypair::generate()).expect("extra");
        let mut chain = (*listener.key).clone();
        chain.cert.push(CertificateDer::from(extra));
        let mut server = listener.server_config().expect("server");
        server.cert_resolver = Arc::new(SingleCertAndKey::from(chain));

        let message = rejection(handshake(
            dialer.client_config(None).expect("client"),
            server,
        ));
        assert!(message.contains("presented 2 certificates"), "{message}");
    }

    /// The libp2p TLS spec's invalid test vector: a well-formed, self-signed
    /// certificate whose extension's host signature does not cover its key.
    const MISMATCHED_EXTENSION_CERT_HEX: &str = "308201f73082019da0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea381c23081bf3081bc060a2b0601040183a25a01010481ad3081aa045f0803125b3059301306072a8648ce3d020106082a8648ce3d03010703420004bf30511f909414ebdd3242178fd290f093a551cf75c973155de0bb5a96fedf6cb5d52da7563e794b512f66e60c7f55ba8a3acf3dd72a801980d205e8a1ad29f204473045022100bb6e03577b7cc7a3cd1558df0da2b117dfdcc0399bc2504ebe7de6f65cade72802206de96e2a5be9b6202adba24ee0362e490641ac45c240db71fe955f2c5cf8df6e300a06082a8648ce3d0403020348003045022100e847f267f43717358f850355bdcabbefb2cfbf8a3c043b203a14788a092fe8db022027c1d04a2d41fd6b57a7e8b3989e470325de4406e52e084e34a3fd56eef0d0df";

    #[test]
    fn an_extension_that_does_not_sign_the_certificate_key_is_rejected() {
        let hex = MISMATCHED_EXTENSION_CERT_HEX.as_bytes();
        let cert: Vec<u8> = hex
            .chunks(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("ascii"), 16).expect("hex")
            })
            .collect();
        let verifier = Libp2pVerifier {
            algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
            expected: None,
        };
        // Inside the vector's validity window (1975 to 4096).
        let now = UnixTime::since_unix_epoch(Duration::from_secs(1_700_000_000));
        let error = verifier
            .verify_client_cert(&CertificateDer::from(cert), &[], now)
            .expect_err("mismatched extension");
        assert!(
            error
                .to_string()
                .contains("extension signature verification failed"),
            "{error}"
        );
    }

    #[test]
    fn a_certificate_verify_by_another_key_is_rejected() {
        let time = Arc::new(HostTime::default());
        let (dialer, _) = identity(&time);
        let (listener, _) = identity(&time);
        let (cert, _) = minip2p_tls::generate_certificate(&Ed25519Keypair::generate()).expect("a");
        let (_, other_key) =
            minip2p_tls::generate_certificate(&Ed25519Keypair::generate()).expect("b");
        let mut server = listener.server_config().expect("server");
        server.cert_resolver = Arc::new(SingleCertAndKey::from(certified(cert, other_key)));

        // The certificate itself is a valid libp2p certificate; only the
        // handshake signature betrays that the peer does not hold its key.
        let result = handshake(dialer.client_config(None).expect("client"), server);
        assert!(
            matches!(&result, Err(rustls::Error::InvalidCertificate(error))
                if !matches!(error, CertificateError::Other(_))),
            "{result:?}"
        );
    }

    #[test]
    fn validity_is_judged_at_host_time_not_the_system_clock() {
        let time = Arc::new(HostTime::default());
        let (dialer, _) = identity(&time);
        let (listener, _) = identity(&time);
        // Generated certificates are valid for a hundred years from now; the
        // system clock accepts them, a host two centuries ahead does not.
        time.set(Some(system_time().as_secs() + 200 * 365 * 24 * 60 * 60));

        let message = rejection(handshake(
            dialer.client_config(None).expect("client"),
            listener.server_config().expect("server"),
        ));
        assert!(message.contains("is not valid at"), "{message}");

        time.set(None);
        handshake(
            dialer.client_config(None).expect("client"),
            listener.server_config().expect("server"),
        )
        .expect("the system clock answers once the host supplies no time");
    }

    #[test]
    fn a_dial_rejects_a_listener_proving_another_peer_id() {
        let time = Arc::new(HostTime::default());
        let (dialer, _) = identity(&time);
        let (listener, _) = identity(&time);
        let other = Ed25519Keypair::generate().peer_id();

        let message = rejection(handshake(
            dialer.client_config(Some(other)).expect("client"),
            listener.server_config().expect("server"),
        ));
        assert!(message.contains("peer id mismatch"), "{message}");
    }
}
