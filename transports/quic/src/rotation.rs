//! The WebTransport certificate a listener serves: derived and rotated by the
//! host's wall clock, or provided by the operator and fixed.
//!
//! During certificate period `k` a derived listener presents certificate
//! `k`, advertises `{k, k+1}` in its addresses, and lists `{k−1, k, k+1}` in
//! Noise, so an address learned in the previous period still verifies. Each
//! poll compares the clock's period with the current one and, on any
//! change (a boundary, or a clock jump either way), recomputes everything
//! from the clock's period. Live connections keep what they started with:
//! the certificate only matters during a TLS handshake.
//!
//! A provided (CA-signed) certificate advertises no certhash, since browsers
//! check it with WebPKI, lists its leaf's hash in Noise as the spec
//! requires, and never rotates.

use std::sync::{Arc, RwLock};

use minip2p_core::Multihash;
use minip2p_core::platform::{Deadline, Now};
use minip2p_identity::Ed25519Keypair;
use minip2p_tls::webtransport::{certhash, next_boundary, period_at, webtransport_certificate};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::QuicBindError;
use crate::tls::{TlsIdentity, WebTransportCertificate};
use crate::webtransport::WebTransportContext;

/// A WebTransport listener's certificate state.
pub(crate) struct Certificates {
    /// The certificate the TLS resolver presents, swapped in place.
    certificate: WebTransportCertificate,
    /// What addresses advertise: periods `k` and `k+1`, or nothing for a
    /// provided certificate.
    advertised: Vec<Multihash>,
    /// What new WebTransport connections authenticate with.
    context: Arc<WebTransportContext>,
    /// Bumped by every rotation.
    revision: u64,
    /// Where a derived certificate is in its schedule; `None` for a provided
    /// one, which never rotates.
    schedule: Option<Schedule>,
}

struct Schedule {
    /// The period whose certificate is presented.
    period: u64,
    /// The wall clock of the last [`Certificates::advance`].
    unix: u64,
}

impl Certificates {
    /// The derived state for the period containing `unix`.
    pub(crate) fn derived(
        tls: &TlsIdentity,
        keypair: &Ed25519Keypair,
        unix: u64,
    ) -> Result<Self, QuicBindError> {
        let period = period_at(unix);
        let certificate = Arc::new(RwLock::new(tls.webtransport_key(keypair, period)?));
        let (advertised, context) = hashes(keypair, period)?;
        Ok(Self {
            certificate,
            advertised,
            context,
            revision: 0,
            schedule: Some(Schedule { period, unix }),
        })
    }

    /// The fixed state for an operator's chain and key, refused if the key
    /// does not match the leaf or the leaf expired before `unix`. A leaf
    /// not yet valid is accepted: the host's clock may be the one that's off.
    pub(crate) fn provided(
        tls: &TlsIdentity,
        keypair: &Ed25519Keypair,
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        unix: u64,
    ) -> Result<Self, QuicBindError> {
        let invalid = QuicBindError::WebTransportCertificate;
        let leaf = chain
            .first()
            .ok_or_else(|| invalid("the chain is empty".into()))?;
        let not_after = minip2p_tls::certificate_validity(leaf)
            .map_err(|error| invalid(format!("the leaf certificate does not parse: {error}")))?
            .not_after;
        if not_after.to_unix_duration().as_secs() < unix {
            return Err(invalid(format!(
                "the leaf certificate expired at {not_after} (the host clock reads {unix} \
                 Unix seconds); renew it"
            )));
        }
        let context = Arc::new(WebTransportContext {
            keypair: keypair.clone(),
            certhashes: vec![certhash(leaf)],
        });
        Ok(Self {
            certificate: Arc::new(RwLock::new(tls.provided_key(chain, key)?)),
            advertised: Vec::new(),
            context,
            revision: 0,
            schedule: None,
        })
    }

    /// The certificate cell the TLS resolver reads.
    pub(crate) fn certificate(&self) -> WebTransportCertificate {
        Arc::clone(&self.certificate)
    }

    pub(crate) fn advertised(&self) -> &[Multihash] {
        &self.advertised
    }

    pub(crate) fn context(&self) -> &Arc<WebTransportContext> {
        &self.context
    }

    pub(crate) fn revision(&self) -> u64 {
        self.revision
    }

    /// Moves a derived certificate to the period containing `unix`; returns
    /// whether it rotated. A provided certificate never does.
    ///
    /// A certificate that cannot be built (a period past year 9999) keeps
    /// the current one, recorded as the new period so it is not retried
    /// every poll.
    pub(crate) fn advance(
        &mut self,
        tls: &TlsIdentity,
        keypair: &Ed25519Keypair,
        unix: u64,
    ) -> bool {
        let Some(schedule) = &mut self.schedule else {
            return false;
        };
        schedule.unix = unix;
        let period = period_at(unix);
        if period == schedule.period {
            return false;
        }
        schedule.period = period;
        let (Ok(key), Ok((advertised, context))) = (
            tls.webtransport_key(keypair, period),
            hashes(keypair, period),
        ) else {
            return false;
        };
        match self.certificate.write() {
            Ok(mut current) => *current = key,
            Err(poisoned) => *poisoned.into_inner() = key,
        }
        self.advertised = advertised;
        self.context = context;
        self.revision = self.revision.wrapping_add(1);
        true
    }

    /// A derived certificate's next period boundary on the host's timeline,
    /// given the sample `now` taken with the last [`advance`](Self::advance);
    /// `None` for a provided certificate.
    pub(crate) fn deadline(&self, now: Now) -> Option<Deadline> {
        let unix = self.schedule.as_ref()?.unix;
        let secs = next_boundary(unix).saturating_sub(unix);
        Some(now.deadline_after(secs.saturating_mul(1_000)))
    }
}

/// Period `period`'s advertised certhashes `{k, k+1}` and the context
/// whose Noise extensions list `{k−1, k, k+1}`.
fn hashes(
    keypair: &Ed25519Keypair,
    period: u64,
) -> Result<(Vec<Multihash>, Arc<WebTransportContext>), QuicBindError> {
    let hash = |period| {
        webtransport_certificate(keypair, period)
            .map(|(der, _)| certhash(&der))
            .map_err(QuicBindError::Certificate)
    };
    let advertised = vec![hash(period)?, hash(period.saturating_add(1))?];
    let previous = period.checked_sub(1).map(hash).transpose()?;
    let certhashes = previous.into_iter().chain(advertised.clone()).collect();
    let context = Arc::new(WebTransportContext {
        keypair: keypair.clone(),
        certhashes,
    });
    Ok((advertised, context))
}
