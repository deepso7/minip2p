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
//! requires, and never rotates; the operator may replace it live through a
//! [`WebTransportCertificateHandle`].

use std::sync::{Arc, RwLock};

use minip2p_core::Multihash;
use minip2p_core::platform::{Deadline, Now};
use minip2p_identity::Ed25519Keypair;
use minip2p_tls::webtransport::{certhash, next_boundary, period_at, webtransport_certificate};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;

use crate::tls::{TlsIdentity, WebTransportCertificate};
use crate::webtransport::WebTransportContext;
use crate::{QuicBindError, WebTransportCertificateError};

/// The Noise context new WebTransport connections take, swapped in place.
pub(crate) type SharedContext = Arc<RwLock<Arc<WebTransportContext>>>;

/// A WebTransport listener's certificate state.
pub(crate) struct Certificates {
    /// The certificate the TLS resolver presents, swapped in place.
    certificate: WebTransportCertificate,
    /// What addresses advertise: periods `k` and `k+1`, or nothing for a
    /// provided certificate.
    advertised: Vec<Multihash>,
    /// What new WebTransport connections authenticate with.
    context: SharedContext,
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
            context: Arc::new(RwLock::new(context)),
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
        let (certificate, context) = load_provided(tls, keypair, chain, key, unix)
            .map_err(QuicBindError::WebTransportCertificate)?;
        Ok(Self {
            certificate: Arc::new(RwLock::new(certificate)),
            advertised: Vec::new(),
            context: Arc::new(RwLock::new(context)),
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

    /// The cell a new WebTransport connection reads its context from, once
    /// its TLS handshake is done (see [`current_context`]).
    pub(crate) fn context(&self) -> SharedContext {
        Arc::clone(&self.context)
    }

    /// A handle that replaces a provided certificate; `None` for a derived
    /// one, which follows its schedule instead.
    pub(crate) fn handle(&self, tls: &TlsIdentity) -> Option<WebTransportCertificateHandle> {
        self.schedule
            .is_none()
            .then(|| WebTransportCertificateHandle {
                tls: tls.clone(),
                certificate: Arc::clone(&self.certificate),
                context: Arc::clone(&self.context),
            })
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
        store(&self.certificate, key);
        store(&self.context, context);
        self.advertised = advertised;
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

/// Replaces a CA-signed WebTransport certificate while the transport runs.
///
/// From [`QuicTransport::webtransport_certificate_handle`](crate::QuicTransport::webtransport_certificate_handle),
/// for hosts that no longer hold the transport itself (one boxed into a
/// transport set, say). Cloning it shares the same certificate.
#[derive(Clone)]
pub struct WebTransportCertificateHandle {
    tls: TlsIdentity,
    certificate: WebTransportCertificate,
    context: SharedContext,
}

impl WebTransportCertificateHandle {
    /// Serves `chain` (leaf first, then intermediates) and its `key` to new
    /// WebTransport handshakes, after the checks bind makes: the key matches
    /// the leaf and the leaf has not expired by the host clock.
    ///
    /// Live connections keep the certificate they were set up with. The
    /// listen addresses carry no `/certhash`, so they don't change and no
    /// `Listening` event follows. On error the current certificate stays.
    pub fn replace(
        &self,
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<(), WebTransportCertificateError> {
        // Held across the swap: concurrent replaces take turns, so the
        // certificate and the hashes Noise lists never come from two of them.
        let mut current = self
            .context
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let unix = self.tls.now().as_secs();
        let (certificate, mut context) =
            load_provided(&self.tls, &current.keypair, chain, key, unix)
                .map_err(WebTransportCertificateError::Invalid)?;
        // A handshake whose certificate resolved just before this swap reads
        // the new context after it, so the previous leaf stays listed. A
        // reload of the same leaf keeps the list as it was.
        if let Some(fresh) = Arc::get_mut(&mut context) {
            if current.certhashes.first() == fresh.certhashes.first() {
                fresh.certhashes = current.certhashes.clone();
            } else if let Some(previous) = current.certhashes.first() {
                fresh.certhashes.push(*previous);
            }
        }
        store(&self.certificate, certificate);
        *current = context;
        Ok(())
    }
}

impl core::fmt::Debug for WebTransportCertificateHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WebTransportCertificateHandle")
            .finish_non_exhaustive()
    }
}

/// An operator's chain and key, loaded for serving, with the Noise context
/// listing the leaf's hash. Refused, with the reason, if the key does not
/// match the leaf or the leaf expired before `unix`. A leaf not yet valid is
/// accepted: the host's clock may be the one that's off.
fn load_provided(
    tls: &TlsIdentity,
    keypair: &Ed25519Keypair,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    unix: u64,
) -> Result<(Arc<CertifiedKey>, Arc<WebTransportContext>), String> {
    let leaf = chain.first().ok_or("the chain is empty")?;
    let not_after = minip2p_tls::certificate_validity(leaf)
        .map_err(|error| format!("the leaf certificate does not parse: {error}"))?
        .not_after;
    if not_after.to_unix_duration().as_secs() < unix {
        return Err(format!(
            "the leaf certificate expired at {not_after} (the host clock reads {unix} \
             Unix seconds); renew it"
        ));
    }
    let context = Arc::new(WebTransportContext {
        keypair: keypair.clone(),
        certhashes: vec![certhash(leaf)],
    });
    Ok((tls.provided_key(chain, key)?, context))
}

/// The context in `cell` now, even if a writer panicked holding it.
pub(crate) fn current_context(cell: &SharedContext) -> Arc<WebTransportContext> {
    Arc::clone(
        &cell
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
}

/// Swaps a shared cell's value, even if a reader panicked holding it.
fn store<T>(cell: &RwLock<T>, value: T) {
    match cell.write() {
        Ok(mut current) => *current = value,
        Err(poisoned) => *poisoned.into_inner() = value,
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
