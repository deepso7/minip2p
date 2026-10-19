//! WebTransport certificate rotation, driven by the host's wall clock.
//!
//! During certificate period `k` the listener presents certificate `k`,
//! advertises `{k, k+1}` in its addresses, and lists `{k−1, k, k+1}` in
//! Noise, so an address learned in the previous period still verifies. Each
//! poll compares the clock's period with the current one and, on any
//! change (a boundary, or a clock jump either way), recomputes everything
//! from the clock's period. Live connections keep what they started with:
//! the certificate only matters during a TLS handshake.

use std::sync::{Arc, RwLock};

use minip2p_core::Multihash;
use minip2p_core::platform::{Deadline, Now};
use minip2p_identity::Ed25519Keypair;
use minip2p_tls::webtransport::{certhash, next_boundary, period_at, webtransport_certificate};

use crate::QuicBindError;
use crate::tls::{TlsIdentity, WebTransportCertificate};
use crate::webtransport::WebTransportContext;

/// A WebTransport listener's certificate state.
pub(crate) struct Rotation {
    /// The certificate the TLS resolver presents, swapped in place.
    certificate: WebTransportCertificate,
    /// The period whose certificate is presented.
    period: u64,
    /// What addresses advertise: periods `k` and `k+1`.
    advertised: Vec<Multihash>,
    /// What new WebTransport connections authenticate with.
    context: Arc<WebTransportContext>,
    /// The wall clock of the last [`advance`](Self::advance).
    unix: u64,
    /// Bumped by every rotation.
    revision: u64,
}

impl Rotation {
    /// The state for the period containing `unix`.
    pub(crate) fn new(
        tls: &TlsIdentity,
        keypair: &Ed25519Keypair,
        unix: u64,
    ) -> Result<Self, QuicBindError> {
        let period = period_at(unix);
        let certificate = Arc::new(RwLock::new(tls.webtransport_key(keypair, period)?));
        let (advertised, context) = hashes(keypair, period)?;
        Ok(Self {
            certificate,
            period,
            advertised,
            context,
            unix,
            revision: 0,
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

    /// Moves to the period containing `unix`; returns whether it rotated.
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
        self.unix = unix;
        let period = period_at(unix);
        if period == self.period {
            return false;
        }
        self.period = period;
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

    /// The next period boundary on the host's timeline, given the sample
    /// `now` taken with the last [`advance`](Self::advance).
    pub(crate) fn deadline(&self, now: Now) -> Deadline {
        let secs = next_boundary(self.unix).saturating_sub(self.unix);
        now.deadline_after(secs.saturating_mul(1_000))
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
