use alloc::vec::Vec;

use crate::Multiaddr;

/// Maximum number of confirmed external addresses kept for one local peer.
pub const MAX_EXTERNAL_ADDRS: usize = 20;

/// Where an external address came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalAddressSource {
    /// User-supplied explicit public address.
    Manual,
    /// Address reported by a remote peer through Identify's observed address.
    IdentifyObserved,
    /// Address confirmed by AutoNAT dial-back.
    AutoNat,
    /// Address discovered through NAT-PMP, PCP, or UPnP port mapping.
    PortMapped,
    /// Address discovered through a STUN-like probe.
    Stun,
}

impl ExternalAddressSource {
    /// Stable text for logs and diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::IdentifyObserved => "identify-observed",
            Self::AutoNat => "autonat",
            Self::PortMapped => "port-mapped",
            Self::Stun => "stun",
        }
    }
}

/// A source-tagged external address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalAddress {
    pub source: ExternalAddressSource,
    pub addr: Multiaddr,
}

/// Result of confirming an external address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalAddressUpdate {
    /// True when the confirmed set changed, false when an existing address was
    /// only refreshed or re-sourced.
    pub changed: bool,
    /// Address evicted because the confirmed-address limit was exceeded.
    pub expired: Option<ExternalAddress>,
}

/// Sans-I/O external address lifecycle.
///
/// Candidates are addresses we have heard about but have not proven yet.
/// Confirmed addresses are the addresses we should advertise through Identify
/// and prefer for direct-connection candidates.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExternalAddressBook {
    candidates: Vec<ExternalAddress>,
    confirmed: Vec<ExternalAddress>,
}

impl ExternalAddressBook {
    /// Returns unconfirmed candidate addresses in discovery order.
    pub fn candidates(&self) -> &[ExternalAddress] {
        &self.candidates
    }

    /// Returns confirmed external addresses in priority order.
    pub fn confirmed(&self) -> &[ExternalAddress] {
        &self.confirmed
    }

    /// Returns true if `addr` is already confirmed.
    pub fn is_confirmed(&self, addr: &Multiaddr) -> bool {
        self.confirmed.iter().any(|entry| &entry.addr == addr)
    }

    /// Records a candidate address.
    ///
    /// Returns true when this is a newly observed candidate. Already confirmed
    /// addresses and duplicate candidates are ignored.
    pub fn observe_candidate(&mut self, source: ExternalAddressSource, addr: Multiaddr) -> bool {
        if self.is_confirmed(&addr)
            || self
                .candidates
                .iter()
                .any(|candidate| candidate.addr == addr)
        {
            return false;
        }

        self.candidates.push(ExternalAddress { source, addr });
        true
    }

    /// Promotes an address to confirmed, refreshing it to the front if it was
    /// already known.
    pub fn confirm(
        &mut self,
        source: ExternalAddressSource,
        addr: Multiaddr,
    ) -> ExternalAddressUpdate {
        self.candidates.retain(|candidate| candidate.addr != addr);

        if let Some(pos) = self
            .confirmed
            .iter()
            .position(|candidate| candidate.addr == addr)
        {
            let mut entry = self.confirmed.remove(pos);
            entry.source = source;
            self.confirmed.insert(0, entry);
            return ExternalAddressUpdate {
                changed: false,
                expired: None,
            };
        }

        self.confirmed.insert(0, ExternalAddress { source, addr });
        let expired = if self.confirmed.len() > MAX_EXTERNAL_ADDRS {
            self.confirmed.pop()
        } else {
            None
        };

        ExternalAddressUpdate {
            changed: true,
            expired,
        }
    }

    /// Removes a confirmed address.
    pub fn remove(&mut self, addr: &Multiaddr) -> Option<ExternalAddress> {
        let pos = self
            .confirmed
            .iter()
            .position(|candidate| &candidate.addr == addr)?;
        Some(self.confirmed.remove(pos))
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;

    fn addr(value: &str) -> Multiaddr {
        Multiaddr::from_str(value).unwrap()
    }

    #[test]
    fn candidate_is_not_duplicated_or_readded_after_confirmation() {
        let mut book = ExternalAddressBook::default();
        let observed = addr("/ip4/203.0.113.7/udp/4001/quic-v1");

        assert!(book.observe_candidate(ExternalAddressSource::IdentifyObserved, observed.clone()));
        assert!(!book.observe_candidate(ExternalAddressSource::IdentifyObserved, observed.clone()));

        let update = book.confirm(ExternalAddressSource::AutoNat, observed.clone());
        assert!(update.changed);
        assert!(update.expired.is_none());
        assert!(book.candidates().is_empty());
        assert!(!book.observe_candidate(ExternalAddressSource::IdentifyObserved, observed));
    }

    #[test]
    fn confirming_existing_address_refreshes_priority_without_counting_change() {
        let mut book = ExternalAddressBook::default();
        let first = addr("/ip4/203.0.113.1/udp/4001/quic-v1");
        let second = addr("/ip4/203.0.113.2/udp/4001/quic-v1");

        assert!(
            book.confirm(ExternalAddressSource::Manual, first.clone())
                .changed
        );
        assert!(
            book.confirm(ExternalAddressSource::Manual, second.clone())
                .changed
        );
        let update = book.confirm(ExternalAddressSource::AutoNat, first.clone());

        assert!(!update.changed);
        assert_eq!(book.confirmed()[0].addr, first);
        assert_eq!(book.confirmed()[0].source, ExternalAddressSource::AutoNat);
    }

    #[test]
    fn confirmed_addresses_are_capped() {
        let mut book = ExternalAddressBook::default();

        for i in 0..=MAX_EXTERNAL_ADDRS {
            let addr = addr(&alloc::format!("/ip4/203.0.113.{i}/udp/4001/quic-v1"));
            let update = book.confirm(ExternalAddressSource::Manual, addr);
            if i < MAX_EXTERNAL_ADDRS {
                assert!(update.expired.is_none());
            } else {
                assert!(update.expired.is_some());
            }
        }

        assert_eq!(book.confirmed().len(), MAX_EXTERNAL_ADDRS);
    }
}
