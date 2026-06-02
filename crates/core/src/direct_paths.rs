use alloc::vec::Vec;

use crate::{ExternalAddressSource, Multiaddr};

/// Maximum number of direct paths tracked for one peer.
pub const MAX_DIRECT_PATHS: usize = 30;

/// Default delay before retrying a failed direct path.
pub const DEFAULT_DIRECT_PATH_RETRY_MS: u64 = 5_000;

/// Where a direct path candidate came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectPathSource {
    /// User-supplied explicit public address.
    Manual,
    /// Confirmed external address, when the original source no longer matters.
    ConfirmedExternal,
    /// Address reported by a remote peer through Identify's observed address.
    IdentifyObserved,
    /// Address confirmed by AutoNAT dial-back.
    AutoNat,
    /// Address discovered through NAT-PMP, PCP, or UPnP port mapping.
    PortMapped,
    /// Address discovered through a STUN/QAD-like probe.
    Stun,
    /// Local non-wildcard listen address.
    Listen,
    /// Address exchanged by DCUtR over a relay connection.
    Dcutr,
}

impl DirectPathSource {
    /// Stable text for logs and diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::ConfirmedExternal => "confirmed-external",
            Self::IdentifyObserved => "identify-observed",
            Self::AutoNat => "autonat",
            Self::PortMapped => "port-mapped",
            Self::Stun => "stun",
            Self::Listen => "listen",
            Self::Dcutr => "dcutr",
        }
    }
}

impl From<ExternalAddressSource> for DirectPathSource {
    fn from(source: ExternalAddressSource) -> Self {
        match source {
            ExternalAddressSource::Manual => Self::Manual,
            ExternalAddressSource::IdentifyObserved => Self::IdentifyObserved,
            ExternalAddressSource::AutoNat => Self::AutoNat,
            ExternalAddressSource::PortMapped => Self::PortMapped,
            ExternalAddressSource::Stun => Self::Stun,
        }
    }
}

/// Current direct path usability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectPathStatus {
    /// Path has not been tried yet.
    Unknown,
    /// A direct connection attempt is currently in flight.
    Dialing,
    /// Path has opened successfully.
    Open,
    /// Path opened before but is no longer active.
    Inactive,
    /// A recent direct connection attempt failed.
    Failed,
}

impl DirectPathStatus {
    /// Stable text for logs and diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Dialing => "dialing",
            Self::Open => "open",
            Self::Inactive => "inactive",
            Self::Failed => "failed",
        }
    }
}

/// A source-tagged direct path candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectPath {
    pub source: DirectPathSource,
    pub addr: Multiaddr,
    pub status: DirectPathStatus,
    pub attempts: u32,
    pub last_updated_ms: u64,
    pub next_attempt_ms: u64,
}

/// Result of inserting or refreshing a direct path candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectPathUpdate {
    pub changed: bool,
    pub expired: Option<DirectPath>,
}

/// Sans-I/O direct path lifecycle.
///
/// This is intentionally transport-agnostic policy. It records candidates,
/// path state, and retry timing, but never opens sockets, resolves DNS, sends
/// packets, sleeps, or reads a clock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectPathBook {
    paths: Vec<DirectPath>,
    retry_interval_ms: u64,
    max_paths: usize,
}

impl Default for DirectPathBook {
    fn default() -> Self {
        Self::new()
    }
}

impl DirectPathBook {
    /// Creates an empty book with default retry and capacity settings.
    pub fn new() -> Self {
        Self {
            paths: Vec::new(),
            retry_interval_ms: DEFAULT_DIRECT_PATH_RETRY_MS,
            max_paths: MAX_DIRECT_PATHS,
        }
    }

    /// Overrides the retry interval for failed paths.
    pub fn with_retry_interval_ms(mut self, retry_interval_ms: u64) -> Self {
        self.retry_interval_ms = retry_interval_ms;
        self
    }

    /// Returns all tracked paths in priority order.
    pub fn paths(&self) -> &[DirectPath] {
        &self.paths
    }

    /// Returns true when no direct paths are tracked.
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    /// Inserts or refreshes a path.
    ///
    /// New and refreshed paths move to the front. If capacity is exceeded,
    /// failed/inactive paths are evicted first, then the oldest path.
    pub fn insert(
        &mut self,
        source: DirectPathSource,
        addr: Multiaddr,
        now_ms: u64,
    ) -> DirectPathUpdate {
        if let Some(pos) = self.paths.iter().position(|path| path.addr == addr) {
            let mut path = self.paths.remove(pos);
            path.source = source;
            path.last_updated_ms = now_ms;
            self.paths.insert(0, path);
            return DirectPathUpdate {
                changed: false,
                expired: None,
            };
        }

        self.paths.insert(
            0,
            DirectPath {
                source,
                addr,
                status: DirectPathStatus::Unknown,
                attempts: 0,
                last_updated_ms: now_ms,
                next_attempt_ms: now_ms,
            },
        );

        let expired = self.prune_one();
        DirectPathUpdate {
            changed: true,
            expired,
        }
    }

    /// Marks all matching paths as in-flight if they are eligible to be tried.
    pub fn begin_attempts(&mut self, now_ms: u64) -> Vec<Multiaddr> {
        let mut attempts = Vec::new();
        for path in &mut self.paths {
            if matches!(
                path.status,
                DirectPathStatus::Open | DirectPathStatus::Dialing
            ) || now_ms < path.next_attempt_ms
            {
                continue;
            }
            path.status = DirectPathStatus::Dialing;
            path.attempts = path.attempts.saturating_add(1);
            path.last_updated_ms = now_ms;
            attempts.push(path.addr.clone());
        }
        attempts
    }

    /// Marks every in-flight path as failed and schedules retry.
    pub fn fail_attempts(&mut self, now_ms: u64) {
        for path in &mut self.paths {
            if path.status != DirectPathStatus::Dialing {
                continue;
            }
            path.status = DirectPathStatus::Failed;
            path.last_updated_ms = now_ms;
            path.next_attempt_ms = now_ms.saturating_add(self.retry_interval_ms);
        }
    }

    /// Marks one path as open.
    pub fn mark_open(&mut self, addr: &Multiaddr, now_ms: u64) -> bool {
        self.mark(addr, DirectPathStatus::Open, now_ms)
    }

    /// Marks one path as inactive.
    pub fn mark_inactive(&mut self, addr: &Multiaddr, now_ms: u64) -> bool {
        self.mark(addr, DirectPathStatus::Inactive, now_ms)
    }

    /// Returns all tracked path addresses.
    pub fn addrs(&self) -> Vec<Multiaddr> {
        self.paths.iter().map(|path| path.addr.clone()).collect()
    }

    /// Returns all paths which are not known to be failed.
    pub fn usable_addrs(&self) -> Vec<Multiaddr> {
        self.paths
            .iter()
            .filter(|path| path.status != DirectPathStatus::Failed)
            .map(|path| path.addr.clone())
            .collect()
    }

    fn mark(&mut self, addr: &Multiaddr, status: DirectPathStatus, now_ms: u64) -> bool {
        let Some(pos) = self.paths.iter().position(|path| &path.addr == addr) else {
            return false;
        };
        let mut path = self.paths.remove(pos);
        path.status = status;
        path.last_updated_ms = now_ms;
        if status == DirectPathStatus::Open {
            path.next_attempt_ms = now_ms;
        }
        self.paths.insert(0, path);
        true
    }

    fn prune_one(&mut self) -> Option<DirectPath> {
        if self.paths.len() <= self.max_paths {
            return None;
        }

        let prune_pos = self
            .paths
            .iter()
            .rposition(|path| {
                matches!(
                    path.status,
                    DirectPathStatus::Failed | DirectPathStatus::Inactive
                )
            })
            .unwrap_or(self.paths.len() - 1);

        Some(self.paths.remove(prune_pos))
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
    fn insert_deduplicates_and_refreshes_priority() {
        let mut book = DirectPathBook::new();
        let first = addr("/ip4/203.0.113.1/udp/4001/quic-v1");
        let second = addr("/ip4/203.0.113.2/udp/4001/quic-v1");

        assert!(
            book.insert(DirectPathSource::Dcutr, first.clone(), 10)
                .changed
        );
        assert!(
            book.insert(DirectPathSource::Stun, second.clone(), 20)
                .changed
        );
        assert!(
            !book
                .insert(DirectPathSource::AutoNat, first.clone(), 30)
                .changed
        );

        assert_eq!(book.paths()[0].addr, first);
        assert_eq!(book.paths()[0].source, DirectPathSource::AutoNat);
        assert_eq!(book.paths()[1].addr, second);
    }

    #[test]
    fn attempts_are_retry_gated_after_failure() {
        let mut book = DirectPathBook::new().with_retry_interval_ms(5_000);
        let first = addr("/ip4/203.0.113.1/udp/4001/quic-v1");
        book.insert(DirectPathSource::Dcutr, first.clone(), 10);

        assert_eq!(book.begin_attempts(10), vec![first.clone()]);
        assert_eq!(book.paths()[0].status, DirectPathStatus::Dialing);
        assert_eq!(book.begin_attempts(10), Vec::<Multiaddr>::new());
        assert_eq!(book.paths()[0].attempts, 1);
        book.fail_attempts(100);
        assert_eq!(book.begin_attempts(1_000), Vec::<Multiaddr>::new());
        assert_eq!(book.begin_attempts(5_100), vec![first]);
        assert_eq!(book.paths()[0].attempts, 2);
    }

    #[test]
    fn fail_attempts_only_marks_paths_that_were_dialed() {
        let mut book = DirectPathBook::new().with_retry_interval_ms(5_000);
        let ready = addr("/ip4/203.0.113.1/udp/4001/quic-v1");
        let not_ready = addr("/ip4/203.0.113.2/udp/4001/quic-v1");
        book.insert(DirectPathSource::Dcutr, ready.clone(), 0);
        book.insert(DirectPathSource::Dcutr, not_ready.clone(), 100);

        assert_eq!(book.begin_attempts(0), vec![ready.clone()]);
        book.fail_attempts(10);

        let ready_path = book.paths().iter().find(|path| path.addr == ready).unwrap();
        let not_ready_path = book
            .paths()
            .iter()
            .find(|path| path.addr == not_ready)
            .unwrap();
        assert_eq!(ready_path.status, DirectPathStatus::Failed);
        assert_eq!(not_ready_path.status, DirectPathStatus::Unknown);
    }

    #[test]
    fn failed_paths_are_evicted_before_unknown_paths() {
        let mut book = DirectPathBook {
            paths: Vec::new(),
            retry_interval_ms: DEFAULT_DIRECT_PATH_RETRY_MS,
            max_paths: 2,
        };
        let first = addr("/ip4/203.0.113.1/udp/4001/quic-v1");
        let second = addr("/ip4/203.0.113.2/udp/4001/quic-v1");
        let third = addr("/ip4/203.0.113.3/udp/4001/quic-v1");

        book.insert(DirectPathSource::Dcutr, first.clone(), 1);
        book.insert(DirectPathSource::Dcutr, second.clone(), 2);
        assert_eq!(book.begin_attempts(3), vec![second.clone(), first.clone()]);
        book.fail_attempts(3);
        let update = book.insert(DirectPathSource::Dcutr, third.clone(), 4);

        assert_eq!(update.expired.expect("expired").addr, first);
        assert_eq!(book.addrs(), vec![third, second]);
    }
}
