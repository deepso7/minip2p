//! Source-neutral discovery address book and dial policy.

use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    string::String,
    vec::Vec,
};

use minip2p_core::{Multiaddr, PeerId};

use crate::beacon::normalize_addr;
use crate::{
    DiscoveryAction, DiscoveryConfigError, DiscoveryEvent, DiscoverySource, KnownPeer, Observation,
    PeerDiscoveryConfig,
};

const MAX_DIAL_FAILURE_REASON_CHARS: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
enum DialState {
    Idle,
    InFlight,
    Backoff { until_ms: u64 },
}

#[derive(Clone, Debug)]
struct BeaconSource {
    addrs: Vec<Multiaddr>,
    last_seen_ms: u64,
}

#[derive(Clone, Debug)]
struct MdnsRecord {
    observed_at_ms: u64,
    expires_at_ms: u64,
}

#[derive(Clone, Debug, Default)]
struct RateWindow {
    attempts: VecDeque<u64>,
}

impl RateWindow {
    fn allows(&self, now_ms: u64, window_ms: u64, limit: u32) -> bool {
        self.attempts
            .iter()
            .filter(|at| at.saturating_add(window_ms) > now_ms)
            .count()
            < limit as usize
    }

    fn charge(&mut self, now_ms: u64, window_ms: u64) {
        while self
            .attempts
            .front()
            .is_some_and(|at| at.saturating_add(window_ms) <= now_ms)
        {
            self.attempts.pop_front();
        }
        self.attempts.push_back(now_ms);
    }
}

#[derive(Clone, Debug)]
struct PeerEntry {
    beacon: Option<BeaconSource>,
    mdns: BTreeMap<Multiaddr, MdnsRecord>,
    mdns_order: Vec<Multiaddr>,
    dial: DialState,
    mdns_attempts: RateWindow,
}

impl PeerEntry {
    fn empty() -> Self {
        Self {
            beacon: None,
            mdns: BTreeMap::new(),
            mdns_order: Vec::new(),
            dial: DialState::Idle,
            mdns_attempts: RateWindow::default(),
        }
    }

    fn is_empty(&self) -> bool {
        self.beacon.is_none() && self.mdns.is_empty()
    }

    fn last_seen_ms(&self) -> u64 {
        let beacon = self
            .beacon
            .as_ref()
            .map(|source| source.last_seen_ms)
            .unwrap_or(0);
        let mdns = self
            .mdns
            .values()
            .map(|record| record.observed_at_ms)
            .max()
            .unwrap_or(0);
        beacon.max(mdns)
    }

    fn assert_mdns_order(&self) {
        debug_assert_eq!(self.mdns.len(), self.mdns_order.len());
        debug_assert!(
            self.mdns_order
                .iter()
                .all(|addr| self.mdns.contains_key(addr))
        );
        debug_assert_eq!(
            self.mdns_order.iter().collect::<BTreeSet<_>>().len(),
            self.mdns_order.len()
        );
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PeerView {
    merged: Vec<Multiaddr>,
    provenance: Vec<(Multiaddr, bool, bool)>,
    beacon_present: bool,
    mdns_present: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StateTransition {
    Discovered(DiscoverySource),
    Updated(DiscoverySource),
    Expired,
}

#[derive(Clone, Debug, Default)]
struct PendingPeer {
    state: Option<StateTransition>,
    dial_failed: Option<String>,
}

#[derive(Clone, Debug)]
struct PendingViolation {
    peer: Option<PeerId>,
    source: DiscoverySource,
    reason: String,
    suppressed: u32,
}

/// Shared sans-I/O peer address book and automatic-dial state machine.
pub struct PeerDiscoveryAgent {
    config: PeerDiscoveryConfig,
    local_peer_id: PeerId,
    book: BTreeMap<PeerId, PeerEntry>,
    connected: BTreeSet<PeerId>,
    actions: VecDeque<DiscoveryAction>,
    pending: BTreeMap<PeerId, PendingPeer>,
    order: VecDeque<PeerId>,
    reported: BTreeMap<PeerId, PeerView>,
    violations: VecDeque<PendingViolation>,
    global_mdns_attempts: RateWindow,
}

impl PeerDiscoveryAgent {
    /// Constructs a shared peer book after validating its policy.
    pub fn new(
        local_peer_id: PeerId,
        config: PeerDiscoveryConfig,
    ) -> Result<Self, DiscoveryConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            local_peer_id,
            book: BTreeMap::new(),
            connected: BTreeSet::new(),
            actions: VecDeque::new(),
            pending: BTreeMap::new(),
            order: VecDeque::new(),
            reported: BTreeMap::new(),
            violations: VecDeque::new(),
            global_mdns_attempts: RateWindow::default(),
        })
    }

    /// Returns the local identity used by deterministic dial tie-breaking.
    pub fn local_peer_id(&self) -> &PeerId {
        &self.local_peer_id
    }

    /// Incorporates an authenticated signed-beacon observation.
    ///
    /// An empty address list still creates or refreshes authenticated presence.
    pub fn observe_beacon(&mut self, observation: Observation, now_ms: u64) {
        if observation.peer == self.local_peer_id {
            return;
        }
        let peer = observation.peer;
        let addrs =
            normalize_observed_addrs(&peer, observation.addrs, self.config.max_addrs_per_peer);

        if !self.book.contains_key(&peer) && !self.make_room(&peer, DiscoverySource::SignedBeacon) {
            return;
        }
        let before = self.book.get(&peer).map(|entry| self.view(entry));
        let entry = self
            .book
            .entry(peer.clone())
            .or_insert_with(PeerEntry::empty);
        let address_changed = entry
            .beacon
            .as_ref()
            .map(|source| source.addrs != addrs)
            .unwrap_or(!addrs.is_empty());
        entry.beacon = Some(BeaconSource {
            addrs: addrs.clone(),
            last_seen_ms: now_ms,
        });
        if address_changed && matches!(entry.dial, DialState::Backoff { .. }) {
            entry.dial = DialState::Idle;
        }

        let after = self.book.get(&peer).map(|entry| self.view(entry));
        if before != after {
            self.mark_state(&peer, DiscoverySource::SignedBeacon);
        }
        if !addrs.is_empty() {
            self.maybe_dial(&peer, DiscoverySource::SignedBeacon, now_ms);
        }
    }

    /// Incorporates unauthenticated mDNS address claims and their individual TTLs.
    ///
    /// The input order is the sender's preference order. TTL zero removes the
    /// corresponding address immediately.
    pub fn observe_mdns(&mut self, peer: PeerId, addrs: Vec<(Multiaddr, u64)>, now_ms: u64) {
        if peer == self.local_peer_id {
            return;
        }
        let mut normalized = Vec::new();
        for (addr, ttl_ms) in addrs {
            if let Some(addr) = normalize_addr(&peer, addr) {
                normalized.push((addr, ttl_ms));
            }
        }
        let has_positive = normalized.iter().any(|(_, ttl)| *ttl > 0);
        if !self.book.contains_key(&peer)
            && (!has_positive || !self.make_room(&peer, DiscoverySource::Mdns))
        {
            return;
        }

        let before = self.book.get(&peer).map(|entry| self.view(entry));
        self.book
            .entry(peer.clone())
            .or_insert_with(PeerEntry::empty);

        for (addr, ttl_ms) in normalized {
            let entry = self.book.get_mut(&peer).expect("entry inserted above");
            if ttl_ms == 0 {
                if entry.mdns.remove(&addr).is_some() {
                    entry.mdns_order.retain(|known| known != &addr);
                }
                entry.assert_mdns_order();
                continue;
            }

            let ttl_ms = ttl_ms.min(self.config.max_observed_ttl_ms);
            let record = MdnsRecord {
                observed_at_ms: now_ms,
                expires_at_ms: now_ms.saturating_add(ttl_ms),
            };
            if let Some(existing) = entry.mdns.get_mut(&addr) {
                *existing = record;
                entry.assert_mdns_order();
                continue;
            }
            if entry.mdns.len() == self.config.max_addrs_per_peer {
                let candidate = entry
                    .mdns
                    .iter()
                    .min_by(|(a_addr, a), (b_addr, b)| {
                        (a.expires_at_ms, *a_addr).cmp(&(b.expires_at_ms, *b_addr))
                    })
                    .map(|(candidate, record)| (candidate.clone(), record.expires_at_ms));
                let Some((candidate, candidate_expiry)) = candidate else {
                    continue;
                };
                if record.expires_at_ms <= candidate_expiry {
                    continue;
                }
                entry.mdns.remove(&candidate);
                entry.mdns_order.retain(|known| known != &candidate);
            }
            entry.mdns.insert(addr.clone(), record);
            entry.mdns_order.push(addr);
            entry.assert_mdns_order();
        }

        if self.book.get(&peer).is_some_and(PeerEntry::is_empty) {
            self.remove_peer(&peer);
            return;
        }

        let after = self.book.get(&peer).map(|entry| self.view(entry));
        if before != after {
            self.mark_state(&peer, DiscoverySource::Mdns);
        }
        if has_positive {
            self.maybe_dial(&peer, DiscoverySource::Mdns, now_ms);
        }
    }

    /// Records a recognizable invalid claim using bounded pending slots.
    pub fn report_violation(
        &mut self,
        peer: Option<PeerId>,
        source: DiscoverySource,
        reason: &str,
    ) {
        if self.violations.len() < self.config.max_pending_violations as usize {
            self.violations.push_back(PendingViolation {
                peer,
                source,
                reason: cap_reason(reason),
                suppressed: 0,
            });
        } else if let Some(newest) = self.violations.back_mut() {
            newest.suppressed = newest.suppressed.saturating_add(1);
        }
    }

    /// Reports that the swarm has a connection to a peer.
    pub fn peer_connected(&mut self, peer: &PeerId, _now_ms: u64) {
        self.connected.insert(peer.clone());
        if let Some(entry) = self.book.get_mut(peer) {
            entry.dial = DialState::Idle;
        }
    }

    /// Reports that the swarm no longer has a connection to a peer.
    pub fn peer_disconnected(&mut self, peer: &PeerId, _now_ms: u64) {
        self.connected.remove(peer);
    }

    /// Reports successful completion of an automatic dial.
    pub fn dial_succeeded(&mut self, peer: &PeerId, _now_ms: u64) {
        if let Some(entry) = self.book.get_mut(peer)
            && matches!(entry.dial, DialState::InFlight)
        {
            entry.dial = DialState::Idle;
        }
    }

    /// Reports failure of an automatic dial.
    pub fn dial_failed(&mut self, peer: &PeerId, reason: &str, now_ms: u64) {
        if let Some(entry) = self.book.get_mut(peer)
            && matches!(entry.dial, DialState::InFlight)
        {
            entry.dial = DialState::Backoff {
                until_ms: now_ms.saturating_add(self.config.redial_backoff_ms),
            };
            self.mark_dial_failed(peer, reason);
        }
    }

    /// Expires stale source records.
    pub fn handle_tick(&mut self, now_ms: u64) {
        let peers: Vec<PeerId> = self.book.keys().cloned().collect();
        for peer in peers {
            let before = self.book.get(&peer).map(|entry| self.view(entry));
            let mut beacon_changed = false;
            let mut mdns_changed = false;
            if let Some(entry) = self.book.get_mut(&peer) {
                if entry.beacon.as_ref().is_some_and(|source| {
                    now_ms
                        >= source
                            .last_seen_ms
                            .saturating_add(self.config.beacon_peer_ttl_ms)
                }) {
                    entry.beacon = None;
                    beacon_changed = true;
                }
                let expired: Vec<Multiaddr> = entry
                    .mdns
                    .iter()
                    .filter(|(_, record)| now_ms >= record.expires_at_ms)
                    .map(|(addr, _)| addr.clone())
                    .collect();
                for addr in expired {
                    entry.mdns.remove(&addr);
                    entry.mdns_order.retain(|known| known != &addr);
                    mdns_changed = true;
                }
                entry.assert_mdns_order();
            }

            if self.book.get(&peer).is_some_and(PeerEntry::is_empty) {
                self.remove_peer(&peer);
                continue;
            }
            let after = self.book.get(&peer).map(|entry| self.view(entry));
            if before != after {
                self.mark_state(
                    &peer,
                    if beacon_changed {
                        DiscoverySource::SignedBeacon
                    } else if mdns_changed {
                        DiscoverySource::Mdns
                    } else {
                        continue;
                    },
                );
            }
        }
    }

    /// Pops the next requested dial side effect.
    pub fn poll_action(&mut self) -> Option<DiscoveryAction> {
        self.actions.pop_front()
    }

    /// Returns the number of application events represented by bounded pending state.
    pub fn pending_event_count(&self) -> usize {
        self.pending
            .values()
            .map(|pending| {
                usize::from(pending.state.is_some()) + usize::from(pending.dial_failed.is_some())
            })
            .sum::<usize>()
            .saturating_add(self.violations.len())
    }

    /// Pops the next coalesced application-facing event.
    ///
    /// A peer's state transition is returned before a pending dial failure for
    /// that peer, and the peer remains at the FIFO head until both are drained.
    pub fn poll_event(&mut self) -> Option<DiscoveryEvent> {
        while let Some(peer) = self.order.front().cloned() {
            let state = self
                .pending
                .get_mut(&peer)
                .and_then(|pending| pending.state.take());
            if let Some(state) = state {
                let event = match state {
                    StateTransition::Discovered(source) => {
                        let Some(entry) = self.book.get(&peer) else {
                            self.cleanup_pending_head(&peer);
                            continue;
                        };
                        let view = self.view(entry);
                        self.reported.insert(peer.clone(), view.clone());
                        DiscoveryEvent::PeerDiscovered {
                            peer: peer.clone(),
                            addrs: view.merged,
                            source,
                        }
                    }
                    StateTransition::Updated(source) => {
                        let Some(entry) = self.book.get(&peer) else {
                            self.cleanup_pending_head(&peer);
                            continue;
                        };
                        let view = self.view(entry);
                        self.reported.insert(peer.clone(), view.clone());
                        DiscoveryEvent::PeerUpdated {
                            peer: peer.clone(),
                            addrs: view.merged,
                            source,
                        }
                    }
                    StateTransition::Expired => {
                        self.reported.remove(&peer);
                        DiscoveryEvent::PeerExpired { peer: peer.clone() }
                    }
                };
                self.cleanup_pending_head(&peer);
                self.assert_pending_invariants();
                return Some(event);
            }

            let dial_failed = self
                .pending
                .get_mut(&peer)
                .and_then(|pending| pending.dial_failed.take());
            if let Some(reason) = dial_failed {
                self.cleanup_pending_head(&peer);
                self.assert_pending_invariants();
                return Some(DiscoveryEvent::DialFailed { peer, reason });
            }
            self.remove_pending(&peer);
        }

        self.violations
            .pop_front()
            .map(|violation| DiscoveryEvent::ProtocolViolation {
                peer: violation.peer,
                source: violation.source,
                reason: violation.reason,
                suppressed: violation.suppressed,
            })
    }

    /// Returns milliseconds until the next source expiry, if the book is non-empty.
    pub fn next_timeout(&self, now_ms: u64) -> Option<u64> {
        self.book
            .values()
            .flat_map(|entry| {
                let beacon = entry.beacon.as_ref().map(|source| {
                    source
                        .last_seen_ms
                        .saturating_add(self.config.beacon_peer_ttl_ms)
                });
                beacon
                    .into_iter()
                    .chain(entry.mdns.values().map(|record| record.expires_at_ms))
            })
            .min()
            .map(|deadline| deadline.saturating_sub(now_ms))
    }

    /// Returns a deterministic peer-id-ordered snapshot of the address book.
    pub fn known_peers(&self) -> Vec<KnownPeer> {
        self.book
            .iter()
            .map(|(peer, entry)| KnownPeer {
                peer: peer.clone(),
                addrs: self.view(entry).merged,
                beacon_addrs: entry
                    .beacon
                    .as_ref()
                    .map(|source| source.addrs.clone())
                    .unwrap_or_default(),
                mdns_addrs: entry.mdns_order.clone(),
                beacon_last_seen_ms: entry.beacon.as_ref().map(|source| source.last_seen_ms),
                mdns_last_seen_ms: entry
                    .mdns
                    .values()
                    .map(|record| record.observed_at_ms)
                    .max(),
                connected: self.connected.contains(peer),
            })
            .collect()
    }

    fn view(&self, entry: &PeerEntry) -> PeerView {
        let beacon_addrs = entry
            .beacon
            .as_ref()
            .map(|source| source.addrs.as_slice())
            .unwrap_or_default();
        let mut all = beacon_addrs.to_vec();
        for addr in &entry.mdns_order {
            if !all.contains(addr) {
                all.push(addr.clone());
            }
        }
        let provenance = all
            .iter()
            .map(|addr| {
                (
                    addr.clone(),
                    beacon_addrs.contains(addr),
                    entry.mdns.contains_key(addr),
                )
            })
            .collect();
        all.truncate(self.config.max_addrs_per_peer);
        PeerView {
            merged: all,
            provenance,
            beacon_present: entry.beacon.is_some(),
            mdns_present: !entry.mdns.is_empty(),
        }
    }

    fn make_room(&mut self, incoming: &PeerId, source: DiscoverySource) -> bool {
        if self.book.len() < self.config.max_known_peers {
            return true;
        }
        let candidate = self
            .book
            .iter()
            .filter(|(_, entry)| source != DiscoverySource::Mdns || entry.beacon.is_none())
            .min_by(|(a_peer, a), (b_peer, b)| {
                (
                    self.connected.contains(*a_peer),
                    a.beacon.is_some(),
                    a.last_seen_ms(),
                    *a_peer,
                )
                    .cmp(&(
                        self.connected.contains(*b_peer),
                        b.beacon.is_some(),
                        b.last_seen_ms(),
                        *b_peer,
                    ))
            })
            .map(|(peer, _)| peer.clone());
        let Some(candidate) = candidate else {
            return false;
        };
        if &candidate == incoming {
            return true;
        }
        self.remove_peer(&candidate);
        true
    }

    fn maybe_dial(&mut self, peer: &PeerId, source: DiscoverySource, now_ms: u64) {
        if !self.config.auto_dial
            || self.connected.contains(peer)
            || (self.config.dial_tie_break && self.local_peer_id >= *peer)
        {
            return;
        }
        let Some(entry) = self.book.get(peer) else {
            return;
        };
        let permitted = match entry.dial {
            DialState::Idle => true,
            DialState::InFlight => false,
            DialState::Backoff { until_ms } => now_ms >= until_ms,
        };
        if !permitted {
            return;
        }
        if source == DiscoverySource::Mdns {
            let per_peer_allowed = entry.mdns_attempts.allows(
                now_ms,
                self.config.mdns_dial_window_ms,
                self.config.max_mdns_dials_per_window,
            );
            let global_allowed = self.global_mdns_attempts.allows(
                now_ms,
                self.config.mdns_dial_window_ms,
                self.config.max_mdns_dials_per_window_global,
            );
            if !per_peer_allowed || !global_allowed {
                return;
            }
        }
        let addrs = self.view(entry).merged;
        if addrs.is_empty() {
            return;
        }

        let entry = self.book.get_mut(peer).expect("entry checked above");
        entry.dial = DialState::InFlight;
        if source == DiscoverySource::Mdns {
            entry
                .mdns_attempts
                .charge(now_ms, self.config.mdns_dial_window_ms);
            self.global_mdns_attempts
                .charge(now_ms, self.config.mdns_dial_window_ms);
        }
        self.actions.push_back(DiscoveryAction::Dial {
            peer: peer.clone(),
            addrs,
        });
    }

    fn remove_peer(&mut self, peer: &PeerId) {
        let Some(entry) = self.book.remove(peer) else {
            return;
        };
        let queued = self.actions.iter().any(
            |action| matches!(action, DiscoveryAction::Dial { peer: queued, .. } if queued == peer),
        );
        self.actions.retain(
            |action| !matches!(action, DiscoveryAction::Dial { peer: queued, .. } if queued == peer),
        );
        if matches!(entry.dial, DialState::InFlight) || queued {
            self.actions
                .push_back(DiscoveryAction::CancelDial { peer: peer.clone() });
        }
        self.mark_state(peer, DiscoverySource::Mdns);
    }

    fn mark_state(&mut self, peer: &PeerId, source: DiscoverySource) {
        let current = self.book.get(peer).map(|entry| self.view(entry));
        let reported = self.reported.get(peer);
        let state = match (reported, current.as_ref()) {
            (None, Some(_)) => Some(StateTransition::Discovered(source)),
            (Some(previous), Some(current)) if previous != current => {
                Some(StateTransition::Updated(source))
            }
            (Some(_), None) => Some(StateTransition::Expired),
            _ => None,
        };

        if state.is_none() && reported.is_none() && current.is_none() {
            self.remove_pending(peer);
            self.assert_pending_invariants();
            return;
        }
        if let Some(state) = state {
            let pending = self.pending_entry(peer);
            pending.state = Some(state);
        } else if let Some(pending) = self.pending.get_mut(peer) {
            pending.state = None;
            if pending.dial_failed.is_none() {
                self.remove_pending(peer);
            }
        }
        self.assert_pending_invariants();
    }

    fn mark_dial_failed(&mut self, peer: &PeerId, reason: &str) {
        if !self.book.contains_key(peer) && !self.reported.contains_key(peer) {
            self.remove_pending(peer);
            return;
        }
        self.pending_entry(peer).dial_failed = Some(cap_reason(reason));
        self.assert_pending_invariants();
    }

    fn pending_entry(&mut self, peer: &PeerId) -> &mut PendingPeer {
        if !self.pending.contains_key(peer) {
            self.order.push_back(peer.clone());
        }
        self.pending.entry(peer.clone()).or_default()
    }

    fn cleanup_pending_head(&mut self, peer: &PeerId) {
        if self
            .pending
            .get(peer)
            .is_some_and(|pending| pending.state.is_none() && pending.dial_failed.is_none())
        {
            self.remove_pending(peer);
        }
    }

    fn remove_pending(&mut self, peer: &PeerId) {
        self.pending.remove(peer);
        self.order.retain(|queued| queued != peer);
    }

    fn assert_pending_invariants(&self) {
        debug_assert_eq!(self.pending.len(), self.order.len());
        debug_assert_eq!(
            self.order.iter().collect::<BTreeSet<_>>().len(),
            self.order.len()
        );
        debug_assert!(
            self.order
                .iter()
                .all(|peer| self.pending.contains_key(peer))
        );
        debug_assert!(self.pending.len() <= self.config.max_known_peers.saturating_mul(2));
    }
}

fn normalize_observed_addrs(peer: &PeerId, addrs: Vec<Multiaddr>, cap: usize) -> Vec<Multiaddr> {
    let mut normalized = Vec::new();
    for addr in addrs {
        let Some(addr) = normalize_addr(peer, addr) else {
            continue;
        };
        if !normalized.contains(&addr) {
            normalized.push(addr);
            if normalized.len() == cap {
                break;
            }
        }
    }
    normalized
}

fn cap_reason(reason: &str) -> String {
    reason.chars().take(MAX_DIAL_FAILURE_REASON_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, vec};
    use core::str::FromStr;
    use minip2p_identity::{KeyType, PublicKey};

    fn peer(byte: u8) -> PeerId {
        PeerId::from_public_key(&PublicKey::new(KeyType::Ed25519, vec![byte; 32]))
    }

    fn addr(port: u16) -> Multiaddr {
        Multiaddr::from_str(&format!("/ip4/127.0.0.1/udp/{port}/quic-v1")).unwrap()
    }

    fn agent(mut config: PeerDiscoveryConfig) -> PeerDiscoveryAgent {
        config.dial_tie_break = false;
        PeerDiscoveryAgent::new(peer(1), config).unwrap()
    }

    fn beacon(peer: PeerId, addrs: Vec<Multiaddr>) -> Observation {
        Observation { peer, addrs }
    }

    #[test]
    fn addressless_beacon_presence_survives_mdns_expiry() {
        let mut agent = agent(PeerDiscoveryConfig::default());
        let remote = peer(2);
        agent.observe_mdns(remote.clone(), vec![(addr(1), 5)], 0);
        agent.observe_beacon(beacon(remote.clone(), vec![]), 1);
        let known = &agent.known_peers()[0];
        assert_eq!(known.beacon_last_seen_ms, Some(1));
        assert_eq!(known.mdns_addrs, vec![addr(1)]);

        agent.handle_tick(5);
        let known = &agent.known_peers()[0];
        assert!(known.addrs.is_empty());
        assert_eq!(known.beacon_last_seen_ms, Some(1));
    }

    #[test]
    fn provenance_changes_emit_updates_without_merged_address_changes() {
        let config = PeerDiscoveryConfig {
            auto_dial: false,
            beacon_peer_ttl_ms: 5,
            ..PeerDiscoveryConfig::default()
        };
        let mut agent = agent(config);
        let remote = peer(2);
        let candidate = addr(1);
        agent.observe_mdns(remote.clone(), vec![(candidate.clone(), 100)], 0);
        assert!(matches!(
            agent.poll_event(),
            Some(DiscoveryEvent::PeerDiscovered {
                source: DiscoverySource::Mdns,
                ..
            })
        ));

        agent.observe_beacon(beacon(remote.clone(), vec![candidate.clone()]), 1);
        assert!(matches!(
            agent.poll_event(),
            Some(DiscoveryEvent::PeerUpdated {
                addrs,
                source: DiscoverySource::SignedBeacon,
                ..
            }) if addrs == vec![candidate.clone()]
        ));
        agent.handle_tick(6);
        assert!(matches!(
            agent.poll_event(),
            Some(DiscoveryEvent::PeerUpdated {
                addrs,
                source: DiscoverySource::SignedBeacon,
                ..
            }) if addrs == vec![candidate]
        ));
    }

    #[test]
    fn pure_ttl_refresh_emits_no_update() {
        let config = PeerDiscoveryConfig {
            auto_dial: false,
            ..PeerDiscoveryConfig::default()
        };
        let mut agent = agent(config);
        let remote = peer(2);
        agent.observe_mdns(remote.clone(), vec![(addr(1), 100)], 0);
        let _ = agent.poll_event();
        agent.observe_mdns(remote, vec![(addr(1), 200)], 1);
        assert!(agent.poll_event().is_none());
        assert_eq!(agent.known_peers()[0].mdns_last_seen_ms, Some(1));
    }

    #[test]
    fn mdns_storage_is_bounded_and_keeps_first_observation_order() {
        let config = PeerDiscoveryConfig {
            auto_dial: false,
            max_addrs_per_peer: 2,
            ..PeerDiscoveryConfig::default()
        };
        let mut agent = agent(config);
        let remote = peer(2);
        agent.observe_mdns(remote.clone(), vec![(addr(1), 10), (addr(2), 20)], 0);
        agent.observe_mdns(remote, vec![(addr(3), 30)], 0);
        let known = &agent.known_peers()[0];
        assert_eq!(known.mdns_addrs, vec![addr(2), addr(3)]);
        assert_eq!(known.mdns_addrs.len(), 2);
    }

    #[test]
    fn mdns_cannot_evict_a_beacon_backed_entry() {
        let config = PeerDiscoveryConfig {
            auto_dial: false,
            max_known_peers: 1,
            ..PeerDiscoveryConfig::default()
        };
        let mut agent = agent(config);
        let authenticated = peer(2);
        agent.observe_beacon(beacon(authenticated.clone(), vec![]), 0);
        agent.observe_mdns(peer(3), vec![(addr(3), 100)], 1);
        assert_eq!(agent.known_peers()[0].peer, authenticated);
    }

    #[test]
    fn both_mdns_rate_windows_charge_only_enqueued_dials() {
        let config = PeerDiscoveryConfig {
            max_mdns_dials_per_window: 1,
            max_mdns_dials_per_window_global: 2,
            ..PeerDiscoveryConfig::default()
        };
        let mut agent = agent(config);
        let first = peer(2);
        agent.observe_mdns(first.clone(), vec![(addr(1), 100)], 0);
        assert!(matches!(
            agent.poll_action(),
            Some(DiscoveryAction::Dial { .. })
        ));
        agent.dial_failed(&first, "failed", 1);
        agent.observe_mdns(first, vec![(addr(2), 100)], 2);
        assert!(agent.poll_action().is_none());
        let second = peer(3);
        agent.observe_mdns(second.clone(), vec![(addr(3), 100)], 3);
        assert!(matches!(
            agent.poll_action(),
            Some(DiscoveryAction::Dial { peer, .. }) if peer == second
        ));
        agent.dial_failed(&second, "failed", 4);
        agent.observe_mdns(second, vec![(addr(4), 100)], 5);
        assert!(agent.poll_action().is_none());
        agent.observe_mdns(peer(4), vec![(addr(5), 100)], 6);
        assert!(agent.poll_action().is_none());
    }

    #[test]
    fn only_authenticated_address_change_clears_backoff() {
        let mut agent = agent(PeerDiscoveryConfig::default());
        let remote = peer(2);
        agent.observe_mdns(remote.clone(), vec![(addr(1), 100)], 0);
        let _ = agent.poll_action();
        agent.dial_failed(&remote, "failed", 1);

        agent.observe_mdns(remote.clone(), vec![(addr(2), 100)], 2);
        assert!(agent.poll_action().is_none());
        agent.observe_beacon(beacon(remote.clone(), vec![]), 3);
        assert!(agent.poll_action().is_none());
        agent.observe_beacon(beacon(remote, vec![addr(1)]), 4);
        assert!(matches!(
            agent.poll_action(),
            Some(DiscoveryAction::Dial { .. })
        ));
    }

    #[test]
    fn violation_slots_coalesce_and_saturate() {
        let config = PeerDiscoveryConfig {
            max_pending_violations: 1,
            ..PeerDiscoveryConfig::default()
        };
        let mut agent = agent(config);
        agent.report_violation(None, DiscoverySource::Mdns, "first");
        agent.report_violation(None, DiscoverySource::Mdns, "second");
        assert!(matches!(
            agent.poll_event(),
            Some(DiscoveryEvent::ProtocolViolation { suppressed: 1, .. })
        ));
    }

    #[test]
    fn discover_then_expire_before_drain_cancels_the_state_and_failure() {
        let config = PeerDiscoveryConfig {
            beacon_peer_ttl_ms: 1,
            ..PeerDiscoveryConfig::default()
        };
        let mut agent = agent(config);
        let remote = peer(2);
        agent.observe_beacon(beacon(remote.clone(), vec![addr(1)]), 0);
        let _ = agent.poll_action();
        agent.dial_failed(&remote, "failed", 0);
        agent.handle_tick(1);
        assert!(agent.poll_event().is_none());
        assert!(agent.pending.is_empty());
        assert!(agent.order.is_empty());
    }

    #[test]
    fn fifo_eviction_reports_expiry_before_replacement_discovery() {
        let config = PeerDiscoveryConfig {
            auto_dial: false,
            max_known_peers: 1,
            ..PeerDiscoveryConfig::default()
        };
        let mut agent = agent(config);
        let first = peer(250);
        let second = peer(2);
        agent.observe_beacon(beacon(first.clone(), vec![]), 0);
        assert!(matches!(
            agent.poll_event(),
            Some(DiscoveryEvent::PeerDiscovered { peer, .. }) if peer == first
        ));
        agent.observe_beacon(beacon(second.clone(), vec![]), 1);
        assert!(matches!(
            agent.poll_event(),
            Some(DiscoveryEvent::PeerExpired { peer }) if peer == first
        ));
        assert!(matches!(
            agent.poll_event(),
            Some(DiscoveryEvent::PeerDiscovered { peer, .. }) if peer == second
        ));
    }

    #[test]
    fn adversarial_peer_order_and_one_event_drains_preserve_the_two_n_bound() {
        let config = PeerDiscoveryConfig {
            auto_dial: false,
            max_known_peers: 2,
            ..PeerDiscoveryConfig::default()
        };
        let mut agent = agent(config);
        let mut peers = (2..30).map(peer).collect::<Vec<_>>();
        peers.sort();
        let initial = peers.split_off(peers.len() - 2);
        for remote in &initial {
            agent.observe_beacon(beacon(remote.clone(), vec![]), 0);
        }
        while agent.poll_event().is_some() {}
        assert_eq!(agent.reported.len(), 2);

        for (now, remote) in peers.into_iter().enumerate() {
            agent.observe_beacon(beacon(remote, vec![]), now as u64 + 1);
            let _ = agent.poll_event();
            assert!(agent.reported.len() <= 2);
            assert!(agent.pending.len() <= 4);
            assert_eq!(agent.pending.len(), agent.order.len());
        }
        while agent.poll_event().is_some() {
            assert!(agent.reported.len() <= 2);
            assert!(agent.pending.len() <= 4);
        }
    }

    #[test]
    fn rotating_undrained_dial_failures_leave_no_orphans() {
        let config = PeerDiscoveryConfig {
            max_known_peers: 1,
            beacon_peer_ttl_ms: 1,
            ..PeerDiscoveryConfig::default()
        };
        let mut agent = agent(config);
        for (index, remote) in (2..40).map(peer).enumerate() {
            let now = index as u64;
            agent.observe_beacon(beacon(remote.clone(), vec![addr(index as u16 + 1)]), now);
            let _ = agent.poll_action();
            agent.dial_failed(&remote, "failed", now);
            assert!(agent.pending.len() <= 1);
        }
        agent.handle_tick(100);
        assert!(agent.pending.is_empty());
        assert!(agent.order.is_empty());
    }

    #[test]
    fn config_rejects_zero_violation_slots() {
        let config = PeerDiscoveryConfig {
            max_pending_violations: 0,
            ..PeerDiscoveryConfig::default()
        };
        assert_eq!(
            config.validate(),
            Err(DiscoveryConfigError::ZeroPendingViolations)
        );
    }
}
