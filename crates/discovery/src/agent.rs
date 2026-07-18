//! Deterministic discovery state machine.

use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    format,
    string::ToString,
    vec::Vec,
};

use minip2p_core::{Multiaddr, PeerId, Protocol};
use minip2p_identity::PublicKey;

use crate::{
    Beacon, DiscoveryAction, DiscoveryConfig, DiscoveryConfigError, DiscoveryEvent, KnownPeer,
};

#[derive(Clone, Debug, Eq, PartialEq)]
enum DialState {
    Idle,
    InFlight,
    Backoff { until_ms: u64 },
}

#[derive(Clone, Debug)]
struct PeerEntry {
    addrs: Vec<Multiaddr>,
    last_seen_ms: u64,
    dial: DialState,
}

/// Sans-I/O pubsub peer-discovery state machine.
pub struct DiscoveryAgent {
    config: DiscoveryConfig,
    local_peer_id: PeerId,
    public_key: Vec<u8>,
    local_addrs: Vec<Multiaddr>,
    next_beacon_at_ms: u64,
    book: BTreeMap<PeerId, PeerEntry>,
    connected: BTreeSet<PeerId>,
    actions: VecDeque<DiscoveryAction>,
    events: VecDeque<DiscoveryEvent>,
}

impl DiscoveryAgent {
    /// Constructs an agent after validating its configuration.
    pub fn new(
        public_key: PublicKey,
        config: DiscoveryConfig,
    ) -> Result<Self, DiscoveryConfigError> {
        config.validate()?;
        Ok(Self {
            local_peer_id: PeerId::from_public_key(&public_key),
            public_key: public_key.encode_protobuf(),
            config,
            local_addrs: Vec::new(),
            next_beacon_at_ms: 0,
            book: BTreeMap::new(),
            connected: BTreeSet::new(),
            actions: VecDeque::new(),
            events: VecDeque::new(),
        })
    }

    /// Returns the identity advertised by this agent.
    pub fn local_peer_id(&self) -> &PeerId {
        &self.local_peer_id
    }

    /// Returns the configured pubsub discovery topic.
    pub fn topic(&self) -> &str {
        &self.config.topic
    }

    /// Replaces local addresses; an actual change schedules an immediate beacon.
    pub fn set_local_addrs(&mut self, addrs: &[Multiaddr], now_ms: u64) {
        if self.local_addrs != addrs {
            self.local_addrs = addrs.to_vec();
            self.next_beacon_at_ms = now_ms;
        }
    }

    /// Validates and incorporates a received pubsub beacon.
    pub fn handle_beacon(&mut self, from: &PeerId, payload: &[u8], signed: bool, now_ms: u64) {
        if from == &self.local_peer_id {
            return;
        }
        if !signed {
            self.violation(from, "unsigned discovery beacon");
            return;
        }
        let beacon = match Beacon::decode(payload) {
            Ok(beacon) => beacon,
            Err(error) => {
                self.violation(from, &error.to_string());
                return;
            }
        };
        let public_key = match PublicKey::decode_protobuf(&beacon.public_key) {
            Ok(key) => key,
            Err(error) => {
                self.violation(from, &format!("invalid discovery public key: {error}"));
                return;
            }
        };
        if PeerId::from_public_key(&public_key) != *from {
            self.violation(from, "discovery public key does not match publisher");
            return;
        }

        let addrs = normalize_addrs(from, beacon.addrs, self.config.max_addrs_per_peer);
        if !self.book.contains_key(from) && self.book.len() == self.config.max_known_peers {
            let candidate = self
                .book
                .iter()
                .filter(|(peer, _)| !self.connected.contains(*peer))
                .min_by(|(a_peer, a), (b_peer, b)| {
                    (a.last_seen_ms, *a_peer).cmp(&(b.last_seen_ms, *b_peer))
                })
                .map(|(peer, _)| peer.clone());
            let Some(candidate) = candidate else {
                return;
            };
            self.remove_peer(&candidate);
        }

        let mut changed = false;
        let is_new = !self.book.contains_key(from);
        if let Some(entry) = self.book.get_mut(from) {
            changed = entry.addrs != addrs;
            entry.last_seen_ms = now_ms;
            if changed {
                entry.addrs = addrs.clone();
                if matches!(entry.dial, DialState::Backoff { .. }) {
                    entry.dial = DialState::Idle;
                }
            }
        } else {
            self.book.insert(
                from.clone(),
                PeerEntry {
                    addrs: addrs.clone(),
                    last_seen_ms: now_ms,
                    dial: DialState::Idle,
                },
            );
        }

        if is_new {
            self.events.push_back(DiscoveryEvent::PeerDiscovered {
                peer: from.clone(),
                addrs: addrs.clone(),
            });
        } else if changed {
            self.events.push_back(DiscoveryEvent::PeerUpdated {
                peer: from.clone(),
                addrs: addrs.clone(),
            });
        }
        self.maybe_dial(from, now_ms);
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
            self.events.push_back(DiscoveryEvent::DialFailed {
                peer: peer.clone(),
                reason: reason.to_string(),
            });
        }
    }

    /// Emits a due beacon and expires stale peer records.
    pub fn handle_tick(&mut self, now_ms: u64) {
        if now_ms >= self.next_beacon_at_ms {
            self.actions.push_back(DiscoveryAction::PublishBeacon {
                topic: self.config.topic.clone(),
                payload: self.build_beacon().encode(),
            });
            self.next_beacon_at_ms = now_ms.saturating_add(self.config.beacon_interval_ms);
        }
        let expired: Vec<PeerId> = self
            .book
            .iter()
            .filter(|(_, entry)| {
                now_ms >= entry.last_seen_ms.saturating_add(self.config.peer_ttl_ms)
            })
            .map(|(peer, _)| peer.clone())
            .collect();
        for peer in expired {
            self.remove_peer(&peer);
        }
    }

    /// Pops the next requested side effect.
    pub fn poll_action(&mut self) -> Option<DiscoveryAction> {
        self.actions.pop_front()
    }

    /// Pops the next application-facing event.
    pub fn poll_event(&mut self) -> Option<DiscoveryEvent> {
        self.events.pop_front()
    }

    /// Returns milliseconds until the next beacon or peer expiry.
    pub fn next_timeout(&self, now_ms: u64) -> Option<u64> {
        let expiry = self
            .book
            .values()
            .map(|entry| entry.last_seen_ms.saturating_add(self.config.peer_ttl_ms))
            .min();
        let deadline = expiry
            .map(|value| value.min(self.next_beacon_at_ms))
            .unwrap_or(self.next_beacon_at_ms);
        Some(deadline.saturating_sub(now_ms))
    }

    /// Returns a deterministic peer-id-ordered snapshot of the address book.
    pub fn known_peers(&self) -> Vec<KnownPeer> {
        self.book
            .iter()
            .map(|(peer, entry)| KnownPeer {
                peer: peer.clone(),
                addrs: entry.addrs.clone(),
                last_seen_ms: entry.last_seen_ms,
                connected: self.connected.contains(peer),
            })
            .collect()
    }

    fn build_beacon(&self) -> Beacon {
        let mut addrs = Vec::new();
        for addr in &self.local_addrs {
            if is_wildcard_addr(addr) {
                continue;
            }
            let mut advertised = addr.clone();
            advertised.push(Protocol::P2p(self.local_peer_id.clone()));
            let bytes = advertised.to_bytes();
            if bytes.len() <= crate::MAX_ADDR_LEN && !addrs.contains(&bytes) {
                addrs.push(bytes);
                if addrs.len() == self.config.max_addrs_per_peer {
                    break;
                }
            }
        }
        Beacon {
            public_key: self.public_key.clone(),
            addrs,
        }
    }

    fn maybe_dial(&mut self, peer: &PeerId, now_ms: u64) {
        if !self.config.auto_dial
            || self.connected.contains(peer)
            || (self.config.dial_tie_break && self.local_peer_id >= *peer)
        {
            return;
        }
        let Some(entry) = self.book.get_mut(peer) else {
            return;
        };
        let permitted = match entry.dial {
            DialState::Idle => true,
            DialState::InFlight => false,
            DialState::Backoff { until_ms } => now_ms >= until_ms,
        };
        if permitted {
            entry.dial = DialState::InFlight;
            self.actions.push_back(DiscoveryAction::Dial {
                peer: peer.clone(),
                addrs: entry.addrs.clone(),
            });
        }
    }

    fn remove_peer(&mut self, peer: &PeerId) {
        let Some(entry) = self.book.remove(peer) else {
            return;
        };
        self.events
            .push_back(DiscoveryEvent::PeerExpired { peer: peer.clone() });
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
    }

    fn violation(&mut self, peer: &PeerId, reason: &str) {
        self.events.push_back(DiscoveryEvent::ProtocolViolation {
            peer: peer.clone(),
            reason: reason.to_string(),
        });
    }
}

fn normalize_addrs(from: &PeerId, raw: Vec<Vec<u8>>, cap: usize) -> Vec<Multiaddr> {
    let mut normalized = Vec::new();
    for bytes in raw {
        let Ok(addr) = Multiaddr::from_bytes(&bytes) else {
            continue;
        };
        let protocols = addr.protocols();
        let addr = match protocols.last() {
            Some(Protocol::P2p(peer)) if peer == from => {
                Multiaddr::from_protocols(protocols[..protocols.len() - 1].to_vec())
            }
            Some(Protocol::P2p(_)) => continue,
            _ => addr,
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

fn is_wildcard_addr(addr: &Multiaddr) -> bool {
    matches!(addr.protocols().first(), Some(Protocol::Ip4(ip)) if *ip == [0, 0, 0, 0])
        || matches!(addr.protocols().first(), Some(Protocol::Ip6(ip)) if *ip == [0; 16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr;
    use minip2p_identity::{KeyType, PublicKey};

    fn key(byte: u8) -> PublicKey {
        PublicKey::new(KeyType::Ed25519, vec![byte; 32])
    }

    fn agent_with(mut config: DiscoveryConfig, local: u8) -> DiscoveryAgent {
        config.dial_tie_break = false;
        DiscoveryAgent::new(key(local), config).unwrap()
    }

    fn payload(remote: u8, addrs: &[&str]) -> (PeerId, Vec<u8>) {
        let key = key(remote);
        let peer = PeerId::from_public_key(&key);
        let addrs = addrs
            .iter()
            .map(|addr| {
                let mut addr = Multiaddr::from_str(addr).unwrap();
                addr.push(Protocol::P2p(peer.clone()));
                addr.to_bytes()
            })
            .collect();
        (
            peer,
            Beacon {
                public_key: key.encode_protobuf(),
                addrs,
            }
            .encode(),
        )
    }

    #[test]
    fn authentication_rejects_unsigned_and_accepts_signed_sibling() {
        let mut agent = agent_with(DiscoveryConfig::default(), 1);
        let (peer, payload) = payload(2, &[]);
        agent.handle_beacon(&peer, &payload, false, 1);
        assert!(matches!(
            agent.poll_event(),
            Some(DiscoveryEvent::ProtocolViolation { .. })
        ));
        assert!(agent.known_peers().is_empty());
        agent.handle_beacon(&peer, &payload, true, 2);
        assert!(matches!(
            agent.poll_event(),
            Some(DiscoveryEvent::PeerDiscovered { .. })
        ));
    }

    #[test]
    fn announces_suffix_filters_wildcard_and_normalizes_snapshot() {
        let config = DiscoveryConfig {
            auto_dial: false,
            ..DiscoveryConfig::default()
        };
        let mut agent = agent_with(config, 1);
        agent.set_local_addrs(
            &[
                Multiaddr::from_str("/ip4/0.0.0.0/udp/1/quic-v1").unwrap(),
                Multiaddr::from_str("/ip4/127.0.0.1/udp/2/quic-v1").unwrap(),
            ],
            5,
        );
        agent.handle_tick(5);
        let Some(DiscoveryAction::PublishBeacon {
            payload: encoded, ..
        }) = agent.poll_action()
        else {
            panic!()
        };
        let beacon = Beacon::decode(&encoded).unwrap();
        assert_eq!(beacon.addrs.len(), 1);
        let advertised = Multiaddr::from_bytes(&beacon.addrs[0]).unwrap();
        assert_eq!(
            advertised.protocols().last(),
            Some(&Protocol::P2p(agent.local_peer_id().clone()))
        );

        let (peer, payload) = payload(2, &["/ip4/127.0.0.1/udp/2/quic-v1"]);
        agent.handle_beacon(&peer, &payload, true, 6);
        assert_eq!(
            agent.known_peers()[0].addrs[0].to_string(),
            "/ip4/127.0.0.1/udp/2/quic-v1"
        );
    }

    #[test]
    fn expiry_scrubs_queued_dial_and_emits_cancel() {
        let config = DiscoveryConfig {
            peer_ttl_ms: 5,
            ..DiscoveryConfig::default()
        };
        let mut agent = agent_with(config, 1);
        let (peer, payload) = payload(2, &[]);
        agent.handle_beacon(&peer, &payload, true, 10);
        assert!(matches!(
            agent.poll_action(),
            Some(DiscoveryAction::Dial { .. })
        ));
        // Simulate a second still-queued attempt by accepting a changed snapshot after backoff.
        agent.handle_tick(15);
        assert!(matches!(
            agent.poll_action(),
            Some(DiscoveryAction::PublishBeacon { .. })
        ));
        assert!(
            matches!(agent.poll_action(), Some(DiscoveryAction::CancelDial { peer: got }) if got == peer)
        );
        assert!(matches!(
            agent.poll_event(),
            Some(DiscoveryEvent::PeerDiscovered { .. })
        ));
        assert!(matches!(
            agent.poll_event(),
            Some(DiscoveryEvent::PeerExpired { .. })
        ));
    }

    #[test]
    fn replacement_backoff_and_connectivity_are_deterministic() {
        let mut agent = agent_with(DiscoveryConfig::default(), 1);
        let (peer, first) = payload(2, &["/ip4/127.0.0.1/udp/1/quic-v1"]);
        agent.handle_beacon(&peer, &first, true, 1);
        let _ = agent.poll_action();
        agent.dial_failed(&peer, "no path", 2);
        assert!(matches!(
            agent.poll_event(),
            Some(DiscoveryEvent::PeerDiscovered { .. })
        ));
        assert!(matches!(
            agent.poll_event(),
            Some(DiscoveryEvent::DialFailed { .. })
        ));
        agent.handle_beacon(&peer, &first, true, 3);
        assert!(agent.poll_action().is_none());
        let (_, changed) = payload(2, &["/ip4/127.0.0.1/udp/2/quic-v1"]);
        agent.handle_beacon(&peer, &changed, true, 4);
        assert!(matches!(
            agent.poll_action(),
            Some(DiscoveryAction::Dial { .. })
        ));
        agent.peer_connected(&peer, 5);
        assert!(agent.known_peers()[0].connected);
        agent.peer_disconnected(&peer, 6);
        agent.handle_beacon(&peer, &changed, true, 7);
        assert!(matches!(
            agent.poll_action(),
            Some(DiscoveryAction::Dial { .. })
        ));
    }

    #[test]
    fn config_validation_and_saturating_deadlines() {
        let mut config = DiscoveryConfig::default();
        config.topic.clear();
        assert_eq!(config.validate(), Err(DiscoveryConfigError::EmptyTopic));
        config = DiscoveryConfig::default();
        config.beacon_interval_ms = 0;
        assert_eq!(
            config.validate(),
            Err(DiscoveryConfigError::ZeroBeaconInterval)
        );
        config = DiscoveryConfig::default();
        config.peer_ttl_ms = 0;
        assert_eq!(config.validate(), Err(DiscoveryConfigError::ZeroPeerTtl));
        config = DiscoveryConfig::default();
        config.max_known_peers = 0;
        assert_eq!(
            config.validate(),
            Err(DiscoveryConfigError::ZeroMaxKnownPeers)
        );
        config = DiscoveryConfig::default();
        config.max_addrs_per_peer = 0;
        assert_eq!(
            config.validate(),
            Err(DiscoveryConfigError::InvalidMaxAddrs)
        );
        config = DiscoveryConfig::default();
        config.topic = "x".repeat(crate::MAX_TOPIC_LEN + 1);
        assert_eq!(config.validate(), Err(DiscoveryConfigError::TopicTooLong));
        config = DiscoveryConfig::default();
        config.max_addrs_per_peer = crate::MAX_BEACON_ADDRS + 1;
        assert_eq!(
            config.validate(),
            Err(DiscoveryConfigError::InvalidMaxAddrs)
        );
        let mut agent = agent_with(DiscoveryConfig::default(), 1);
        agent.handle_tick(u64::MAX);
        assert_eq!(agent.next_timeout(u64::MAX), Some(0));
    }

    #[test]
    fn self_malformed_and_mismatched_identity_beacons_never_refresh() {
        let mut agent = agent_with(DiscoveryConfig::default(), 1);
        let local = agent.local_peer_id().clone();
        agent.handle_beacon(&local, b"bad", false, 1);
        assert!(agent.poll_event().is_none());

        let remote = PeerId::from_public_key(&key(2));
        agent.handle_beacon(&remote, b"bad", true, 2);
        assert!(matches!(
            agent.poll_event(),
            Some(DiscoveryEvent::ProtocolViolation { .. })
        ));
        let forged = Beacon {
            public_key: key(3).encode_protobuf(),
            addrs: vec![],
        }
        .encode();
        agent.handle_beacon(&remote, &forged, true, 3);
        assert!(matches!(
            agent.poll_event(),
            Some(DiscoveryEvent::ProtocolViolation { .. })
        ));
        assert!(agent.known_peers().is_empty());
    }

    #[test]
    fn invalid_and_mismatched_addresses_are_skipped_beside_valid_siblings() {
        let config = DiscoveryConfig {
            auto_dial: false,
            ..DiscoveryConfig::default()
        };
        let mut agent = agent_with(config, 1);
        let remote_key = key(2);
        let remote = PeerId::from_public_key(&remote_key);
        let other = PeerId::from_public_key(&key(3));
        let valid = Multiaddr::from_str("/ip4/127.0.0.1/udp/9/quic-v1")
            .unwrap()
            .to_bytes();
        let mut mismatch = Multiaddr::from_str("/ip4/127.0.0.1/udp/10/quic-v1").unwrap();
        mismatch.push(Protocol::P2p(other));
        let beacon = Beacon {
            public_key: remote_key.encode_protobuf(),
            addrs: vec![vec![0xff], mismatch.to_bytes(), valid],
        }
        .encode();
        agent.handle_beacon(&remote, &beacon, true, 1);
        assert_eq!(agent.known_peers()[0].addrs.len(), 1);
    }

    #[test]
    fn capacity_evicts_oldest_non_connected_and_cancels_its_dial() {
        let config = DiscoveryConfig {
            max_known_peers: 1,
            ..DiscoveryConfig::default()
        };
        let mut agent = agent_with(config, 1);
        let (first, first_payload) = payload(2, &[]);
        let (second, second_payload) = payload(3, &[]);
        agent.handle_beacon(&first, &first_payload, true, 1);
        agent.handle_beacon(&second, &second_payload, true, 2);
        assert_eq!(agent.known_peers()[0].peer, second);
        assert!(agent.actions.iter().any(
            |action| matches!(action, DiscoveryAction::CancelDial { peer } if peer == &first)
        ));

        agent.peer_connected(&second, 3);
        let (third, third_payload) = payload(4, &[]);
        agent.handle_beacon(&third, &third_payload, true, 4);
        assert_eq!(agent.known_peers()[0].peer, second);
    }

    #[test]
    fn tie_break_and_beacon_rearming_follow_policy() {
        let a_key = key(10);
        let b_key = key(20);
        let a = PeerId::from_public_key(&a_key);
        let b = PeerId::from_public_key(&b_key);
        let (local_key, remote_key) = if a < b {
            (b_key, a_key)
        } else {
            (a_key, b_key)
        };
        let remote = PeerId::from_public_key(&remote_key);
        let payload = Beacon {
            public_key: remote_key.encode_protobuf(),
            addrs: vec![],
        }
        .encode();
        let mut agent = DiscoveryAgent::new(local_key, DiscoveryConfig::default()).unwrap();
        agent.handle_beacon(&remote, &payload, true, 0);
        assert!(
            agent.poll_action().is_none(),
            "higher peer id must not dial"
        );

        agent.handle_tick(0);
        let _ = agent.poll_action();
        assert_eq!(agent.next_timeout(1), Some(9_999));
        agent.set_local_addrs(&[], 5);
        assert_eq!(agent.next_timeout(5), Some(9_995));
        let addr = Multiaddr::from_str("/ip4/127.0.0.1/udp/1/quic-v1").unwrap();
        agent.set_local_addrs(&[addr], 6);
        assert_eq!(agent.next_timeout(6), Some(0));
    }
}
