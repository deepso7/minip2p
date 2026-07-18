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
    MAX_PUBLIC_KEY_LEN,
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
    /// Constructs an agent after validating its configuration and identity size.
    pub fn new(
        public_key: PublicKey,
        config: DiscoveryConfig,
    ) -> Result<Self, DiscoveryConfigError> {
        config.validate()?;
        let public_key = public_key.encode_protobuf();
        if public_key.len() > MAX_PUBLIC_KEY_LEN {
            return Err(DiscoveryConfigError::LocalPublicKeyTooLarge);
        }
        Ok(Self {
            local_peer_id: PeerId::from_public_key_protobuf(&public_key),
            public_key,
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
    /// Unsupported, empty, and wildcard addresses are omitted when publishing.
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
        if !addrs.is_empty() {
            self.maybe_dial(from, now_ms);
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
        let mut beacon = Beacon {
            public_key: self.public_key.clone(),
            addrs: Vec::new(),
        };
        for addr in &self.local_addrs {
            if !is_supported_addr(addr) {
                continue;
            }
            let mut advertised = addr.clone();
            advertised.push(Protocol::P2p(self.local_peer_id.clone()));
            let bytes = advertised.to_bytes();
            if bytes.len() <= crate::MAX_ADDR_LEN && !beacon.addrs.contains(&bytes) {
                beacon.addrs.push(bytes);
                if beacon.encoded_len() > crate::MAX_BEACON_SIZE {
                    beacon.addrs.pop();
                    break;
                }
                if beacon.addrs.len() == self.config.max_addrs_per_peer {
                    break;
                }
            }
        }
        beacon
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
        if !is_supported_addr(&addr) {
            continue;
        }
        if !normalized.contains(&addr) {
            normalized.push(addr);
            if normalized.len() == cap {
                break;
            }
        }
    }
    normalized
}

fn is_supported_addr(addr: &Multiaddr) -> bool {
    if is_wildcard_addr(addr) || addr.is_empty() {
        return false;
    }
    if addr.is_quic_transport() {
        return true;
    }

    // Keep canonical relay circuit addresses. They intentionally trigger the
    // NAT agent's relay leg even though they are not direct QUIC candidates.
    let protocols = addr.protocols();
    protocols.len() == 5
        && protocols[0].is_host()
        && matches!(protocols[1], Protocol::Udp(_))
        && matches!(protocols[2], Protocol::QuicV1)
        && matches!(protocols[3], Protocol::P2p(_))
        && matches!(protocols[4], Protocol::P2pCircuit)
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
    fn variable_length_keys_interoperate_and_oversized_local_keys_are_rejected() {
        let remote_key = PublicKey::new(KeyType::Rsa, vec![7; 1_024]);
        let remote = PeerId::from_public_key(&remote_key);
        let payload = Beacon {
            public_key: remote_key.encode_protobuf(),
            addrs: vec![],
        }
        .encode();
        let mut agent = agent_with(DiscoveryConfig::default(), 1);

        agent.handle_beacon(&remote, &payload, true, 1);
        assert_eq!(agent.known_peers()[0].peer, remote);

        let oversized = PublicKey::new(KeyType::Rsa, vec![0; MAX_PUBLIC_KEY_LEN]);
        assert!(matches!(
            DiscoveryAgent::new(oversized, DiscoveryConfig::default()),
            Err(DiscoveryConfigError::LocalPublicKeyTooLarge)
        ));
    }

    #[test]
    fn presence_only_beacons_refresh_without_dialing() {
        let config = DiscoveryConfig {
            peer_ttl_ms: 5,
            ..DiscoveryConfig::default()
        };
        let mut agent = agent_with(config, 1);
        agent.handle_tick(0);
        let _ = agent.poll_action();
        let (peer, presence) = payload(2, &[]);

        agent.handle_beacon(&peer, &presence, true, 1);
        assert!(agent.poll_action().is_none());
        assert_eq!(agent.known_peers().len(), 1);
        agent.handle_beacon(&peer, &presence, true, 4);
        assert!(agent.poll_action().is_none());
        assert_eq!(agent.next_timeout(4), Some(5));

        let (_, with_addr) = payload(2, &["/ip4/127.0.0.1/udp/9/quic-v1"]);
        agent.handle_beacon(&peer, &with_addr, true, 5);
        assert!(matches!(
            agent.poll_action(),
            Some(DiscoveryAction::Dial { peer: got, addrs })
                if got == peer && addrs.len() == 1
        ));
    }

    #[test]
    fn announces_only_supported_addresses_with_publisher_suffix() {
        let config = DiscoveryConfig {
            auto_dial: false,
            ..DiscoveryConfig::default()
        };
        let mut agent = agent_with(config, 1);
        let relay = PeerId::from_public_key(&key(3));
        agent.set_local_addrs(
            &[
                Multiaddr::from_protocols(vec![]),
                Multiaddr::from_str("/ip4/127.0.0.1/udp/1").unwrap(),
                Multiaddr::from_str("/ip4/0.0.0.0/udp/1/quic-v1").unwrap(),
                Multiaddr::from_str("/ip4/127.0.0.1/udp/2/quic-v1").unwrap(),
                Multiaddr::from_protocols(vec![
                    Protocol::Ip4([127, 0, 0, 1]),
                    Protocol::Udp(3),
                    Protocol::QuicV1,
                    Protocol::P2p(relay),
                    Protocol::P2pCircuit,
                ]),
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
        assert_eq!(beacon.addrs.len(), 2);
        for advertised in beacon
            .addrs
            .iter()
            .map(|bytes| Multiaddr::from_bytes(bytes).unwrap())
        {
            assert_eq!(
                advertised.protocols().last(),
                Some(&Protocol::P2p(agent.local_peer_id().clone()))
            );
            let without_publisher = Multiaddr::from_protocols(
                advertised.protocols()[..advertised.protocols().len() - 1].to_vec(),
            );
            assert!(is_supported_addr(&without_publisher));
        }

        let (peer, payload) = payload(2, &["/ip4/127.0.0.1/udp/2/quic-v1"]);
        agent.handle_beacon(&peer, &payload, true, 6);
        assert_eq!(
            agent.known_peers()[0].addrs[0].to_string(),
            "/ip4/127.0.0.1/udp/2/quic-v1"
        );
    }

    #[test]
    fn published_beacon_never_exceeds_decoder_limit() {
        let mut agent = agent_with(DiscoveryConfig::default(), 1);
        let addrs = (0..16)
            .map(|index| {
                Multiaddr::from_protocols(vec![
                    Protocol::Dns(format!("{index}{}", "a".repeat(850))),
                    Protocol::Udp(1),
                    Protocol::QuicV1,
                ])
            })
            .collect::<Vec<_>>();
        agent.set_local_addrs(&addrs, 0);
        agent.handle_tick(0);
        let Some(DiscoveryAction::PublishBeacon { payload, .. }) = agent.poll_action() else {
            panic!("expected discovery beacon");
        };

        assert!(payload.len() <= crate::MAX_BEACON_SIZE);
        let beacon = Beacon::decode(&payload).expect("agent must publish a decodable beacon");
        assert!(beacon.addrs.len() < addrs.len());
    }

    #[test]
    fn expiry_scrubs_queued_dial_and_emits_cancel() {
        let config = DiscoveryConfig {
            peer_ttl_ms: 5,
            ..DiscoveryConfig::default()
        };
        let mut agent = agent_with(config, 1);
        let (peer, payload) = payload(2, &["/ip4/127.0.0.1/udp/9/quic-v1"]);
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
    fn empty_non_quic_and_wildcard_addresses_behave_as_presence() {
        let mut agent = agent_with(DiscoveryConfig::default(), 1);
        let remote_key = key(2);
        let remote = PeerId::from_public_key(&remote_key);
        let mut non_quic = Multiaddr::from_str("/ip4/127.0.0.1/udp/9").unwrap();
        non_quic.push(Protocol::P2p(remote.clone()));
        let mut wildcard = Multiaddr::from_str("/ip4/0.0.0.0/udp/9/quic-v1").unwrap();
        wildcard.push(Protocol::P2p(remote.clone()));
        let beacon = Beacon {
            public_key: remote_key.encode_protobuf(),
            addrs: vec![vec![], non_quic.to_bytes(), wildcard.to_bytes()],
        }
        .encode();

        agent.handle_beacon(&remote, &beacon, true, 1);

        assert!(agent.poll_action().is_none());
        assert!(matches!(
            agent.poll_event(),
            Some(DiscoveryEvent::PeerDiscovered { peer, addrs })
                if peer == remote && addrs.is_empty()
        ));
        assert!(agent.known_peers()[0].addrs.is_empty());
    }

    #[test]
    fn canonical_circuit_address_still_triggers_the_relay_leg() {
        let mut agent = agent_with(DiscoveryConfig::default(), 1);
        let remote_key = key(2);
        let remote = PeerId::from_public_key(&remote_key);
        let relay = PeerId::from_public_key(&key(3));
        let circuit = Multiaddr::from_protocols(vec![
            Protocol::Ip4([127, 0, 0, 1]),
            Protocol::Udp(9),
            Protocol::QuicV1,
            Protocol::P2p(relay),
            Protocol::P2pCircuit,
            Protocol::P2p(remote.clone()),
        ]);
        let beacon = Beacon {
            public_key: remote_key.encode_protobuf(),
            addrs: vec![circuit.to_bytes()],
        }
        .encode();

        agent.handle_beacon(&remote, &beacon, true, 1);

        assert!(matches!(
            agent.poll_action(),
            Some(DiscoveryAction::Dial { peer, addrs })
                if peer == remote
                    && addrs.len() == 1
                    && matches!(addrs[0].protocols().last(), Some(Protocol::P2pCircuit))
        ));
    }

    #[test]
    fn capacity_evicts_oldest_non_connected_and_cancels_its_dial() {
        let config = DiscoveryConfig {
            max_known_peers: 1,
            ..DiscoveryConfig::default()
        };
        let mut agent = agent_with(config, 1);
        let (first, first_payload) = payload(2, &["/ip4/127.0.0.1/udp/9/quic-v1"]);
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
