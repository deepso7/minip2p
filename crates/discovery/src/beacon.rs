//! Deterministic signed-beacon scheduling and validation.

use alloc::{collections::VecDeque, format, string::ToString, vec::Vec};

use minip2p_core::{Multiaddr, PeerId, Protocol};
use minip2p_identity::PublicKey;

use crate::{
    Beacon, BeaconAction, BeaconConfig, BeaconEvent, DiscoveryConfigError, MAX_PUBLIC_KEY_LEN,
    Observation,
};

/// Sans-I/O signed pubsub presence-beacon agent.
pub struct BeaconAgent {
    config: BeaconConfig,
    local_peer_id: PeerId,
    public_key: Vec<u8>,
    local_addrs: Vec<Multiaddr>,
    next_beacon_at_ms: u64,
    actions: VecDeque<BeaconAction>,
    events: VecDeque<BeaconEvent>,
}

impl BeaconAgent {
    /// Constructs an agent after validating its configuration and identity size.
    pub fn new(public_key: PublicKey, config: BeaconConfig) -> Result<Self, DiscoveryConfigError> {
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
    ///
    /// Unsupported, empty, and wildcard addresses are omitted when publishing.
    pub fn set_local_addrs(&mut self, addrs: &[Multiaddr], now_ms: u64) {
        if self.local_addrs != addrs {
            self.local_addrs = addrs.to_vec();
            self.next_beacon_at_ms = now_ms;
        }
    }

    /// Validates a received signed pubsub beacon.
    ///
    /// Valid address-less beacons still emit an [`Observation`], allowing the
    /// shared book to refresh authenticated presence independently of addresses.
    pub fn handle_beacon(&mut self, from: &PeerId, payload: &[u8], signed: bool) {
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

        self.events.push_back(BeaconEvent::Observation(Observation {
            peer: from.clone(),
            addrs: normalize_addrs(from, beacon.addrs, self.config.max_announced_addrs),
        }));
    }

    /// Emits a due local beacon.
    pub fn handle_tick(&mut self, now_ms: u64) {
        if now_ms < self.next_beacon_at_ms {
            return;
        }
        self.actions.push_back(BeaconAction::PublishBeacon {
            topic: self.config.topic.clone(),
            payload: self.build_beacon().encode(),
        });
        self.next_beacon_at_ms = now_ms.saturating_add(self.config.beacon_interval_ms);
    }

    /// Pops the next requested side effect.
    pub fn poll_action(&mut self) -> Option<BeaconAction> {
        self.actions.pop_front()
    }

    /// Pops the next validated observation or protocol violation.
    pub fn poll_event(&mut self) -> Option<BeaconEvent> {
        self.events.pop_front()
    }

    /// Returns milliseconds until the next local beacon.
    pub fn next_timeout(&self, now_ms: u64) -> Option<u64> {
        Some(self.next_beacon_at_ms.saturating_sub(now_ms))
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
                if beacon.addrs.len() == self.config.max_announced_addrs {
                    break;
                }
            }
        }
        beacon
    }

    fn violation(&mut self, peer: &PeerId, reason: &str) {
        self.events.push_back(BeaconEvent::ProtocolViolation {
            peer: peer.clone(),
            reason: reason.to_string(),
        });
    }
}

pub(crate) fn normalize_addr(peer: &PeerId, addr: Multiaddr) -> Option<Multiaddr> {
    let protocols = addr.protocols();
    let addr = match protocols.last() {
        Some(Protocol::P2p(suffix)) if suffix == peer => {
            Multiaddr::from_protocols(protocols[..protocols.len() - 1].to_vec())
        }
        Some(Protocol::P2p(_)) => return None,
        _ => addr,
    };
    is_supported_addr(&addr).then_some(addr)
}

fn normalize_addrs(from: &PeerId, raw: Vec<Vec<u8>>, cap: usize) -> Vec<Multiaddr> {
    let mut normalized = Vec::new();
    for bytes in raw {
        let Ok(addr) = Multiaddr::from_bytes(&bytes) else {
            continue;
        };
        let Some(addr) = normalize_addr(from, addr) else {
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

pub(crate) fn is_supported_addr(addr: &Multiaddr) -> bool {
    if is_wildcard_addr(addr) || addr.is_empty() {
        return false;
    }
    if addr.is_quic_transport() {
        return true;
    }

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
        PublicKey::new(KeyType::Ed25519, alloc::vec![byte; 32])
    }

    fn payload(remote: u8, addrs: &[&str]) -> (PeerId, Vec<u8>) {
        let key = key(remote);
        let peer = PeerId::from_public_key(&key);
        let addrs = addrs
            .iter()
            .map(|addr| {
                let mut addr = Multiaddr::from_str(addr).expect("valid test multiaddr");
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
    fn validates_signed_beacons_and_preserves_addressless_presence() {
        let mut agent = BeaconAgent::new(key(1), BeaconConfig::default()).unwrap();
        let (peer, payload) = payload(2, &[]);

        agent.handle_beacon(&peer, &payload, false);
        assert!(matches!(
            agent.poll_event(),
            Some(BeaconEvent::ProtocolViolation { .. })
        ));
        agent.handle_beacon(&peer, &payload, true);
        assert!(matches!(
            agent.poll_event(),
            Some(BeaconEvent::Observation(Observation { peer: got, addrs }))
                if got == peer && addrs.is_empty()
        ));
    }

    #[test]
    fn announces_only_supported_addresses_with_peer_suffix() {
        let mut agent = BeaconAgent::new(key(1), BeaconConfig::default()).unwrap();
        agent.set_local_addrs(
            &[
                Multiaddr::from_str("/ip4/0.0.0.0/udp/1/quic-v1").unwrap(),
                Multiaddr::from_str("/ip4/127.0.0.1/udp/2/quic-v1").unwrap(),
            ],
            5,
        );
        agent.handle_tick(5);
        let Some(BeaconAction::PublishBeacon { payload, .. }) = agent.poll_action() else {
            panic!("beacon not published");
        };
        let beacon = Beacon::decode(&payload).unwrap();
        assert_eq!(beacon.addrs.len(), 1);
        let advertised = Multiaddr::from_bytes(&beacon.addrs[0]).unwrap();
        assert_eq!(
            advertised.protocols().last(),
            Some(&Protocol::P2p(agent.local_peer_id().clone()))
        );
    }

    #[test]
    fn local_address_change_rearms_beacon_without_empty_churn() {
        let mut agent = BeaconAgent::new(key(1), BeaconConfig::default()).unwrap();
        agent.handle_tick(0);
        let _ = agent.poll_action();
        assert_eq!(agent.next_timeout(1), Some(9_999));
        agent.set_local_addrs(&[], 5);
        assert_eq!(agent.next_timeout(5), Some(9_995));
        agent.set_local_addrs(
            &[Multiaddr::from_str("/ip4/127.0.0.1/udp/1/quic-v1").unwrap()],
            6,
        );
        assert_eq!(agent.next_timeout(6), Some(0));
    }
}
