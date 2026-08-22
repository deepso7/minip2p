//! Deterministic libp2p mDNS scheduling and packet handling.

use alloc::{
    collections::VecDeque,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use minip2p_core::{Multiaddr, PeerId, Protocol};

use crate::dns::{
    CLASS_IN, DnsMessage, DnsQuestion, DnsRecordData, META_QUERY_NAME, ResponseSpec, SERVICE_NAME,
    TYPE_PTR, encode_query, encode_response_segments, names_equal,
};
use crate::{
    InterfaceId, InterfaceSnapshot, IpFamily, MdnsAction, MdnsConfig, MdnsConfigError, MdnsEvent,
    MdnsTarget,
};

const MDNS_PORT: u16 = 5353;
const MIN_RESPONSE_JITTER_MS: u64 = 20;
const RESPONSE_JITTER_SPAN_MS: u64 = 101;
const TXT_PREFIX: &[u8] = b"dnsaddr=";
const MAX_SCHEDULED_RESPONSES: usize = 128;
const MAX_PENDING_ACTIONS: usize = 256;
const MAX_RESPONSE_ACTIONS_PER_TICK: usize = 128;

#[derive(Clone, Debug)]
struct ScheduledResponse {
    due_at_ms: u64,
    interface: InterfaceId,
    target: MdnsTarget,
    payloads: VecDeque<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct DeterministicRng {
    state: [u64; 4],
}

impl DeterministicRng {
    fn new(seed: [u8; 32]) -> Self {
        let mut state = [0; 4];
        for (index, chunk) in seed.as_chunks::<8>().0.iter().enumerate() {
            state[index] = u64::from_le_bytes(*chunk);
        }
        if state == [0; 4] {
            state = [
                0x9e37_79b9_7f4a_7c15,
                0x6a09_e667_f3bc_c909,
                0xbb67_ae85_84ca_a73b,
                0x3c6e_f372_fe94_f82b,
            ];
        }
        Self { state }
    }

    fn next_u64(&mut self) -> u64 {
        let result = self.state[0]
            .wrapping_add(self.state[3])
            .rotate_left(23)
            .wrapping_add(self.state[0]);
        let t = self.state[1] << 17;
        self.state[2] ^= self.state[0];
        self.state[3] ^= self.state[1];
        self.state[1] ^= self.state[2];
        self.state[0] ^= self.state[3];
        self.state[2] ^= t;
        self.state[3] = self.state[3].rotate_left(45);
        result
    }
}

/// Sans-I/O libp2p mDNS agent.
pub struct MdnsAgent {
    peer_id: PeerId,
    config: MdnsConfig,
    peer_name: String,
    rng: DeterministicRng,
    interfaces: Vec<InterfaceSnapshot>,
    local_addrs: Vec<Multiaddr>,
    next_query_at_ms: u64,
    next_fast_delay_ms: u64,
    fast_phase: bool,
    scheduled: Vec<ScheduledResponse>,
    actions: VecDeque<MdnsAction>,
    events: VecDeque<MdnsEvent>,
    closed: bool,
}

impl MdnsAgent {
    /// Constructs an agent from a local identity, validated config, and deterministic seed.
    ///
    /// The seed controls only the random peer-name and response jitter.
    pub fn new(
        peer_id: PeerId,
        config: MdnsConfig,
        seed: [u8; 32],
    ) -> Result<Self, MdnsConfigError> {
        config.validate()?;
        let mut rng = DeterministicRng::new(seed);
        let peer_name = random_peer_name(&mut rng);
        Ok(Self {
            peer_id,
            config,
            peer_name,
            rng,
            interfaces: Vec::new(),
            local_addrs: Vec::new(),
            next_query_at_ms: 0,
            next_fast_delay_ms: 1_000,
            fast_phase: true,
            scheduled: Vec::new(),
            actions: VecDeque::new(),
            events: VecDeque::new(),
            closed: false,
        })
    }

    /// Replaces interface snapshots and restarts startup probing on a real change.
    pub fn set_interfaces(&mut self, ifaces: &[InterfaceSnapshot], now_ms: u64) {
        if self.closed {
            return;
        }
        let filtered: Vec<InterfaceSnapshot> = ifaces
            .iter()
            .filter(|iface| self.config.enable_ipv6 || iface.family == IpFamily::V4)
            .cloned()
            .collect();
        if self.interfaces != filtered {
            // Even a stable id can have a changed address set. Encoded
            // responses capture the old expansion, so all prior interface
            // work becomes stale on any snapshot change.
            self.scheduled.clear();
            self.actions.clear();
            self.interfaces = filtered;
            self.restart_fast_phase(now_ms);
        }
    }

    /// Replaces local QUIC listen addresses and restarts startup probing on a change.
    ///
    /// Returns whether the address snapshot changed. Any encoded work based
    /// on the previous snapshot is discarded.
    pub fn set_local_addrs(&mut self, addrs: &[Multiaddr], now_ms: u64) -> bool {
        if self.closed || self.local_addrs == addrs {
            return false;
        }
        self.scheduled.clear();
        self.actions.clear();
        self.local_addrs = addrs.to_vec();
        self.restart_fast_phase(now_ms);
        true
    }

    /// Handles one datagram received on a known interface/family socket.
    pub fn handle_packet(
        &mut self,
        iface: InterfaceId,
        from: SocketAddr,
        payload: &[u8],
        now_ms: u64,
    ) {
        if self.closed || !self.interfaces.iter().any(|known| known.id == iface) {
            return;
        }
        let message = match DnsMessage::decode(payload) {
            Ok(message) => message,
            Err(error) => {
                if recognizable_claim(payload) {
                    self.violation(None, &error.to_string());
                }
                return;
            }
        };
        if message.opcode() != 0 || message.rcode() != 0 {
            if message_claims_libp2p(&message) {
                self.violation(
                    None,
                    "libp2p mDNS message uses an unsupported opcode or rcode",
                );
            }
            return;
        }
        if message.is_response() {
            self.handle_response(message, now_ms);
        } else {
            self.handle_query(iface, from, message, now_ms);
        }
    }

    /// Emits due queries and delayed responses.
    pub fn handle_tick(&mut self, now_ms: u64) {
        if self.closed {
            return;
        }

        let mut emitted = 0usize;
        for response in &mut self.scheduled {
            if response.due_at_ms > now_ms {
                continue;
            }
            while emitted < MAX_RESPONSE_ACTIONS_PER_TICK
                && self.actions.len() < MAX_PENDING_ACTIONS
            {
                let Some(payload) = response.payloads.pop_front() else {
                    break;
                };
                self.actions.push_back(MdnsAction::Send {
                    interface: response.interface,
                    target: response.target,
                    payload,
                });
                emitted += 1;
            }
        }
        self.scheduled
            .retain(|response| !response.payloads.is_empty());

        if now_ms >= self.next_query_at_ms {
            let payload = encode_query();
            for iface in &self.interfaces {
                if self.actions.len() >= MAX_PENDING_ACTIONS {
                    break;
                }
                self.actions.push_back(MdnsAction::Send {
                    interface: iface.id,
                    target: MdnsTarget::Multicast,
                    payload: payload.clone(),
                });
            }
            let delay = self.next_fast_delay_ms.min(self.config.query_interval_ms);
            self.next_query_at_ms = now_ms.saturating_add(if self.fast_phase {
                delay
            } else {
                self.config.query_interval_ms
            });
            if self.fast_phase {
                self.next_fast_delay_ms =
                    delay.saturating_mul(2).min(self.config.query_interval_ms);
            }
        }
    }

    /// Permanently closes the agent and queues TTL-zero goodbyes once.
    pub fn shutdown(&mut self, _now_ms: u64) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.scheduled.clear();
        self.actions.clear();
        for iface in &self.interfaces {
            for payload in self.response_packets(iface.id, 0, 0, None, false) {
                self.actions.push_back(MdnsAction::Send {
                    interface: iface.id,
                    target: MdnsTarget::Multicast,
                    payload,
                });
            }
        }
    }

    /// Pops the next encoded send action.
    pub fn poll_action(&mut self) -> Option<MdnsAction> {
        self.actions.pop_front()
    }

    /// Pops the next peer observation or recognizable protocol violation.
    pub fn poll_event(&mut self) -> Option<MdnsEvent> {
        self.events.pop_front()
    }

    /// Returns milliseconds until the next query or delayed response.
    pub fn next_timeout(&self, now_ms: u64) -> Option<u64> {
        if self.closed {
            return None;
        }
        let response = self
            .scheduled
            .iter()
            .map(|scheduled| scheduled.due_at_ms)
            .min();
        let deadline = response
            .map(|due| due.min(self.next_query_at_ms))
            .unwrap_or(self.next_query_at_ms);
        Some(deadline.saturating_sub(now_ms))
    }

    fn restart_fast_phase(&mut self, now_ms: u64) {
        self.fast_phase = true;
        self.next_fast_delay_ms = 1_000;
        self.next_query_at_ms = now_ms;
    }

    fn handle_query(
        &mut self,
        iface: InterfaceId,
        from: SocketAddr,
        message: DnsMessage,
        now_ms: u64,
    ) {
        let Some(question) = message.questions.iter().find(|question| {
            question.qtype == TYPE_PTR
                && question.base_class() == CLASS_IN
                && (names_equal(&question.name, SERVICE_NAME)
                    || names_equal(&question.name, META_QUERY_NAME))
        }) else {
            return;
        };
        let legacy = from.port() != MDNS_PORT;
        let unicast = legacy || question.requests_unicast();
        let target = if unicast {
            MdnsTarget::Unicast { to: from }
        } else {
            MdnsTarget::Multicast
        };
        let ttl_seconds = wire_ttl_seconds(self.config.ttl_ms, legacy);
        let question_copy = legacy.then(|| question.clone());
        let meta = names_equal(&question.name, META_QUERY_NAME);
        if self.scheduled.len() == MAX_SCHEDULED_RESPONSES {
            return;
        }
        let payloads = if meta {
            encode_response_segments(ResponseSpec {
                id: if legacy { message.id } else { 0 },
                question: question_copy,
                ptr_owner: META_QUERY_NAME.to_string(),
                ptr_target: SERVICE_NAME.to_string(),
                txt_values: Vec::new(),
                ttl_seconds,
                txt_cache_flush: false,
                max_packet_bytes: self.config.max_packet_bytes,
            })
        } else {
            self.response_packets(
                iface,
                if legacy { message.id } else { 0 },
                ttl_seconds,
                question_copy,
                !legacy,
            )
        };
        if payloads.is_empty() {
            return;
        }
        let jitter = MIN_RESPONSE_JITTER_MS + self.rng.next_u64() % RESPONSE_JITTER_SPAN_MS;
        self.scheduled.push(ScheduledResponse {
            due_at_ms: now_ms.saturating_add(jitter),
            interface: iface,
            target,
            payloads: payloads.into(),
        });
    }

    fn handle_response(&mut self, message: DnsMessage, now_ms: u64) {
        let records = message.answers.iter().chain(&message.additionals);
        let ptrs: Vec<(&str, u32)> = records
            .clone()
            .filter_map(|record| match &record.data {
                DnsRecordData::Ptr(target)
                    if record.rr_type == TYPE_PTR
                        && record.base_class() == CLASS_IN
                        && names_equal(&record.name, SERVICE_NAME) =>
                {
                    Some((target.as_str(), record.ttl))
                }
                _ => None,
            })
            .collect();
        if ptrs.is_empty() {
            return;
        }

        let mut observed = Vec::new();
        let mut claimed_peer: Option<PeerId> = None;
        let mut invalid_claim = false;
        for (target, ptr_ttl) in ptrs {
            for record in message.answers.iter().chain(&message.additionals) {
                let DnsRecordData::Txt(strings) = &record.data else {
                    continue;
                };
                if record.base_class() != CLASS_IN || !names_equal(&record.name, target) {
                    continue;
                }
                for value in strings {
                    if !value.starts_with(TXT_PREFIX) {
                        continue;
                    }
                    let Ok(text) = core::str::from_utf8(&value[TXT_PREFIX.len()..]) else {
                        invalid_claim = true;
                        continue;
                    };
                    let Ok(addr) = Multiaddr::from_str(text) else {
                        invalid_claim = true;
                        continue;
                    };
                    let protocols = addr.protocols();
                    let Some(Protocol::P2p(peer)) = protocols.last() else {
                        invalid_claim = true;
                        continue;
                    };
                    if claimed_peer.as_ref().is_some_and(|known| known != peer) {
                        self.violation(
                            claimed_peer,
                            "one mDNS response claims more than one peer id",
                        );
                        return;
                    }
                    claimed_peer.get_or_insert_with(|| peer.clone());
                    let transport =
                        Multiaddr::from_protocols(protocols[..protocols.len() - 1].to_vec());
                    if !is_supported_transport(&transport) {
                        invalid_claim = true;
                        continue;
                    }
                    let ttl_ms = u64::from(ptr_ttl.min(record.ttl)).saturating_mul(1_000);
                    if !observed
                        .iter()
                        .any(|(known, _): &(Multiaddr, u64)| known == &transport)
                    {
                        observed.push((transport, ttl_ms));
                    }
                }
            }
        }

        if observed.is_empty() {
            if invalid_claim {
                self.violation(claimed_peer, "libp2p mDNS addresses failed normalization");
            }
            return;
        }
        let Some(peer) = claimed_peer else {
            return;
        };
        if peer == self.peer_id {
            return;
        }
        if observed.iter().any(|(_, ttl_ms)| *ttl_ms > 0) {
            self.fast_phase = false;
            self.next_query_at_ms = now_ms.saturating_add(self.config.query_interval_ms);
            self.next_fast_delay_ms = self.config.query_interval_ms;
        }
        self.events.push_back(MdnsEvent::PeerObserved {
            peer,
            addrs: observed,
        });
    }

    fn response_packets(
        &self,
        iface: InterfaceId,
        id: u16,
        ttl_seconds: u32,
        question: Option<DnsQuestion>,
        txt_cache_flush: bool,
    ) -> Vec<Vec<u8>> {
        let target = format!("{}.{}", self.peer_name, SERVICE_NAME);
        encode_response_segments(ResponseSpec {
            id,
            question,
            ptr_owner: SERVICE_NAME.to_string(),
            ptr_target: target,
            txt_values: self.advertised_txt_values(iface),
            ttl_seconds,
            txt_cache_flush,
            max_packet_bytes: self.config.max_packet_bytes,
        })
    }

    fn advertised_txt_values(&self, iface: InterfaceId) -> Vec<Vec<u8>> {
        let Some(snapshot) = self.interfaces.iter().find(|known| known.id == iface) else {
            return Vec::new();
        };
        let expanded = expand_addresses(&self.local_addrs, snapshot, self.config.enable_ipv6);
        let mut values = Vec::new();
        for mut addr in expanded {
            if values.len() == self.config.max_announced_addrs {
                break;
            }
            addr.push(Protocol::P2p(self.peer_id.clone()));
            let text = addr.to_string();
            if text.len() > 247 {
                continue;
            }
            let mut value = TXT_PREFIX.to_vec();
            value.extend_from_slice(text.as_bytes());
            if !values.contains(&value) {
                values.push(value);
            }
        }
        values
    }

    fn violation(&mut self, peer: Option<PeerId>, reason: &str) {
        self.events.push_back(MdnsEvent::ProtocolViolation {
            peer,
            reason: reason.to_string(),
        });
    }
}

fn random_peer_name(rng: &mut DeterministicRng) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let len = 32 + (rng.next_u64() % 32) as usize;
    let mut name = String::with_capacity(len);
    for _ in 0..len {
        let index = (rng.next_u64() % ALPHABET.len() as u64) as usize;
        name.push(ALPHABET[index] as char);
    }
    name
}

fn wire_ttl_seconds(ttl_ms: u64, legacy: bool) -> u32 {
    let seconds = (ttl_ms / 1_000).max(1).min(u64::from(u32::MAX)) as u32;
    if legacy { seconds.min(10) } else { seconds }
}

/// Whether an address is worth announcing to the link.
///
/// Anything a transport can dial, plus a circuit through a relay. A device
/// with no operating system has no QUIC, so a TCP listener is the only thing
/// it has to say -- and mDNS that could not say it would find peers on the
/// link and tell them nothing about how to reach it.
fn is_supported_transport(addr: &Multiaddr) -> bool {
    if addr.transport_kind().is_some() {
        return !addr.is_wildcard_host();
    }
    addr.is_relay_circuit_transport()
}

fn expand_addresses(
    local_addrs: &[Multiaddr],
    iface: &InterfaceSnapshot,
    enable_ipv6: bool,
) -> Vec<Multiaddr> {
    let mut result = Vec::new();
    let mut interface_ips: Vec<IpAddr> = iface
        .addrs
        .iter()
        .map(|net| net.ip())
        .filter(|ip| match ip {
            IpAddr::V4(_) => iface.family == IpFamily::V4,
            IpAddr::V6(ip) => {
                enable_ipv6 && iface.family == IpFamily::V6 && !is_ipv6_link_local(*ip)
            }
        })
        .collect();
    if interface_ips.iter().any(|ip| !ip.is_loopback()) {
        interface_ips.retain(|ip| !ip.is_loopback());
    }

    for addr in local_addrs {
        let protocols = addr.protocols();
        match protocols.first() {
            Some(Protocol::Ip4(ip)) if *ip == [0; 4] && iface.family == IpFamily::V4 => {
                for ip in &interface_ips {
                    let IpAddr::V4(ip) = ip else {
                        continue;
                    };
                    let mut expanded = protocols.to_vec();
                    expanded[0] = Protocol::Ip4(ip.octets());
                    push_unique_supported(&mut result, Multiaddr::from_protocols(expanded));
                }
            }
            Some(Protocol::Ip6(ip))
                if *ip == [0; 16] && iface.family == IpFamily::V6 && enable_ipv6 =>
            {
                for ip in &interface_ips {
                    let IpAddr::V6(ip) = ip else {
                        continue;
                    };
                    let mut expanded = protocols.to_vec();
                    expanded[0] = Protocol::Ip6(ip.octets());
                    push_unique_supported(&mut result, Multiaddr::from_protocols(expanded));
                }
            }
            Some(Protocol::Ip6(ip)) if !enable_ipv6 || is_ipv6_link_local((*ip).into()) => {}
            _ => push_unique_supported(&mut result, addr.clone()),
        }
    }
    result
}

fn push_unique_supported(result: &mut Vec<Multiaddr>, addr: Multiaddr) {
    if is_supported_transport(&addr) && !result.contains(&addr) {
        result.push(addr);
    }
}

fn is_ipv6_link_local(ip: core::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

fn recognizable_claim(payload: &[u8]) -> bool {
    contains_ascii_case_insensitive(payload, TXT_PREFIX)
        || contains_ascii_case_insensitive(payload, b"\x04_p2p\x04_udp\x05local\x00")
}

fn message_claims_libp2p(message: &DnsMessage) -> bool {
    message
        .questions
        .iter()
        .any(|question| names_equal(&question.name, SERVICE_NAME))
        || message
            .answers
            .iter()
            .chain(&message.additionals)
            .any(|record| {
                names_equal(&record.name, SERVICE_NAME)
                    || matches!(&record.data, DnsRecordData::Txt(strings)
                        if strings.iter().any(|value| value.starts_with(TXT_PREFIX)))
            })
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IpNet, dns::DnsMessage};
    use alloc::vec;
    use core::net::{IpAddr, Ipv4Addr, SocketAddrV4};
    use minip2p_identity::{KeyType, PublicKey};

    fn peer(byte: u8) -> PeerId {
        PeerId::from_public_key(&PublicKey::new(KeyType::Ed25519, vec![byte; 32]))
    }

    fn iface(id: u32) -> InterfaceSnapshot {
        InterfaceSnapshot {
            id: InterfaceId::new(id),
            index: id,
            family: IpFamily::V4,
            addrs: vec![IpNet::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, id as u8)), 24).unwrap()],
        }
    }

    fn local_addr() -> Multiaddr {
        "/ip4/0.0.0.0/udp/4001/quic-v1".parse().unwrap()
    }

    fn response_from(remote: &PeerId, ttl: u32) -> Vec<u8> {
        let mut addr: Multiaddr = "/ip4/192.168.1.2/udp/4001/quic-v1".parse().unwrap();
        addr.push(Protocol::P2p(remote.clone()));
        encode_response_segments(ResponseSpec {
            id: 0,
            question: None,
            ptr_owner: SERVICE_NAME.to_string(),
            ptr_target: "remote._p2p._udp.local".to_string(),
            txt_values: vec![format!("dnsaddr={addr}").into_bytes()],
            ttl_seconds: ttl,
            txt_cache_flush: true,
            max_packet_bytes: 1_400,
        })
        .remove(0)
    }

    #[test]
    fn emits_one_query_per_interface_and_restarts_on_change() {
        let mut agent = MdnsAgent::new(peer(1), MdnsConfig::default(), [7; 32]).unwrap();
        agent.set_interfaces(&[iface(1), iface(2)], 5);
        agent.handle_tick(5);
        let actions = core::iter::from_fn(|| agent.poll_action()).collect::<Vec<_>>();
        assert_eq!(actions.len(), 2);
        assert!(actions.iter().all(|action| matches!(
            action,
            MdnsAction::Send {
                target: MdnsTarget::Multicast,
                ..
            }
        )));
        assert_eq!(agent.next_timeout(5), Some(1_000));
        agent.set_interfaces(&[iface(1), iface(2)], 6);
        assert_eq!(agent.next_timeout(6), Some(999));
    }

    #[test]
    fn accepted_non_self_response_ends_fast_phase() {
        let remote = peer(2);
        let mut agent = MdnsAgent::new(peer(1), MdnsConfig::default(), [7; 32]).unwrap();
        agent.set_interfaces(&[iface(1)], 0);
        agent.handle_packet(
            InterfaceId::new(1),
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 2), MDNS_PORT).into(),
            &response_from(&remote, 120),
            10,
        );
        assert!(matches!(
            agent.poll_event(),
            Some(MdnsEvent::PeerObserved { peer, addrs })
                if peer == remote && addrs[0].1 == 120_000
        ));
        assert!(!agent.fast_phase);
    }

    #[test]
    fn own_response_and_ttl_zero_do_not_end_fast_phase() {
        let local = peer(1);
        let mut agent = MdnsAgent::new(local.clone(), MdnsConfig::default(), [7; 32]).unwrap();
        agent.set_interfaces(&[iface(1)], 0);
        let from = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 2), MDNS_PORT).into();
        agent.handle_packet(InterfaceId::new(1), from, &response_from(&local, 120), 1);
        assert!(agent.poll_event().is_none());
        assert!(agent.fast_phase);
        agent.handle_packet(InterfaceId::new(1), from, &response_from(&peer(2), 0), 2);
        assert!(matches!(
            agent.poll_event(),
            Some(MdnsEvent::PeerObserved { .. })
        ));
        assert!(agent.fast_phase);
    }

    #[test]
    fn service_query_schedules_jittered_interface_aware_response() {
        let mut agent = MdnsAgent::new(peer(1), MdnsConfig::default(), [7; 32]).unwrap();
        agent.set_interfaces(&[iface(1)], 0);
        agent.set_local_addrs(&[local_addr()], 0);
        agent.handle_tick(0);
        while agent.poll_action().is_some() {}
        let query = encode_query();
        let from = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 2), MDNS_PORT).into();
        agent.handle_packet(InterfaceId::new(1), from, &query, 1);
        let wait = agent.next_timeout(1).unwrap();
        assert!((20..=120).contains(&wait));
        agent.handle_tick(1 + wait);
        let Some(MdnsAction::Send {
            payload, target, ..
        }) = agent.poll_action()
        else {
            panic!("response not emitted");
        };
        assert_eq!(target, MdnsTarget::Multicast);
        let decoded = DnsMessage::decode(&payload).unwrap();
        assert_eq!(decoded.answers[0].class, 0x0001);
        assert_eq!(decoded.additionals[0].class, 0x8001);
        let DnsRecordData::Txt(strings) = &decoded.additionals[0].data else {
            panic!("expected TXT");
        };
        assert!(
            core::str::from_utf8(&strings[0])
                .unwrap()
                .contains("/ip4/192.168.1.1/")
        );
    }

    #[test]
    fn a_tcp_listener_is_announced_and_expanded_like_any_other() {
        let mut agent = MdnsAgent::new(peer(1), MdnsConfig::default(), [7; 32]).unwrap();
        agent.set_interfaces(&[iface(1)], 0);
        // The only thing a device with no operating system has to say. mDNS
        // that could not say it would find peers on the link and leave them
        // with no way to reach it -- which is the whole of what mDNS is for.
        agent.set_local_addrs(&["/ip4/0.0.0.0/tcp/4001".parse().unwrap()], 0);
        agent.handle_tick(0);
        while agent.poll_action().is_some() {}

        let query = encode_query();
        let from = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 2), MDNS_PORT).into();
        agent.handle_packet(InterfaceId::new(1), from, &query, 1);
        let wait = agent.next_timeout(1).unwrap();
        agent.handle_tick(1 + wait);
        let Some(MdnsAction::Send { payload, .. }) = agent.poll_action() else {
            panic!("response not emitted");
        };
        let decoded = DnsMessage::decode(&payload).unwrap();
        let DnsRecordData::Txt(strings) = &decoded.additionals[0].data else {
            panic!("expected TXT");
        };
        let advertised = core::str::from_utf8(&strings[0]).unwrap();
        assert!(
            advertised.contains("/ip4/192.168.1.1/tcp/4001/"),
            // The wildcard is replaced by the interface's own address, the
            // same substitution a QUIC listener gets: everything after the
            // host is carried through untouched.
            "expected the interface address on a /tcp listener, got {advertised}"
        );
    }

    #[test]
    fn qu_and_legacy_unicast_follow_id_question_ttl_and_flush_rules() {
        let mut agent = MdnsAgent::new(peer(1), MdnsConfig::default(), [9; 32]).unwrap();
        agent.set_interfaces(&[iface(1)], 0);
        agent.set_local_addrs(&[local_addr()], 0);
        agent.handle_tick(0);
        while agent.poll_action().is_some() {}

        let mut qu = encode_query();
        qu[0..2].copy_from_slice(&77u16.to_be_bytes());
        qu[31..33].copy_from_slice(&0x8001u16.to_be_bytes());
        let requester = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 2), MDNS_PORT).into();
        agent.handle_packet(InterfaceId::new(1), requester, &qu, 1);
        let due = 1 + agent.next_timeout(1).unwrap();
        agent.handle_tick(due);
        let Some(MdnsAction::Send {
            target, payload, ..
        }) = agent.poll_action()
        else {
            panic!("QU response not emitted");
        };
        assert_eq!(target, MdnsTarget::Unicast { to: requester });
        let decoded = DnsMessage::decode(&payload).unwrap();
        assert_eq!(decoded.id, 0);
        assert!(decoded.questions.is_empty());
        assert!(
            decoded
                .additionals
                .iter()
                .all(|record| record.cache_flush())
        );

        let mut legacy = encode_query();
        legacy[0..2].copy_from_slice(&91u16.to_be_bytes());
        let requester = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 2), 9_999).into();
        agent.handle_packet(InterfaceId::new(1), requester, &legacy, due + 1);
        let due = due + 1 + agent.next_timeout(due + 1).unwrap();
        agent.handle_tick(due);
        let Some(MdnsAction::Send {
            target, payload, ..
        }) = agent.poll_action()
        else {
            panic!("legacy response not emitted");
        };
        assert_eq!(target, MdnsTarget::Unicast { to: requester });
        let decoded = DnsMessage::decode(&payload).unwrap();
        assert_eq!(decoded.id, 91);
        assert_eq!(decoded.questions.len(), 1);
        assert!(
            decoded
                .answers
                .iter()
                .chain(&decoded.additionals)
                .all(|record| record.ttl <= 10 && !record.cache_flush())
        );
    }

    #[test]
    fn malformed_non_libp2p_packet_is_silent_but_claim_is_reported() {
        let mut agent = MdnsAgent::new(peer(1), MdnsConfig::default(), [7; 32]).unwrap();
        agent.set_interfaces(&[iface(1)], 0);
        let from = SocketAddrV4::new(Ipv4Addr::LOCALHOST, MDNS_PORT).into();
        agent.handle_packet(InterfaceId::new(1), from, b"printer", 0);
        assert!(agent.poll_event().is_none());
        agent.handle_packet(
            InterfaceId::new(1),
            from,
            b"\x04_p2p\x04_udp\x05local\x00",
            0,
        );
        assert!(matches!(
            agent.poll_event(),
            Some(MdnsEvent::ProtocolViolation { .. })
        ));
    }

    #[test]
    fn dnsaddr_character_string_limit_includes_the_prefix() {
        let local = peer(1);
        let mut agent = MdnsAgent::new(local.clone(), MdnsConfig::default(), [7; 32]).unwrap();
        agent.set_interfaces(&[iface(1)], 0);

        let address_with_len = |wanted: usize| {
            (1..1_000)
                .find_map(|length| {
                    let addr = Multiaddr::from_protocols(vec![
                        Protocol::Dns("a".repeat(length)),
                        Protocol::Udp(1),
                        Protocol::QuicV1,
                    ]);
                    let mut advertised = addr.clone();
                    advertised.push(Protocol::P2p(local.clone()));
                    (advertised.to_string().len() == wanted).then_some(addr)
                })
                .expect("a DNS multiaddr reaches the requested text length")
        };
        agent.set_local_addrs(&[address_with_len(247)], 0);
        let values = agent.advertised_txt_values(InterfaceId::new(1));
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].len(), 255);

        agent.set_local_addrs(&[address_with_len(248)], 1);
        assert!(agent.advertised_txt_values(InterfaceId::new(1)).is_empty());
    }

    #[test]
    fn shutdown_is_terminal_and_idempotent() {
        let mut agent = MdnsAgent::new(peer(1), MdnsConfig::default(), [7; 32]).unwrap();
        agent.set_interfaces(&[iface(1)], 0);
        agent.set_local_addrs(&[local_addr()], 0);
        agent.shutdown(1);
        let first = core::iter::from_fn(|| agent.poll_action()).collect::<Vec<_>>();
        assert!(!first.is_empty());
        agent.shutdown(2);
        agent.handle_tick(2);
        assert!(agent.poll_action().is_none());
        assert_eq!(agent.next_timeout(2), None);
    }

    #[test]
    fn query_flood_keeps_response_and_action_queues_bounded() {
        let mut agent = MdnsAgent::new(peer(1), MdnsConfig::default(), [7; 32]).unwrap();
        agent.set_interfaces(&[iface(1)], 0);
        agent.set_local_addrs(&[local_addr()], 0);
        agent.handle_tick(0);
        while agent.poll_action().is_some() {}

        let query = encode_query();
        let from = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 2), MDNS_PORT).into();
        for _ in 0..1_000 {
            agent.handle_packet(InterfaceId::new(1), from, &query, 1);
        }
        assert_eq!(agent.scheduled.len(), MAX_SCHEDULED_RESPONSES);

        agent.handle_tick(1_000);
        assert!(agent.actions.len() <= MAX_PENDING_ACTIONS);

        for _ in 0..1_000 {
            agent.handle_packet(InterfaceId::new(1), from, &query, 1_001);
        }
        agent.handle_tick(2_000);
        assert_eq!(agent.actions.len(), MAX_PENDING_ACTIONS);

        for _ in 0..1_000 {
            agent.handle_packet(InterfaceId::new(1), from, &query, 2_001);
        }
        agent.handle_tick(3_000);
        assert_eq!(agent.actions.len(), MAX_PENDING_ACTIONS);
        assert_eq!(agent.scheduled.len(), MAX_SCHEDULED_RESPONSES);
    }

    #[test]
    fn interface_change_discards_work_for_retired_ids() {
        let mut agent = MdnsAgent::new(peer(1), MdnsConfig::default(), [7; 32]).unwrap();
        agent.set_interfaces(&[iface(1)], 0);
        agent.set_local_addrs(&[local_addr()], 0);
        agent.handle_tick(0);

        let query = encode_query();
        let from = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 2), MDNS_PORT).into();
        agent.handle_packet(InterfaceId::new(1), from, &query, 1);
        assert!(!agent.scheduled.is_empty());
        assert!(!agent.actions.is_empty());

        agent.set_interfaces(&[iface(2)], 2);
        assert!(agent.scheduled.is_empty());
        assert!(agent.actions.is_empty());
        agent.handle_tick(2);
        assert!(
            core::iter::from_fn(|| agent.poll_action()).all(|action| matches!(
                action,
                MdnsAction::Send {
                    interface,
                    ..
                } if interface == InterfaceId::new(2)
            ))
        );
    }

    #[test]
    fn local_address_change_discards_stale_encoded_work() {
        let mut agent = MdnsAgent::new(peer(1), MdnsConfig::default(), [7; 32]).unwrap();
        agent.set_interfaces(&[iface(1)], 0);
        agent.set_local_addrs(&[local_addr()], 0);
        agent.handle_tick(0);

        let query = encode_query();
        let from = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 2), MDNS_PORT).into();
        agent.handle_packet(InterfaceId::new(1), from, &query, 1);
        assert!(!agent.scheduled.is_empty());
        assert!(!agent.actions.is_empty());

        let replacement = "/ip4/192.168.1.10/udp/5001/quic-v1".parse().unwrap();
        assert!(agent.set_local_addrs(&[replacement], 2));
        assert!(agent.scheduled.is_empty());
        assert!(agent.actions.is_empty());
    }
}
