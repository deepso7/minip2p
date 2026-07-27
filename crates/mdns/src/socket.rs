//! Synchronous per-interface mDNS socket adapter.

use std::{
    collections::BTreeMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket},
};

use if_addrs::IfAddr;
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};

use crate::{
    InterfaceId, InterfaceSnapshot, IpFamily, IpNet, MdnsAction, MdnsAgent, MdnsConfig, MdnsTarget,
};

const MDNS_PORT: u16 = 5353;
const MDNS_V4_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_V6_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb);
const RECEIVE_BUFFER_BYTES: usize = 9_001;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct InterfaceKey {
    index: u32,
    family: IpFamily,
}

#[derive(Debug, Default)]
struct InterfaceRegistry {
    next_id: u32,
    active: BTreeMap<InterfaceKey, InterfaceId>,
}

impl InterfaceRegistry {
    fn assign(
        &mut self,
        grouped: &BTreeMap<InterfaceKey, Vec<IpNet>>,
    ) -> Result<Vec<InterfaceSnapshot>, MdnsError> {
        self.active.retain(|key, _| grouped.contains_key(key));
        let mut snapshots = Vec::with_capacity(grouped.len());
        for (key, addrs) in grouped {
            let id = if let Some(id) = self.active.get(key) {
                *id
            } else {
                let next = self
                    .next_id
                    .checked_add(1)
                    .ok_or(MdnsError::InterfaceIdsExhausted)?;
                let id = InterfaceId::new(next);
                self.next_id = next;
                self.active.insert(*key, id);
                id
            };
            snapshots.push(InterfaceSnapshot {
                id,
                index: key.index,
                family: key.family,
                addrs: addrs.clone(),
            });
        }
        Ok(snapshots)
    }
}

#[derive(Debug)]
struct SocketPair {
    snapshot: InterfaceSnapshot,
    receive: UdpSocket,
    send: UdpSocket,
}

/// Socket-adapter failures.
#[derive(Debug, thiserror::Error)]
pub enum MdnsError {
    /// The current target cannot provide the required multicast socket options.
    #[error("mDNS sockets are unsupported on this target")]
    Unsupported,
    /// No usable address exists for an enumerated interface/family pair.
    #[error("mDNS interface {interface:?} has no usable address")]
    NoInterfaceAddress {
        /// Interface that could not be bound.
        interface: InterfaceId,
    },
    /// A send action referenced an interface that has disappeared.
    #[error("mDNS interface {interface:?} is no longer active")]
    UnknownInterface {
        /// Missing interface handle.
        interface: InterfaceId,
    },
    /// The stable interface-id counter was exhausted.
    #[error("mDNS interface id space is exhausted")]
    InterfaceIdsExhausted,
    /// An operating-system socket or interface-enumeration operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Per-interface mDNS receive/send socket collection.
#[derive(Debug)]
pub struct MdnsSockets {
    enable_ipv6: bool,
    registry: InterfaceRegistry,
    snapshots: Vec<InterfaceSnapshot>,
    pairs: BTreeMap<InterfaceId, SocketPair>,
    next_receive_offset: usize,
}

impl MdnsSockets {
    /// Enumerates active interfaces and constructs non-blocking socket pairs.
    pub fn new(config: &MdnsConfig) -> Result<Self, MdnsError> {
        #[cfg(not(any(unix, windows)))]
        {
            let _ = config;
            return Err(MdnsError::Unsupported);
        }
        #[cfg(any(unix, windows))]
        {
            let mut sockets = Self {
                enable_ipv6: config.enable_ipv6,
                registry: InterfaceRegistry::default(),
                snapshots: Vec::new(),
                pairs: BTreeMap::new(),
                next_receive_offset: 0,
            };
            sockets.refresh()?;
            Ok(sockets)
        }
    }

    /// Returns the current stable interface/family snapshots.
    pub fn interfaces(&self) -> &[InterfaceSnapshot] {
        &self.snapshots
    }

    /// Re-enumerates interfaces, preserving ids and sockets for unchanged pairs.
    ///
    /// Returns `true` when the snapshot changed.
    pub fn refresh(&mut self) -> Result<bool, MdnsError> {
        let grouped = enumerate_interfaces(self.enable_ipv6)?;
        let snapshots = self.registry.assign(&grouped)?;
        if snapshots == self.snapshots {
            return Ok(false);
        }

        let mut old = core::mem::take(&mut self.pairs);
        let mut pairs = BTreeMap::new();
        for snapshot in &snapshots {
            let pair = match old.remove(&snapshot.id) {
                Some(pair) if pair.snapshot == *snapshot => pair,
                _ => SocketPair::new(snapshot.clone())?,
            };
            pairs.insert(snapshot.id, pair);
        }
        self.snapshots = snapshots;
        self.pairs = pairs;
        self.next_receive_offset = 0;
        Ok(true)
    }

    /// Drains at most `limit` datagrams into the sans-I/O agent.
    ///
    /// Returns `true` when the cap was reached and the caller should re-poll
    /// promptly. Off-link and oversized datagrams count toward the fairness cap.
    pub fn drain_into(
        &mut self,
        agent: &mut MdnsAgent,
        now_ms: u64,
        limit: usize,
    ) -> Result<bool, MdnsError> {
        if limit == 0 || self.pairs.is_empty() {
            return Ok(false);
        }
        let ids: Vec<InterfaceId> = self.pairs.keys().copied().collect();
        let mut processed = 0usize;
        while processed < limit {
            let mut made_progress = false;
            for offset in 0..ids.len() {
                if processed == limit {
                    break;
                }
                let index = (self.next_receive_offset + offset) % ids.len();
                let id = ids[index];
                let pair = self
                    .pairs
                    .get_mut(&id)
                    .expect("ids are collected from the pair map");
                let mut buffer = [0u8; RECEIVE_BUFFER_BYTES];
                match pair.receive.recv_from(&mut buffer) {
                    Ok((len, from)) => {
                        processed += 1;
                        made_progress = true;
                        self.next_receive_offset = (index + 1) % ids.len();
                        if len > 9_000 || !source_is_on_link(&pair.snapshot, from.ip()) {
                            continue;
                        }
                        agent.handle_packet(id, from, &buffer[..len], now_ms);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if !made_progress {
                break;
            }
        }
        Ok(processed == limit)
    }

    /// Sends one agent action through its selected interface socket.
    pub fn send(&self, action: &MdnsAction) -> Result<(), MdnsError> {
        let MdnsAction::Send {
            interface,
            target,
            payload,
        } = action;
        let pair = self
            .pairs
            .get(interface)
            .ok_or(MdnsError::UnknownInterface {
                interface: *interface,
            })?;
        let destination = match target {
            MdnsTarget::Multicast => match pair.snapshot.family {
                IpFamily::V4 => SocketAddr::V4(SocketAddrV4::new(MDNS_V4_GROUP, MDNS_PORT)),
                IpFamily::V6 => SocketAddr::V6(SocketAddrV6::new(
                    MDNS_V6_GROUP,
                    MDNS_PORT,
                    0,
                    pair.snapshot.index,
                )),
            },
            MdnsTarget::Unicast { to } => *to,
        };
        pair.send.send_to(payload, destination)?;
        Ok(())
    }
}

impl SocketPair {
    fn new(snapshot: InterfaceSnapshot) -> Result<Self, MdnsError> {
        let receive = create_receive_socket(&snapshot)?;
        let send = create_send_socket(&snapshot)?;
        Ok(Self {
            snapshot,
            receive,
            send,
        })
    }
}

fn enumerate_interfaces(
    enable_ipv6: bool,
) -> Result<BTreeMap<InterfaceKey, Vec<IpNet>>, MdnsError> {
    let mut grouped: BTreeMap<InterfaceKey, Vec<IpNet>> = BTreeMap::new();
    for iface in if_addrs::get_if_addrs()? {
        let Some(index) = iface.index else {
            continue;
        };
        let (family, net) = match iface.addr {
            IfAddr::V4(addr) => (
                IpFamily::V4,
                IpNet::new(IpAddr::V4(addr.ip), addr.prefixlen),
            ),
            IfAddr::V6(addr) if enable_ipv6 => (
                IpFamily::V6,
                IpNet::new(IpAddr::V6(addr.ip), addr.prefixlen),
            ),
            IfAddr::V6(_) => continue,
        };
        let Some(net) = net else {
            continue;
        };
        let addrs = grouped.entry(InterfaceKey { index, family }).or_default();
        if !addrs.contains(&net) {
            addrs.push(net);
            addrs.sort_unstable();
        }
    }
    grouped.retain(|_, addrs| !addrs.is_empty());
    Ok(grouped)
}

fn create_receive_socket(snapshot: &InterfaceSnapshot) -> Result<UdpSocket, MdnsError> {
    let domain = match snapshot.family {
        IpFamily::V4 => Domain::IPV4,
        IpFamily::V6 => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(SocketProtocol::UDP))?;
    configure_reuse(&socket)?;
    if snapshot.family == IpFamily::V6 {
        socket.set_only_v6(true)?;
    }
    let bind = match snapshot.family {
        IpFamily::V4 => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT)),
        IpFamily::V6 => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MDNS_PORT, 0, 0)),
    };
    socket.bind(&bind.into())?;

    match snapshot.family {
        IpFamily::V4 => {
            let interface = primary_v4(snapshot)?;
            #[cfg(target_os = "linux")]
            socket.set_multicast_all_v4(false)?;
            socket.join_multicast_v4(&MDNS_V4_GROUP, &interface)?;
        }
        IpFamily::V6 => {
            #[cfg(target_os = "linux")]
            socket.set_multicast_all_v6(false)?;
            socket.join_multicast_v6(&MDNS_V6_GROUP, snapshot.index)?;
        }
    }
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

fn create_send_socket(snapshot: &InterfaceSnapshot) -> Result<UdpSocket, MdnsError> {
    let domain = match snapshot.family {
        IpFamily::V4 => Domain::IPV4,
        IpFamily::V6 => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(SocketProtocol::UDP))?;
    configure_reuse(&socket)?;
    let bind = match snapshot.family {
        IpFamily::V4 => {
            let interface = primary_v4(snapshot)?;
            socket.set_multicast_if_v4(&interface)?;
            socket.set_multicast_loop_v4(true)?;
            socket.set_multicast_ttl_v4(255)?;
            SocketAddr::V4(SocketAddrV4::new(interface, MDNS_PORT))
        }
        IpFamily::V6 => {
            socket.set_only_v6(true)?;
            socket.set_multicast_if_v6(snapshot.index)?;
            socket.set_multicast_loop_v6(true)?;
            socket.set_multicast_hops_v6(255)?;
            let interface = primary_v6(snapshot)?;
            SocketAddr::V6(SocketAddrV6::new(interface, MDNS_PORT, 0, snapshot.index))
        }
    };
    socket.bind(&bind.into())?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

fn configure_reuse(socket: &Socket) -> Result<(), MdnsError> {
    socket.set_reuse_address(true)?;
    #[cfg(all(
        unix,
        not(any(
            target_os = "solaris",
            target_os = "illumos",
            target_os = "cygwin",
            target_os = "nuttx",
            target_os = "wasi"
        ))
    ))]
    socket.set_reuse_port(true)?;
    Ok(())
}

fn primary_v4(snapshot: &InterfaceSnapshot) -> Result<Ipv4Addr, MdnsError> {
    snapshot
        .addrs
        .iter()
        .find_map(|net| match net.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
        .ok_or(MdnsError::NoInterfaceAddress {
            interface: snapshot.id,
        })
}

fn primary_v6(snapshot: &InterfaceSnapshot) -> Result<Ipv6Addr, MdnsError> {
    snapshot
        .addrs
        .iter()
        .find_map(|net| match net.ip() {
            IpAddr::V6(ip) => Some(ip),
            IpAddr::V4(_) => None,
        })
        .ok_or(MdnsError::NoInterfaceAddress {
            interface: snapshot.id,
        })
}

fn source_is_on_link(snapshot: &InterfaceSnapshot, source: IpAddr) -> bool {
    snapshot
        .addrs
        .iter()
        .any(|network| same_subnet(*network, source))
}

fn same_subnet(network: IpNet, source: IpAddr) -> bool {
    let prefix_len = network.prefix_len();
    match (network.ip(), source) {
        (IpAddr::V4(network_ip), IpAddr::V4(source_ip)) => {
            let mask = prefix_mask_u32(prefix_len);
            u32::from(source_ip) & mask == u32::from(network_ip) & mask
        }
        (IpAddr::V6(network_ip), IpAddr::V6(source_ip)) => {
            let mask = prefix_mask_u128(prefix_len);
            u128::from(source_ip) & mask == u128::from(network_ip) & mask
        }
        _ => false,
    }
}

fn prefix_mask_u32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn prefix_mask_u128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(ip: IpAddr, prefix: u8) -> IpNet {
        IpNet::new(ip, prefix).unwrap()
    }

    #[test]
    fn stable_ids_change_only_after_disappearance() {
        let key = InterfaceKey {
            index: 7,
            family: IpFamily::V4,
        };
        let mut grouped = BTreeMap::from([(
            key,
            vec![net(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 24)],
        )]);
        let mut registry = InterfaceRegistry::default();
        let first = registry.assign(&grouped).unwrap()[0].id;
        let unchanged = registry.assign(&grouped).unwrap()[0].id;
        assert_eq!(first, unchanged);
        grouped.clear();
        assert!(registry.assign(&grouped).unwrap().is_empty());
        grouped.insert(
            key,
            vec![net(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3)), 24)],
        );
        let reappeared = registry.assign(&grouped).unwrap()[0].id;
        assert_ne!(first, reappeared);
    }

    #[test]
    fn on_link_check_uses_checked_prefix() {
        let snapshot = InterfaceSnapshot {
            id: InterfaceId::new(1),
            index: 1,
            family: IpFamily::V4,
            addrs: vec![net(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 24)],
        };
        assert!(source_is_on_link(
            &snapshot,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99))
        ));
        assert!(!source_is_on_link(
            &snapshot,
            IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))
        ));
    }
}
