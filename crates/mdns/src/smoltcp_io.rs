//! An [`MdnsIo`] over [smoltcp], for hosts with no operating system.

use alloc::vec;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::phy::Device;
use smoltcp::socket::udp::{self, PacketBuffer, PacketMetadata, UdpMetadata};
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint};

use crate::io::{MAX_DATAGRAM_BYTES, MdnsDatagram, MdnsError, MdnsIo};
use crate::{InterfaceId, InterfaceSnapshot, IpFamily, IpNet, MdnsAction, MdnsTarget};

/// The port mDNS runs on.
const MDNS_PORT: u16 = 5353;
const MDNS_V4_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_V6_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb);

/// The one interface handle this reports for IPv4, and the one for IPv6.
///
/// A host hands over one interface, so there is nothing to enumerate and
/// nothing to keep stable across a re-enumeration: the two families are the
/// two ids, for as long as this exists.
const IPV4_INTERFACE: InterfaceId = InterfaceId::new(1);
const IPV6_INTERFACE: InterfaceId = InterfaceId::new(2);

/// How much memory [`SmoltcpMdnsIo`] gives each family's socket.
///
/// The defaults are sized for a link where mDNS is a background conversation
/// among a handful of peers. A device with less to spare can shrink them: the
/// cost of a payload buffer too small for a claim is that the claim is
/// dropped, not that anything breaks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmoltcpMdnsConfig {
    /// Bytes held for datagrams waiting to be read.
    pub rx_payload_bytes: usize,
    /// Bytes held for datagrams waiting to go out.
    pub tx_payload_bytes: usize,
    /// How many datagrams may be queued in each direction at once.
    pub packet_slots: usize,
    /// Whether to run on the interface's IPv6 addresses as well as its IPv4
    /// ones.
    pub enable_ipv6: bool,
}

impl Default for SmoltcpMdnsConfig {
    fn default() -> Self {
        Self {
            // Two ordinary claims' worth: enough that a burst from a peer
            // does not drop what a poll has not read yet, far short of what
            // mDNS technically allows.
            rx_payload_bytes: 4 * 1024,
            tx_payload_bytes: 4 * 1024,
            packet_slots: 4,
            enable_ipv6: true,
        }
    }
}

struct Family {
    id: InterfaceId,
    family: IpFamily,
    socket: SocketHandle,
    group: IpAddress,
}

/// An [`MdnsIo`] over a [smoltcp] interface the host configured.
///
/// Everything above this -- the agent's scheduling and validation, the
/// driver's budgets and its on-link check -- is the code the hosted
/// [`MdnsSockets`](crate::MdnsSockets) runs under. This is the other end of
/// that seam.
///
/// # Ownership
///
/// The host builds the [`Interface`] and hands it over, because addressing is
/// its business: which medium the link speaks and what addresses it holds.
/// This owns the mDNS sockets on it and the multicast memberships they need,
/// and reaches the interface through
/// [`interface_mut`](Self::interface_mut) if the host has to reconfigure it.
///
/// # Interfaces
///
/// smoltcp has one interface, so mDNS sees one per family: everything the
/// interface holds in that family is that snapshot's addresses.
/// [`refresh`](MdnsIo::refresh) re-reads them, which is how an address
/// arriving by DHCP or SLAAC reaches the agent.
///
/// # Driving it
///
/// Nothing moves except when [`poll`](MdnsIo::poll) is called, so a host that
/// stops driving this stops mDNS -- and
/// [`next_deadline`](MdnsIo::next_deadline) is what lets it sleep in between
/// rather than poll to find out nothing happened.
///
/// [smoltcp]: https://docs.rs/smoltcp
pub struct SmoltcpMdnsIo<D: Device> {
    device: D,
    iface: Interface,
    sockets: SocketSet<'static>,
    families: Vec<Family>,
    snapshots: Vec<InterfaceSnapshot>,
    /// Where the next receive starts looking, so one family cannot spend a
    /// whole budget while the other waits.
    next_receive: usize,
    /// The last reading a caller gave, so a send between polls can be
    /// timestamped without reading a clock.
    now_ms: u64,
    /// smoltcp's own answer to when it next needs driving, captured during
    /// `poll` because computing it needs the interface mutably.
    poll_at_ms: Option<u64>,
}

impl<D: Device> SmoltcpMdnsIo<D> {
    /// Opens mDNS sockets on `iface` and joins the mDNS groups.
    ///
    /// Fails only if the interface will not take the memberships; an
    /// interface with no address in a family simply has no snapshot for it
    /// until one arrives.
    pub fn new(
        device: D,
        mut iface: Interface,
        config: SmoltcpMdnsConfig,
    ) -> Result<Self, MdnsError> {
        let mut sockets = SocketSet::new(Vec::new());
        let mut families = Vec::new();

        for (family, id, group) in [
            (IpFamily::V4, IPV4_INTERFACE, IpAddress::Ipv4(MDNS_V4_GROUP)),
            (IpFamily::V6, IPV6_INTERFACE, IpAddress::Ipv6(MDNS_V6_GROUP)),
        ] {
            if family == IpFamily::V6 && !config.enable_ipv6 {
                continue;
            }
            iface.join_multicast_group(group).map_err(|error| {
                MdnsError::io("joining the mDNS multicast group", DisplayError(error))
            })?;
            let mut socket = udp::Socket::new(
                PacketBuffer::new(
                    vec![PacketMetadata::EMPTY; config.packet_slots],
                    vec![0u8; config.rx_payload_bytes],
                ),
                PacketBuffer::new(
                    vec![PacketMetadata::EMPTY; config.packet_slots],
                    vec![0u8; config.tx_payload_bytes],
                ),
            );
            // Bound to the port rather than to an address: one socket serves
            // the group and any unicast reply, whichever address of this
            // family the datagram was sent to.
            socket
                .bind(IpListenEndpoint {
                    addr: None,
                    port: MDNS_PORT,
                })
                .map_err(|error| MdnsError::io("binding the mDNS port", DisplayError(error)))?;
            // mDNS is link-local by definition, and a hop limit of 255 is what
            // says so on the wire.
            socket.set_hop_limit(Some(255));
            families.push(Family {
                id,
                family,
                socket: sockets.add(socket),
                group,
            });
        }

        let mut io = Self {
            device,
            iface,
            sockets,
            families,
            snapshots: Vec::new(),
            next_receive: 0,
            now_ms: 0,
            poll_at_ms: None,
        };
        io.snapshots = io.read_snapshots();
        Ok(io)
    }

    /// Borrows the interface, for a host that reconfigures its addresses.
    pub fn interface_mut(&mut self) -> &mut Interface {
        &mut self.iface
    }

    /// Borrows the link.
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }

    /// What the interface currently holds, one snapshot per family it has an
    /// address in.
    fn read_snapshots(&self) -> Vec<InterfaceSnapshot> {
        self.families
            .iter()
            .filter_map(|family| {
                let addrs: Vec<IpNet> = self
                    .iface
                    .ip_addrs()
                    .iter()
                    .filter_map(|cidr| {
                        let ip = match cidr.address() {
                            IpAddress::Ipv4(v4) => IpAddr::V4(v4),
                            IpAddress::Ipv6(v6) => IpAddr::V6(v6),
                        };
                        let matches = matches!(
                            (family.family, ip),
                            (IpFamily::V4, IpAddr::V4(_)) | (IpFamily::V6, IpAddr::V6(_))
                        );
                        matches.then(|| IpNet::new(ip, cidr.prefix_len())).flatten()
                    })
                    .collect();
                // A family with no address is not an interface mDNS can speak
                // on: it has no source to claim and nothing on-link to accept.
                (!addrs.is_empty()).then_some(InterfaceSnapshot {
                    id: family.id,
                    // One interface, so smoltcp needs no index to tell them
                    // apart and IPv6 needs no scope to pick one.
                    index: 0,
                    family: family.family,
                    addrs,
                })
            })
            .collect()
    }
}

fn instant(millis: u64) -> Instant {
    // smoltcp keeps time as microseconds in an `i64`, so the largest
    // millisecond value it can hold is a thousandth of `i64::MAX`. Saturating
    // at `i64::MAX` itself would overflow the multiplication inside.
    let ceiling = i64::MAX / 1000;
    Instant::from_millis(i64::try_from(millis).unwrap_or(ceiling).min(ceiling))
}

fn endpoint_to_socket_addr(endpoint: IpEndpoint) -> SocketAddr {
    let ip = match endpoint.addr {
        IpAddress::Ipv4(v4) => IpAddr::V4(v4),
        IpAddress::Ipv6(v6) => IpAddr::V6(v6),
    };
    SocketAddr::new(ip, endpoint.port)
}

fn socket_addr_to_endpoint(addr: SocketAddr) -> IpEndpoint {
    let address = match addr.ip() {
        IpAddr::V4(v4) => IpAddress::Ipv4(v4),
        IpAddr::V6(v6) => IpAddress::Ipv6(v6),
    };
    IpEndpoint::new(address, addr.port())
}

/// Wraps a smoltcp error so it can be described without `std::error::Error`.
struct DisplayError<E>(E);

impl<E: core::fmt::Display> core::fmt::Display for DisplayError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl<D: Device> MdnsIo for SmoltcpMdnsIo<D> {
    fn interfaces(&self) -> &[InterfaceSnapshot] {
        &self.snapshots
    }

    fn refresh(&mut self) -> Result<bool, MdnsError> {
        let snapshots = self.read_snapshots();
        if snapshots == self.snapshots {
            return Ok(false);
        }
        self.snapshots = snapshots;
        Ok(true)
    }

    fn receive(&mut self, buffer: &mut [u8]) -> Result<Option<MdnsDatagram>, MdnsError> {
        let count = self.families.len();
        if count == 0 {
            return Ok(None);
        }
        for step in 0..count {
            let index = (self.next_receive + step) % count;
            let family = &self.families[index];
            let socket = self.sockets.get_mut::<udp::Socket>(family.socket);
            let (payload, metadata) = match socket.recv() {
                Ok(received) => received,
                Err(udp::RecvError::Exhausted) => continue,
                // smoltcp drops a datagram it could not fit rather than
                // handing over part of one, so there is nothing to report but
                // the loss -- and the driver would have dropped it anyway.
                Err(udp::RecvError::Truncated) => continue,
            };
            // As much as fits and no more: filling the buffer is how the
            // driver recognises a datagram too big to act on.
            let len = payload.len().min(buffer.len());
            buffer[..len].copy_from_slice(&payload[..len]);
            let from = endpoint_to_socket_addr(metadata.endpoint);
            self.next_receive = (index + 1) % count;
            return Ok(Some(MdnsDatagram {
                interface: family.id,
                from,
                len,
            }));
        }
        Ok(None)
    }

    fn send(&mut self, action: &MdnsAction) -> Result<(), MdnsError> {
        let MdnsAction::Send {
            interface,
            target,
            payload,
        } = action;
        let family = self
            .families
            .iter()
            .find(|family| family.id == *interface)
            .ok_or(MdnsError::UnknownInterface {
                interface: *interface,
            })?;
        let destination = match target {
            MdnsTarget::Multicast => IpEndpoint::new(family.group, MDNS_PORT),
            MdnsTarget::Unicast { to } => socket_addr_to_endpoint(*to),
        };
        let handle = family.socket;
        let socket = self.sockets.get_mut::<udp::Socket>(handle);
        socket
            .send_slice(payload, UdpMetadata::from(destination))
            .map_err(|error| MdnsError::io("queueing an mDNS datagram", DisplayError(error)))?;
        Ok(())
    }

    fn poll(&mut self, now_ms: u64) -> Result<(), MdnsError> {
        self.now_ms = now_ms;
        let timestamp = instant(now_ms);
        self.iface
            .poll(timestamp, &mut self.device, &mut self.sockets);
        self.poll_at_ms = self
            .iface
            .poll_at(timestamp, &self.sockets)
            .map(|at| u64::try_from(at.total_millis()).unwrap_or(0));
        Ok(())
    }

    fn next_deadline(&self, now_ms: u64) -> Option<u64> {
        // A datagram already queued leaves on the next poll, so that poll is
        // due now rather than whenever smoltcp's own timers say.
        let queued = self.families.iter().any(|family| {
            self.sockets
                .get::<udp::Socket>(family.socket)
                .send_queue()
                .gt(&0)
        });
        if queued {
            return Some(0);
        }
        self.poll_at_ms.map(|at| at.saturating_sub(now_ms))
    }
}

/// The largest datagram this can hand over, whatever the driver's buffer is.
///
/// Nothing enforces the relationship here -- a smaller receive buffer simply
/// drops bigger claims inside smoltcp -- but a host sizing
/// [`SmoltcpMdnsConfig`] against it knows what it is trading away.
pub const MAX_USEFUL_PAYLOAD_BYTES: usize = MAX_DATAGRAM_BYTES;
