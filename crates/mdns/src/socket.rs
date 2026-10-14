//! Synchronous per-interface mDNS socket adapter.

use std::{
    collections::BTreeMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket},
    sync::Arc,
};

use if_addrs::IfAddr;
use minip2p_transport::mio::{self, Interest, Registry, Waker, event::Event};
use minip2p_transport::{PollSource, TokenSpace};
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};

use minip2p_platform::IoErrorKind;

use crate::io::{MdnsDatagram, MdnsError, MdnsIo, MdnsIoOperation};
use crate::{InterfaceId, InterfaceSnapshot, IpFamily, IpNet, MdnsAction, MdnsConfig, MdnsTarget};

const MDNS_PORT: u16 = 5353;
const MDNS_V4_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_V6_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct InterfaceKey {
    index: u32,
    family: IpFamily,
}

#[derive(Clone, Debug, Default)]
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
    /// Registered with the host's shared poll, once attached.
    receive: mio::net::UdpSocket,
    send: UdpSocket,
}

/// The host's shared poll, once attached.
struct Registration {
    registry: Registry,
    tokens: TokenSpace,
}

impl core::fmt::Debug for Registration {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Registration")
            .field("tokens", &self.tokens)
            .finish_non_exhaustive()
    }
}

impl Registration {
    /// Registers the receive socket of `pair`, under a token derived from its
    /// interface id.
    ///
    /// Ids are stable and never reused, so a socket kept across a refresh
    /// keeps its token and never needs registering again: a refresh only adds
    /// fresh sockets and drops gone ones, which is what lets a failed one
    /// leave the poll exactly as it found it.
    fn register(&self, pair: &mut SocketPair) -> Result<(), MdnsError> {
        let interface = pair.snapshot.id;
        let token = usize::try_from(interface.get())
            .ok()
            .and_then(|index| self.tokens.token(index))
            .ok_or_else(|| {
                MdnsError::io(
                    MdnsIoOperation::Register,
                    IoErrorKind::OutOfMemory,
                    Some(interface),
                    "no readiness token left for an mDNS socket",
                )
            })?;
        self.registry
            .register(&mut pair.receive, token, Interest::READABLE)
            .map_err(io_error(interface, MdnsIoOperation::Register))
    }

    /// Registers every pair, all or nothing: a failure deregisters the ones
    /// that got in, so the caller can drop or retry them from scratch.
    fn register_all(&self, pairs: &mut [SocketPair]) -> Result<(), MdnsError> {
        let failed = pairs
            .iter_mut()
            .enumerate()
            .find_map(|(index, pair)| self.register(pair).err().map(|error| (index, error)));
        let Some((index, error)) = failed else {
            return Ok(());
        };
        for registered in pairs.iter_mut().take(index) {
            self.deregister(registered);
        }
        Err(error)
    }

    /// Releases `pair`'s registration ahead of dropping it.
    fn deregister(&self, pair: &mut SocketPair) {
        // About to drop, which releases the registration too.
        drop(self.registry.deregister(&mut pair.receive));
    }
}

/// Per-interface mDNS receive/send socket collection.
///
/// The sockets are a list rather than a map: there are a handful of them, a
/// receive happens up to a full budget's worth per tick, and walking a short
/// list beats allocating anything at all on that path.
///
/// # Waking a host
///
/// As a [`PollSource`] attached to a std host's shared poll (the `Endpoint`
/// attaches it to its swarm as a host source), the receive sockets are
/// registered for readiness, and an interface refresh registers the sockets it
/// adds. Readiness only wakes the host: the driver's next tick reads
/// every socket until it has nothing more (or its budget runs out, which it
/// reports as due now), so nothing is dispatched to this. Without a poll the
/// host has to tick it on a cadence of its own to hear anything.
#[derive(Debug)]
pub struct MdnsSockets {
    /// The host's shared poll, once attached.
    registration: Option<Registration>,
    enable_ipv6: bool,
    registry: InterfaceRegistry,
    snapshots: Vec<InterfaceSnapshot>,
    pairs: Vec<SocketPair>,
    /// Where the next receive starts looking, so one talkative interface
    /// cannot spend a whole budget while a quiet one waits.
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
                registration: None,
                enable_ipv6: config.enable_ipv6,
                registry: InterfaceRegistry::default(),
                snapshots: Vec::new(),
                pairs: Vec::new(),
                next_receive_offset: 0,
            };
            sockets.refresh_interfaces()?;
            Ok(sockets)
        }
    }

    fn refresh_interfaces(&mut self) -> Result<bool, MdnsError> {
        let grouped = enumerate_interfaces(self.enable_ipv6)?;
        // Assigned on a copy, so a refresh that fails hands out no ids.
        let mut registry = self.registry.clone();
        let snapshots = registry.assign(&grouped)?;
        self.replace(registry, snapshots, SocketPair::new)
    }

    /// Moves to `snapshots`, all or nothing.
    ///
    /// An interface still here with the same addresses keeps its sockets:
    /// rebuilding one would drop the multicast membership and lose whatever
    /// had arrived on it. Every other socket is built with `build` and
    /// registered before anything is swapped, so a failure leaves the
    /// accepted sockets, snapshots, ids, and registrations exactly as they
    /// were -- mDNS keeps running on them while the driver retries.
    fn replace(
        &mut self,
        registry: InterfaceRegistry,
        snapshots: Vec<InterfaceSnapshot>,
        mut build: impl FnMut(InterfaceSnapshot) -> Result<SocketPair, MdnsError>,
    ) -> Result<bool, MdnsError> {
        if snapshots == self.snapshots {
            self.registry = registry;
            return Ok(false);
        }

        let mut fresh = Vec::new();
        for snapshot in &snapshots {
            if !self.pairs.iter().any(|pair| pair.snapshot == *snapshot) {
                fresh.push(build(snapshot.clone())?);
            }
        }
        if let Some(registration) = &self.registration {
            registration.register_all(&mut fresh)?;
        }

        // Nothing below fails: this is the commit.
        let mut old = core::mem::take(&mut self.pairs);
        let mut fresh = fresh.into_iter();
        for snapshot in &snapshots {
            let pair = match old.iter().position(|pair| pair.snapshot == *snapshot) {
                Some(index) => Some(old.swap_remove(index)),
                None => fresh.next(),
            };
            self.pairs.extend(pair);
        }
        if let Some(registration) = &self.registration {
            for gone in &mut old {
                registration.deregister(gone);
            }
        }
        self.registry = registry;
        self.snapshots = snapshots;
        self.next_receive_offset = 0;
        Ok(true)
    }
}

impl MdnsIo for MdnsSockets {
    fn interfaces(&self) -> &[InterfaceSnapshot] {
        &self.snapshots
    }

    fn refresh(&mut self) -> Result<bool, MdnsError> {
        self.refresh_interfaces()
    }

    fn receive(&mut self, buffer: &mut [u8]) -> Result<Option<MdnsDatagram>, MdnsError> {
        let count = self.pairs.len();
        if count == 0 {
            return Ok(None);
        }
        // Starts where the last read stopped, and allocates nothing: this runs
        // once per datagram, so a flood would pay for anything done here a
        // budget's worth of times per tick.
        for step in 0..count {
            let index = (self.next_receive_offset + step) % count;
            let Some(pair) = self.pairs.get_mut(index) else {
                continue;
            };
            match pair.receive.recv_from(buffer) {
                Ok((len, from)) => {
                    self.next_receive_offset = (index + 1) % count;
                    return Ok(Some(MdnsDatagram {
                        interface: pair.snapshot.id,
                        from,
                        len,
                    }));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => {
                    return Err(MdnsError::std_io(
                        MdnsIoOperation::Receive,
                        Some(pair.snapshot.id),
                        &error,
                    ));
                }
            }
        }
        Ok(None)
    }

    fn send(&mut self, action: &MdnsAction) -> Result<(), MdnsError> {
        let MdnsAction::Send {
            interface,
            target,
            payload,
        } = action;
        let pair = self
            .pairs
            .iter()
            .find(|pair| pair.snapshot.id == *interface)
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
        pair.send
            .send_to(payload, destination)
            .map_err(|error| send_error(*interface, error))?;
        Ok(())
    }
}

impl PollSource for MdnsSockets {
    fn attach(&mut self, registry: Registry, tokens: TokenSpace, _: Arc<Waker>) -> io::Result<()> {
        let registration = Registration { registry, tokens };
        registration
            .register_all(&mut self.pairs)
            .map_err(io::Error::other)?;
        self.registration = Some(registration);
        Ok(())
    }

    /// Nothing to record: the driver reads every socket on its tick.
    fn dispatch(&mut self, _: &Event) {}
}

impl SocketPair {
    /// Opens and configures both sockets for `snapshot`'s interface.
    fn new(snapshot: InterfaceSnapshot) -> Result<Self, MdnsError> {
        let receive = mio::net::UdpSocket::from_std(create_receive_socket(&snapshot)?);
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
    let interfaces = if_addrs::get_if_addrs()
        .map_err(|error| MdnsError::std_io(MdnsIoOperation::EnumerateInterfaces, None, &error))?;
    for iface in interfaces {
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
    use MdnsIoOperation::{Bind, ConfigureSocket, JoinGroup, OpenSocket};
    let id = snapshot.id;
    let domain = match snapshot.family {
        IpFamily::V4 => Domain::IPV4,
        IpFamily::V6 => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(SocketProtocol::UDP))
        .map_err(io_error(id, OpenSocket))?;
    configure_reuse(&socket, id)?;
    if snapshot.family == IpFamily::V6 {
        socket
            .set_only_v6(true)
            .map_err(io_error(id, ConfigureSocket))?;
    }
    let bind = match snapshot.family {
        IpFamily::V4 => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT)),
        IpFamily::V6 => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MDNS_PORT, 0, 0)),
    };
    socket.bind(&bind.into()).map_err(io_error(id, Bind))?;

    match snapshot.family {
        IpFamily::V4 => {
            let interface = primary_v4(snapshot)?;
            #[cfg(target_os = "linux")]
            socket
                .set_multicast_all_v4(false)
                .map_err(io_error(id, ConfigureSocket))?;
            socket
                .join_multicast_v4(&MDNS_V4_GROUP, &interface)
                .map_err(io_error(id, JoinGroup))?;
        }
        IpFamily::V6 => {
            #[cfg(target_os = "linux")]
            socket
                .set_multicast_all_v6(false)
                .map_err(io_error(id, ConfigureSocket))?;
            socket
                .join_multicast_v6(&MDNS_V6_GROUP, snapshot.index)
                .map_err(io_error(id, JoinGroup))?;
        }
    }
    socket
        .set_nonblocking(true)
        .map_err(io_error(id, ConfigureSocket))?;
    Ok(socket.into())
}

fn create_send_socket(snapshot: &InterfaceSnapshot) -> Result<UdpSocket, MdnsError> {
    use MdnsIoOperation::{Bind, ConfigureSocket, OpenSocket};
    let id = snapshot.id;
    let configure = io_error(id, ConfigureSocket);
    let domain = match snapshot.family {
        IpFamily::V4 => Domain::IPV4,
        IpFamily::V6 => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(SocketProtocol::UDP))
        .map_err(io_error(id, OpenSocket))?;
    configure_reuse(&socket, id)?;
    let bind = match snapshot.family {
        IpFamily::V4 => {
            let interface = primary_v4(snapshot)?;
            socket.set_multicast_if_v4(&interface).map_err(configure)?;
            socket.set_multicast_loop_v4(true).map_err(configure)?;
            socket.set_multicast_ttl_v4(255).map_err(configure)?;
            SocketAddr::V4(SocketAddrV4::new(interface, MDNS_PORT))
        }
        IpFamily::V6 => {
            socket.set_only_v6(true).map_err(configure)?;
            socket
                .set_multicast_if_v6(snapshot.index)
                .map_err(configure)?;
            socket.set_multicast_loop_v6(true).map_err(configure)?;
            socket.set_multicast_hops_v6(255).map_err(configure)?;
            let interface = primary_v6(snapshot)?;
            SocketAddr::V6(SocketAddrV6::new(interface, MDNS_PORT, 0, snapshot.index))
        }
    };
    socket.bind(&bind.into()).map_err(io_error(id, Bind))?;
    socket.set_nonblocking(true).map_err(configure)?;
    Ok(socket.into())
}

/// What a failed send means.
///
/// These sockets are non-blocking, so a full kernel send buffer reports itself
/// rather than waiting. That is backpressure and not a broken socket: the
/// driver parks the datagram and comes back for it once the buffer has
/// drained. Calling it an I/O failure would put mDNS into its failure state
/// over a moment of it -- which is the same distinction an embedded stack
/// draws when its transmit ring fills.
fn send_error(interface: InterfaceId, error: io::Error) -> MdnsError {
    if error.kind() == io::ErrorKind::WouldBlock {
        return MdnsError::Congested { interface };
    }
    MdnsError::std_io(MdnsIoOperation::Send, Some(interface), &error)
}

/// Maps a failed socket call for `interface` to an [`MdnsError::Io`].
fn io_error(
    interface: InterfaceId,
    operation: MdnsIoOperation,
) -> impl Fn(io::Error) -> MdnsError + Copy {
    move |error| MdnsError::std_io(operation, Some(interface), &error)
}

fn configure_reuse(socket: &Socket, interface: InterfaceId) -> Result<(), MdnsError> {
    let configure = io_error(interface, MdnsIoOperation::ConfigureSocket);
    socket.set_reuse_address(true).map_err(configure)?;
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
    socket.set_reuse_port(true).map_err(configure)?;
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

#[cfg(test)]
impl MdnsSockets {
    /// Builds a collection over sockets a test bound itself.
    ///
    /// The real constructor needs multicast membership on a real interface,
    /// which a test machine may not have; the rotation between sockets is
    /// ordinary logic that plain loopback sockets exercise just as well.
    fn from_pairs(pairs: Vec<SocketPair>) -> Self {
        Self {
            registration: None,
            enable_ipv6: false,
            registry: InterfaceRegistry::default(),
            snapshots: pairs.iter().map(|pair| pair.snapshot.clone()).collect(),
            pairs,
            next_receive_offset: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(ip: IpAddr, prefix: u8) -> IpNet {
        IpNet::new(ip, prefix).unwrap()
    }

    /// A pair whose receive socket is a plain loopback UDP socket.
    fn loopback_pair(id: u32) -> (SocketPair, SocketAddr) {
        let receive = UdpSocket::bind("127.0.0.1:0").expect("a loopback socket");
        receive.set_nonblocking(true).expect("nonblocking");
        let addr = receive.local_addr().expect("bound address");
        let receive = mio::net::UdpSocket::from_std(receive);
        let send = UdpSocket::bind("127.0.0.1:0").expect("a loopback socket");
        let snapshot = InterfaceSnapshot {
            id: InterfaceId::new(id),
            index: id,
            family: IpFamily::V4,
            addrs: vec![net(IpAddr::V4(Ipv4Addr::LOCALHOST), 8)],
        };
        (
            SocketPair {
                snapshot,
                receive,
                send,
            },
            addr,
        )
    }

    fn next_interface(sockets: &mut MdnsSockets) -> InterfaceId {
        let mut buffer = [0u8; 64];
        sockets
            .receive(&mut buffer)
            .expect("receive")
            .expect("a datagram was waiting")
            .interface
    }

    /// Waits until every socket has something waiting.
    ///
    /// Loopback delivery is prompt but not synchronous, and reading before it
    /// lands would test the kernel's timing rather than the rotation.
    fn wait_until_all_ready(sockets: &MdnsSockets) {
        for pair in &sockets.pairs {
            let mut peek = [0u8; 1];
            let mut ready = false;
            for _ in 0..1_000 {
                if pair.receive.peek_from(&mut peek).is_ok() {
                    ready = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            assert!(ready, "a datagram sent on loopback never arrived");
        }
    }

    #[test]
    fn a_datagram_on_an_attached_socket_wakes_the_host_without_being_read() {
        let (first, _) = loopback_pair(1);
        let (second, addr) = loopback_pair(2);
        let mut sockets = MdnsSockets::from_pairs(vec![first, second]);
        let mut poll = minip2p_transport::SharedPoll::new().expect("poll");
        poll.attach_host_source(&mut sockets).expect("attach");

        UdpSocket::bind("127.0.0.1:0")
            .expect("sender")
            .send_to(b"query", addr)
            .expect("send");
        // A host source is never dispatched to, so any transport will do.
        let mut transport = MdnsSockets::from_pairs(Vec::new());
        let events = poll
            .harvest(&mut transport, std::time::Duration::from_secs(5))
            .expect("harvest");
        assert!(events > 0, "the datagram woke the poll");
        assert!(poll.take_wake(), "and surfaces as a host wake");
        assert_eq!(
            next_interface(&mut sockets),
            InterfaceId::new(2),
            "readiness consumed nothing"
        );
    }

    #[test]
    fn a_refresh_that_cannot_build_a_socket_keeps_the_ones_it_had() {
        let (kept, addr) = loopback_pair(1);
        let snapshot = kept.snapshot.clone();
        let mut sockets = MdnsSockets::from_pairs(vec![kept]);
        let mut poll = minip2p_transport::SharedPoll::new().expect("poll");
        poll.attach_host_source(&mut sockets).expect("attach");

        // Interface 1 went away and interface 2 arrived, but 2's socket
        // cannot be built. Swapping half-way would leave mDNS on nothing.
        let mut arrived = snapshot.clone();
        arrived.id = InterfaceId::new(2);
        let error = sockets
            .replace(InterfaceRegistry::default(), vec![arrived], |snapshot| {
                Err(MdnsError::io(
                    MdnsIoOperation::Bind,
                    IoErrorKind::AddrInUse,
                    Some(snapshot.id),
                    "scripted",
                ))
            })
            .expect_err("the build failed");
        assert!(matches!(error, MdnsError::Io { .. }), "{error:?}");
        assert_eq!(sockets.interfaces(), [snapshot], "the snapshots stand");

        // And so does the socket, still registered for readiness.
        UdpSocket::bind("127.0.0.1:0")
            .expect("sender")
            .send_to(b"query", addr)
            .expect("send");
        let mut transport = MdnsSockets::from_pairs(Vec::new());
        poll.harvest(&mut transport, std::time::Duration::from_secs(5))
            .expect("harvest");
        assert!(poll.take_wake(), "the kept socket still wakes the host");
        assert_eq!(next_interface(&mut sockets), InterfaceId::new(1));
    }

    #[test]
    fn a_full_send_buffer_is_backpressure_and_not_a_broken_socket() {
        // Kernel send-buffer pressure is not something a test can conjure on
        // demand, so the decision is checked where it is made. What it costs
        // to get wrong is not small: the driver backs off on an I/O failure,
        // so every busy moment would take the host off the link for a while.
        assert_eq!(
            send_error(
                InterfaceId::new(1),
                io::Error::from(io::ErrorKind::WouldBlock)
            ),
            MdnsError::Congested {
                interface: InterfaceId::new(1)
            }
        );
        // Anything else is what it says it is.
        assert!(matches!(
            send_error(
                InterfaceId::new(1),
                io::Error::from(io::ErrorKind::PermissionDenied)
            ),
            MdnsError::Io { .. }
        ));
    }

    #[test]
    fn receiving_rotates_between_interfaces() {
        let (first, first_addr) = loopback_pair(1);
        let (second, second_addr) = loopback_pair(2);
        let mut sockets = MdnsSockets::from_pairs(vec![first, second]);
        let sender = UdpSocket::bind("127.0.0.1:0").expect("a loopback socket");

        // Two waiting on one interface and one on the other. Draining the
        // first would spend a caller's budget on whichever interface happened
        // to be talking most, and a quiet one could wait indefinitely.
        sender.send_to(b"a", first_addr).expect("send");
        sender.send_to(b"a", first_addr).expect("send");
        sender.send_to(b"b", second_addr).expect("send");
        wait_until_all_ready(&sockets);

        assert_eq!(
            [
                next_interface(&mut sockets),
                next_interface(&mut sockets),
                next_interface(&mut sockets),
            ],
            [
                InterfaceId::new(1),
                InterfaceId::new(2),
                InterfaceId::new(1)
            ],
            "each read starts where the last one stopped"
        );
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
}
