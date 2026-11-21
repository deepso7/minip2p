use super::*;
#[cfg(not(feature = "mdns"))]
use alloc::boxed::Box;
use alloc::{rc::Rc, vec, vec::Vec};
use core::cell::Cell;
use minip2p_core::platform::EntropyError;
use minip2p_core::platform::ManualClock;
use minip2p_test_support::InMemoryTransport;
use minip2p_transport::{ConnectionEndpoint, ConnectionNamespace, TransportEvent};

struct NoopTransport;

impl Transport for NoopTransport {
    fn ack_stream(
        &mut self,
        _: minip2p_transport::ConnectionId,
        _: minip2p_transport::StreamId,
        _: usize,
    ) -> Result<(), minip2p_transport::TransportError> {
        Ok(())
    }

    fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
        Err(TransportError::Unsupported { operation: "dial" })
    }

    fn listen(&mut self, _: &Multiaddr) -> Result<Multiaddr, TransportError> {
        Err(TransportError::Unsupported {
            operation: "listen",
        })
    }

    fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
        Err(TransportError::Unsupported {
            operation: "open stream",
        })
    }

    fn send_stream(
        &mut self,
        _: ConnectionId,
        _: StreamId,
        _: minip2p_core::Bytes,
    ) -> Result<(), TransportError> {
        Err(TransportError::Unsupported {
            operation: "send stream",
        })
    }

    fn close_stream_write(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Err(TransportError::Unsupported {
            operation: "close stream write",
        })
    }

    fn reset_stream(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Err(TransportError::Unsupported {
            operation: "reset stream",
        })
    }

    fn close(&mut self, _: ConnectionId) -> Result<(), TransportError> {
        Err(TransportError::Unsupported {
            operation: "close connection",
        })
    }

    fn poll(&mut self, _: Now) -> Result<Vec<TransportEvent>, TransportError> {
        Ok(Vec::new())
    }
}

struct ZeroEntropy;

impl EntropySource for ZeroEntropy {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        output.fill(0);
        Ok(())
    }
}

struct RecordingTransport {
    events: Vec<TransportEvent>,
    local_address: Multiaddr,
    next_stream_id: u64,
    closed: Rc<Cell<bool>>,
    /// Fails every close and poll, as a transport that has gone away.
    broken: bool,
}

impl Transport for RecordingTransport {
    fn ack_stream(
        &mut self,
        _: minip2p_transport::ConnectionId,
        _: minip2p_transport::StreamId,
        _: usize,
    ) -> Result<(), minip2p_transport::TransportError> {
        Ok(())
    }

    fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
        Err(TransportError::Unsupported { operation: "dial" })
    }

    fn listen(&mut self, address: &Multiaddr) -> Result<Multiaddr, TransportError> {
        Ok(address.clone())
    }

    fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
        self.next_stream_id += 1;
        Ok(StreamId::new(self.next_stream_id))
    }

    fn send_stream(
        &mut self,
        _: ConnectionId,
        _: StreamId,
        _: minip2p_core::Bytes,
    ) -> Result<(), TransportError> {
        Ok(())
    }

    fn close_stream_write(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Ok(())
    }

    fn reset_stream(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
        Ok(())
    }

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
        if self.broken {
            return Err(TransportError::PollError {
                reason: "transport gone".into(),
            });
        }
        self.closed.set(true);
        self.events.push(TransportEvent::Closed {
            id,
            reason: ConnectionCloseReason::Local,
        });
        Ok(())
    }

    fn poll(&mut self, _: Now) -> Result<Vec<TransportEvent>, TransportError> {
        if self.broken {
            return Err(TransportError::PollError {
                reason: "transport gone".into(),
            });
        }
        Ok(core::mem::take(&mut self.events))
    }

    fn local_addresses(&self) -> Vec<Multiaddr> {
        vec![self.local_address.clone()]
    }
}

/// An mDNS carrier with no interfaces whose driving fails, as a stack
/// that has gone away does.
#[cfg(feature = "mdns")]
struct BrokenMdns;

#[cfg(feature = "mdns")]
impl MdnsIo for BrokenMdns {
    fn interfaces(&self) -> &[minip2p_mdns::InterfaceSnapshot] {
        &[]
    }
    fn refresh(&mut self) -> Result<bool, MdnsError> {
        Ok(false)
    }
    fn receive(&mut self, _: &mut [u8]) -> Result<Option<minip2p_mdns::MdnsDatagram>, MdnsError> {
        Ok(None)
    }
    fn send(&mut self, _: &minip2p_mdns::MdnsAction) -> Result<(), MdnsError> {
        Ok(())
    }
    fn poll(&mut self, _: u64) -> Result<(), MdnsError> {
        Err(MdnsError::io(
            MdnsIoOperation::Poll,
            minip2p_core::platform::IoErrorKind::NotConnected,
            None,
            "stack gone",
        ))
    }
}

/// A stream whose close is still queued in the endpoint is gone from
/// the swarm, yet abandoning it drops every queued event for it.
#[cfg(feature = "mdns")]
#[test]
fn abandoning_a_stream_closed_in_held_events_drops_them() {
    let identity = Ed25519Keypair::from_secret_key_bytes([7; 32]);
    let mut endpoint = PortableEndpointBuilder::new(&identity, ZeroEntropy, ManualClock::default())
        .mdns(BrokenMdns, MdnsConfig::default())
        .build(NoopTransport)
        .expect("mdns endpoint");
    let peer = Ed25519Keypair::from_secret_key_bytes([8; 32]).peer_id();
    let stream = StreamKey::new(ConnectionId::new(1), StreamId::new(3));
    let other = EndpointEvent::ConnectionClosed {
        peer_id: peer,
        conn_id: ConnectionId::new(2),
        reason: ConnectionCloseReason::Local,
    };
    endpoint.engine.events.extend([
        EndpointEvent::StreamData {
            peer_id: peer,
            stream,
            data: minip2p_core::Bytes::from_static(b"late"),
        },
        EndpointEvent::StreamClosed {
            peer_id: peer,
            stream,
        },
        other,
    ]);
    endpoint
        .at(Now::from_millis(0))
        .abandon_stream(stream)
        .expect("a held close proves the stream");
    assert!(
        matches!(
            endpoint.engine.events.make_contiguous(),
            [EndpointEvent::ConnectionClosed { conn_id, .. }] if *conn_id == ConnectionId::new(2)
        ),
        "{:?}",
        endpoint.engine.events
    );
}

/// A failing mDNS carrier never fails the poll: the failure is one
/// capability event, reported once, and the rest of the batch (here an
/// attempt's terminal) is unaffected.
#[cfg(feature = "mdns")]
#[test]
fn a_failing_mdns_carrier_is_an_event_not_a_poll_error() {
    let identity = Ed25519Keypair::from_secret_key_bytes([7; 32]);
    let mut endpoint = PortableEndpointBuilder::new(&identity, ZeroEntropy, ManualClock::default())
        .mdns(BrokenMdns, MdnsConfig::default())
        .build(NoopTransport)
        .expect("mdns endpoint");
    let peer = Ed25519Keypair::from_secret_key_bytes([8; 32]).peer_id();
    let target = PeerAddr::new(
        <Multiaddr as core::str::FromStr>::from_str("/ip4/192.0.2.1/tcp/4001").expect("addr"),
        peer,
    )
    .expect("peer addr");
    // The transport refuses the dial, so the attempt settles at once.
    let id = endpoint
        .at(Now::from_millis(0))
        .connect(target)
        .expect("admitted");

    let events = endpoint.at(Now::from_millis(1)).poll().expect("poll");
    let failures = |events: &[EndpointEvent]| {
        events
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    EndpointEvent::MdnsFailed {
                        error: MdnsError::Io {
                            operation: MdnsIoOperation::Poll,
                            ..
                        }
                    }
                )
            })
            .count()
    };
    assert_eq!(failures(&events), 1, "{events:?}");
    assert!(
        events.iter().any(|event| matches!(
            event,
            EndpointEvent::ConnectSettled { connect_id, .. } if *connect_id == id
        )),
        "{events:?}"
    );
    // The retry fails the same way: still running, nothing new to report.
    let retried = endpoint
        .at(Now::from_millis(1 + MDNS_FAILURE_RETRY))
        .poll()
        .expect("poll");
    assert_eq!(failures(&retried), 0, "{retried:?}");
}

/// Goodbyes are best effort: one that cannot be sent is a final
/// `MdnsFailed` among the shutdown's events, not a shutdown error.
#[cfg(feature = "mdns")]
#[test]
fn a_failed_goodbye_is_an_event_from_shutdown() {
    let identity = Ed25519Keypair::from_secret_key_bytes([7; 32]);
    let mut endpoint = PortableEndpointBuilder::new(&identity, ZeroEntropy, ManualClock::default())
        .mdns(BrokenMdns, MdnsConfig::default())
        .build(NoopTransport)
        .expect("mdns endpoint");
    endpoint.at(Now::from_millis(0));
    let report = endpoint.close();
    assert!(report.errors.is_empty(), "goodbyes are best effort");
    let events = report.events;
    assert!(
        events
            .iter()
            .any(|event| matches!(event, EndpointEvent::MdnsFailed { .. })),
        "{events:?}"
    );
}

#[test]
fn builder_protocols_are_numbered_by_first_registration() {
    let identity = Ed25519Keypair::from_secret_key_bytes([7; 32]);
    let endpoint = PortableEndpointBuilder::new(&identity, ZeroEntropy, ManualClock::default())
        .protocol("/a/1")
        .manual_ack_protocol("/b/1")
        .protocol("/a/1")
        .build(NoopTransport)
        .expect("portable endpoint configuration is valid");
    let (a, b) = (endpoint.protocol_id("/a/1"), endpoint.protocol_id("/b/1"));
    assert!(a.is_some() && b.is_some() && a < b, "{a:?} {b:?}");
}

#[test]
fn portable_builder_constructs_a_protocol_ready_endpoint() {
    let identity = Ed25519Keypair::from_secret_key_bytes([7; 32]);
    let mut endpoint = PortableEndpointBuilder::new(&identity, ZeroEntropy, ManualClock::default())
        .protocol("/example/1.0.0")
        .build(NoopTransport)
        .expect("portable endpoint configuration is valid");
    let remote = Ed25519Keypair::from_secret_key_bytes([8; 32]).peer_id();

    assert_eq!(endpoint.peer_id(), &identity.peer_id());
    let now = Now::from_millis(0);
    assert!(matches!(
        endpoint.at(now).open_stream(&remote, "/example/1.0.0"),
        Err(DriverError::Swarm(SwarmError::NotConnected { .. }))
    ));
    assert!(matches!(
        endpoint.at(now).open_stream(&remote, "/missing/1.0.0"),
        Err(DriverError::Swarm(SwarmError::ProtocolNotRegistered { .. }))
    ));

    let error = PortableEndpointBuilder::new(&identity, ZeroEntropy, ManualClock::default())
        .protocol(minip2p_swarm::RESERVED_PROTOCOL_IDS[0])
        .build(NoopTransport)
        .err()
        .expect("reserved protocols must be rejected");
    assert!(matches!(
        error,
        PortableBuildError::Swarm(SwarmError::ReservedProtocol { .. })
    ));

    let error = PortableEndpointBuilder::new(&identity, ZeroEntropy, ManualClock::default())
        .timeouts(SwarmTimeouts {
            negotiation_ms: 0,
            ..SwarmTimeouts::default()
        })
        .build(NoopTransport)
        .err()
        .expect("a zero deadline must be rejected");
    assert!(matches!(
        error,
        PortableBuildError::Swarm(SwarmError::ZeroTimeout {
            field: "negotiation_ms"
        })
    ));
}

/// A circuit is Relayed through the relay its address names; the direct
/// connection that replaces it is Direct, inheriting nothing; pending,
/// replaced, and closed connections have no info.
#[test]
fn every_established_connection_has_its_own_path() {
    let identity = Ed25519Keypair::from_secret_key_bytes([31; 32]);
    let peer = Ed25519Keypair::from_secret_key_bytes([32; 32]).peer_id();
    let relay = Ed25519Keypair::from_secret_key_bytes([33; 32]).peer_id();
    let circuit = ConnectionId::namespaced(ConnectionNamespace::CIRCUIT, 1).expect("id");
    let circuit_addr = Multiaddr::from_protocols(vec![Protocol::P2p(relay), Protocol::P2pCircuit]);
    let direct = ConnectionId::namespaced(ConnectionNamespace::TCP_IPV4, 1).expect("id");
    let direct_addr: Multiaddr = "/ip4/192.0.2.7/tcp/4001".parse().expect("address");
    let transport = RecordingTransport {
        events: vec![
            TransportEvent::Connected {
                id: circuit,
                endpoint: Box::new(ConnectionEndpoint::with_peer_id(circuit_addr.clone(), peer)),
            },
            TransportEvent::IncomingConnection {
                id: direct,
                endpoint: Box::new(ConnectionEndpoint::new(direct_addr.clone())),
            },
        ],
        local_address: direct_addr.clone(),
        next_stream_id: 0,
        closed: Rc::new(Cell::new(false)),
        broken: false,
    };
    let mut endpoint = PortableEndpointBuilder::new(&identity, ZeroEntropy, ManualClock::default())
        .build(transport)
        .expect("endpoint configuration is valid");
    endpoint.at(Now::from_millis(0)).poll().expect("poll");

    assert_eq!(
        endpoint.connection_info(circuit),
        Some(ConnectionInfo {
            peer_id: peer,
            conn_id: circuit,
            remote_addr: circuit_addr,
            path: Path::Relayed { relay },
            ready_protocols: None,
        })
    );
    assert_eq!(
        endpoint.connection_info(direct),
        None,
        "a pending handshake"
    );

    // The accepted direct connection identifies the peer and replaces
    // the circuit.
    endpoint
        .engine
        .core
        .transport_mut()
        .events
        .push(TransportEvent::Connected {
            id: direct,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(direct_addr, peer)),
        });
    endpoint.at(Now::from_millis(1)).poll().expect("poll");
    assert_eq!(endpoint.connection_info(circuit), None, "replaced");
    assert_eq!(
        endpoint.connection_info(direct).map(|info| info.path),
        Some(Path::Direct)
    );
    assert_eq!(endpoint.path(&peer), Some(Path::Direct));

    endpoint
        .engine
        .core
        .transport_mut()
        .events
        .push(TransportEvent::Closed {
            id: direct,
            reason: ConnectionCloseReason::Local,
        });
    endpoint.at(Now::from_millis(2)).poll().expect("poll");
    assert_eq!(endpoint.connection_info(direct), None, "closed");
    assert_eq!(endpoint.path(&peer), None);
}

/// A Connected terminal names the path it settled on, even when that
/// connection is replaced before the application reads the terminal.
#[test]
fn a_settled_attempt_keeps_its_path_after_the_connection_is_replaced() {
    let identity = Ed25519Keypair::from_secret_key_bytes([36; 32]);
    let peer = Ed25519Keypair::from_secret_key_bytes([37; 32]).peer_id();
    let relay = Ed25519Keypair::from_secret_key_bytes([38; 32]).peer_id();
    let circuit = ConnectionId::namespaced(ConnectionNamespace::CIRCUIT, 1).expect("id");
    let circuit_addr = Multiaddr::from_protocols(vec![Protocol::P2p(relay), Protocol::P2pCircuit]);
    let direct = ConnectionId::namespaced(ConnectionNamespace::TCP_IPV4, 1).expect("id");
    let direct_addr: Multiaddr = "/ip4/192.0.2.8/tcp/4001".parse().expect("address");
    let transport = RecordingTransport {
        events: vec![TransportEvent::Connected {
            id: circuit,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(circuit_addr, peer)),
        }],
        local_address: direct_addr.clone(),
        next_stream_id: 0,
        closed: Rc::new(Cell::new(false)),
        broken: false,
    };
    let mut endpoint = PortableEndpointBuilder::new(&identity, ZeroEntropy, ManualClock::default())
        .build(transport)
        .expect("endpoint configuration is valid");
    endpoint.at(Now::from_millis(0)).poll().expect("poll");

    // Settles at once on the circuit; a direct connection replaces it
    // before the terminal is read.
    let target = PeerAddr::new(direct_addr.clone(), peer).expect("peer addr");
    let id = endpoint
        .at(Now::from_millis(1))
        .connect(target)
        .expect("connect admitted");
    endpoint
        .engine
        .core
        .transport_mut()
        .events
        .push(TransportEvent::Connected {
            id: direct,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(direct_addr, peer)),
        });
    let events = endpoint.at(Now::from_millis(2)).poll().expect("poll");

    assert_eq!(endpoint.connection_info(circuit), None, "replaced");
    let settled = events.iter().find_map(|event| match event {
        EndpointEvent::ConnectSettled {
            connect_id,
            outcome,
            ..
        } if *connect_id == id => Some(outcome),
        _ => None,
    });
    assert_eq!(
        settled,
        Some(&ConnectOutcome::Connected {
            conn_id: circuit,
            path: Path::Relayed { relay },
        }),
        "{events:?}"
    );
}

/// `ready_protocols` is `None` until the connection is identified, then
/// the protocols the peer advertised on it.
#[test]
fn connection_info_reports_protocols_once_identified() {
    let a_identity = Ed25519Keypair::from_secret_key_bytes([34; 32]);
    let b_identity = Ed25519Keypair::from_secret_key_bytes([35; 32]);
    let (a_transport, b_transport) =
        InMemoryTransport::pair(a_identity.peer_id(), b_identity.peer_id());
    let conn_id = a_transport.connection_id();
    let mut a = PortableEndpointBuilder::new(&a_identity, ZeroEntropy, ManualClock::default())
        .build(a_transport)
        .expect("a endpoint configuration is valid");
    let mut b = PortableEndpointBuilder::new(&b_identity, ZeroEntropy, ManualClock::default())
        .protocol("/app/1")
        .build(b_transport)
        .expect("b endpoint configuration is valid");

    a.at(Now::from_millis(0)).poll().expect("drive a");
    let info = a.connection_info(conn_id).expect("established");
    assert_eq!(info.path, Path::Direct);
    assert_eq!(info.ready_protocols, None, "not identified yet");

    for now_ms in 1..64 {
        b.at(Now::from_millis(now_ms)).poll().expect("drive b");
        a.at(Now::from_millis(now_ms)).poll().expect("drive a");
        if a.is_peer_ready(&b_identity.peer_id()) {
            break;
        }
    }
    let protocols = a
        .connection_info(conn_id)
        .and_then(|info| info.ready_protocols)
        .expect("identified");
    assert!(protocols.iter().any(|protocol| protocol == "/app/1"));
}

#[test]
fn portable_stats_count_identify_ready_peers() {
    let a_identity = Ed25519Keypair::from_secret_key_bytes([11; 32]);
    let b_identity = Ed25519Keypair::from_secret_key_bytes([12; 32]);
    let (a_transport, b_transport) =
        InMemoryTransport::pair(a_identity.peer_id(), b_identity.peer_id());
    let mut a = PortableEndpointBuilder::new(&a_identity, ZeroEntropy, ManualClock::default())
        .build(a_transport)
        .expect("a endpoint configuration is valid");
    let mut b = PortableEndpointBuilder::new(&b_identity, ZeroEntropy, ManualClock::default())
        .build(b_transport)
        .expect("b endpoint configuration is valid");

    for now_ms in 0..64 {
        a.at(Now::from_millis(now_ms)).poll().expect("drive a");
        b.at(Now::from_millis(now_ms)).poll().expect("drive b");
        if a.is_peer_ready(&b_identity.peer_id()) && b.is_peer_ready(&a_identity.peer_id()) {
            break;
        }
    }

    assert_eq!(a.stats().connected_peers, 1);
    assert_eq!(a.stats().ready_peers, 1);
    assert_eq!(b.stats().connected_peers, 1);
    assert_eq!(b.stats().ready_peers, 1);
    assert!(
        a.connection_id(&b_identity.peer_id()).is_some(),
        "connection id is visible through the State getter"
    );
    assert!(!a.bound_addresses().is_empty());
}

#[test]
fn portable_connect_settles_when_the_peer_is_already_connected() {
    let a_identity = Ed25519Keypair::from_secret_key_bytes([21; 32]);
    let b_identity = Ed25519Keypair::from_secret_key_bytes([22; 32]);
    let (a_transport, b_transport) =
        InMemoryTransport::pair(a_identity.peer_id(), b_identity.peer_id());
    let mut a = PortableEndpointBuilder::new(&a_identity, ZeroEntropy, ManualClock::default())
        .build(a_transport)
        .expect("a endpoint configuration is valid");
    let mut b = PortableEndpointBuilder::new(&b_identity, ZeroEntropy, ManualClock::default())
        .build(b_transport)
        .expect("b endpoint configuration is valid");

    for now_ms in 0..64 {
        a.at(Now::from_millis(now_ms)).poll().expect("drive a");
        b.at(Now::from_millis(now_ms)).poll().expect("drive b");
        if a.connection_id(&b_identity.peer_id()).is_some() {
            break;
        }
    }
    let conn_id = a
        .connection_id(&b_identity.peer_id())
        .expect("pair is connected");
    let target = PeerAddr::new(
        "/ip4/192.0.2.2/udp/4002/quic-v1".parse().expect("address"),
        b_identity.peer_id(),
    )
    .expect("peer addr");
    let id = a
        .at(Now::from_millis(80))
        .connect(target)
        .expect("connect admitted");
    let events = a.at(Now::from_millis(80)).poll().expect("drain settled");
    assert!(events.iter().any(|event| matches!(
        event,
        EndpointEvent::ConnectSettled {
            connect_id,
            outcome: ConnectOutcome::Connected { conn_id: settled, .. },
            ..
        } if *connect_id == id && *settled == conn_id
    )));
}

#[test]
fn portable_shutdown_closes_established_peers_and_releases_the_endpoint() {
    let identity = Ed25519Keypair::from_secret_key_bytes([9; 32]);
    let remote = Ed25519Keypair::from_secret_key_bytes([10; 32]).peer_id();
    let address: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().expect("address");
    let conn_id = ConnectionId::new(1);
    let closed = Rc::new(Cell::new(false));
    let transport = RecordingTransport {
        events: vec![TransportEvent::Connected {
            id: conn_id,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(address.clone(), remote)),
        }],
        local_address: address.clone(),
        next_stream_id: 0,
        closed: closed.clone(),
        broken: false,
    };
    let mut endpoint = PortableEndpointBuilder::new(&identity, ZeroEntropy, ManualClock::default())
        .build(transport)
        .expect("portable endpoint configuration is valid");

    endpoint
        .at(Now::from_millis(1))
        .poll()
        .expect("connection event is accepted");
    assert_eq!(
        endpoint.stats(),
        EndpointStats {
            connected_peers: 1,
            ready_peers: 0,
            bound_addresses: vec![address],
        }
    );

    endpoint.at(Now::from_millis(2));

    let report = endpoint.close();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert!(report.unfinished.is_empty(), "{:?}", report.unfinished);
    assert!(
        closed.get(),
        "the established transport connection was closed"
    );
    assert!(report.events.iter().any(|event| matches!(
        event,
        EndpointEvent::ConnectionClosed { peer_id, conn_id: closed_id, .. }
            if peer_id == &remote && closed_id == &conn_id
    )));
}

/// A failed final drive still hands over the events the shutdown
/// queued (here the close failure the swarm reported), reports the
/// error, and lists the connection the transport drop abandons.
#[test]
fn a_failed_shutdown_still_reports_its_events_errors_and_unfinished() {
    let identity = Ed25519Keypair::from_secret_key_bytes([13; 32]);
    let remote = Ed25519Keypair::from_secret_key_bytes([14; 32]).peer_id();
    let address: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().expect("address");
    let conn_id = ConnectionId::new(1);
    let transport = RecordingTransport {
        events: vec![TransportEvent::Connected {
            id: conn_id,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(address.clone(), remote)),
        }],
        local_address: address,
        next_stream_id: 0,
        closed: Rc::new(Cell::new(false)),
        broken: false,
    };
    let mut endpoint = PortableEndpointBuilder::new(&identity, ZeroEntropy, ManualClock::default())
        .build(transport)
        .expect("portable endpoint configuration is valid");
    endpoint.at(Now::from_millis(1)).poll().expect("connected");
    endpoint.engine.core.transport_mut().broken = true;

    endpoint.at(Now::from_millis(2));

    let report = endpoint.close();
    assert!(
        matches!(
            report.errors.as_slice(),
            [DriverError::Transport(TransportError::PollError { .. })]
        ),
        "{:?}",
        report.errors
    );
    assert!(
        report.events.iter().any(|event| matches!(
            event,
            EndpointEvent::Error(error) if error.conn_id == Some(conn_id)
        )),
        "the close failure was dropped: {:?}",
        report.events
    );
    assert_eq!(report.unfinished, vec![(conn_id, Some(remote))]);
    assert_eq!(report.outcome, CloseOutcome::Failed);
}

/// A clock that advances on every read, counting the reads.
struct CountingClock {
    reads: Rc<Cell<u64>>,
}

impl Clock for CountingClock {
    fn now(&mut self) -> Now {
        self.reads.set(self.reads.get() + 1);
        Now::from_millis(self.reads.get())
    }
}

/// `poll` and the whole of `close` (its `Drop` included, after a failed
/// final drive left the peer connected) each sample the clock once.
#[test]
fn poll_and_close_each_sample_the_clock_once() {
    let identity = Ed25519Keypair::from_secret_key_bytes([15; 32]);
    let remote = Ed25519Keypair::from_secret_key_bytes([16; 32]).peer_id();
    let address: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().expect("address");
    let transport = RecordingTransport {
        events: vec![TransportEvent::Connected {
            id: ConnectionId::new(1),
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(address.clone(), remote)),
        }],
        local_address: address,
        next_stream_id: 0,
        closed: Rc::new(Cell::new(false)),
        broken: false,
    };
    let reads = Rc::new(Cell::new(0));
    let mut endpoint = PortableEndpointBuilder::new(
        &identity,
        ZeroEntropy,
        CountingClock {
            reads: reads.clone(),
        },
    )
    .build(transport)
    .expect("portable endpoint configuration is valid");

    let before = reads.get();
    endpoint.poll().expect("connected");
    assert_eq!(reads.get(), before + 1, "poll samples once");
    endpoint.engine.core.transport_mut().broken = true;

    let before = reads.get();
    let report = endpoint.close();
    assert!(!report.unfinished.is_empty(), "the peer survives the drive");
    assert_eq!(reads.get(), before + 1, "close and its Drop sample once");
}

#[cfg(all(feature = "smoltcp", feature = "pubsub"))]
#[test]
fn smoltcp_shutdown_returns_gossipsub_events_still_in_the_agent() {
    use minip2p_pubsub::{GossipsubEvent, MESHSUB_PROTOCOL_ID_V11, Rpc, SubOpts, encode_frame};
    use smoltcp::iface::{Config, Interface};
    use smoltcp::phy::{Loopback, Medium};
    use smoltcp::wire::HardwareAddress;

    let identity = Ed25519Keypair::from_secret_key_bytes([70; 32]);
    let mut device = Loopback::new(Medium::Ip);
    let interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        smoltcp::time::Instant::from_millis(0),
    );
    let mut endpoint = PortableEndpointBuilder::new(&identity, ZeroEntropy, ManualClock::default())
        .smoltcp(SmoltcpStack::new(device, interface))
        .gossipsub()
        .build()
        .expect("embedded endpoint builds");

    // An inbound meshsub stream carrying a subscribe leaves
    // `PeerSubscribed` in the agent; nothing has polled it out yet.
    let peer = Ed25519Keypair::from_secret_key_bytes([71; 32]).peer_id();
    let (conn_id, stream_id) = (ConnectionId::new(1), StreamId::new(1));
    let agent = &mut endpoint.engine.gossipsub.as_mut().expect("gossipsub").agent;
    assert!(agent.handle_event(
        &SwarmEvent::StreamReady {
            peer_id: peer,
            conn_id,
            stream_id,
            protocol_id: MESHSUB_PROTOCOL_ID_V11.into(),
            initiated_locally: false,
        },
        0,
    ));
    let rpc = Rpc {
        subscriptions: vec![SubOpts {
            subscribe: Some(true),
            topic_id: Some("still-in-agent".into()),
        }],
        publish: Vec::new(),
        control: None,
    };
    assert!(agent.handle_event(
        &SwarmEvent::StreamData {
            peer_id: peer,
            conn_id,
            stream_id,
            data: Bytes::from(encode_frame(&rpc.encode())),
        },
        0,
    ));

    endpoint.at(Now::from_millis(0));

    let report = endpoint.close();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    let events = report.events;
    assert!(
        events.iter().any(|event| matches!(
            event,
            EndpointEvent::Gossipsub(GossipsubEvent::PeerSubscribed {
                peer: returned,
                topic,
            }) if returned == &peer && topic == "still-in-agent"
        )),
        "shutdown dropped a Gossipsub event still in the agent: {events:?}"
    );
}
