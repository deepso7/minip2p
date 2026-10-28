//! Endpoint setup tests, once for both endpoints: the validation rules, the
//! protocols each configuration advertises (as a peer learns them through
//! Identify), auto-NAT, and seeding from the engine's entropy.

// Which capability fields exist depends on the build, so a struct update
// that fills the rest is needless in some builds only.
#![allow(
    clippy::needless_update,
    reason = "capability fields exist only in some builds"
)]

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use minip2p_core::PeerAddr;
use minip2p_core::platform::{EntropyError, EntropySource, Now};
use minip2p_identity::Ed25519Keypair;
use minip2p_swarm::SwarmBuilder;
use minip2p_test_support::InMemoryTransport;

use super::{Capabilities, Platform, SetupError, install, validate};
use crate::engine::Engine;
use crate::portable::StreamAcks;
use crate::portable::connect::Expansion;
#[cfg(feature = "autonat")]
use {
    super::NatConfigError,
    minip2p_nat::{NatConfig, ReservationPolicy},
};

struct CountingEntropy(u8);

impl EntropySource for CountingEntropy {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        for byte in output {
            self.0 = self.0.wrapping_add(1);
            *byte = self.0;
        }
        Ok(())
    }
}

/// An entropy source that always fails, as a broken OS RNG would.
#[cfg(any(feature = "autonat", feature = "pubsub", feature = "mdns"))]
struct FailingEntropy;

#[cfg(any(feature = "autonat", feature = "pubsub", feature = "mdns"))]
impl EntropySource for FailingEntropy {
    fn fill_bytes(&mut self, _: &mut [u8]) -> Result<(), EntropyError> {
        Err(EntropyError::unavailable("no entropy"))
    }
}

/// The std endpoint with QUIC: runs DCUtR, has circuits.
const STD_QUIC: Platform = Platform {
    runs_dcutr: true,
    has_circuits: true,
    mdns_shares_transport: false,
};

/// A portable endpoint built with circuits: no DCUtR.
#[cfg(feature = "relay")]
const PORTABLE_CIRCUITS: Platform = Platform {
    runs_dcutr: false,
    has_circuits: true,
    mdns_shares_transport: true,
};

/// A portable endpoint over a plain transport.
const PORTABLE_PLAIN: Platform = Platform {
    runs_dcutr: false,
    has_circuits: false,
    mdns_shares_transport: true,
};

#[cfg(feature = "mdns")]
type TestCarrier = alloc::boxed::Box<dyn minip2p_mdns::MdnsIo>;
#[cfg(not(feature = "mdns"))]
type TestCarrier = ();

type TestEngine<E> = Engine<InMemoryTransport, E, TestCarrier>;

fn key(byte: u8) -> Ed25519Keypair {
    Ed25519Keypair::from_secret_key_bytes([byte; 32])
}

#[cfg(feature = "autonat")]
fn server(byte: u8) -> PeerAddr {
    PeerAddr::new(
        "/ip4/192.0.2.9/tcp/4001".parse().expect("address"),
        key(byte).peer_id(),
    )
    .expect("peer address")
}

fn engine<E: EntropySource>(
    identity: &Ed25519Keypair,
    transport: InMemoryTransport,
    entropy: E,
) -> TestEngine<E> {
    let core = SwarmBuilder::new(identity)
        .build_core(transport, entropy)
        .expect("swarm");
    Engine::new(core, 30_000, StreamAcks::default())
}

fn setup<E: EntropySource>(
    engine: &mut TestEngine<E>,
    capabilities: Capabilities,
    platform: Platform,
    identity: &Ed25519Keypair,
) -> Result<(), SetupError> {
    let validated = validate(capabilities, platform, &identity.peer_id())?;
    install(
        engine,
        validated,
        identity,
        #[cfg(feature = "relay")]
        None,
        #[cfg(feature = "mdns")]
        None,
    )
}

/// Validates `capabilities` for `platform`, for the rules that need no
/// engine.
#[cfg(feature = "autonat")]
fn check(capabilities: Capabilities, platform: Platform) -> Result<(), SetupError> {
    validate(capabilities, platform, &key(1).peer_id()).map(drop)
}

/// Installs `capabilities` on one endpoint and returns the protocols a
/// plain peer learns through Identify.
fn advertised(capabilities: Capabilities, platform: Platform) -> Vec<String> {
    let (a_id, b_id) = (key(1), key(2));
    let (a_transport, b_transport) = InMemoryTransport::pair(a_id.peer_id(), b_id.peer_id());
    let mut a = engine(&a_id, a_transport, CountingEntropy(0));
    setup(&mut a, capabilities, platform, &a_id).expect("installs");
    let mut b = engine(&b_id, b_transport, CountingEntropy(1));
    let mut expand = |addr: &PeerAddr| Expansion::Ready(vec![addr.clone()]);
    for ms in 0..64 {
        let now = Now::from_millis(ms);
        a.drive(now, &mut expand).expect("drive a");
        b.drive(now, &mut expand).expect("drive b");
        if b.core.is_peer_ready(&a_id.peer_id()) {
            break;
        }
    }
    b.core
        .peer_info(&a_id.peer_id())
        .expect("identified")
        .protocols
        .clone()
}

fn has(protocols: &[String], id: &str) -> bool {
    protocols.iter().any(|protocol| protocol == id)
}

#[cfg(feature = "autonat")]
fn nat(config: NatConfig) -> Capabilities {
    Capabilities {
        nat: Some(config),
        ..Capabilities::default()
    }
}

#[cfg(feature = "autonat")]
fn nat_error(result: Result<(), SetupError>) -> NatConfigError {
    match result {
        Err(SetupError::NatConfig(error)) => error,
        other => panic!("expected a NAT config error, got {other:?}"),
    }
}

/// NAT with nothing to talk to is refused on every platform, as is a
/// reservation policy without a relay to reserve on.
#[cfg(feature = "autonat")]
#[test]
fn nat_needs_a_server_and_a_reservation_needs_a_relay() {
    for platform in [STD_QUIC, PORTABLE_PLAIN] {
        assert_eq!(
            nat_error(check(nat(NatConfig::default()), platform)),
            NatConfigError::NoServers
        );
        let autonat_only = NatConfig {
            autonat_servers: vec![server(3)],
            ..NatConfig::default()
        };
        assert_eq!(
            nat_error(check(nat(autonat_only.clone()), platform)),
            NatConfigError::ReservationWithoutRelay
        );
        check(
            nat(NatConfig {
                reservation_policy: ReservationPolicy::Never,
                ..autonat_only
            }),
            platform,
        )
        .expect("AutoNAT without a reservation runs");
    }
}

/// Relay errors follow the platform: circuits are needed, and DCUtR must be
/// off (or the relay forced) where the endpoint does not run it.
#[cfg(feature = "relay")]
#[test]
fn relays_are_checked_against_the_platform() {
    let relayed = |dcutr: bool, force_relay: bool| {
        nat(NatConfig {
            relays: vec![server(3)],
            dcutr,
            force_relay,
            ..NatConfig::default()
        })
    };
    assert_eq!(
        nat_error(check(relayed(false, false), PORTABLE_PLAIN)),
        NatConfigError::RelayWithoutCircuits
    );
    assert_eq!(
        nat_error(check(relayed(true, false), PORTABLE_CIRCUITS)),
        NatConfigError::RelayWithDcutr
    );
    check(relayed(false, false), PORTABLE_CIRCUITS).expect("DCUtR off runs");
    check(relayed(true, true), PORTABLE_CIRCUITS).expect("a forced relay runs");
    check(relayed(true, false), STD_QUIC).expect("std with QUIC runs DCUtR");
}

/// Relays need the `relay` feature even where AutoNAT is built.
#[cfg(all(feature = "autonat", not(feature = "relay")))]
#[test]
fn relays_without_the_relay_feature_are_refused() {
    let config = NatConfig {
        relays: vec![server(3)],
        dcutr: false,
        ..NatConfig::default()
    };
    assert_eq!(
        nat_error(check(nat(config), STD_QUIC)),
        NatConfigError::RelayFeatureMissing
    );
}

/// An AutoNAT client advertises AutoNAT and nothing a relay client would.
#[cfg(feature = "autonat")]
#[test]
fn an_autonat_client_advertises_only_autonat() {
    let protocols = advertised(
        nat(NatConfig {
            autonat_servers: vec![server(3)],
            reservation_policy: ReservationPolicy::Never,
            ..NatConfig::default()
        }),
        STD_QUIC,
    );
    assert!(
        has(&protocols, minip2p_nat::AUTONAT_PROTOCOL_ID),
        "{protocols:?}"
    );
    assert!(
        !has(&protocols, minip2p_nat::STOP_PROTOCOL_ID),
        "{protocols:?}"
    );
    assert!(
        !has(&protocols, minip2p_nat::DCUTR_PROTOCOL_ID),
        "{protocols:?}"
    );
}

/// A relay client advertises STOP; DCUtR only where the platform runs it
/// and the config upgrades (DCUtR on, relay not forced).
#[cfg(feature = "relay")]
#[test]
fn a_relay_client_advertises_dcutr_only_where_it_runs() {
    let relayed = |dcutr: bool, force_relay: bool| {
        nat(NatConfig {
            relays: vec![server(3)],
            dcutr,
            force_relay,
            reservation_policy: ReservationPolicy::Never,
            ..NatConfig::default()
        })
    };
    let std_quic = advertised(relayed(true, false), STD_QUIC);
    assert!(
        has(&std_quic, minip2p_nat::STOP_PROTOCOL_ID),
        "{std_quic:?}"
    );
    assert!(
        has(&std_quic, minip2p_nat::DCUTR_PROTOCOL_ID),
        "{std_quic:?}"
    );
    assert!(
        !has(&std_quic, minip2p_nat::AUTONAT_PROTOCOL_ID),
        "{std_quic:?}"
    );

    let forced = advertised(relayed(true, true), STD_QUIC);
    assert!(!has(&forced, minip2p_nat::DCUTR_PROTOCOL_ID), "{forced:?}");

    let portable = advertised(relayed(false, false), PORTABLE_CIRCUITS);
    assert!(
        has(&portable, minip2p_nat::STOP_PROTOCOL_ID),
        "{portable:?}"
    );
    assert!(
        !has(&portable, minip2p_nat::DCUTR_PROTOCOL_ID),
        "{portable:?}"
    );
}

/// A relay server advertises inbound HOP.
#[cfg(feature = "relay-server")]
#[test]
fn a_relay_server_advertises_hop() {
    let protocols = advertised(
        Capabilities {
            relay_server: Some(super::RelayServerSetup {
                config: minip2p_relay_server::RelayServerConfig::default(),
                announce_addrs: Vec::new(),
            }),
            ..Capabilities::default()
        },
        PORTABLE_PLAIN,
    );
    assert!(
        has(&protocols, "/libp2p/circuit/relay/0.2.0/hop"),
        "{protocols:?}"
    );
}

/// Gossipsub advertises its protocol ids.
#[cfg(feature = "pubsub")]
#[test]
fn gossipsub_advertises_its_protocols() {
    let protocols = advertised(
        Capabilities {
            gossipsub: Some(minip2p_pubsub::GossipsubConfig::default()),
            ..Capabilities::default()
        },
        PORTABLE_PLAIN,
    );
    for id in minip2p_pubsub::GOSSIPSUB_PROTOCOL_IDS {
        assert!(has(&protocols, id), "{protocols:?}");
    }
}

/// Nothing configured advertises no capability protocol.
#[test]
fn an_endpoint_without_capabilities_advertises_only_identify_and_ping() {
    for platform in [STD_QUIC, PORTABLE_PLAIN] {
        let protocols = advertised(Capabilities::default(), platform);
        assert!(has(&protocols, "/ipfs/id/1.0.0"), "{protocols:?}");
        assert!(has(&protocols, "/ipfs/ping/1.0.0"), "{protocols:?}");
        assert_eq!(protocols.len(), 2, "{protocols:?}");
    }
}

#[cfg(all(feature = "discovery", feature = "autonat"))]
fn discovery_only() -> Capabilities {
    Capabilities {
        gossipsub: Some(minip2p_pubsub::GossipsubConfig::default()),
        beacon: Some(minip2p_discovery::BeaconConfig::default()),
        ..Capabilities::default()
    }
}

/// Discovery turns NAT on with no servers and no reservation, so discovered
/// peers go through the connect race, and advertises no NAT protocol.
#[cfg(all(feature = "discovery", feature = "autonat"))]
#[test]
fn discovery_turns_nat_on_without_advertising_it() {
    let identity = key(1);
    let (transport, _) = InMemoryTransport::pair(identity.peer_id(), key(2).peer_id());
    let mut engine = engine(&identity, transport, CountingEntropy(0));
    setup(&mut engine, discovery_only(), STD_QUIC, &identity).expect("installs");
    assert!(engine.nat.is_some(), "auto-NAT");
    assert!(engine.discovery.is_some());

    let protocols = advertised(discovery_only(), STD_QUIC);
    for id in [
        minip2p_nat::AUTONAT_PROTOCOL_ID,
        minip2p_nat::STOP_PROTOCOL_ID,
        minip2p_nat::DCUTR_PROTOCOL_ID,
        "/libp2p/circuit/relay/0.2.0/hop",
    ] {
        assert!(!has(&protocols, id), "{protocols:?}");
    }

    // Only NAT that discovery turned on goes without a server: an explicit
    // config still needs one.
    let capabilities = Capabilities {
        nat: Some(super::no_reservation_nat()),
        ..discovery_only()
    };
    assert_eq!(
        nat_error(check(capabilities, PORTABLE_PLAIN)),
        NatConfigError::NoServers
    );
}

/// Without discovery, nothing turns NAT on.
#[cfg(feature = "autonat")]
#[test]
fn without_discovery_nat_stays_off() {
    let identity = key(1);
    let (transport, _) = InMemoryTransport::pair(identity.peer_id(), key(2).peer_id());
    let mut engine = engine(&identity, transport, CountingEntropy(0));
    setup(&mut engine, Capabilities::default(), STD_QUIC, &identity).expect("installs");
    assert!(engine.nat.is_none());
}

/// Installs `capabilities` over a failing entropy source, with `carrier` as
/// the mDNS carrier, and expects setup to fail on the seed draw.
#[cfg(any(feature = "autonat", feature = "pubsub", feature = "mdns"))]
fn assert_seed_failure_fails_setup(
    capabilities: Capabilities,
    #[cfg(feature = "mdns")] carrier: Option<TestCarrier>,
) {
    let identity = key(1);
    let (transport, _) = InMemoryTransport::pair(identity.peer_id(), key(2).peer_id());
    let mut engine = engine(&identity, transport, FailingEntropy);
    let validated = validate(capabilities, PORTABLE_PLAIN, &identity.peer_id()).expect("validates");
    let result = install(
        &mut engine,
        validated,
        &identity,
        #[cfg(feature = "relay")]
        None,
        #[cfg(feature = "mdns")]
        carrier,
    );
    assert!(matches!(result, Err(SetupError::Entropy(_))), "{result:?}");
}

/// Seeds come from the engine's entropy, with no fallback: a failing source
/// fails setup for NAT jitter, Gossipsub, and mDNS alike.
#[cfg(feature = "autonat")]
#[test]
fn a_failing_entropy_source_fails_nat_setup() {
    assert_seed_failure_fails_setup(
        nat(NatConfig {
            autonat_servers: vec![server(3)],
            reservation_policy: ReservationPolicy::Never,
            ..NatConfig::default()
        }),
        #[cfg(feature = "mdns")]
        None,
    );
}

#[cfg(feature = "pubsub")]
#[test]
fn a_failing_entropy_source_fails_gossipsub_setup() {
    assert_seed_failure_fails_setup(
        Capabilities {
            gossipsub: Some(minip2p_pubsub::GossipsubConfig::default()),
            ..Capabilities::default()
        },
        #[cfg(feature = "mdns")]
        None,
    );
}

/// An mDNS carrier with no interfaces that never has input.
#[cfg(feature = "mdns")]
struct IdleMdns;

#[cfg(feature = "mdns")]
impl minip2p_mdns::MdnsIo for IdleMdns {
    fn interfaces(&self) -> &[minip2p_mdns::InterfaceSnapshot] {
        &[]
    }
    fn refresh(&mut self) -> Result<bool, minip2p_mdns::MdnsError> {
        Ok(false)
    }
    fn receive(
        &mut self,
        _: &mut [u8],
    ) -> Result<Option<minip2p_mdns::MdnsDatagram>, minip2p_mdns::MdnsError> {
        Ok(None)
    }
    fn send(&mut self, _: &minip2p_mdns::MdnsAction) -> Result<(), minip2p_mdns::MdnsError> {
        Ok(())
    }
}

#[cfg(feature = "mdns")]
#[test]
fn a_failing_entropy_source_fails_mdns_setup() {
    assert_seed_failure_fails_setup(
        Capabilities {
            mdns: Some(minip2p_mdns::MdnsConfig::default()),
            ..Capabilities::default()
        },
        Some(alloc::boxed::Box::new(IdleMdns)),
    );
}
