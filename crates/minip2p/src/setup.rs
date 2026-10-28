//! Endpoint setup: the one place that turns an endpoint's capability
//! configuration into running capabilities over the shared [`Engine`], the
//! same way for the std `Endpoint` and [`crate::PortableEndpoint`].
//!
//! A builder collects [`Capabilities`]. [`validate`] checks them against
//! the [`Platform`] before any socket opens and turns NAT on for discovered
//! peers (auto-NAT); [`install`] then registers each capability's protocols
//! on the swarm and installs its agent. A capability's protocols are
//! registered, and so advertised through Identify, only when its config uses
//! them. Every seed (Gossipsub, mDNS, NAT jitter) comes from the engine's
//! entropy source, so a failing source fails the build.
//!
//! The std endpoint adds only OS resources around this: its clock and
//! readiness poll, the mDNS sockets it hands in as the carrier, parked
//! Name resolution for NAT dials, and WebTransport certificates.

#[cfg(feature = "relay-server")]
use alloc::vec::Vec;

use minip2p_core::PeerId;
use minip2p_core::platform::{EntropyError, EntropySource};
use minip2p_identity::Ed25519Keypair;
use minip2p_swarm::SwarmError;
use minip2p_transport::Transport;

#[cfg(feature = "_peer-book")]
use crate::discovery::DiscoveryDriver;
use crate::engine::{Carrier, Engine};
#[cfg(feature = "relay")]
use crate::nat::CircuitOps;
#[cfg(feature = "autonat")]
use crate::nat::NatDriver;
#[cfg(feature = "pubsub")]
use crate::pubsub::GossipsubDriver;
#[cfg(feature = "relay-server")]
use crate::relay_server::RelayServerDriver;
#[cfg(feature = "discovery")]
use minip2p_discovery::BeaconConfig;
#[cfg(feature = "_peer-book")]
use minip2p_discovery::{DiscoveryConfigError, PeerDiscoveryConfig};
#[cfg(feature = "mdns")]
use minip2p_mdns::{MdnsConfig, MdnsConfigError};
#[cfg(feature = "autonat")]
use minip2p_nat::{NatConfig, ReservationPolicy};
#[cfg(feature = "discovery")]
use minip2p_pubsub::TopicError;
#[cfg(feature = "pubsub")]
use minip2p_pubsub::{GossipsubConfig, GossipsubConfigError};
#[cfg(feature = "relay-server")]
use minip2p_relay_server::{RelayServerAddressError, RelayServerConfig, RelayServerConfigError};

/// The capability configuration a builder collected. A capability is
/// configured when its field is set; it runs only if its Cargo feature
/// built it, which the fields' own gates already ensure.
#[derive(Default)]
pub(crate) struct Capabilities {
    #[cfg(feature = "autonat")]
    pub(crate) nat: Option<NatConfig>,
    #[cfg(feature = "relay-server")]
    pub(crate) relay_server: Option<RelayServerSetup>,
    #[cfg(feature = "pubsub")]
    pub(crate) gossipsub: Option<GossipsubConfig>,
    #[cfg(feature = "discovery")]
    pub(crate) beacon: Option<BeaconConfig>,
    #[cfg(feature = "mdns")]
    pub(crate) mdns: Option<MdnsConfig>,
    #[cfg(feature = "_peer-book")]
    pub(crate) peer_discovery: PeerDiscoveryConfig,
}

impl Capabilities {
    /// Whether a discovery source (signed beacons or mDNS) is configured,
    /// whose peers the endpoint dials itself.
    #[cfg(feature = "autonat")]
    fn discovers_peers(&self) -> bool {
        #[cfg(feature = "discovery")]
        let beacon = self.beacon.is_some();
        #[cfg(not(feature = "discovery"))]
        let beacon = false;
        #[cfg(feature = "mdns")]
        let mdns = self.mdns.is_some();
        #[cfg(not(feature = "mdns"))]
        let mdns = false;
        beacon || mdns
    }
}

/// The relay server's configuration and its explicit announce addresses.
#[cfg(feature = "relay-server")]
pub(crate) struct RelayServerSetup {
    pub(crate) config: RelayServerConfig,
    pub(crate) announce_addrs: Vec<minip2p_core::Multiaddr>,
}

/// What the endpoint's platform offers its capabilities.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Platform {
    /// Whether the endpoint runs DCUtR hole punching: only the std endpoint
    /// with QUIC does.
    #[cfg_attr(
        not(feature = "autonat"),
        expect(dead_code, reason = "only NAT reads it")
    )]
    pub(crate) runs_dcutr: bool,
    /// Whether the transport has circuit operations, so relay legs and
    /// reservations can run.
    #[cfg_attr(
        not(feature = "autonat"),
        expect(dead_code, reason = "only NAT reads it")
    )]
    pub(crate) has_circuits: bool,
    /// Whether the mDNS carrier shares the transport's stack, so the
    /// transport is polled again after each mDNS tick.
    #[cfg_attr(
        not(feature = "mdns"),
        expect(dead_code, reason = "only mDNS reads it")
    )]
    pub(crate) mdns_shares_transport: bool,
}

/// Capabilities [`validate`] accepted for one platform, ready to
/// [`install`].
pub(crate) struct Validated {
    capabilities: Capabilities,
    platform: Platform,
    /// The relay server's agent, built (and its announce addresses checked)
    /// while validating.
    #[cfg(feature = "relay-server")]
    relay_server: Option<minip2p_relay_server::RelayServerAgent>,
}

/// NAT configuration that holds no reservation: what the AutoNAT and relay
/// setters start from, and what discovery turns on.
#[cfg(feature = "autonat")]
pub(crate) fn no_reservation_nat() -> NatConfig {
    NatConfig {
        reservation_policy: ReservationPolicy::Never,
        ..NatConfig::default()
    }
}

impl Validated {
    /// Whether mDNS is configured, and the configuration its carrier is
    /// built from.
    #[cfg(all(feature = "std", feature = "mdns"))]
    pub(crate) fn mdns(&self) -> Option<&MdnsConfig> {
        self.capabilities.mdns.as_ref()
    }
}

/// NAT configuration that cannot run on this endpoint.
#[cfg(feature = "autonat")]
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum NatConfigError {
    /// An explicit NAT configuration names neither a relay nor an AutoNAT
    /// server. (Discovery and mDNS turn NAT on for the peers they find
    /// without one, when no NAT configuration is given.)
    #[error(
        "NAT needs at least one relay or AutoNAT server; leave NAT unconfigured to let discovery or mDNS dial the peers they find"
    )]
    NoServers,
    /// A reservation policy other than `Never` without a relay to reserve
    /// on.
    #[error(
        "relay reservation policy requires at least one relay address; set NatConfig::reservation_policy to Never"
    )]
    ReservationWithoutRelay,
    /// Relays with DCUtR on, on an endpoint that does not run DCUtR (only
    /// the std `Endpoint` with QUIC does), so a relay is only ever a path,
    /// never an upgrade. Set `dcutr = false` to keep racing direct
    /// candidates, or `force_relay = true` to use the relay alone.
    #[error(
        "this endpoint does not run DCUtR (only the std Endpoint with QUIC does); relays need NatConfig::dcutr = false (or force_relay = true)"
    )]
    RelayWithDcutr,
    /// Relays without the `relay` feature.
    #[error("relay addresses require the relay feature")]
    RelayFeatureMissing,
    /// Relays over a transport without circuit operations.
    #[error(
        "relay addresses need circuit operations from the transport: wrap it in a CircuitTransport and build with build_with_circuits"
    )]
    RelayWithoutCircuits,
}

/// Why setup refused or failed a capability. Each endpoint maps it onto its
/// own public build error.
#[derive(Debug)]
pub(crate) enum SetupError {
    Entropy(EntropyError),
    Swarm(SwarmError),
    #[cfg(feature = "autonat")]
    NatConfig(NatConfigError),
    #[cfg(feature = "pubsub")]
    Gossipsub(GossipsubConfigError),
    #[cfg(feature = "discovery")]
    Topic(TopicError),
    #[cfg(feature = "_peer-book")]
    Discovery(DiscoveryConfigError),
    #[cfg(feature = "mdns")]
    Mdns(MdnsConfigError),
    #[cfg(feature = "relay-server")]
    RelayServer(RelayServerConfigError),
    #[cfg(feature = "relay-server")]
    RelayServerAnnounce(alloc::boxed::Box<RelayServerAddressError>),
}

impl From<EntropyError> for SetupError {
    fn from(error: EntropyError) -> Self {
        Self::Entropy(error)
    }
}

impl From<SwarmError> for SetupError {
    fn from(error: SwarmError) -> Self {
        Self::Swarm(error)
    }
}

#[cfg(feature = "_peer-book")]
impl From<DiscoveryConfigError> for SetupError {
    fn from(error: DiscoveryConfigError) -> Self {
        Self::Discovery(error)
    }
}

#[cfg(feature = "mdns")]
impl From<MdnsConfigError> for SetupError {
    fn from(error: MdnsConfigError) -> Self {
        Self::Mdns(error)
    }
}

#[cfg(feature = "relay-server")]
impl From<RelayServerConfigError> for SetupError {
    fn from(error: RelayServerConfigError) -> Self {
        Self::RelayServer(error)
    }
}

/// Validates every configured capability for `platform`, before any socket
/// opens, and turns NAT on for discovered peers (auto-NAT): with discovery
/// or mDNS configured and NAT built, an endpoint without its own NAT config
/// dials discovered peers through the connect race, with no servers and no
/// reservation. An explicit NAT config still needs a server.
///
/// `local_peer` is the identity relay-server announce addresses must name.
#[cfg_attr(
    not(feature = "relay-server"),
    expect(unused_variables, reason = "only announce addresses name the peer")
)]
#[cfg_attr(
    not(any(feature = "autonat", feature = "relay-server")),
    expect(
        unused_mut,
        reason = "only auto-NAT and the relay server change the configuration"
    )
)]
pub(crate) fn validate(
    mut capabilities: Capabilities,
    platform: Platform,
    local_peer: &PeerId,
) -> Result<Validated, SetupError> {
    #[cfg(feature = "pubsub")]
    if let Some(config) = &capabilities.gossipsub {
        config.validate().map_err(SetupError::Gossipsub)?;
    }
    #[cfg(feature = "discovery")]
    if let Some(config) = &capabilities.beacon {
        config.validate()?;
    }
    #[cfg(feature = "_peer-book")]
    capabilities.peer_discovery.validate()?;
    #[cfg(feature = "mdns")]
    if let Some(config) = &capabilities.mdns {
        config.validate()?;
    }
    #[cfg(feature = "relay-server")]
    let relay_server = match capabilities.relay_server.take() {
        Some(setup) => {
            let mut agent =
                minip2p_relay_server::RelayServerAgent::new(local_peer.clone(), setup.config)?;
            agent
                .replace_announce_addrs(setup.announce_addrs)
                .map_err(|error| SetupError::RelayServerAnnounce(alloc::boxed::Box::new(error)))?;
            Some(agent)
        }
        None => None,
    };
    #[cfg(feature = "autonat")]
    match &capabilities.nat {
        Some(config) => validate_nat(config, platform).map_err(SetupError::NatConfig)?,
        None if capabilities.discovers_peers() => capabilities.nat = Some(no_reservation_nat()),
        None => {}
    }
    Ok(Validated {
        capabilities,
        platform,
        #[cfg(feature = "relay-server")]
        relay_server,
    })
}

/// Rejects NAT configuration that cannot run on `platform`.
#[cfg(feature = "autonat")]
fn validate_nat(config: &NatConfig, platform: Platform) -> Result<(), NatConfigError> {
    let relays = !config.relays.is_empty();
    if !relays && config.autonat_servers.is_empty() {
        Err(NatConfigError::NoServers)
    } else if !relays && config.reservation_policy != ReservationPolicy::Never {
        Err(NatConfigError::ReservationWithoutRelay)
    } else if relays && cfg!(not(feature = "relay")) {
        Err(NatConfigError::RelayFeatureMissing)
    } else if relays && !platform.has_circuits {
        Err(NatConfigError::RelayWithoutCircuits)
    } else if relays && config.dcutr && !config.force_relay && !platform.runs_dcutr {
        Err(NatConfigError::RelayWithDcutr)
    } else {
        Ok(())
    }
}

/// Registers every validated capability's protocols on the engine's swarm
/// and installs its agent: relay server, NAT, Gossipsub (subscribed to the
/// beacon topic), mDNS over `mdns_carrier`, then the shared peer book.
///
/// `circuits` are the transport's circuit operations, which relay legs
/// need; [`validate`] already refused relays without them.
#[cfg_attr(
    not(any(feature = "pubsub", feature = "discovery")),
    expect(unused_variables, reason = "only Gossipsub and beacons sign")
)]
pub(crate) fn install<T: Transport, E: EntropySource, M: Carrier>(
    engine: &mut Engine<T, E, M>,
    validated: Validated,
    identity: &Ed25519Keypair,
    #[cfg(feature = "relay")] circuits: Option<CircuitOps<T>>,
    #[cfg(feature = "mdns")] mdns_carrier: Option<M>,
) -> Result<(), SetupError> {
    let Validated {
        capabilities,
        platform,
        #[cfg(feature = "relay-server")]
        relay_server,
    } = validated;
    #[cfg(not(any(feature = "autonat", feature = "mdns")))]
    let _ = platform;

    #[cfg(feature = "relay-server")]
    if let Some(mut agent) = relay_server {
        let core = &mut engine.core;
        minip2p_relay_server::RelayServerAgent::register_swarm_roles(core)?;
        // Derived from the bound transport, not configured: a rejection is
        // queued as `AddrsRejected` and drained with the first batch, like
        // any later listener refresh.
        drop(
            agent.set_listener_addrs(crate::relay_server::concrete_relay_listener_addrs(
                core.transport().local_addresses(),
            )),
        );
        engine.relay_server = Some(RelayServerDriver::new(agent));
    }

    #[cfg(feature = "autonat")]
    if let Some(config) = capabilities.nat {
        let core = &mut engine.core;
        if !config.relays.is_empty() {
            core.add_outbound_protocol(minip2p_nat::HOP_PROTOCOL_ID)?;
            core.add_inbound_protocol(minip2p_nat::STOP_PROTOCOL_ID)?;
            core.add_advertised_protocol(minip2p_nat::STOP_PROTOCOL_ID)?;
            // As the agent itself decides: a forced relay never upgrades.
            if config.dcutr && !config.force_relay && platform.runs_dcutr {
                core.add_protocol(minip2p_nat::DCUTR_PROTOCOL_ID)?;
            }
        }
        if !config.autonat_servers.is_empty() {
            core.add_protocol(minip2p_nat::AUTONAT_PROTOCOL_ID)?;
        }
        let relay_addrs = config
            .relays
            .iter()
            .map(|relay| (relay.peer_id().clone(), relay.transport().clone()))
            .collect();
        let jitter_seed = core.entropy_mut().next_u64()?;
        // The driver seeds the agent's listen addresses on its first turn.
        let agent = minip2p_nat::NatAgent::new(core.local_peer_id().clone(), config);
        let driver = NatDriver::new(agent, relay_addrs, jitter_seed);
        #[cfg(feature = "relay")]
        let driver = match circuits {
            Some(circuits) => driver.with_circuits(circuits),
            None => driver,
        };
        engine.nat = Some(driver);
    }

    #[cfg(feature = "pubsub")]
    #[cfg_attr(
        not(feature = "discovery"),
        expect(unused_mut, reason = "only the beacon subscribes during setup")
    )]
    let mut pubsub = match capabilities.gossipsub {
        Some(config) => {
            let core = &mut engine.core;
            for protocol in minip2p_pubsub::GOSSIPSUB_PROTOCOL_IDS {
                core.add_protocol(*protocol)?;
            }
            let initial_seqno = core.entropy_mut().next_u64()?;
            let seed = core.entropy_mut().next_u64()?;
            Some(
                minip2p_pubsub::GossipsubAgent::new(identity.clone(), config, initial_seqno, seed)
                    .map_err(SetupError::Gossipsub)?,
            )
        }
        None => None,
    };
    #[cfg(feature = "discovery")]
    let beacon = capabilities
        .beacon
        .map(|config| minip2p_discovery::BeaconAgent::new(identity.public_key(), config))
        .transpose()?;
    #[cfg(feature = "discovery")]
    if let (Some(pubsub), Some(beacon)) = (&mut pubsub, &beacon) {
        pubsub
            .subscribe(beacon.topic(), 0)
            .map_err(SetupError::Topic)?;
    }
    // `mdns` builds the peer book without signed beacons.
    #[cfg(all(feature = "pubsub", feature = "_peer-book", not(feature = "discovery")))]
    let beacon = None;
    #[cfg(feature = "pubsub")]
    {
        engine.gossipsub = pubsub.map(GossipsubDriver::new);
    }

    #[cfg(feature = "mdns")]
    if let (Some(config), Some(io)) = (capabilities.mdns, mdns_carrier) {
        let mut seed = [0; 32];
        engine.core.entropy_mut().fill_bytes(&mut seed)?;
        let agent = minip2p_mdns::MdnsAgent::new(
            engine.core.local_peer_id().clone(),
            config.clone(),
            seed,
        )?;
        engine.set_mdns(
            minip2p_mdns::MdnsDriver::new(agent, io, &config),
            platform.mdns_shares_transport,
        );
    }

    #[cfg(feature = "_peer-book")]
    {
        #[cfg(feature = "pubsub")]
        let beacon_enabled = beacon.is_some();
        #[cfg(not(feature = "pubsub"))]
        let beacon_enabled = false;
        #[cfg(feature = "mdns")]
        let mdns_enabled = engine.has_mdns();
        #[cfg(not(feature = "mdns"))]
        let mdns_enabled = false;
        if beacon_enabled || mdns_enabled {
            let book = minip2p_discovery::PeerDiscoveryAgent::new(
                engine.core.local_peer_id().clone(),
                capabilities.peer_discovery,
            )?;
            engine.discovery = Some(DiscoveryDriver::new(
                book,
                #[cfg(feature = "pubsub")]
                beacon,
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "setup_tests.rs"]
mod tests;
