//! Sans-I/O multi-source peer discovery for minip2p.
//!
//! [`BeaconAgent`] validates and schedules signed pubsub presence beacons.
//! [`PeerDiscoveryAgent`] maintains one bounded address book and dial policy
//! across authenticated beacon observations and unauthenticated mDNS claims.
//! Neither component owns sockets, clocks, streams, or an executor.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod beacon;
mod book;
mod config;
mod events;
mod message;

pub use beacon::BeaconAgent;
pub use book::PeerDiscoveryAgent;
pub use config::{BeaconConfig, DiscoveryConfigError, PeerDiscoveryConfig};
pub use events::{
    BeaconAction, BeaconEvent, DiscoveryAction, DiscoveryEvent, DiscoverySource, KnownPeer,
    Observation,
};
pub use message::{Beacon, DISCOVERY_TOPIC, DiscoveryWireError, MAX_BEACON_ADDRS, MAX_BEACON_SIZE};
pub(crate) use message::{MAX_ADDR_LEN, MAX_PUBLIC_KEY_LEN, MAX_TOPIC_LEN};
