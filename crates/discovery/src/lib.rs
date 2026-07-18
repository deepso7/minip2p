//! Sans-I/O pubsub peer discovery for minip2p.
//!
//! Peers periodically advertise signed presence beacons. The state machine
//! validates identities, maintains a bounded TTL address book, and emits dial
//! actions without owning sockets, clocks, streams, or an executor.
//! Address-less beacons refresh presence and TTL state without triggering a
//! dial request.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod agent;
mod config;
mod events;
mod message;

pub use agent::DiscoveryAgent;
pub use config::{DiscoveryConfig, DiscoveryConfigError};
pub use events::{DiscoveryAction, DiscoveryEvent, KnownPeer};
pub use message::{
    Beacon, DISCOVERY_TOPIC, DiscoveryWireError, MAX_ADDR_LEN, MAX_BEACON_ADDRS, MAX_BEACON_SIZE,
    MAX_PUBLIC_KEY_LEN, MAX_TOPIC_LEN,
};
