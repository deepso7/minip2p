//! Sans-I/O libp2p mDNS discovery with an optional synchronous socket driver.
//!
//! The deterministic [`MdnsAgent`] owns DNS scheduling and validation while
//! callers provide time, interface snapshots, and datagrams. With the default
//! `std` feature, the crate also provides a socket adapter.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod agent;
mod config;
mod dns;
mod events;
#[cfg(feature = "std")]
mod socket;

pub use agent::MdnsAgent;
pub use config::{MdnsConfig, MdnsConfigError};
pub use dns::{
    CLASS_IN, DnsCodecError, DnsMessage, DnsQuestion, DnsRecord, DnsRecordData,
    MDNS_MAX_DECODE_BYTES, META_QUERY_NAME, SERVICE_NAME, TYPE_PTR, TYPE_TXT,
};
pub use events::{
    InterfaceId, InterfaceSnapshot, IpFamily, IpNet, MdnsAction, MdnsEvent, MdnsTarget,
};
#[cfg(feature = "std")]
pub use socket::{MdnsError, MdnsSockets};
