//! Sans-I/O libp2p mDNS discovery, with a driver and an optional socket
//! adapter.
//!
//! ```text
//! MdnsDriver          budgets, interface refresh, the on-link check
//!   -> MdnsAgent      DNS scheduling and validation
//!   -> MdnsIo         interfaces, datagrams in, datagrams out
//! ```
//!
//! The deterministic [`MdnsAgent`] owns DNS scheduling and validation while
//! callers provide time, interface snapshots, and datagrams. [`MdnsDriver`]
//! runs it against an [`MdnsIo`], and owns everything about *how much* to do
//! per turn -- which is policy, not platform work, so it is the same code
//! wherever the datagrams come from. `no_std + alloc`.
//!
//! With the default `std` feature, [`MdnsSockets`] is the hosted [`MdnsIo`]:
//! per-interface multicast sockets over `socket2`, with interface enumeration.
//! A host without an operating system implements [`MdnsIo`] over its own
//! stack; nothing above that seam changes.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod agent;
mod config;
mod dns;
mod driver;
mod events;
mod io;
#[cfg(feature = "std")]
mod socket;

pub use agent::MdnsAgent;
pub use config::{MdnsConfig, MdnsConfigError};
pub use dns::{DnsCodecError, DnsMessage, DnsQuestion, DnsRecord, DnsRecordData};
pub use driver::{MAX_ACTIONS_PER_TICK, MAX_DATAGRAMS_PER_TICK, MdnsDriver};
pub use events::{
    InterfaceId, InterfaceSnapshot, IpFamily, IpNet, MdnsAction, MdnsEvent, MdnsTarget,
};
pub use io::{MAX_DATAGRAM_BYTES, MdnsDatagram, MdnsError, MdnsIo};
#[cfg(feature = "std")]
pub use socket::MdnsSockets;
