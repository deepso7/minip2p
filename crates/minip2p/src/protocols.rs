//! Interned application protocol handles (ADR 0031).
//!
//! An endpoint numbers each application protocol it registers, in
//! registration order, and hands out the number as a [`ProtocolId`]: a
//! `Copy` handle that [`EndpointEvent::StreamReady`](crate::EndpointEvent::StreamReady)
//! carries and [`open_stream`](crate::Endpoint::open_stream) takes, so a
//! dispatcher compares two integers instead of two strings. The string id
//! stays the protocol's identity on the wire, in the builder's
//! `.protocol(&str)`, and in every binding.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use minip2p_swarm::{DriverError, SwarmError};

/// A handle for one of an endpoint's application protocols.
///
/// Issued by the endpoint that registered the protocol, from
/// [`Endpoint::protocol_id`](crate::Endpoint::protocol_id) or
/// [`Endpoint::add_protocol`](crate::Endpoint::add_protocol), and carried on
/// [`EndpointEvent::StreamReady`](crate::EndpointEvent::StreamReady).
/// [`Endpoint::protocol_name`](crate::Endpoint::protocol_name) turns it back
/// into the string id.
///
/// A handle is an index into its endpoint's table, not a checked token:
/// keep it with the endpoint that issued it. Two endpoints number their
/// protocols independently, so another endpoint resolves the same handle
/// to whatever it registered at that position, or to nothing.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolId(u16);

impl ProtocolId {
    /// The handle's number: the protocol's position in its endpoint's
    /// registration order.
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

impl fmt::Display for ProtocolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "protocol #{}", self.0)
    }
}

/// The protocol [`Endpoint::open_stream`](crate::Endpoint::open_stream)
/// negotiates: a [`ProtocolId`] handle or the protocol's string id. Both
/// convert with `.into()`, so `open_stream(&peer, "/chat/1")` and
/// `open_stream(&peer, chat)` both work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolRef<'a> {
    /// A handle this endpoint issued.
    Id(ProtocolId),
    /// A string protocol id.
    Name(&'a str),
}

impl From<ProtocolId> for ProtocolRef<'_> {
    fn from(id: ProtocolId) -> Self {
        Self::Id(id)
    }
}

impl<'a> From<&'a str> for ProtocolRef<'a> {
    fn from(name: &'a str) -> Self {
        Self::Name(name)
    }
}

impl<'a> From<&'a String> for ProtocolRef<'a> {
    fn from(name: &'a String) -> Self {
        Self::Name(name)
    }
}

/// The handle never issued: what a `StreamReady` for a protocol the table
/// could not name carries (only past the table's capacity).
const UNNAMED: ProtocolId = ProtocolId(u16::MAX);

/// Why registering one more protocol failed.
pub(crate) const TABLE_FULL: &str = "an endpoint names at most 65,535 application protocols";

/// An endpoint's protocol names, indexed by [`ProtocolId`].
///
/// Only ever appended to, so a handle stays valid for the endpoint's life.
/// Holds at most `u16::MAX` names; `u16::MAX` itself is never issued.
#[derive(Debug, Default)]
pub(crate) struct ProtocolTable {
    names: Vec<String>,
}

impl ProtocolTable {
    /// The handle for `name`, if the table holds it.
    pub(crate) fn id(&self, name: &str) -> Option<ProtocolId> {
        let index = self.names.iter().position(|known| known == name)?;
        u16::try_from(index).ok().map(ProtocolId)
    }

    /// The name behind `id`, if this table issued it.
    pub(crate) fn name(&self, id: ProtocolId) -> Option<&str> {
        self.names.get(usize::from(id.0)).map(String::as_str)
    }

    /// The handle the next new name gets; `None` when the table is full.
    fn next_id(&self) -> Option<ProtocolId> {
        u16::try_from(self.names.len())
            .ok()
            .filter(|&index| index != UNNAMED.0)
            .map(ProtocolId)
    }

    /// The handle for `name`, numbering it if it is new; `None` only when
    /// the table is full.
    fn try_intern(&mut self, name: &str) -> Option<ProtocolId> {
        if let Some(id) = self.id(name) {
            return Some(id);
        }
        let id = self.next_id()?;
        self.names.push(name.to_string());
        Some(id)
    }

    /// Fails as [`Self::intern`] would for `name`, without numbering it: a
    /// registration checks this before it touches the swarm, so a refused
    /// protocol is never negotiated either.
    pub(crate) fn check_room(&self, name: &str) -> Result<(), DriverError> {
        if self.id(name).is_some() || self.next_id().is_some() {
            Ok(())
        } else {
            Err(DriverError::Invariant { reason: TABLE_FULL })
        }
    }

    /// The handle for a protocol being registered, numbering it if it is
    /// new; fails only when the table is full.
    pub(crate) fn intern(&mut self, name: &str) -> Result<ProtocolId, DriverError> {
        self.try_intern(name)
            .ok_or(DriverError::Invariant { reason: TABLE_FULL })
    }

    /// The handle a `StreamReady` for `name` carries: its own, numbered now
    /// if the protocol was registered some other way (a capability's).
    pub(crate) fn for_event(&mut self, name: &str) -> ProtocolId {
        self.try_intern(name).unwrap_or(UNNAMED)
    }

    /// The string id `protocol` names, or why it names none.
    pub(crate) fn resolve<'a>(&'a self, protocol: ProtocolRef<'a>) -> Result<&'a str, DriverError> {
        match protocol {
            ProtocolRef::Name(name) => Ok(name),
            ProtocolRef::Id(id) => self.name(id).ok_or_else(|| {
                SwarmError::ProtocolNotRegistered {
                    protocol_id: id.to_string(),
                }
                .into()
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_follow_registration_order_and_resolve_both_ways() {
        let mut table = ProtocolTable::default();
        let chat = table.intern("/chat/1").expect("room");
        let file = table.intern("/file/1").expect("room");
        assert_eq!((chat.as_u16(), file.as_u16()), (0, 1));
        assert_eq!(table.intern("/chat/1").expect("known"), chat);
        assert_eq!(table.id("/file/1"), Some(file));
        assert_eq!(table.name(file), Some("/file/1"));
        assert_eq!(table.id("/other/1"), None);
        assert_eq!(table.resolve(chat.into()).expect("issued"), "/chat/1");
        assert_eq!(table.resolve("/any/1".into()).expect("name"), "/any/1");
        assert!(matches!(
            table.resolve(ProtocolId(7).into()),
            Err(DriverError::Swarm(SwarmError::ProtocolNotRegistered { .. }))
        ));
    }

    #[test]
    fn a_full_table_refuses_only_new_names() {
        let mut table = ProtocolTable {
            names: (0..UNNAMED.0).map(|i| alloc::format!("/p/{i}")).collect(),
        };
        table
            .check_room("/p/7")
            .expect("a known name needs no room");
        table
            .check_room("/new/1")
            .expect_err("no room for a new name");
        table.intern("/new/1").expect_err("no room for a new name");
        assert_eq!(table.for_event("/new/1"), UNNAMED);
    }
}
