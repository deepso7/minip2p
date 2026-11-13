//! Relay mesh: several relay nodes serving one public relay identity.
//!
//! Mesh nodes share the relay's public identity and talk to each other over
//! a backbone, as distinct peers with their own backbone identities. Each
//! node pushes its local reservations to every other member on a directory
//! stream ([`DIRECTORY_PROTOCOL_ID`]), and an entry node that gets a CONNECT
//! for a peer reserved elsewhere forwards it to the holding node on a forward
//! stream ([`FORWARD_PROTOCOL_ID`]).
//!
//! A [`RelayServerAgent`](crate::RelayServerAgent) becomes a mesh node when
//! its config carries a [`MeshConfig`]. The host drives it over a
//! [`MeshSwarm`], which joins the public swarm and the backbone swarm; the
//! agent tells backbone connections apart by their [`ConnectionNamespace`]
//! ([`is_backbone_connection`]).
//!
//! This module also holds the wire codec for both protocols and the
//! receiver-side [`Directory`]. Like the rest of the crate it is
//! `no_std + alloc`, does no I/O, and takes time from the caller.

use alloc::collections::BTreeSet;

use minip2p_core::PeerId;
use minip2p_swarm::{EntropySource, SwarmCore, SwarmError};
use minip2p_transport::{ConnectionId, ConnectionNamespace, Transport};

mod codec;
mod directory;
mod swarm;

pub use codec::{
    DIRECTORY_PROTOCOL_ID, DirectoryMessage, FORWARD_PROTOCOL_ID, ForwardMessage,
    MAX_MESH_MESSAGE_SIZE, MeshMessageError, decode_mesh_frame,
};
pub use directory::{
    Claim, DEFAULT_MAX_DIRECTORY_ENTRIES_PER_MEMBER, Directory, DirectoryInput,
    DirectoryResetReason,
};
pub use swarm::MeshSwarm;

/// Makes a [`RelayServerAgent`](crate::RelayServerAgent) a relay-mesh node,
/// through [`RelayServerConfig::mesh`](crate::RelayServerConfig::mesh).
///
/// A mesh node needs [`Now::unix_seconds`](minip2p_core::platform::Now):
/// reservation expiries cross the backbone as UNIX seconds, so nodes need
/// synced clocks. Without it, expiries count from zero.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeshConfig {
    /// Backbone peer ids of the other members, excluding this node's own. A
    /// backbone connection from any other peer is closed when it is
    /// established. Empty is valid: the node runs alone and closes every
    /// backbone connection.
    pub members: BTreeSet<PeerId>,
    /// Most peers one member's directory may claim; a member past it has its
    /// directory stream reset and its entries dropped.
    pub max_directory_entries_per_member: usize,
}

impl MeshConfig {
    /// A mesh of `members` (other nodes' backbone peer ids) with default
    /// limits.
    pub fn new(members: impl IntoIterator<Item = PeerId>) -> Self {
        Self {
            members: members.into_iter().collect(),
            max_directory_entries_per_member: DEFAULT_MAX_DIRECTORY_ENTRIES_PER_MEMBER,
        }
    }
}

impl Default for MeshConfig {
    /// No members, default limits.
    fn default() -> Self {
        Self::new([])
    }
}

/// Whether `conn_id` is a backbone connection: one allocated in
/// [`ConnectionNamespace::MESH_IPV4`] or [`ConnectionNamespace::MESH_IPV6`].
pub const fn is_backbone_connection(conn_id: ConnectionId) -> bool {
    let tag = conn_id.namespace().get();
    tag == ConnectionNamespace::MESH_IPV4.get() || tag == ConnectionNamespace::MESH_IPV6.get()
}

/// Installs the backbone swarm's mesh protocols, inbound and outbound:
/// directory and forward. Neither is advertised.
pub fn register_backbone_roles<T, E>(swarm: &mut SwarmCore<T, E>) -> Result<(), SwarmError>
where
    T: Transport,
    E: EntropySource,
{
    for protocol in [DIRECTORY_PROTOCOL_ID, FORWARD_PROTOCOL_ID] {
        swarm.add_inbound_protocol(protocol)?;
        swarm.add_outbound_protocol(protocol)?;
    }
    Ok(())
}
