//! Relay mesh: several relay nodes serving one public relay identity.
//!
//! Mesh nodes share the relay's public identity and talk to each other over
//! a backbone, as distinct peers with their own backbone identities. A new
//! backbone connection starts pending: both sides prove on a member stream
//! ([`MEMBER_PROTOCOL_ID`]) that the public identity signed their backbone
//! peer id, and only a connection both proofs checked out on becomes a
//! member link (ADR 0028). Each node then pushes its local reservations to
//! every other member on a directory stream ([`DIRECTORY_PROTOCOL_ID`]), and
//! an entry node that gets a CONNECT for a peer reserved elsewhere forwards
//! it to the holding node on a forward stream ([`FORWARD_PROTOCOL_ID`]).
//!
//! A [`RelayServerAgent`](crate::RelayServerAgent) becomes a mesh node when
//! its config carries a [`MeshConfig`]. The host drives it over a
//! [`MeshSwarm`], which joins the public swarm and the backbone swarm; the
//! agent tells backbone connections apart by their [`ConnectionNamespace`]
//! ([`is_backbone_connection`]).
//!
//! This module also holds the wire codec for the three protocols and the
//! receiver-side [`Directory`]. Like the rest of the crate it is
//! `no_std + alloc`, does no I/O, and takes time from the caller.

use minip2p_core::PeerId;
use minip2p_identity::{Ed25519Keypair, PublicKey};
use minip2p_swarm::{EntropySource, SwarmCore, SwarmError};
use minip2p_transport::{ConnectionId, ConnectionNamespace, Transport};

mod backoff;
mod codec;
mod directory;
mod member;
mod swarm;

pub use backoff::Backoff;
pub use codec::{
    DIRECTORY_PROTOCOL_ID, DirectoryMessage, FORWARD_PROTOCOL_ID, ForwardMessage,
    MAX_MESH_MESSAGE_SIZE, MeshMessageError, decode_mesh_frame,
};
pub use directory::{
    Claim, DEFAULT_MAX_DIRECTORY_ENTRIES_PER_MEMBER, Directory, DirectoryInput,
    DirectoryResetReason,
};
pub use member::{
    MEMBER_ACCEPT, MEMBER_PROOF_LEN, MEMBER_PROOF_TIMEOUT_MS, MEMBER_PROTOCOL_ID,
    MemberMessageError, MemberReader, member_proof_message, sign_member_proof, verify_member_proof,
};
pub use swarm::MeshSwarm;

/// Makes a [`RelayServerAgent`](crate::RelayServerAgent) a relay-mesh node,
/// through [`RelayServerConfig::mesh`](crate::RelayServerConfig::mesh).
///
/// There is no member list: any backbone peer that proves the public
/// identity signed its backbone peer id is a member. Which members to dial
/// is the host's business.
///
/// A mesh node needs [`Now::unix_seconds`](minip2p_core::platform::Now):
/// reservation expiries cross the backbone as UNIX seconds, so nodes need
/// synced clocks. Without it, expiries count from zero.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeshConfig {
    /// The relay's public identity key, which every node shares. Its peer id
    /// must be the agent's own; members' proofs are checked against it.
    pub public_key: PublicKey,
    /// This node's proof: the public identity's signature for this node's
    /// backbone peer id, from [`sign_member_proof`]. Sent on every backbone
    /// connection.
    pub proof: [u8; MEMBER_PROOF_LEN],
    /// Most peers one member's directory may claim; a member past it has its
    /// directory stream reset and its entries dropped.
    pub max_directory_entries_per_member: usize,
}

impl MeshConfig {
    /// A mesh node under the shared `public` identity whose backbone peer id
    /// is `backbone`, with default limits. Signs the node's proof.
    pub fn new(public: &Ed25519Keypair, backbone: &PeerId) -> Self {
        Self {
            public_key: public.public_key(),
            proof: sign_member_proof(public, backbone),
            max_directory_entries_per_member: DEFAULT_MAX_DIRECTORY_ENTRIES_PER_MEMBER,
        }
    }
}

/// Whether `conn_id` is a backbone connection: one allocated in
/// [`ConnectionNamespace::MESH_IPV4`] or [`ConnectionNamespace::MESH_IPV6`].
pub const fn is_backbone_connection(conn_id: ConnectionId) -> bool {
    let tag = conn_id.namespace().get();
    tag == ConnectionNamespace::MESH_IPV4.get() || tag == ConnectionNamespace::MESH_IPV6.get()
}

/// Installs the backbone swarm's mesh protocols, member, directory and
/// forward, inbound, outbound and advertised. Advertising matters: once a member's
/// Identify arrives, the swarm refuses opens for protocols it did not
/// advertise. The backbone port is restricted to members, so nobody else
/// sees them.
pub fn register_backbone_roles<T, E>(swarm: &mut SwarmCore<T, E>) -> Result<(), SwarmError>
where
    T: Transport,
    E: EntropySource,
{
    for protocol in [
        MEMBER_PROTOCOL_ID,
        DIRECTORY_PROTOCOL_ID,
        FORWARD_PROTOCOL_ID,
    ] {
        swarm.add_protocol(protocol)?;
    }
    Ok(())
}
