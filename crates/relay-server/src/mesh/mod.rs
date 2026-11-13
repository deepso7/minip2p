//! Relay mesh: several relay nodes serving one public relay identity.
//!
//! Mesh nodes share the relay's public identity and talk to each other over
//! a backbone, as distinct peers with their own backbone identities. Each
//! node pushes its local reservations to every other member on a directory
//! stream ([`DIRECTORY_PROTOCOL_ID`]), and an entry node that gets a CONNECT
//! for a peer reserved elsewhere forwards it to the holding node on a forward
//! stream ([`FORWARD_PROTOCOL_ID`]).
//!
//! This module holds the wire codec for both protocols and the receiver-side
//! [`Directory`]. Like the rest of the crate it is `no_std + alloc`, does no
//! I/O, and takes time from the caller.

mod codec;
mod directory;

pub use codec::{
    DIRECTORY_PROTOCOL_ID, DirectoryMessage, FORWARD_PROTOCOL_ID, ForwardMessage,
    MAX_MESH_MESSAGE_SIZE, MeshMessageError, decode_mesh_frame,
};
pub use directory::{
    Claim, DEFAULT_MAX_DIRECTORY_ENTRIES_PER_MEMBER, Directory, DirectoryInput,
    DirectoryResetReason,
};
