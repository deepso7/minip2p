//! Sans-I/O libp2p gossipsub for minip2p.
//!
//! [`GossipsubAgent`] speaks `/meshsub/1.1.0` and `/meshsub/1.0.0` using a
//! long-lived outbound stream, mesh/fanout routing, heartbeat gossip, and a
//! bounded message cache. RPC field framing uses the shared protobuf
//! vocabulary in [`minip2p_core`]; this crate keeps message types,
//! StrictSign signing and verification, the 64 KiB RPC-body limit, and
//! contextual [`GossipsubWireError`] values.
//!
//! No I/O, no clocks, no async: callers feed inputs and drain
//! actions/events, exactly like the other minip2p protocol crates.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod events;
mod gossipsub;
mod message;
mod seen;

pub use events::{GossipsubAction, GossipsubEvent, GossipsubToken, PublishError, TopicError};
pub use gossipsub::{GossipsubAgent, GossipsubConfig, GossipsubConfigError};
pub use message::{
    ControlGraft, ControlIHave, ControlIWant, ControlMessage, ControlPrune, FrameDecode,
    GOSSIPSUB_PROTOCOL_IDS, GossipsubWireError, MAX_RPC_SIZE, MAX_TOPIC_LEN,
    MESHSUB_PROTOCOL_ID_V10, MESHSUB_PROTOCOL_ID_V11, MessageVerifyError, PeerInfo, RawMessage,
    Rpc, SubOpts, decode_frame, encode_frame,
};
