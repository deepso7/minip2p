//! Sans-I/O libp2p pubsub wire codec and routing engines for minip2p.
//!
//! [`GossipsubAgent`] speaks `/meshsub/1.1.0` and `/meshsub/1.0.0` using a
//! long-lived outbound stream, mesh/fanout routing, heartbeat gossip, and a
//! bounded message cache. [`FloodsubAgent`] speaks `/floodsub/1.0.0` using
//! one outbound stream per RPC. [`PubsubAgent`] provides static engine
//! selection. Both share varint framing, RPC/control encoding, and StrictSign
//! message signing and verification.
//!
//! No I/O, no clocks, no async: callers feed inputs and drain
//! actions/events, exactly like the other minip2p protocol crates.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod agent;
mod config;
mod engine;
mod events;
mod gossipsub;
mod message;
mod seen;

pub use agent::FloodsubAgent;
pub use config::FloodsubConfig;
pub use engine::{PubsubAgent, PubsubConfig};
pub use events::{PublishError, PubsubAction, PubsubEvent, PubsubToken, TopicError};
pub use gossipsub::{GossipsubAgent, GossipsubConfig, PubsubConfigError};
pub use message::{
    ControlGraft, ControlIHave, ControlIWant, ControlMessage, ControlPrune, FLOODSUB_PROTOCOL_ID,
    FrameDecode, MAX_RPC_SIZE, MAX_TOPIC_LEN, MESHSUB_PROTOCOL_ID_V10, MESHSUB_PROTOCOL_ID_V11,
    MessageVerifyError, PeerInfo, PubsubWireError, RawMessage, Rpc, SubOpts, decode_frame,
    encode_frame,
};
