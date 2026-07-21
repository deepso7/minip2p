//! Sans-I/O libp2p pubsub wire codec plus a floodsub router for minip2p.
//!
//! The shared codec covers floodsub message RPCs and meshsub control messages
//! for `/meshsub/1.0.0` and `/meshsub/1.1.0`, with varint-length-prefixed
//! framing and StrictSign message signing. [`FloodsubAgent`] remains the only
//! router in this crate today; it speaks `/floodsub/1.0.0` and deliberately
//! skips meshsub control fields.
//!
//! No I/O, no clocks, no async: callers feed inputs and drain
//! actions/events, exactly like the other minip2p protocol crates.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod agent;
mod config;
mod events;
mod message;
mod seen;

pub use agent::FloodsubAgent;
pub use config::FloodsubConfig;
pub use events::{PublishError, PubsubAction, PubsubEvent, PubsubToken, TopicError};
pub use message::{
    ControlGraft, ControlIHave, ControlIWant, ControlMessage, ControlPrune, FLOODSUB_PROTOCOL_ID,
    FrameDecode, MAX_RPC_SIZE, MAX_TOPIC_LEN, MESHSUB_PROTOCOL_ID_V10, MESHSUB_PROTOCOL_ID_V11,
    MessageVerifyError, PeerInfo, PubsubWireError, RawMessage, Rpc, SubOpts, decode_frame,
    encode_frame,
};
