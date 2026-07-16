//! Sans-I/O floodsub (`/floodsub/1.0.0`) for minip2p.
//!
//! This crate provides the libp2p pubsub wire codec (RPC protobuf,
//! varint-length-prefixed stream framing, StrictSign message signing) and
//! the [`FloodsubAgent`] state machine that routes published messages to
//! subscribed peers by flooding.
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
    FLOODSUB_PROTOCOL_ID, FrameDecode, MAX_RPC_SIZE, MAX_TOPIC_LEN, MessageVerifyError,
    PubsubWireError, RawMessage, Rpc, SubOpts, decode_frame, encode_frame,
};
