//! Sans-I/O NAT-traversal orchestrator for minip2p.
//!
//! The protocol machines for relay circuits ([`minip2p_relay`]), hole
//! punching ([`minip2p_dcutr`]), and reachability probing live in their own
//! crates; this crate provides the relay-leg orchestrator: [`NatAgent`], a
//! state machine that dials a relay, establishes a circuit, and upgrades to
//! a punched direct connection when it can. Direct candidate racing and the
//! attempt's terminal outcome belong to the Connection-attempt engine.
//!
//! Connection model — parallel racing with convergence, not sequential
//! fallback:
//!
//! ```text
//! t0      caller races direct candidates (ConnectEngine)
//! t0+δ    relay leg (stagger δ when direct_racing, else now):
//!           ensure relay session → HOP CONNECT(target)
//!           → Bridged ⇒ promote bridge through Noise + Yamux
//!           → circuit Connected ⇒ PathEstablished(Relayed) (provisional)
//!           → reserved peer opens `/libp2p/dcutr` on that connection
//! inbound STOP circuit Connected ⇒ InboundPathEstablished(Relayed)
//! a better path later ⇒ explicit PathUpgraded
//! punch exhausted ⇒ FellBackToRelay (engine settles Connected)
//! relay leg dead ⇒ ConnectFailed (engine decides the attempt)
//! ```
//!
//! The agent performs no I/O and reads no clocks: feed it swarm events by
//! reference via [`NatAgent::handle_event`], time via [`NatAgent::handle_tick`],
//! and execute the [`NatAction`]s it emits against a [`minip2p_swarm::Swarm`]
//! (or any equivalent runtime). Events for streams the agent does not own
//! cost one map lookup and zero clones.
//!
//! The driver executes [`NatAction::PromoteBridge`] against a circuit
//! transport. Relayed paths are therefore ordinary identity-verified swarm
//! connections: identify, ping, pubsub, and application protocols use the
//! same stream APIs as direct paths.
//!
//! `no_std` + `alloc` compatible.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod agent;
mod attempt;
mod config;
mod events;
mod housekeeping;
mod inbound;
mod types;

pub use agent::{ConnectLegs, NatAgent};
pub use config::{NatConfig, ReservationPolicy};
pub use events::{BridgeRole, NatAction, NatEvent};
pub use types::{NatError, NatToken, Now, Path, PromoteError, ReachabilityState, ReservationInfo};

// Protocol ids for everything the agent drives, so a driver can register
// them without depending on each protocol crate.
pub use minip2p_autonat::AUTONAT_PROTOCOL_ID;
pub use minip2p_dcutr::DCUTR_PROTOCOL_ID;
pub use minip2p_relay::{HOP_PROTOCOL_ID, STOP_PROTOCOL_ID};
