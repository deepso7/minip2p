//! Sans-I/O NAT-traversal orchestrator for minip2p.
//!
//! The protocol machines for relay circuits ([`minip2p_relay`]), hole
//! punching ([`minip2p_dcutr`]), and reachability probing live in their own
//! crates; this crate provides the missing orchestrator: [`NatAgent`], a
//! single state machine that races direct dials against a relayed circuit
//! and upgrades to a punched direct connection when it can.
//!
//! Connection model — parallel racing with convergence, not sequential
//! fallback:
//!
//! ```text
//! t0      direct leg: dial every validated candidate address
//! t0+δ    relay leg (stagger δ, 0 = fully parallel):
//!           ensure relay session → HOP CONNECT(target)
//!           → Bridged ⇒ PathEstablished(Relayed) (usable NOW)
//!           → immediately start a DCUtR punch over the bridge, in parallel
//! first usable path wins; a better path later ⇒ explicit PathUpgraded
//! "fallback" is not a phase — it is what remains when the punch leg
//! exhausts (FellBackToRelay)
//! ```
//!
//! The agent performs no I/O and reads no clocks: feed it swarm events by
//! reference via [`NatAgent::handle_event`], time via [`NatAgent::handle_tick`],
//! and execute the [`NatAction`]s it emits against a [`minip2p_swarm::Swarm`]
//! (or any equivalent runtime). Events for streams the agent does not own
//! cost one map lookup and zero clones.
//!
//! The relayed path is a **raw bridge stream**, not a full swarm connection:
//! no identify, ping, or multistream-select runs over it. See
//! [`Path::Relayed`].
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

pub use agent::NatAgent;
pub use config::{NatConfig, ReservationPolicy};
pub use events::{NatAction, NatEvent};
pub use types::{ConnectId, NatError, NatToken, Now, Path, ReachabilityState, ReservationInfo};

// Protocol ids for everything the agent drives, so a driver can register
// them without depending on each protocol crate.
pub use minip2p_autonat::AUTONAT_PROTOCOL_ID;
pub use minip2p_dcutr::DCUTR_PROTOCOL_ID;
pub use minip2p_relay::{HOP_PROTOCOL_ID, STOP_PROTOCOL_ID};
