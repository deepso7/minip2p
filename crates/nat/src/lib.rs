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
//!           → reserved peer runs up to 3 DCUtR rounds on that connection
//! inbound STOP circuit Connected ⇒ InboundPathEstablished(Relayed)
//! a better path later ⇒ explicit PathUpgraded
//! rounds exhausted, or an upgrade budget spent ⇒ FellBackToRelay
//!   (engine settles Connected, the Relayed path stays)
//! relay leg dead ⇒ ConnectFailed (engine decides the attempt)
//! ```
//!
//! The reservation holder drives DCUtR: each round opens a fresh stream,
//! times a fresh RTT from when its CONNECT is fully written (a CONNECT
//! refused as Full is held and timed once it drains), and opens a punch
//! window on both sides.
//! Every wait is bounded by a [`NatConfig`] budget clipped to the attempt's
//! deadline. Once the host's Connection-attempt engine settles an attempt,
//! [`NatAgent::settled`] drops what the agent still holds for it, and no
//! further attempt event names it.
//!
//! The agent performs no I/O and reads no clocks: pass it the swarm as a
//! [`NatSwarm`] (implemented for [`minip2p_swarm::SwarmCore`]), feed it swarm
//! events by reference via [`NatAgent::handle_event`] and time via
//! [`NatAgent::handle_tick`]. It reads connection and readiness facts from
//! that swarm and issues dials, stream opens, writes, and bridge promotions
//! on it directly; the few [`NatAction`]s it emits need the transport
//! underneath. Events for
//! streams the agent does not own cost one map lookup and zero clones.
//!
//! Every input carries the host's [`Now`] sample. Its monotonic reading
//! orders all of the agent's timers; its wall-clock reading is only used to
//! schedule relay-reservation renewal from the absolute `expire` a relay
//! returns, and without one renewal falls back to
//! [`NatConfig::reservation_default_ttl_secs`].
//!
//! A bridged relay stream is handed to the host's circuit transport through
//! [`NatSwarm::promote_bridge`], which adopts it synchronously and returns
//! the circuit connection; bytes the agent still held for the bridge travel
//! with it in [`BridgeHandoff::unsent_data`]. Relayed paths are therefore ordinary identity-verified swarm
//! connections: identify, ping, pubsub, and application protocols use the
//! same stream APIs as direct paths.
//!
//! `no_std` + `alloc` compatible.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod acquire;
mod agent;
mod attempt;
mod budget;
mod config;
mod events;
mod housekeeping;
mod inbound;
mod ledger;
mod swarm;
mod types;

pub use agent::{ConnectLegs, NatAgent};
pub use config::{MAX_DCUTR_ROUNDS, NatConfig, ReservationPolicy};
pub use events::{NatAction, NatEvent};
pub use housekeeping::{AUTONAT_VOTE_TTL_MS, MAX_RESERVATION_RETRY_BACKOFF_MS};
pub use inbound::MAX_PUNCH_CANDIDATES;
pub use swarm::{BridgeHandoff, BridgeRole, DialStart, NatSwarm, NatSwarmError, is_named};
pub use types::{
    NatError, NatToken, Path, PromoteError, ReachabilityState, RelayStage, ReservationInfo,
    UpgradeStop,
};
// The component time sample and deadline, re-exported so callers need not
// depend on minip2p-core to name them.
pub use minip2p_core::platform::{Deadline, Now};

// Protocol ids for everything the agent drives, so a driver can register
// them without depending on each protocol crate.
pub use minip2p_autonat::AUTONAT_PROTOCOL_ID;
pub use minip2p_dcutr::DCUTR_PROTOCOL_ID;
pub use minip2p_relay::{HOP_PROTOCOL_ID, STOP_PROTOCOL_ID};
