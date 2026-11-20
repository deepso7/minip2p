//! [`CommonBuilder`]: the builder state every endpoint builder shares,
//! whatever its platform.
//!
//! `EndpointBuilder`, `PortableEndpointBuilder` and `SmoltcpEndpointBuilder`
//! keep their own public setters (their docs and checks differ), and each
//! shared setter writes here, so an option common to every endpoint is
//! stored, defaulted and applied in one place.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::time::Duration;

use minip2p_core::platform::EntropySource;
use minip2p_identity::Ed25519Keypair;
use minip2p_swarm::{SwarmBuilder, SwarmCore, SwarmTimeouts};
use minip2p_transport::Transport;

use crate::engine::{Carrier, Engine};
use crate::portable::{DEFAULT_CONNECT_DEADLINE_MS, DriverError, StreamAcks};
use crate::protocols::ProtocolTable;
use crate::setup::Capabilities;
use crate::writes::WriteQueue;

/// The Identify `agentVersion` an endpoint advertises unless told otherwise.
pub(crate) const DEFAULT_AGENT_VERSION: &str = concat!("minip2p/", env!("CARGO_PKG_VERSION"));

/// Builder state every endpoint shares. Not generic, so the setters that
/// write it are compiled once however many platforms a program builds.
pub(crate) struct CommonBuilder {
    pub(crate) agent_version: String,
    pub(crate) timeouts: SwarmTimeouts,
    simultaneous_dial_window_ms: u64,
    connect_deadline_ms: u64,
    pub(crate) write_budget: usize,
    /// Application protocols, each once, in first-registration order: the
    /// order their handles number them in.
    protocols: Vec<String>,
    /// The registered protocols whose data the application acknowledges
    /// itself.
    manual_ack_protocols: Vec<String>,
    /// Capability intent for Endpoint setup, which applies the defaults.
    pub(crate) capabilities: Capabilities,
}

impl Default for CommonBuilder {
    fn default() -> Self {
        Self {
            agent_version: DEFAULT_AGENT_VERSION.to_string(),
            timeouts: SwarmTimeouts::default(),
            simultaneous_dial_window_ms: minip2p_swarm::SIMULTANEOUS_DIAL_WINDOW_MS,
            connect_deadline_ms: DEFAULT_CONNECT_DEADLINE_MS,
            write_budget: crate::DEFAULT_WRITE_BUDGET,
            protocols: Vec::new(),
            manual_ack_protocols: Vec::new(),
            capabilities: Capabilities::default(),
        }
    }
}

impl CommonBuilder {
    pub(crate) fn set_simultaneous_dial_window(&mut self, window: Duration) {
        self.simultaneous_dial_window_ms = duration_ms(window);
    }

    pub(crate) fn set_connect_deadline(&mut self, deadline: Duration) {
        self.connect_deadline_ms = duration_ms(deadline);
    }

    /// Registers an application protocol; a repeat keeps its first place.
    pub(crate) fn protocol(&mut self, protocol_id: String) {
        if !self.protocols.contains(&protocol_id) {
            self.protocols.push(protocol_id);
        }
    }

    /// Registers an application protocol whose data the application
    /// acknowledges itself.
    pub(crate) fn manual_ack_protocol(&mut self, protocol_id: String) {
        if !self.manual_ack_protocols.contains(&protocol_id) {
            self.manual_ack_protocols.push(protocol_id.clone());
        }
        self.protocol(protocol_id);
    }

    /// The application protocols, in registration order.
    #[cfg(feature = "std")]
    pub(crate) fn protocols(&self) -> &[String] {
        &self.protocols
    }

    /// Splits the options into the swarm builder they configure for
    /// `keypair` and what the engine needs once that swarm is built, with
    /// protocol handles numbered in registration order. Take the
    /// capabilities out first; they go to Endpoint setup.
    pub(crate) fn into_parts(
        self,
        keypair: &Ed25519Keypair,
    ) -> Result<(SwarmBuilder, EngineParts), DriverError> {
        let mut acks = StreamAcks::default();
        for protocol in self.manual_ack_protocols {
            acks.set_manual(protocol, []);
        }
        let mut table = ProtocolTable::default();
        let mut swarm = SwarmBuilder::new(keypair)
            .agent_version(self.agent_version)
            .simultaneous_dial_window_ms(self.simultaneous_dial_window_ms)
            .timeouts(self.timeouts);
        for protocol in self.protocols {
            table.intern(&protocol)?;
            swarm = swarm.protocol(protocol);
        }
        let parts = EngineParts {
            connect_deadline_ms: self.connect_deadline_ms,
            write_budget: self.write_budget,
            acks,
            protocols: table,
        };
        Ok((swarm, parts))
    }
}

/// What [`CommonBuilder::into_parts`] leaves for the engine.
pub(crate) struct EngineParts {
    connect_deadline_ms: u64,
    write_budget: usize,
    acks: StreamAcks,
    protocols: ProtocolTable,
}

impl EngineParts {
    /// The endpoint engine over `core`, the swarm built from the parts'
    /// swarm builder.
    pub(crate) fn engine<T: Transport, E: EntropySource, M: Carrier>(
        self,
        core: SwarmCore<T, E>,
    ) -> Engine<T, E, M> {
        let mut engine = Engine::new(core, self.connect_deadline_ms, self.acks);
        engine.writes = WriteQueue::new(self.write_budget);
        engine.protocols = self.protocols;
        engine
    }
}

/// Whole milliseconds in `duration`, saturating.
fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_repeat_registration_keeps_its_first_place() {
        let mut common = CommonBuilder::default();
        common.protocol("/a".into());
        common.manual_ack_protocol("/b".into());
        common.protocol("/a".into());
        common.manual_ack_protocol("/a".into());
        common.manual_ack_protocol("/b".into());
        assert_eq!(common.protocols, ["/a", "/b"]);
        assert_eq!(common.manual_ack_protocols, ["/b", "/a"]);
    }
}
