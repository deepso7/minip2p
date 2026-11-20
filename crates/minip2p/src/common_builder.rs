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

    /// The swarm builder these options configure, for `keypair`.
    pub(crate) fn swarm(&self, keypair: &Ed25519Keypair) -> SwarmBuilder {
        self.protocols.iter().fold(
            SwarmBuilder::new(keypair)
                .agent_version(self.agent_version.clone())
                .simultaneous_dial_window_ms(self.simultaneous_dial_window_ms)
                .timeouts(self.timeouts),
            |swarm, protocol| swarm.protocol(protocol.clone()),
        )
    }

    /// The endpoint engine over `core`, the swarm built from
    /// [`Self::swarm`]: its connect deadline, write budget, acknowledgement
    /// modes, and protocol handles numbered in registration order. The
    /// capabilities stay here for Endpoint setup.
    pub(crate) fn engine<T: Transport, E: EntropySource, M: Carrier>(
        &mut self,
        core: SwarmCore<T, E>,
    ) -> Result<Engine<T, E, M>, DriverError> {
        let (acks, protocols) = self.tables()?;
        let mut engine = Engine::new(core, self.connect_deadline_ms, acks);
        engine.writes = WriteQueue::new(self.write_budget);
        engine.protocols = protocols;
        Ok(engine)
    }

    /// The engine's acknowledgement modes and protocol table, kept out of
    /// the generic [`Self::engine`] so they are compiled once.
    fn tables(&mut self) -> Result<(StreamAcks, ProtocolTable), DriverError> {
        let mut acks = StreamAcks::default();
        for protocol in self.manual_ack_protocols.drain(..) {
            acks.set_manual(protocol, []);
        }
        let mut protocols = ProtocolTable::default();
        for protocol in &self.protocols {
            protocols.intern(protocol)?;
        }
        Ok((acks, protocols))
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
