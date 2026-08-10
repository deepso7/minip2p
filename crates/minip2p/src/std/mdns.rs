//! Std clock adapter for the portable mDNS driver.
//!
//! Everything mDNS does is in `minip2p_mdns::MdnsDriver`, which owns no clock
//! because a `no_std` host has none to give it. This supplies one, and nothing
//! else: an epoch taken when the endpoint starts, read as milliseconds since.

use std::time::Instant;

use minip2p_core::Multiaddr;
use minip2p_mdns::{MdnsAgent, MdnsConfig, MdnsError, MdnsEvent, MdnsSockets};

pub(crate) struct MdnsDriver {
    inner: minip2p_mdns::MdnsDriver<MdnsSockets>,
    epoch: Instant,
}

impl MdnsDriver {
    pub(crate) fn new(agent: MdnsAgent, sockets: MdnsSockets, config: &MdnsConfig) -> Self {
        Self {
            inner: minip2p_mdns::MdnsDriver::new(agent, sockets, config),
            epoch: Instant::now(),
        }
    }

    pub(crate) fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    pub(crate) fn poll_event(&mut self) -> Option<MdnsEvent> {
        self.inner.poll_event()
    }

    pub(crate) fn tick(&mut self, local_addrs: &[Multiaddr]) -> Result<(), MdnsError> {
        self.inner.tick(self.now_ms(), local_addrs)
    }

    pub(crate) fn next_timeout(&self, now_ms: u64) -> Option<u64> {
        self.inner.next_timeout(now_ms)
    }

    pub(crate) fn shutdown(&mut self) -> Result<(), MdnsError> {
        self.inner.shutdown(self.now_ms())
    }
}
