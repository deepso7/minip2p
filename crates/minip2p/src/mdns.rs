//! Facade driver for the synchronous mDNS socket adapter.

use std::time::Instant;

use minip2p_core::Multiaddr;
use minip2p_mdns::{MdnsAgent, MdnsConfig, MdnsError, MdnsEvent, MdnsSockets};

pub(crate) const MAX_MDNS_DATAGRAMS_PER_STEP: usize = 128;

pub(crate) struct MdnsDriver {
    pub(crate) agent: MdnsAgent,
    sockets: Option<MdnsSockets>,
    epoch: Instant,
    next_interface_refresh_ms: u64,
    interface_refresh_ms: u64,
    socket_poll_interval_ms: u64,
    backlog: bool,
    goodbye_sent: bool,
    pub(crate) events: std::collections::VecDeque<MdnsEvent>,
}

impl MdnsDriver {
    pub(crate) fn new(mut agent: MdnsAgent, sockets: MdnsSockets, config: &MdnsConfig) -> Self {
        agent.set_interfaces(sockets.interfaces(), 0);
        Self {
            agent,
            sockets: Some(sockets),
            epoch: Instant::now(),
            next_interface_refresh_ms: config.interface_refresh_ms,
            interface_refresh_ms: config.interface_refresh_ms,
            socket_poll_interval_ms: config.socket_poll_interval_ms,
            backlog: false,
            goodbye_sent: false,
            events: std::collections::VecDeque::new(),
        }
    }

    pub(crate) fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    pub(crate) fn tick(&mut self, local_addrs: &[Multiaddr]) -> Result<(), MdnsError> {
        let now = self.now_ms();
        let Some(sockets) = self.sockets.as_mut() else {
            return Ok(());
        };
        if now >= self.next_interface_refresh_ms {
            if sockets.refresh()? {
                self.agent.set_interfaces(sockets.interfaces(), now);
            }
            self.next_interface_refresh_ms = now.saturating_add(self.interface_refresh_ms);
        }
        self.agent.set_local_addrs(local_addrs, now);
        self.backlog = sockets.drain_into(&mut self.agent, now, MAX_MDNS_DATAGRAMS_PER_STEP)?;
        self.agent.handle_tick(now);
        while let Some(action) = self.agent.poll_action() {
            sockets.send(&action)?;
        }
        while let Some(event) = self.agent.poll_event() {
            self.events.push_back(event);
        }
        Ok(())
    }

    pub(crate) fn next_timeout(&self, now_ms: u64) -> Option<u64> {
        self.sockets.as_ref()?;
        if self.backlog {
            return Some(0);
        }
        let mut timeout = self.socket_poll_interval_ms;
        timeout = timeout.min(self.next_interface_refresh_ms.saturating_sub(now_ms));
        if let Some(agent) = self.agent.next_timeout(now_ms) {
            timeout = timeout.min(agent);
        }
        Some(timeout)
    }

    pub(crate) fn shutdown(&mut self) -> Result<(), MdnsError> {
        if self.goodbye_sent {
            return Ok(());
        }
        self.goodbye_sent = true;
        let now = self.now_ms();
        self.agent.shutdown(now);
        let mut first_error = None;
        if let Some(sockets) = self.sockets.as_ref() {
            while let Some(action) = self.agent.poll_action() {
                if let Err(error) = sockets.send(&action)
                    && first_error.is_none()
                {
                    first_error = Some(error);
                }
            }
        }
        self.sockets = None;
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl Drop for MdnsDriver {
    fn drop(&mut self) {
        if self.goodbye_sent {
            return;
        }
        self.goodbye_sent = true;
        self.agent.shutdown(self.now_ms());
        if let Some(sockets) = self.sockets.as_ref() {
            while let Some(action) = self.agent.poll_action() {
                let _ = sockets.send(&action);
            }
        }
    }
}
