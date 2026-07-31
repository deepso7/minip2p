//! Endpoint driver for the synchronous mDNS socket adapter.

use std::time::Instant;

use minip2p_core::Multiaddr;
use minip2p_mdns::{MdnsAction, MdnsAgent, MdnsConfig, MdnsError, MdnsEvent, MdnsSockets};

pub(crate) const MAX_MDNS_DATAGRAMS_PER_STEP: usize = 128;
pub(crate) const MAX_MDNS_ACTIONS_PER_STEP: usize = 128;

pub(crate) struct MdnsDriver {
    pub(crate) agent: MdnsAgent,
    sockets: Option<MdnsSockets>,
    epoch: Instant,
    next_interface_refresh_ms: u64,
    interface_refresh_ms: u64,
    socket_poll_interval_ms: u64,
    backlog: bool,
    pending_action: Option<MdnsAction>,
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
            pending_action: None,
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
                // The parked action may embed address expansion from the old
                // snapshot even when its stable interface id still exists.
                self.pending_action = None;
            }
            self.next_interface_refresh_ms = now.saturating_add(self.interface_refresh_ms);
        }
        if self.agent.set_local_addrs(local_addrs, now) {
            // A parked packet was encoded from the previous listen-address
            // snapshot and must not be sent after that snapshot changes.
            self.pending_action = None;
        }

        let mut sent = 0usize;
        if let Some(action) = self.pending_action.take() {
            match sockets.send(&action) {
                Ok(()) => sent = 1,
                Err(MdnsError::UnknownInterface { .. }) => {}
                Err(error) => {
                    disable_after_send_error(
                        &mut self.agent,
                        &mut self.pending_action,
                        &mut self.backlog,
                        now,
                    );
                    self.sockets = None;
                    drain_events(&mut self.agent, &mut self.events);
                    return Err(error);
                }
            }
        }
        let receive_backlog =
            sockets.drain_into(&mut self.agent, now, MAX_MDNS_DATAGRAMS_PER_STEP)?;
        self.agent.handle_tick(now);
        let action_result = send_actions(
            &mut self.agent,
            &mut self.pending_action,
            MAX_MDNS_ACTIONS_PER_STEP.saturating_sub(sent),
            |action| sockets.send(action),
        );
        let action_backlog = match action_result {
            Ok(backlog) => backlog,
            Err(error) => {
                disable_after_send_error(
                    &mut self.agent,
                    &mut self.pending_action,
                    &mut self.backlog,
                    now,
                );
                self.sockets = None;
                drain_events(&mut self.agent, &mut self.events);
                return Err(error);
            }
        };
        self.backlog = receive_backlog || action_backlog;
        drain_events(&mut self.agent, &mut self.events);
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
        self.pending_action = None;
        let now = self.now_ms();
        self.agent.shutdown(now);
        let mut first_error = None;
        if let Some(sockets) = self.sockets.as_ref() {
            while let Some(action) = self.agent.poll_action() {
                if let Err(error) = sockets.send(&action)
                    && !matches!(error, MdnsError::UnknownInterface { .. })
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

fn send_actions(
    agent: &mut MdnsAgent,
    pending_action: &mut Option<MdnsAction>,
    limit: usize,
    mut send: impl FnMut(&MdnsAction) -> Result<(), MdnsError>,
) -> Result<bool, MdnsError> {
    for _ in 0..limit {
        let Some(action) = agent.poll_action() else {
            return Ok(false);
        };
        match send(&action) {
            Ok(()) | Err(MdnsError::UnknownInterface { .. }) => {}
            Err(error) => return Err(error),
        }
    }
    *pending_action = agent.poll_action();
    Ok(pending_action.is_some())
}

fn disable_after_send_error(
    agent: &mut MdnsAgent,
    pending_action: &mut Option<MdnsAction>,
    backlog: &mut bool,
    now_ms: u64,
) {
    *pending_action = None;
    *backlog = false;
    agent.shutdown(now_ms);
    while agent.poll_action().is_some() {}
}

fn drain_events(agent: &mut MdnsAgent, events: &mut std::collections::VecDeque<MdnsEvent>) {
    while let Some(event) = agent.poll_event() {
        events.push_back(event);
    }
}

impl Drop for MdnsDriver {
    fn drop(&mut self) {
        if self.goodbye_sent {
            return;
        }
        self.goodbye_sent = true;
        self.pending_action = None;
        self.agent.shutdown(self.now_ms());
        if let Some(sockets) = self.sockets.as_ref() {
            while let Some(action) = self.agent.poll_action() {
                let _ = sockets.send(&action);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        io,
        net::{IpAddr, Ipv4Addr, SocketAddrV4},
    };

    use minip2p_identity::{KeyType, PublicKey};
    use minip2p_mdns::{InterfaceId, InterfaceSnapshot, IpFamily, IpNet};

    use super::*;

    fn agent_with_interfaces(count: u32) -> MdnsAgent {
        let peer =
            minip2p_core::PeerId::from_public_key(&PublicKey::new(KeyType::Ed25519, vec![1; 32]));
        let mut agent = MdnsAgent::new(peer, MdnsConfig::default(), [7; 32]).unwrap();
        let interfaces = (1..=count)
            .map(|id| InterfaceSnapshot {
                id: InterfaceId::new(id),
                index: id,
                family: IpFamily::V4,
                addrs: vec![IpNet::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 24).unwrap()],
            })
            .collect::<Vec<_>>();
        agent.set_interfaces(&interfaces, 0);
        agent.handle_tick(0);
        agent
    }

    #[test]
    fn send_actions_yields_at_the_per_step_budget() {
        let mut agent = agent_with_interfaces(130);
        let mut pending = None;
        let sent = Cell::new(0usize);
        let backlog = send_actions(&mut agent, &mut pending, MAX_MDNS_ACTIONS_PER_STEP, |_| {
            sent.set(sent.get() + 1);
            Ok(())
        })
        .unwrap();
        assert_eq!(sent.get(), MAX_MDNS_ACTIONS_PER_STEP);
        assert!(backlog);
        assert!(pending.is_some());

        let pending_action = pending.take().unwrap();
        let MdnsAction::Send { .. } = pending_action;
        sent.set(sent.get() + 1);
        let backlog = send_actions(
            &mut agent,
            &mut pending,
            MAX_MDNS_ACTIONS_PER_STEP - 1,
            |_| {
                sent.set(sent.get() + 1);
                Ok(())
            },
        )
        .unwrap();
        assert!(!backlog);
        assert_eq!(sent.get(), 130);
    }

    #[test]
    fn send_error_disables_retries_and_events_can_still_be_drained() {
        let mut agent = agent_with_interfaces(1);
        let from = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5353).into();
        agent.handle_packet(
            InterfaceId::new(1),
            from,
            b"\x04_p2p\x04_udp\x05local\x00",
            0,
        );

        let mut pending = None;
        let error = send_actions(&mut agent, &mut pending, 1, |_| {
            Err(MdnsError::Io(io::Error::other("injected send failure")))
        })
        .unwrap_err();
        assert!(matches!(error, MdnsError::Io(_)));
        assert!(pending.is_none());

        let mut backlog = true;
        disable_after_send_error(&mut agent, &mut pending, &mut backlog, 0);
        assert!(!backlog);
        assert_eq!(agent.next_timeout(0), None);

        let mut events = std::collections::VecDeque::new();
        drain_events(&mut agent, &mut events);
        assert!(matches!(
            events.pop_front(),
            Some(MdnsEvent::ProtocolViolation { .. })
        ));

        let attempts = Cell::new(0usize);
        let backlog = send_actions(&mut agent, &mut pending, 1, |_| {
            attempts.set(attempts.get() + 1);
            Err(MdnsError::Io(io::Error::other(
                "must not retry after disable",
            )))
        })
        .unwrap();
        assert!(!backlog);
        assert_eq!(attempts.get(), 0);
    }

    #[test]
    fn retired_interface_actions_are_skipped() {
        let mut agent = agent_with_interfaces(2);
        let mut pending = None;
        let attempts = Cell::new(0usize);
        let backlog = send_actions(&mut agent, &mut pending, 2, |action| {
            attempts.set(attempts.get() + 1);
            let MdnsAction::Send { interface, .. } = action;
            if *interface == InterfaceId::new(1) {
                Err(MdnsError::UnknownInterface {
                    interface: *interface,
                })
            } else {
                Ok(())
            }
        })
        .unwrap();
        assert!(!backlog);
        assert_eq!(attempts.get(), 2);
        assert!(pending.is_none());
    }
}
