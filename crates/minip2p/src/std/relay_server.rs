//! Std adapter for the caller-driven relay-server service.

use std::collections::{BTreeMap, VecDeque};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use minip2p_platform::Now;
use minip2p_relay_server::{
    RelayServerAction, RelayServerAgent, RelayServerEvent, RelayServerToken, StreamKey,
};
use minip2p_swarm::SwarmEvent;

use crate::EndpointSwarm;

pub(crate) struct RelayServerDriver {
    pub(crate) agent: RelayServerAgent,
    pub(crate) events: VecDeque<RelayServerEvent>,
    epoch: Instant,
    pending_opens: BTreeMap<StreamKey, RelayServerToken>,
}

impl RelayServerDriver {
    pub(crate) fn new(agent: RelayServerAgent) -> Self {
        Self {
            agent,
            events: VecDeque::new(),
            epoch: Instant::now(),
            pending_opens: BTreeMap::new(),
        }
    }

    pub(crate) fn now(&self) -> Now {
        Now::new(
            self.epoch.elapsed().as_millis() as u64,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|duration| duration.as_secs())
                .unwrap_or(0),
        )
    }

    pub(crate) fn ingest(&mut self, event: &SwarmEvent, swarm: &mut EndpointSwarm) -> bool {
        let now = self.now();
        let pending_key = match event {
            SwarmEvent::StreamReady {
                conn_id,
                stream_id,
                initiated_locally: true,
                ..
            }
            | SwarmEvent::StreamClosed {
                conn_id, stream_id, ..
            } => Some(StreamKey {
                conn_id: *conn_id,
                stream_id: *stream_id,
            }),
            _ => None,
        };
        if let Some(key) = pending_key
            && let Some(token) = self.pending_opens.remove(&key)
        {
            let result = if matches!(event, SwarmEvent::StreamReady { .. }) {
                Ok(key)
            } else {
                Err("stream closed before protocol negotiation completed".into())
            };
            self.agent.stream_open_result(token, result, now);
            self.pump(swarm);
            return true;
        }
        let is_circuit = match event {
            SwarmEvent::ConnectionEstablished { conn_id, .. }
            | SwarmEvent::ConnectionClosed { conn_id, .. }
            | SwarmEvent::StreamReady { conn_id, .. }
            | SwarmEvent::StreamData { conn_id, .. }
            | SwarmEvent::StreamRemoteWriteClosed { conn_id, .. }
            | SwarmEvent::StreamClosed { conn_id, .. } => conn_id.is_circuit(),
            _ => false,
        };
        // `handle_event` runs the agent tick with this same sample before it
        // dispatches the event, preserving deadline-first ordering.
        let claimed = self.agent.handle_event(event, is_circuit, now);
        if let SwarmEvent::ConnectionEstablished { conn_id, .. } = event
            && let Some(address) = swarm.connection_remote_addr(*conn_id).cloned()
        {
            self.agent.set_connection_addr(*conn_id, address);
        }
        self.pump(swarm);
        claimed
    }

    pub(crate) fn tick(&mut self, swarm: &mut EndpointSwarm) {
        let now = self.now();
        if self.agent.next_timeout(now) == Some(0) {
            self.agent.handle_tick(now);
            self.pump(swarm);
        }
    }

    pub(crate) fn pump(&mut self, swarm: &mut EndpointSwarm) {
        loop {
            let mut progressed = false;
            while let Some(action) = self.agent.poll_action() {
                progressed = true;
                self.execute(action, swarm);
            }
            while let Some(event) = self.agent.poll_event() {
                progressed = true;
                self.events.push_back(event);
            }
            if !progressed {
                break;
            }
        }
    }

    fn execute(&mut self, action: RelayServerAction, swarm: &mut EndpointSwarm) {
        let now = self.now();
        match action {
            RelayServerAction::OpenStream {
                token,
                peer_id,
                expected_conn_id,
                protocol_id,
            } => {
                if swarm.connection_remote_addr(expected_conn_id).is_none() {
                    self.agent.stream_open_result(
                        token,
                        Err(format!(
                            "expected destination connection {expected_conn_id} is no longer active"
                        )),
                        now,
                    );
                    return;
                }
                match swarm.open_stream_with_connection(&peer_id, &protocol_id) {
                    Ok((conn_id, stream_id)) => {
                        self.pending_opens
                            .insert(StreamKey { conn_id, stream_id }, token);
                    }
                    Err(error) => {
                        self.agent
                            .stream_open_result(token, Err(error.to_string()), now);
                    }
                }
            }
            RelayServerAction::SendStream {
                token,
                peer_id,
                stream,
                data,
            } => {
                let result = swarm
                    .send_stream(&peer_id, stream.stream_id, data)
                    .map_err(|error| error.to_string());
                self.agent.send_stream_result(token, result, now);
            }
            RelayServerAction::CloseStreamWrite {
                token,
                peer_id,
                stream,
            } => {
                let result = swarm
                    .close_stream_write(&peer_id, stream.stream_id)
                    .map_err(|error| error.to_string());
                self.agent.close_stream_write_result(token, result, now);
            }
            RelayServerAction::ResetStream {
                token,
                peer_id,
                stream,
            } => {
                let result = swarm
                    .reset_stream(&peer_id, stream.stream_id)
                    .map_err(|error| error.to_string());
                self.agent.reset_stream_result(token, result, now);
            }
        }
    }
}
