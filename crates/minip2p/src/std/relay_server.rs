//! Std adapter for the caller-driven relay-server service.

use std::collections::{BTreeMap, VecDeque};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use minip2p_platform::Now;
use minip2p_relay_server::{
    RelayServerAction, RelayServerAgent, RelayServerEvent, RelayServerSendError, RelayServerToken,
    StreamKey,
};
use minip2p_swarm::{DriverError, SwarmError, SwarmEvent};
use minip2p_transport::{ConnectionId, TransportError};

use crate::EndpointSwarm;

fn take_pending_for_connection<T>(
    pending: &mut BTreeMap<StreamKey, T>,
    conn_id: ConnectionId,
) -> Vec<T> {
    let keys: Vec<_> = pending
        .keys()
        .filter(|stream| stream.conn_id == conn_id)
        .copied()
        .collect();
    keys.into_iter()
        .filter_map(|stream| pending.remove(&stream))
        .collect()
}

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
        // A closed or replaced connection takes its in-flight negotiations with it.
        if let SwarmEvent::ConnectionClosed { conn_id, .. }
        | SwarmEvent::ConnectionReplaced { old: conn_id, .. } = event
        {
            for token in take_pending_for_connection(&mut self.pending_opens, *conn_id) {
                self.agent.stream_open_result(
                    token,
                    Err(format!(
                        "destination connection {conn_id} closed during protocol negotiation"
                    )),
                    now,
                );
            }
        }
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
            | SwarmEvent::StreamWriteStopped { conn_id, .. }
            | SwarmEvent::StreamClosed { conn_id, .. } => conn_id.is_circuit(),
            // The agent's flag describes the connection taking the slot.
            SwarmEvent::ConnectionReplaced { new, .. } => new.is_circuit(),
            _ => false,
        };
        // The first event at this time sample runs the agent tick before
        // dispatch, preserving deadline-first ordering for the batch.
        // The agent acknowledges the data it claims itself, through
        // `AckStream` actions: circuit payload only once the other leg
        // accepts it, which is what pauses a sender behind a full leg.
        let claimed = self.agent.handle_event(event, is_circuit, now);
        if let SwarmEvent::ConnectionEstablished { conn_id, .. }
        | SwarmEvent::ConnectionReplaced { new: conn_id, .. } = event
            && let Some(address) = swarm.core().connection_remote_addr(*conn_id).cloned()
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
                if swarm
                    .core()
                    .connection_remote_addr(expected_conn_id)
                    .is_none()
                {
                    self.agent.stream_open_result(
                        token,
                        Err(format!(
                            "expected destination connection {expected_conn_id} is no longer active"
                        )),
                        now,
                    );
                    return;
                }
                match swarm.open_stream(&peer_id, &protocol_id) {
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
                    .send_stream(&peer_id, stream.conn_id, stream.stream_id, data)
                    .map_err(|error| match error {
                        DriverError::Full { unsent, .. } => RelayServerSendError::Full { unsent },
                        error => RelayServerSendError::Failed(error.to_string()),
                    });
                self.agent.send_stream_result(token, result, now);
            }
            RelayServerAction::AckStream { stream, bytes } => {
                match swarm
                    .core_mut()
                    .ack_stream(stream.conn_id, stream.stream_id, bytes)
                {
                    // A stream or connection that is gone (or torn down by
                    // this ack's flush) released its bytes with it.
                    Ok(())
                    | Err(DriverError::Transport(
                        TransportError::StreamNotFound { .. }
                        | TransportError::ConnectionNotFound { .. }
                        | TransportError::PollError { .. },
                    )) => {}
                    // Anything else (an ack past what was delivered, say)
                    // breaks the agent's accounting.
                    Err(error) => debug_assert!(false, "relay ack refused: {error}"),
                }
            }
            RelayServerAction::CloseStreamWrite {
                token,
                peer_id,
                stream,
            } => {
                let result = swarm
                    .close_stream_write(&peer_id, stream.conn_id, stream.stream_id)
                    .map_err(|error| error.to_string());
                self.agent.close_stream_write_result(token, result, now);
            }
            RelayServerAction::ResetStream {
                token,
                peer_id,
                stream,
            } => {
                let result = match swarm.reset_stream(&peer_id, stream.conn_id, stream.stream_id) {
                    // A stream that is gone (or whose connection is) is
                    // already reset.
                    Ok(()) | Err(DriverError::Swarm(SwarmError::StreamNotFound { .. })) => Ok(()),
                    Err(error) => Err(error.to_string()),
                };
                self.agent.reset_stream_result(token, result, now);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use minip2p_transport::{ConnectionId, StreamId};

    #[test]
    fn connection_cleanup_removes_only_its_pending_opens() {
        let closed = ConnectionId::new(7);
        let live = ConnectionId::new(8);
        let mut pending = BTreeMap::from([
            (
                StreamKey {
                    conn_id: closed,
                    stream_id: StreamId::new(1),
                },
                "first",
            ),
            (
                StreamKey {
                    conn_id: live,
                    stream_id: StreamId::new(2),
                },
                "live",
            ),
            (
                StreamKey {
                    conn_id: closed,
                    stream_id: StreamId::new(3),
                },
                "second",
            ),
        ]);

        let removed = take_pending_for_connection(&mut pending, closed);

        assert_eq!(removed, vec!["first", "second"]);
        assert_eq!(pending.values().copied().collect::<Vec<_>>(), vec!["live"]);
    }
}
