//! Drives the caller-driven relay-server service against the endpoint's
//! swarm. Std-only by policy (relay hosting is a server role), though the
//! driver itself takes the host's time sample like every other capability.

use std::collections::{BTreeMap, VecDeque};

use minip2p_core::platform::{EntropySource, Now};
use minip2p_relay_server::{
    RelayServerAction, RelayServerAgent, RelayServerEvent, RelayServerSendError, RelayServerToken,
    StreamKey,
};
use minip2p_swarm::{
    DriverError, SwarmCore, SwarmError, SwarmErrorKind, SwarmEvent, SwarmRuntimeError,
};
use minip2p_transport::{ConnectionId, Transport, TransportError};

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
    pending_opens: BTreeMap<StreamKey, RelayServerToken>,
}

impl RelayServerDriver {
    pub(crate) fn new(agent: RelayServerAgent) -> Self {
        Self {
            agent,
            events: VecDeque::new(),
            pending_opens: BTreeMap::new(),
        }
    }

    pub(crate) fn ingest<T: Transport, E: EntropySource>(
        &mut self,
        event: &SwarmEvent,
        swarm: &mut SwarmCore<T, E>,
        now: Now,
    ) -> bool {
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
        if let Some((key, result)) = settled_open(event)
            && let Some(token) = self.pending_opens.remove(&key)
        {
            self.agent
                .stream_open_result(token, result.map(|()| key), now);
            self.pump(swarm, now);
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
            && let Some(address) = swarm.connection_remote_addr(*conn_id).cloned()
        {
            self.agent.set_connection_addr(*conn_id, address);
        }
        self.pump(swarm, now);
        claimed
    }

    pub(crate) fn tick<T: Transport, E: EntropySource>(
        &mut self,
        swarm: &mut SwarmCore<T, E>,
        now: Now,
    ) {
        if self
            .agent
            .next_deadline(now)
            .is_some_and(|due| due.is_expired_at(now))
        {
            self.agent.handle_tick(now);
            self.pump(swarm, now);
        }
    }

    pub(crate) fn pump<T: Transport, E: EntropySource>(
        &mut self,
        swarm: &mut SwarmCore<T, E>,
        now: Now,
    ) {
        loop {
            let mut progressed = false;
            while let Some(action) = self.agent.poll_action() {
                progressed = true;
                self.execute(action, swarm, now);
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

    /// Moves events the agent queued outside a pump (an address refresh's
    /// `AddrsRejected`, say) into the driver's queue.
    pub(crate) fn collect_agent_events(&mut self) {
        while let Some(event) = self.agent.poll_event() {
            self.events.push_back(event);
        }
    }

    fn execute<T: Transport, E: EntropySource>(
        &mut self,
        action: RelayServerAction,
        swarm: &mut SwarmCore<T, E>,
        now: Now,
    ) {
        let now_ms = now.monotonic_ms;
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
                match swarm.open_stream(&peer_id, &protocol_id, now_ms) {
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
                    .send_stream(&peer_id, stream.conn_id, stream.stream_id, data, now_ms)
                    .map_err(|error| match error {
                        DriverError::Full { unsent, .. } => RelayServerSendError::Full { unsent },
                        error => RelayServerSendError::Failed(error.to_string()),
                    });
                self.agent.send_stream_result(token, result, now);
            }
            RelayServerAction::AckStream { stream, bytes } => {
                match swarm.ack_stream(stream.conn_id, stream.stream_id, bytes) {
                    // A stream or connection that is gone (or torn down by
                    // this ack's flush) released its bytes with it.
                    Ok(())
                    | Err(DriverError::Transport(
                        TransportError::StreamNotFound { .. }
                        | TransportError::ConnectionNotFound { .. }
                        | TransportError::ConnectionClosed { .. }
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
                    .close_stream_write(&peer_id, stream.conn_id, stream.stream_id, now_ms)
                    .map_err(|error| error.to_string());
                self.agent.close_stream_write_result(token, result, now);
            }
            RelayServerAction::ResetStream {
                token,
                peer_id,
                stream,
            } => {
                let result =
                    match swarm.reset_stream(&peer_id, stream.conn_id, stream.stream_id, now_ms) {
                        // A stream that is gone (or whose connection is) is
                        // already reset.
                        Ok(()) | Err(DriverError::Swarm(SwarmError::StreamNotFound { .. })) => {
                            Ok(())
                        }
                        Err(error) => Err(error.to_string()),
                    };
                self.agent.reset_stream_result(token, result, now);
            }
        }
    }
}

/// The bound addresses a relay server may announce: wildcards are dropped,
/// since a peer cannot dial `0.0.0.0` or `::`.
pub(crate) fn concrete_relay_listener_addrs(
    addrs: Vec<minip2p_core::Multiaddr>,
) -> Vec<minip2p_core::Multiaddr> {
    use minip2p_core::Protocol;
    addrs
        .into_iter()
        .filter(|address| {
            !matches!(address.iter().next(), Some(Protocol::Ip4(ip)) if *ip == [0; 4])
                && !matches!(address.iter().next(), Some(Protocol::Ip6(ip)) if *ip == [0; 16])
        })
        .collect()
}

/// The outbound open `event` settles, if any: ready, or failed with a
/// reason. A failed negotiation (refused protocol, the peer closing the
/// stream first, or the negotiation deadline) ends with an error naming the
/// stream rather than a `StreamClosed`.
fn settled_open(event: &SwarmEvent) -> Option<(StreamKey, Result<(), String>)> {
    let (conn_id, stream_id, result) = match event {
        SwarmEvent::StreamReady {
            conn_id,
            stream_id,
            initiated_locally: true,
            ..
        } => (*conn_id, *stream_id, Ok(())),
        SwarmEvent::StreamClosed {
            conn_id, stream_id, ..
        } => (
            *conn_id,
            *stream_id,
            Err("stream closed before protocol negotiation completed".into()),
        ),
        SwarmEvent::Error(SwarmRuntimeError {
            kind:
                SwarmErrorKind::Multistream
                | SwarmErrorKind::UnsupportedProtocol
                | SwarmErrorKind::OpenStreamFailed,
            conn_id: Some(conn_id),
            stream_id: Some(stream_id),
            detail,
            ..
        }) => (*conn_id, *stream_id, Err(detail.clone())),
        _ => return None,
    };
    Some((StreamKey { conn_id, stream_id }, result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use minip2p_transport::{ConnectionId, StreamId};

    /// A destination that never finishes negotiating STOP settles the
    /// pending open through the swarm's error naming the stream.
    #[test]
    fn a_failed_negotiation_settles_the_pending_open() {
        let conn_id = ConnectionId::new(4);
        let stream_id = StreamId::new(9);
        let failed = SwarmEvent::Error(SwarmRuntimeError {
            kind: SwarmErrorKind::OpenStreamFailed,
            peer_id: None,
            conn_id: Some(conn_id),
            stream_id: Some(stream_id),
            detail: "timed out".into(),
        });
        assert_eq!(
            settled_open(&failed),
            Some((StreamKey { conn_id, stream_id }, Err("timed out".into())))
        );
        let unrelated = SwarmEvent::Error(SwarmRuntimeError {
            kind: SwarmErrorKind::Ping,
            peer_id: None,
            conn_id: Some(conn_id),
            stream_id: Some(stream_id),
            detail: "ping".into(),
        });
        assert_eq!(settled_open(&unrelated), None);
    }

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
