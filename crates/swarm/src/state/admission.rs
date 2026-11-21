use super::*;

pub(super) struct QueuedInbound {
    key: (ConnectionId, StreamId),
    protocol: String,
    events: VecDeque<SwarmEvent>,
}

impl SwarmState {
    pub(super) fn admit_inbound(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        protocol: &str,
    ) {
        let event = SwarmEvent::StreamReady {
            peer_id: self.ensure_peer_id_for_conn(conn_id),
            conn_id,
            stream_id,
            protocol_id: protocol.into(),
            initiated_locally: false,
        };
        let key = (conn_id, stream_id);
        if self.inbound_limits.contains_key(protocol) {
            if !self.inbound_has_room(protocol) {
                self.queued_inbound.push_back(QueuedInbound {
                    key,
                    protocol: protocol.into(),
                    events: VecDeque::from([event]),
                });
                return;
            }
            self.admitted_inbound.insert(key, protocol.into());
        }
        self.events.push_back(event);
    }

    fn inbound_has_room(&self, protocol: &str) -> bool {
        self.inbound_limits.get(protocol).is_none_or(|limit| {
            self.admitted_inbound
                .values()
                .filter(|p| *p == protocol)
                .count()
                < limit.get()
        })
    }

    pub(super) fn queue_inbound_event(
        &mut self,
        conn: ConnectionId,
        stream: StreamId,
        event: SwarmEvent,
    ) {
        if let Some(queued) = self
            .queued_inbound
            .iter_mut()
            .find(|q| q.key == (conn, stream))
        {
            queued.events.push_back(event);
        } else {
            self.events.push_back(event);
        }
    }

    pub(super) fn release_inbound(&mut self, conn: ConnectionId, stream: Option<StreamId>) {
        let matches =
            |key: (ConnectionId, StreamId)| key.0 == conn && stream.is_none_or(|s| key.1 == s);
        self.admitted_inbound.retain(|key, _| !matches(*key));
        let mut retained = VecDeque::new();
        while let Some(queued) = self.queued_inbound.pop_front() {
            if matches(queued.key) {
                let bytes = queued
                    .events
                    .iter()
                    .filter_map(|event| match event {
                        SwarmEvent::StreamData { data, .. } => Some(data.len()),
                        _ => None,
                    })
                    .sum();
                if bytes > 0 {
                    self.actions.push_back(Action::AckStream {
                        conn_id: queued.key.0,
                        stream_id: queued.key.1,
                        bytes,
                    });
                }
            } else {
                retained.push_back(queued);
            }
        }
        self.queued_inbound = retained;
    }

    pub(super) fn promote_inbound(&mut self) {
        let mut waiting = VecDeque::new();
        while let Some(queued) = self.queued_inbound.pop_front() {
            if self.inbound_has_room(&queued.protocol) {
                self.admitted_inbound.insert(queued.key, queued.protocol);
                self.events.extend(queued.events);
            } else {
                waiting.push_back(queued);
            }
        }
        self.queued_inbound = waiting;
    }

    pub(super) fn inbound_is_queued(&self, conn: ConnectionId, stream: StreamId) -> bool {
        self.queued_inbound.iter().any(|q| q.key == (conn, stream))
    }
}
