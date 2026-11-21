use super::*;

pub(super) struct QueuedInbound {
    protocol: String,
    pub(super) events: VecDeque<SwarmEvent>,
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
                self.inbound_order.push_back(key);
                self.queued_inbound.insert(
                    key,
                    QueuedInbound {
                        protocol: protocol.into(),
                        events: VecDeque::from([event]),
                    },
                );
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
        if let Some(queued) = self.queued_inbound.get_mut(&(conn, stream)) {
            if let SwarmEvent::StreamData { data, .. } = &event
                && let Some(SwarmEvent::StreamData { data: held, .. }) = queued.events.back_mut()
            {
                let mut buffer = match core::mem::take(held).try_into_mut() {
                    Ok(buffer) => buffer,
                    Err(bytes) => bytes.into(),
                };
                buffer.extend_from_slice(data);
                *held = buffer.freeze();
                return;
            }
            queued.events.push_back(event);
        } else {
            self.events.push_back(event);
        }
    }

    pub(super) fn release_inbound(&mut self, conn: ConnectionId, stream: Option<StreamId>) {
        if let Some(stream) = stream {
            self.release_inbound_stream((conn, stream));
            return;
        }
        let keys: Vec<_> = self
            .admitted_inbound
            .keys()
            .chain(self.queued_inbound.keys())
            .filter(|key| key.0 == conn)
            .copied()
            .collect();
        for key in keys {
            self.release_inbound_stream(key);
        }
    }

    fn release_inbound_stream(&mut self, key: (ConnectionId, StreamId)) {
        if self.admitted_inbound.remove(&key).is_some() {
            self.inbound_promotion_needed = true;
        }
        if let Some(queued) = self.queued_inbound.remove(&key) {
            self.inbound_promotion_needed = true;
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
                    conn_id: key.0,
                    stream_id: key.1,
                    bytes,
                });
            }
        }
    }

    pub(super) fn promote_inbound(&mut self) {
        if !core::mem::take(&mut self.inbound_promotion_needed) {
            return;
        }
        let mut waiting = VecDeque::new();
        while let Some(key) = self.inbound_order.pop_front() {
            let Some(queued) = self.queued_inbound.get(&key) else {
                continue;
            };
            if self.inbound_has_room(&queued.protocol) {
                if let Some(queued) = self.queued_inbound.remove(&key) {
                    self.admitted_inbound.insert(key, queued.protocol);
                    self.events.extend(queued.events);
                }
            } else {
                waiting.push_back(key);
            }
        }
        self.inbound_order = waiting;
    }

    pub(super) fn inbound_is_queued(&self, conn: ConnectionId, stream: StreamId) -> bool {
        self.queued_inbound.contains_key(&(conn, stream))
    }
}
