#![allow(dead_code)]

//! Loopback Circuit Relay v2 service used by facade and example tests.
//!
//! This is deliberately an application built from public `minip2p` APIs:
//! HOP and STOP are negotiated as ordinary protocols, relay messages are
//! validated by `RelayEmulator`, and the accepted streams are then copied
//! byte-for-byte in both directions. The peers on either side therefore run
//! the production NAT driver, Noise, Yamux, Identify, ping, and protocols.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use minip2p::{Endpoint, Event, PeerAddr, PeerId, StreamId};
use minip2p_relay::{FrameDecode, HOP_PROTOCOL_ID, HopMessage, HopMessageType, STOP_PROTOCOL_ID};
use minip2p_test_support::{ConnectRequestOutcome, PendingConnectId, RelayEmulator};

type StreamKey = (PeerId, StreamId);

enum Command {
    CutAll,
    Stop,
}

struct PendingStop {
    pending_id: PendingConnectId,
    hop: StreamKey,
    target: PeerId,
    connect_bytes: Vec<u8>,
    hop_trailing: Vec<u8>,
    response: Vec<u8>,
}

#[derive(Default)]
struct RelayMachine {
    protocol: RelayEmulator,
    hop_buffers: BTreeMap<StreamKey, Vec<u8>>,
    pending_stops: BTreeMap<StreamKey, PendingStop>,
    hop_to_stop: BTreeMap<StreamKey, StreamKey>,
    bridges: BTreeMap<StreamKey, StreamKey>,
    trace: Vec<String>,
}

impl RelayMachine {
    fn handle(&mut self, endpoint: &mut Endpoint, event: Event) -> Result<(), String> {
        match event {
            Event::StreamReady {
                peer_id,
                stream_id,
                protocol_id,
                initiated_locally,
                ..
            } if protocol_id == HOP_PROTOCOL_ID && !initiated_locally => {
                self.hop_buffers.entry((peer_id, stream_id)).or_default();
            }
            Event::StreamReady {
                peer_id,
                stream_id,
                protocol_id,
                initiated_locally,
                ..
            } if protocol_id == STOP_PROTOCOL_ID && initiated_locally => {
                let key = (peer_id.clone(), stream_id);
                let bytes = self
                    .pending_stops
                    .get(&key)
                    .ok_or_else(|| format!("STOP stream ready without pending CONNECT: {key:?}"))?
                    .connect_bytes
                    .clone();
                endpoint
                    .send_stream(&peer_id, stream_id, bytes)
                    .map_err(|e| format!("send STOP CONNECT: {e}"))?;
            }
            Event::StreamData {
                peer_id,
                stream_id,
                data,
                ..
            } => self.on_data(endpoint, (peer_id, stream_id), data)?,
            Event::StreamRemoteWriteClosed {
                peer_id, stream_id, ..
            } => {
                let key = (peer_id, stream_id);
                if let Some((other_peer, other_stream)) = self.bridges.get(&key).cloned() {
                    let _ = endpoint.close_stream_write(&other_peer, other_stream);
                }
            }
            Event::StreamClosed {
                peer_id, stream_id, ..
            } => self.drop_stream(endpoint, &(peer_id, stream_id)),
            Event::ConnectionClosed { peer_id, .. } => {
                let dead: Vec<_> = self
                    .bridges
                    .keys()
                    .filter(|(peer, _)| peer == &peer_id)
                    .cloned()
                    .collect();
                for key in dead {
                    self.drop_stream(endpoint, &key);
                }
                self.hop_buffers.retain(|(peer, _), _| peer != &peer_id);
                self.pending_stops.retain(|(peer, _), _| peer != &peer_id);
                self.hop_to_stop
                    .retain(|(peer, _), stop| peer != &peer_id && stop.0 != peer_id);
            }
            _ => {}
        }
        Ok(())
    }

    fn on_data(
        &mut self,
        endpoint: &mut Endpoint,
        key: StreamKey,
        data: Vec<u8>,
    ) -> Result<(), String> {
        if let Some((other_peer, other_stream)) = self.bridges.get(&key).cloned() {
            self.trace.push(format!(
                "forward {} bytes {:?} -> ({other_peer}, {other_stream})",
                data.len(),
                key
            ));
            endpoint
                .send_stream(&other_peer, other_stream, data)
                .map_err(|e| format!("forward bridge data: {e}"))?;
            return Ok(());
        }

        if let Some(stop_key) = self.hop_to_stop.get(&key).cloned() {
            let pending = self
                .pending_stops
                .get_mut(&stop_key)
                .expect("hop-to-stop index points at pending STOP");
            pending.hop_trailing.extend(data);
            return Ok(());
        }

        if self.pending_stops.contains_key(&key) {
            return self.on_stop_data(endpoint, key, data);
        }

        let Some(buffer) = self.hop_buffers.get_mut(&key) else {
            return Ok(());
        };
        buffer.extend(data);
        let FrameDecode::Complete { payload, .. } = minip2p_relay::decode_frame(buffer) else {
            return Ok(());
        };
        let message =
            HopMessage::decode(payload).map_err(|e| format!("decode HOP request: {e}"))?;
        let request = self
            .hop_buffers
            .remove(&key)
            .expect("complete HOP buffer exists");

        match message.kind {
            HopMessageType::Reserve => {
                let trailing = self
                    .protocol
                    .on_reserve_request(&key.0, &request)
                    .map_err(|e| format!("handle RESERVE: {e}"))?;
                if !trailing.is_empty() {
                    return Err("unexpected bytes trailing RESERVE".into());
                }
                let response = self.protocol.drain_hop_bytes_for(&key.0);
                endpoint
                    .send_stream(&key.0, key.1, response)
                    .map_err(|e| format!("send RESERVE response: {e}"))?;
            }
            HopMessageType::Connect => {
                let mut response = Vec::new();
                match self
                    .protocol
                    .on_connect_request(&key.0, &request, &mut response)
                    .map_err(|e| format!("handle CONNECT: {e}"))?
                {
                    ConnectRequestOutcome::Refused { trailing } => {
                        if !trailing.is_empty() {
                            return Err("unexpected bytes trailing refused CONNECT".into());
                        }
                        endpoint
                            .send_stream(&key.0, key.1, response)
                            .map_err(|e| format!("send CONNECT refusal: {e}"))?;
                    }
                    ConnectRequestOutcome::Bridging {
                        pending_id,
                        target,
                        trailing,
                    } => {
                        let stop_stream = endpoint
                            .open_stream(&target, STOP_PROTOCOL_ID)
                            .map_err(|e| format!("open STOP stream to {target}: {e}"))?;
                        let stop_key = (target.clone(), stop_stream);
                        let connect_bytes = self.protocol.drain_stop_bytes_for(&target);
                        self.hop_to_stop.insert(key.clone(), stop_key.clone());
                        self.pending_stops.insert(
                            stop_key,
                            PendingStop {
                                pending_id,
                                hop: key,
                                target,
                                connect_bytes,
                                hop_trailing: trailing,
                                response,
                            },
                        );
                    }
                }
            }
            other => return Err(format!("unexpected HOP request kind: {other:?}")),
        }
        Ok(())
    }

    fn on_stop_data(
        &mut self,
        endpoint: &mut Endpoint,
        key: StreamKey,
        data: Vec<u8>,
    ) -> Result<(), String> {
        {
            let pending = self
                .pending_stops
                .get_mut(&key)
                .expect("pending STOP exists");
            pending.response.extend(data);
            if !matches!(
                minip2p_relay::decode_frame(&pending.response),
                FrameDecode::Complete { .. }
            ) {
                return Ok(());
            }
        }

        let pending = self
            .pending_stops
            .remove(&key)
            .expect("complete pending STOP exists");
        self.hop_to_stop.remove(&pending.hop);
        let mut initiator_response = Vec::new();
        let stop_trailing = self
            .protocol
            .on_stop_ack_from_target(
                pending.pending_id,
                &pending.target,
                &pending.response,
                &mut initiator_response,
            )
            .map_err(|e| format!("handle STOP response: {e}"))?;

        endpoint
            .send_stream(&pending.hop.0, pending.hop.1, initiator_response)
            .map_err(|e| format!("send HOP success: {e}"))?;
        if !pending.hop_trailing.is_empty() {
            endpoint
                .send_stream(&key.0, key.1, pending.hop_trailing)
                .map_err(|e| format!("forward pipelined initiator bytes: {e}"))?;
        }
        if !stop_trailing.is_empty() {
            endpoint
                .send_stream(&pending.hop.0, pending.hop.1, stop_trailing)
                .map_err(|e| format!("forward pipelined responder bytes: {e}"))?;
        }
        self.bridges.insert(pending.hop.clone(), key.clone());
        self.bridges.insert(key, pending.hop);
        self.trace.push("bridge active".into());
        Ok(())
    }

    fn drop_stream(&mut self, endpoint: &mut Endpoint, key: &StreamKey) {
        self.hop_buffers.remove(key);
        if let Some(stop) = self.hop_to_stop.remove(key) {
            self.pending_stops.remove(&stop);
            let _ = endpoint.reset_stream(&stop.0, stop.1);
        }
        if let Some(other) = self.bridges.remove(key) {
            self.bridges.remove(&other);
            let _ = endpoint.reset_stream(&other.0, other.1);
        }
    }
}

/// Background loopback relay with an address suitable for NAT configuration.
pub struct RelayServer {
    addr: PeerAddr,
    commands: mpsc::Sender<Command>,
    failure: Arc<Mutex<Option<String>>>,
    trace: Arc<Mutex<VecDeque<String>>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl RelayServer {
    pub fn spawn() -> Self {
        let mut endpoint = Endpoint::builder()
            .protocol(HOP_PROTOCOL_ID)
            .protocol(STOP_PROTOCOL_ID)
            .bind_quic("127.0.0.1:0")
            .expect("bind relay endpoint");
        let addr = endpoint.listen().expect("relay listens");
        let (commands, receiver) = mpsc::channel();
        let failure = Arc::new(Mutex::new(None));
        let failure_sink = Arc::clone(&failure);
        let trace = Arc::new(Mutex::new(VecDeque::new()));
        let trace_sink = Arc::clone(&trace);
        let thread = thread::spawn(move || {
            let mut machine = RelayMachine::default();
            loop {
                match receiver.try_recv() {
                    Ok(Command::CutAll) => {
                        for peer in endpoint.connected_peers() {
                            let _ = endpoint.disconnect(&peer);
                        }
                    }
                    Ok(Command::Stop) => break,
                    Err(mpsc::TryRecvError::Disconnected) => break,
                    Err(mpsc::TryRecvError::Empty) => {}
                }
                match endpoint.next_event(Duration::from_millis(10)) {
                    Ok(Some(event)) => {
                        let mut trace = trace_sink.lock().expect("relay trace lock");
                        if trace.len() == 256 {
                            trace.pop_front();
                        }
                        trace.push_back(format!("{event:?}"));
                        drop(trace);
                        if let Err(error) = machine.handle(&mut endpoint, event) {
                            *failure_sink.lock().expect("relay failure lock") = Some(error);
                            break;
                        }
                        let mut trace = trace_sink.lock().expect("relay trace lock");
                        for entry in machine.trace.drain(..) {
                            if trace.len() == 256 {
                                trace.pop_front();
                            }
                            trace.push_back(entry);
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        *failure_sink.lock().expect("relay failure lock") =
                            Some(format!("relay endpoint: {error}"));
                        break;
                    }
                }
            }
        });
        Self {
            addr,
            commands,
            failure,
            trace,
            thread: Some(thread),
        }
    }

    pub fn addr(&self) -> &PeerAddr {
        &self.addr
    }

    /// Closes both underlying relay sessions while leaving the relay loop up
    /// long enough for peers to observe transport closure.
    pub fn cut_all(&self) {
        self.commands.send(Command::CutAll).expect("relay is alive");
    }

    pub fn assert_healthy(&self) {
        if let Some(error) = self.failure.lock().expect("relay failure lock").clone() {
            panic!("loopback relay failed: {error}");
        }
    }

    pub fn trace(&self) -> Vec<String> {
        self.trace
            .lock()
            .expect("relay trace lock")
            .iter()
            .cloned()
            .collect()
    }
}

impl Drop for RelayServer {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Stop);
        if let Some(thread) = self.thread.take() {
            thread.join().expect("relay thread joins");
        }
        self.assert_healthy();
    }
}
