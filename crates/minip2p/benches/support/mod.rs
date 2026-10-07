//! Endpoint setup shared by the Endpoint benches: event helpers, a driver
//! thread, and the three-Endpoint forced relayed circuit.

#![allow(
    dead_code,
    reason = "each bench compiles this module on its own and uses a subset of it"
)]

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use minip2p::{
    Bytes, ConnectOutcome, ConnectionId, Deadline, Endpoint, EndpointBuilder, EndpointEvent,
    EndpointWaitOutcome, Error, NatConfig, PeerAddr, PeerId, RelayServerConfig, ReservationPolicy,
    StreamId,
};

/// Upper bound for every setup step.
pub const SETUP_TIMEOUT: Duration = Duration::from_secs(15);

/// The next Endpoint event, or `None` once `deadline` passes.
pub fn next_event(endpoint: &mut Endpoint, deadline: impl Into<Deadline>) -> Option<EndpointEvent> {
    let deadline = deadline.into();
    loop {
        match endpoint.wait(deadline).expect("endpoint wait") {
            EndpointWaitOutcome::Event(event) => return Some(event),
            EndpointWaitOutcome::Deadline => return None,
            EndpointWaitOutcome::Interrupted => {}
        }
    }
}

/// An Endpoint bound to an ephemeral loopback address of one transport.
pub fn bind_on(builder: EndpointBuilder, listen: &str) -> Endpoint {
    builder
        .agent_version("minip2p-bench")
        .listen_on(listen)
        .expect("listen address")
        .bind()
        .expect("bind endpoint")
}

/// One write of a bulk sender: resends the held unsent tail if there is one,
/// otherwise a fresh `chunk` (a cheap `Bytes` handle clone). Returns the bytes
/// accepted and whether the stream reported Full; on Full the exact unsent
/// suffix is kept in `held` for the next call (ADR 0012). Any other error
/// panics.
pub fn send_chunk(
    endpoint: &mut Endpoint,
    peer: &PeerId,
    stream: (ConnectionId, StreamId),
    chunk: &Bytes,
    held: &mut Option<Bytes>,
) -> (u64, bool) {
    let data = held.take().unwrap_or_else(|| chunk.clone());
    let len = data.len();
    match endpoint.send_stream(peer, stream.0, stream.1, data) {
        Err(Error::Full { unsent, .. }) => {
            let accepted = len - unsent.len();
            *held = Some(unsent);
            (accepted as u64, true)
        }
        other => {
            other.expect("send failed");
            (len as u64, false)
        }
    }
}

/// Drives an Endpoint on its own thread until dropped.
pub struct Driven {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Driven {
    /// Hands every event to `on_event`.
    pub fn spawn(
        endpoint: Endpoint,
        mut on_event: impl FnMut(&mut Endpoint, EndpointEvent) + Send + 'static,
    ) -> Self {
        Self::run(endpoint, move |endpoint| {
            if let Some(event) = next_event(endpoint, Duration::from_millis(10)) {
                on_event(endpoint, event);
            }
        })
    }

    /// Calls `step` repeatedly; each call must drive the Endpoint itself and
    /// return within a few milliseconds, so a drop is not held up.
    pub fn run(
        mut endpoint: Endpoint,
        mut step: impl FnMut(&mut Endpoint) + Send + 'static,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !worker_stop.load(Ordering::Relaxed) {
                step(&mut endpoint);
            }
        });
        Self {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Driven {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            // Re-raise a driver-thread panic unless already unwinding.
            if let Err(payload) = thread.join()
                && !thread::panicking()
            {
                std::panic::resume_unwind(payload);
            }
        }
    }
}

/// A relay server with circuit byte and duration caps far above anything a
/// bench forwards.
pub fn relay_builder() -> EndpointBuilder {
    let config = RelayServerConfig {
        max_circuit_bytes: 1 << 40,
        max_circuit_duration_secs: 3600,
        ..RelayServerConfig::default()
    };
    Endpoint::builder()
        .relay_server_config(config)
        .expect("relay server config")
}

/// A [`relay_builder`] relay listening on loopback QUIC.
pub fn bind_relay() -> (Endpoint, PeerAddr) {
    let mut relay = bind_on(relay_builder(), "/ip4/127.0.0.1/udp/0/quic-v1");
    let address = relay.listen().expect("relay listens");
    (relay, address)
}

/// A target and a client connected over a forced relayed circuit through
/// `relay`, both speaking `protocol`.
pub struct Relayed {
    pub target: Endpoint,
    pub client: Endpoint,
    pub target_peer: PeerId,
}

impl Relayed {
    /// Builds both peers with `relay` configured and `force_relay` set (no
    /// direct dial, no DCUtR), waits for the target's reservation, then
    /// connects the client to the target through the relay and waits until
    /// Identify completes on both ends. Asserts the connection is a circuit.
    ///
    /// Everything runs on the calling thread, `relay` included, so the caller
    /// decides afterwards which thread drives which Endpoint.
    pub fn connect(relay: &mut Endpoint, relay_addr: &PeerAddr, protocol: &str) -> Self {
        let peer = |policy| {
            let mut endpoint = bind_on(
                Endpoint::builder()
                    .protocol(protocol)
                    .relay(relay_addr.clone())
                    .nat_config(NatConfig {
                        force_relay: true,
                        reservation_policy: policy,
                        ..NatConfig::default()
                    }),
                "/ip4/127.0.0.1/udp/0/quic-v1",
            );
            endpoint.listen().expect("listen");
            endpoint
        };
        let tick = Duration::from_millis(1);

        let mut target = peer(ReservationPolicy::Always);
        let target_peer = target.peer_id().clone();
        let deadline = Instant::now() + SETUP_TIMEOUT;
        loop {
            assert!(Instant::now() < deadline, "target reservation timed out");
            next_event(relay, tick);
            if let Some(EndpointEvent::Nat(minip2p::NatEvent::RelayReserved { relay, .. })) =
                next_event(&mut target, tick)
                && &relay == relay_addr.peer_id()
            {
                break;
            }
        }

        let mut client = peer(ReservationPolicy::Never);
        let client_peer = client.peer_id().clone();
        let connect_id = client.connect(&target_peer).expect("relayed connect");
        let deadline = Instant::now() + SETUP_TIMEOUT;
        let (mut circuit, mut client_ready, mut target_ready) = (false, false, false);
        while !(circuit && client_ready && target_ready) {
            assert!(Instant::now() < deadline, "relayed connect timed out");
            next_event(relay, tick);
            match next_event(&mut client, tick) {
                Some(EndpointEvent::ConnectSettled {
                    connect_id: settled,
                    outcome,
                    ..
                }) if settled == connect_id => {
                    assert!(
                        matches!(outcome, ConnectOutcome::Connected { conn_id } if conn_id.is_circuit()),
                        "relayed connect did not settle on a circuit: {outcome:?}"
                    );
                    circuit = true;
                }
                Some(EndpointEvent::PeerReady { peer_id, .. }) if peer_id == target_peer => {
                    client_ready = true;
                }
                _ => {}
            }
            if let Some(EndpointEvent::PeerReady { peer_id, .. }) = next_event(&mut target, tick)
                && peer_id == client_peer
            {
                target_ready = true;
            }
        }
        Self {
            target,
            client,
            target_peer,
        }
    }
}
