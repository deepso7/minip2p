//! Endpoint setup shared by the Endpoint benches: event helpers, a driver
//! thread, and the three-Endpoint forced relayed circuit.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use minip2p::{
    ConnectOutcome, Deadline, Endpoint, EndpointBuilder, EndpointEvent, EndpointWaitOutcome,
    NatConfig, PeerAddr, PeerId, RelayServerConfig, ReservationPolicy,
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

/// Drives an Endpoint on its own thread, handing every event to a callback,
/// until dropped.
pub struct Driven {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Driven {
    pub fn spawn(
        mut endpoint: Endpoint,
        mut on_event: impl FnMut(&mut Endpoint, EndpointEvent) + Send + 'static,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !worker_stop.load(Ordering::Relaxed) {
                if let Some(event) = next_event(&mut endpoint, Duration::from_millis(10)) {
                    on_event(&mut endpoint, event);
                }
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
            let joined = thread.join();
            assert!(
                joined.is_ok() || thread::panicking(),
                "endpoint driver thread panicked"
            );
        }
    }
}

/// A relay server with circuit byte and duration caps far above anything a
/// bench forwards, listening on loopback QUIC.
pub fn bind_relay() -> (Endpoint, PeerAddr) {
    let config = RelayServerConfig {
        max_circuit_bytes: 1 << 40,
        max_circuit_duration_secs: 3600,
        ..RelayServerConfig::default()
    };
    let mut relay = bind_on(
        Endpoint::builder()
            .relay_server_config(config)
            .expect("relay server config"),
        "/ip4/127.0.0.1/udp/0/quic-v1",
    );
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
