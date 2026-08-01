//! One entropy adapter, both transports.
//!
//! Circuit and TCP draw randomness from the same
//! [`minip2p_platform::EntropySource`], so a host that composes both stacks
//! writes a single impl over its RNG. This test exists to fail compilation if
//! either transport ever grows a private entropy trait again.

#![cfg(feature = "std")]

use minip2p_circuit::CircuitTransport;
use minip2p_identity::Ed25519Keypair;
use minip2p_platform::{EntropyError, EntropySource};
use minip2p_tcp::{StdTcpProvider, TcpTransport};
use minip2p_test_support::InMemoryTransport;
use minip2p_transport::Transport;

/// Stands in for a board's single RNG adapter; deterministic so the test does
/// not depend on an OS entropy source being reachable.
#[derive(Clone, Copy, Debug)]
struct BoardRng(u8);

impl EntropySource for BoardRng {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        self.0 = self.0.wrapping_add(1);
        output.fill(self.0);
        Ok(())
    }
}

#[test]
fn one_entropy_adapter_serves_the_circuit_and_tcp_transports() {
    let identity = Ed25519Keypair::from_secret_key_bytes([7; 32]);
    let peer = identity.peer_id();
    let (inner, _remote) = InMemoryTransport::pair(peer.clone(), peer.clone());
    let rng = BoardRng(0);

    let circuit = CircuitTransport::new(inner, identity.clone(), rng);
    let tcp = TcpTransport::new(
        StdTcpProvider::new().expect("a readiness registry"),
        identity,
        rng,
    );

    // Both are live `Transport`s built from one adapter, which is the whole
    // point: no per-crate entropy trait to bridge between them.
    fn assert_transport<T: Transport>(_: &T) {}
    assert_transport(&circuit);
    assert_transport(&tcp);

    assert!(circuit.circuit_ids().is_empty());
    assert_eq!(tcp.local_peer_id(), peer);
    assert!(tcp.local_addresses().is_empty());
}
