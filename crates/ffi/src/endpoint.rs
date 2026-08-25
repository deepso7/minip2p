//! Thin UniFFI endpoint shell.

use crate::{
    EndpointConfig, FfiError, IdentifyInfo, KnownPeerInfo, OpenStreamResult, P2pEvent,
    P2pEventDoorbell, PathKind, Reachability, RelayReservationInfo,
};
use std::sync::Arc;

struct Doorbell(Arc<dyn P2pEventDoorbell>);
impl minip2p_ffi_core::EventDoorbell for Doorbell {
    fn on_events_ready(&self) {
        self.0.on_events_ready();
    }
}

/// A minip2p endpoint owned by a foreign runtime.
#[derive(uniffi::Object)]
pub struct P2pEndpoint(Arc<minip2p_ffi_core::P2pEndpoint>);

#[uniffi::export]
impl P2pEndpoint {
    /// Creates an endpoint after validating configuration and binding sockets.
    #[uniffi::constructor]
    pub fn new(secret_key: Vec<u8>, mut config: EndpointConfig) -> Result<Arc<Self>, FfiError> {
        if config.agent_version.is_none() {
            config.agent_version = Some(format!("minip2p-rn/{}", env!("CARGO_PKG_VERSION")));
        }
        minip2p_ffi_core::P2pEndpoint::new(secret_key, config).map(|core| Arc::new(Self(core)))
    }
    /// Returns the local peer ID.
    pub fn peer_id(&self) -> String {
        self.0.peer_id()
    }
    /// Returns bound peer addresses.
    pub fn listen_addrs(&self) -> Vec<String> {
        self.0.listen_addrs()
    }
    /// Returns connected peers.
    pub fn connected_peers(&self) -> Result<Vec<String>, FfiError> {
        self.0.connected_peers()
    }
    /// Returns whether Identify completed for a peer.
    pub fn is_peer_ready(&self, peer_id: String) -> Result<bool, FfiError> {
        self.0.is_peer_ready(peer_id)
    }
    /// Returns the latest Identify snapshot.
    pub fn peer_info(&self, peer_id: String) -> Result<Option<IdentifyInfo>, FfiError> {
        self.0.peer_info(peer_id)
    }
    /// Selects active or idle polling.
    pub fn set_active(&self, active: bool) {
        self.0.set_active(active);
    }
    /// Returns whether the driver accepts work.
    pub fn is_running(&self) -> bool {
        self.0.is_running()
    }
    /// Starts the detached driver and registers its doorbell.
    pub fn start(&self, doorbell: Arc<dyn P2pEventDoorbell>) -> Result<(), FfiError> {
        self.0.start(Arc::new(Doorbell(doorbell)))
    }
    /// Pulls at most `limit` queued events in order.
    pub fn drain_events(&self, limit: u32) -> Vec<P2pEvent> {
        self.0.drain_events(limit)
    }
    /// Requests shutdown.
    pub fn stop(&self) {
        self.0.stop();
    }
    /// Waits for complete driver shutdown.
    pub fn wait_stopped(&self, timeout_ms: u64) -> bool {
        self.0.wait_stopped(timeout_ms)
    }
    /// Subscribes to a pubsub topic.
    pub fn subscribe(&self, topic: String) -> Result<bool, FfiError> {
        self.0.subscribe(topic)
    }
    /// Withdraws a pubsub subscription.
    pub fn unsubscribe(&self, topic: String) -> Result<bool, FfiError> {
        self.0.unsubscribe(topic)
    }
    /// Publishes one payload.
    pub fn publish(&self, topic: String, data: Vec<u8>) -> Result<(), FfiError> {
        self.0.publish(topic, data)
    }
    /// Sends an explicit ping.
    pub fn ping(&self, peer_id: String) -> Result<(), FfiError> {
        self.0.ping(peer_id)
    }
    /// Registers an application protocol.
    pub fn add_protocol(&self, protocol_id: String) -> Result<(), FfiError> {
        self.0.add_protocol(protocol_id)
    }
    /// Opens an application stream.
    pub fn open_stream(
        &self,
        peer_id: String,
        protocol_id: String,
    ) -> Result<OpenStreamResult, FfiError> {
        self.0.open_stream(peer_id, protocol_id)
    }
    /// Sends bytes on a stream.
    pub fn send_stream(
        &self,
        peer_id: String,
        stream_id: u64,
        data: Vec<u8>,
    ) -> Result<(), FfiError> {
        self.0.send_stream(peer_id, stream_id, data)
    }
    /// Half-closes a stream's write side.
    pub fn close_stream_write(&self, peer_id: String, stream_id: u64) -> Result<(), FfiError> {
        self.0.close_stream_write(peer_id, stream_id)
    }
    /// Resets a stream.
    pub fn reset_stream(&self, peer_id: String, stream_id: u64) -> Result<(), FfiError> {
        self.0.reset_stream(peer_id, stream_id)
    }
    /// Forgets a stream.
    pub fn abandon_stream(&self, peer_id: String, stream_id: u64) -> Result<(), FfiError> {
        self.0.abandon_stream(peer_id, stream_id)
    }
    /// Starts a connection attempt.
    pub fn connect(&self, peer_id: String) -> Result<u64, FfiError> {
        self.0.connect(peer_id)
    }
    /// Starts a connection attempt with explicit addresses.
    pub fn connect_with_addrs(
        &self,
        peer_id: String,
        addresses: Vec<String>,
    ) -> Result<u64, FfiError> {
        self.0.connect_with_addrs(peer_id, addresses)
    }
    /// Starts a direct-address connection attempt.
    pub fn connect_addr(&self, address: String) -> Result<u64, FfiError> {
        self.0.connect_addr(address)
    }
    /// Dials on all applicable address families.
    pub fn dial(&self, address: String) -> Result<Vec<u64>, FfiError> {
        self.0.dial(address)
    }
    /// Dials using IPv4.
    pub fn dial_ip4(&self, address: String) -> Result<u64, FfiError> {
        self.0.dial_ip4(address)
    }
    /// Dials using IPv6.
    pub fn dial_ip6(&self, address: String) -> Result<u64, FfiError> {
        self.0.dial_ip6(address)
    }
    /// Cancels a connection attempt.
    pub fn cancel_connect(&self, id: u64) -> Result<(), FfiError> {
        self.0.cancel_connect(id)
    }
    /// Disconnects a peer.
    pub fn disconnect(&self, peer_id: String) -> Result<(), FfiError> {
        self.0.disconnect(peer_id)
    }
    /// Returns the current path to a peer.
    pub fn path(&self, peer_id: String) -> Result<Option<PathKind>, FfiError> {
        self.0.path(peer_id)
    }
    /// Returns the discovery address book.
    pub fn known_peers(&self) -> Result<Vec<KnownPeerInfo>, FfiError> {
        self.0.known_peers()
    }
    /// Returns the discovery clock.
    pub fn discovery_now_ms(&self) -> Result<Option<u64>, FfiError> {
        self.0.discovery_now_ms()
    }
    /// Returns the current reachability verdict.
    pub fn reachability(&self) -> Result<Reachability, FfiError> {
        self.0.reachability()
    }
    /// Returns the active relay reservation.
    pub fn active_reservation(&self) -> Result<Option<RelayReservationInfo>, FfiError> {
        self.0.active_reservation()
    }
}

impl P2pEndpoint {
    /// Returns Rust-side driver diagnostics.
    pub fn driver_stats(&self) -> minip2p_ffi_core::DriverStats {
        self.0.driver_stats()
    }
}
