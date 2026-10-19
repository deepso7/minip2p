//! The JavaScript surface: `WebEndpoint`, shaped like the Node addon's
//! `NodeEndpoint` so the TypeScript adapters share one backend.
//!
//! Values cross as ffi-core's serde shape (`js_shape`), with every `u64` a
//! `bigint` and an absent value `null`, as napi-rs hands them. Errors are JS
//! `Error`s tagged with `code`, `detail` and `capability`, as the Node addon
//! throws them.

use minip2p::Now;
use minip2p_ffi_core::{
    ConnectTarget, DiscoveryOptions, EndpointConfig, FfiError, MdnsOptions, PUMP_DRAIN_LIMIT,
};
use minip2p_webtransport::WebTransportClient;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::io::{JsIo, JsIoHandle};
use crate::{Host, WebEntropy};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = performance, js_name = now)]
    fn performance_now() -> f64;
}

type WebHost = Host<WebTransportClient<JsIo, WebEntropy>>;

/// A minip2p endpoint in the browser, dialing over WebTransport.
///
/// It is driven by its TypeScript owner: every call returns at once, and
/// `pump` polls the endpoint, which the owner schedules after each call, each
/// `JsIo` event, and at the deadline `pump` returns.
#[wasm_bindgen]
pub struct WebEndpoint {
    host: WebHost,
    doorbell: Option<js_sys::Function>,
    /// The last monotonic sample, so time never runs backwards.
    last_ms: u64,
}

#[wasm_bindgen]
impl WebEndpoint {
    /// Validates the key and config and builds the endpoint over `io`,
    /// without driving it yet.
    #[wasm_bindgen(constructor)]
    pub fn new(secret_key: Vec<u8>, config: JsValue, io: JsIoHandle) -> Result<Self, JsValue> {
        let config: WebEndpointConfig =
            serde_wasm_bindgen::from_value(config).map_err(|error| {
                js_error(&FfiError::InvalidConfig {
                    capability: minip2p_ffi_core::ConfigCapability::Options,
                    detail: error.to_string(),
                })
            })?;
        let io = JsIo(io);
        let host = Host::new(secret_key, config.into(), |identity| {
            WebTransportClient::new(io, identity.clone(), WebEntropy)
        })
        .map_err(|error| js_error(&error))?;
        Ok(Self {
            host,
            doorbell: None,
            last_ms: 0,
        })
    }

    /// Starts driving; `doorbell` is called when events become ready to drain.
    pub fn start(&mut self, doorbell: js_sys::Function) -> Result<(), JsValue> {
        self.host.start().map_err(|error| js_error(&error))?;
        self.doorbell = Some(doorbell);
        Ok(())
    }

    /// Polls the endpoint once and returns the milliseconds until it needs
    /// polling again (`0` at once), or `undefined` when nothing is
    /// scheduled.
    pub fn pump(&mut self) -> Option<f64> {
        let now = self.now();
        let pumped = self.host.pump(now);
        if pumped.ring {
            self.ring();
        }
        #[expect(
            clippy::cast_precision_loss,
            reason = "a delay past 2^53 ms is never reached"
        )]
        pumped
            .next_deadline
            .map(|deadline| deadline.millis_until(now) as f64)
    }

    /// Closes the endpoint; `EndpointClosed` is the last event drained.
    ///
    /// The timeout is ignored in the browser: every session closes at once
    /// (`WebTransport.close()` sends the close capsule), so there is no
    /// drain for it to bound.
    pub fn close(&mut self, _timeout_ms: u32) {
        let now = self.now();
        if self.host.close(now) {
            self.ring();
        }
    }

    /// The local peer ID.
    #[wasm_bindgen(js_name = peerId)]
    pub fn peer_id(&self) -> String {
        self.host.peer_id()
    }

    /// The listen set; empty, since browsers do not listen.
    #[wasm_bindgen(js_name = listenAddrs)]
    pub fn listen_addrs(&self) -> Vec<String> {
        self.host.listen_addrs()
    }

    /// Whether the endpoint is started and not closed.
    #[wasm_bindgen(js_name = isRunning)]
    pub fn is_running(&self) -> bool {
        self.host.is_running()
    }

    /// Pulls a bounded batch of events.
    #[wasm_bindgen(js_name = drainEvents)]
    pub fn drain_events(&mut self, limit: u32) -> Result<JsValue, JsValue> {
        let limit = usize::try_from(limit)
            .unwrap_or(PUMP_DRAIN_LIMIT)
            .min(PUMP_DRAIN_LIMIT);
        to_js(&self.host.drain_events(limit))
    }

    /// Connected peer IDs.
    #[wasm_bindgen(js_name = connectedPeers)]
    pub fn connected_peers(&mut self) -> Result<Vec<String>, JsValue> {
        self.host
            .connected_peers()
            .map_err(|error| js_error(&error))
    }

    /// Whether Identify completed for a peer.
    #[wasm_bindgen(js_name = isPeerReady)]
    pub fn is_peer_ready(&mut self, peer_id: String) -> Result<bool, JsValue> {
        self.host
            .is_peer_ready(peer_id)
            .map_err(|error| js_error(&error))
    }

    /// The latest Identify snapshot, or `null`.
    #[wasm_bindgen(js_name = peerInfo)]
    pub fn peer_info(&mut self, peer_id: String) -> Result<JsValue, JsValue> {
        js_result(self.host.peer_info(peer_id))
    }

    /// Ignored in the browser, kept for the shared SDK surface: there is no
    /// background driver whose cadence it could change. The page's own
    /// timers pump the endpoint.
    #[wasm_bindgen(js_name = setActive)]
    pub fn set_active(&self, _active: bool) {}

    /// Subscribes to a pubsub topic.
    pub fn subscribe(&mut self, topic: String) -> Result<bool, JsValue> {
        let now = self.now();
        self.host
            .subscribe(topic, now)
            .map_err(|error| js_error(&error))
    }

    /// Unsubscribes from a pubsub topic.
    pub fn unsubscribe(&mut self, topic: String) -> Result<bool, JsValue> {
        let now = self.now();
        self.host
            .unsubscribe(topic, now)
            .map_err(|error| js_error(&error))
    }

    /// Publishes one pubsub payload.
    pub fn publish(&mut self, topic: String, data: Vec<u8>) -> Result<(), JsValue> {
        let now = self.now();
        self.host
            .publish(topic, data, now)
            .map_err(|error| js_error(&error))
    }

    /// Starts one ping.
    pub fn ping(&mut self, peer_id: String) -> Result<(), JsValue> {
        let now = self.now();
        self.host
            .ping(peer_id, now)
            .map_err(|error| js_error(&error))
    }

    /// Registers an application protocol.
    #[wasm_bindgen(js_name = addProtocol)]
    pub fn add_protocol(&mut self, protocol_id: String) -> Result<(), JsValue> {
        self.host
            .add_protocol(protocol_id)
            .map_err(|error| js_error(&error))
    }

    /// Starts opening an application stream.
    #[wasm_bindgen(js_name = openStream)]
    pub fn open_stream(
        &mut self,
        peer_id: String,
        protocol_id: String,
    ) -> Result<JsValue, JsValue> {
        let now = self.now();
        js_result(self.host.open_stream(peer_id, protocol_id, now))
    }

    /// Sends bytes on a stream: `true` once all are accepted, `false` while
    /// the tail is held and `StreamWriteAccepted` is still to come.
    #[wasm_bindgen(js_name = sendStream)]
    pub fn send_stream(
        &mut self,
        conn_id: u64,
        stream_id: u64,
        data: Vec<u8>,
    ) -> Result<bool, JsValue> {
        let now = self.now();
        self.host
            .send_stream(conn_id, stream_id, data, now)
            .map_err(|error| js_error(&error))
    }

    /// Half-closes a stream's write side.
    #[wasm_bindgen(js_name = closeStreamWrite)]
    pub fn close_stream_write(&mut self, conn_id: u64, stream_id: u64) -> Result<(), JsValue> {
        let now = self.now();
        self.host
            .close_stream_write(conn_id, stream_id, now)
            .map_err(|error| js_error(&error))
    }

    /// Resets a stream.
    #[wasm_bindgen(js_name = resetStream)]
    pub fn reset_stream(&mut self, conn_id: u64, stream_id: u64) -> Result<(), JsValue> {
        let now = self.now();
        self.host
            .reset_stream(conn_id, stream_id, now)
            .map_err(|error| js_error(&error))
    }

    /// Resets and relinquishes a stream.
    #[wasm_bindgen(js_name = abandonStream)]
    pub fn abandon_stream(&mut self, conn_id: u64, stream_id: u64) -> Result<(), JsValue> {
        let now = self.now();
        self.host
            .abandon_stream(conn_id, stream_id, now)
            .map_err(|error| js_error(&error))
    }

    /// Acknowledges `bytes` of a stream's received data as consumed.
    #[wasm_bindgen(js_name = streamConsumed)]
    pub fn stream_consumed(
        &mut self,
        conn_id: u64,
        stream_id: u64,
        bytes: u32,
    ) -> Result<(), JsValue> {
        let now = self.now();
        self.host
            .stream_consumed(conn_id, stream_id, u64::from(bytes), now)
            .map_err(|error| js_error(&error))
    }

    /// Starts one Connection attempt: a peer ID string, or an array of peer
    /// addresses naming one peer. Returns the Connect ID.
    pub fn connect(&mut self, target: JsValue) -> Result<u64, JsValue> {
        let target = if let Some(peer_id) = target.as_string() {
            ConnectTarget::Peer { peer_id }
        } else {
            let addresses: Vec<String> =
                serde_wasm_bindgen::from_value(target).map_err(|_shape| {
                    js_error(&FfiError::InvalidAddress {
                        detail: "a connect target is a peer ID or an array of addresses".into(),
                    })
                })?;
            ConnectTarget::Addresses { addresses }
        };
        let now = self.now();
        self.host
            .connect(target, now)
            .map_err(|error| js_error(&error))
    }

    /// Cancels a Connection attempt.
    #[wasm_bindgen(js_name = cancelConnect)]
    pub fn cancel_connect(&mut self, id: u64) -> Result<(), JsValue> {
        let now = self.now();
        self.host
            .cancel_connect(id, now)
            .map_err(|error| js_error(&error))
    }

    /// Disconnects one peer.
    pub fn disconnect(&mut self, peer_id: String) -> Result<(), JsValue> {
        let now = self.now();
        self.host
            .disconnect(peer_id, now)
            .map_err(|error| js_error(&error))
    }

    /// The path of a peer's connection, or `null`.
    pub fn path(&mut self, peer_id: String) -> Result<JsValue, JsValue> {
        js_result(self.host.path(peer_id))
    }

    /// A snapshot of a peer's connection, or `null`.
    #[wasm_bindgen(js_name = connectionInfo)]
    pub fn connection_info(&mut self, peer_id: String) -> Result<JsValue, JsValue> {
        js_result(self.host.connection_info(peer_id))
    }

    /// The discovery book (always empty in a browser).
    #[wasm_bindgen(js_name = knownPeers)]
    pub fn known_peers(&mut self) -> Result<JsValue, JsValue> {
        js_result(self.host.known_peers())
    }

    /// The discovery clock (always `null` in a browser).
    #[wasm_bindgen(js_name = discoveryNowMs)]
    pub fn discovery_now_ms(&mut self) -> Result<JsValue, JsValue> {
        js_result(self.host.discovery_now_ms())
    }

    /// The reachability verdict (always `Unknown` in a browser).
    pub fn reachability(&mut self) -> Result<JsValue, JsValue> {
        js_result(self.host.reachability())
    }

    /// The relay reservation currently held, or `null`.
    #[wasm_bindgen(js_name = activeReservation)]
    pub fn active_reservation(&mut self) -> Result<JsValue, JsValue> {
        js_result(self.host.active_reservation())
    }
}

impl WebEndpoint {
    /// One time sample: `performance.now()`, never running backwards, and
    /// `Date.now()` for the wall clock.
    fn now(&mut self) -> Now {
        self.last_ms = self.last_ms.max(millis(performance_now()));
        Now::new(self.last_ms, millis(js_sys::Date::now()) / 1000)
    }

    fn ring(&self) {
        if let Some(doorbell) = &self.doorbell {
            // Advisory, as in the Node shell: a throwing doorbell must not
            // fail the pump.
            drop(doorbell.call0(&JsValue::NULL));
        }
    }
}

/// Generates a 32-byte Ed25519 secret key from `crypto.getRandomValues`.
#[wasm_bindgen(js_name = generateSecretKey)]
pub fn generate_secret_key() -> Result<Vec<u8>, JsValue> {
    let mut key = vec![0; 32];
    getrandom::fill(&mut key).map_err(|error| {
        js_error(&FfiError::Internal {
            detail: format!("crypto.getRandomValues failed: {error}"),
        })
    })?;
    Ok(key)
}

/// Derives a peer ID from raw Ed25519 secret key material.
#[wasm_bindgen(js_name = peerIdFromSecretKey)]
pub fn peer_id_from_secret_key(secret_key: Vec<u8>) -> Result<String, JsValue> {
    minip2p_ffi_core::peer_id_from_secret_key(secret_key).map_err(|error| js_error(&error))
}

/// Builds a circuit address through a direct relay address.
#[wasm_bindgen(js_name = circuitAddress)]
pub fn circuit_address(relay_address: String, peer_id: String) -> Result<String, JsValue> {
    minip2p_ffi_core::circuit_address(relay_address, peer_id).map_err(|error| js_error(&error))
}

/// The SDK's resolved endpoint config (`BackendEndpointConfig`), with
/// `bigint` `u64` fields.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebEndpointConfig {
    agent_version: Option<String>,
    relays: Vec<String>,
    autonat_servers: Vec<String>,
    listen: Option<Vec<String>>,
    force_relay: bool,
    allow_unsigned: bool,
    protocols: Vec<String>,
    discovery: Option<WebDiscoveryOptions>,
    mdns: Option<WebMdnsOptions>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebDiscoveryOptions {
    topic: String,
    beacon_interval_ms: u64,
    peer_ttl_ms: u64,
    auto_dial: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebMdnsOptions {
    enable_ipv6: bool,
    ttl_ms: u64,
    query_interval_ms: u64,
    max_packet_bytes: u32,
    max_announced_addrs: u32,
    interface_refresh_ms: u64,
    auto_dial: bool,
}

impl From<WebEndpointConfig> for EndpointConfig {
    fn from(config: WebEndpointConfig) -> Self {
        Self {
            agent_version: config.agent_version,
            relays: config.relays,
            autonat_servers: config.autonat_servers,
            listen: config.listen,
            force_relay: config.force_relay,
            allow_unsigned: config.allow_unsigned,
            protocols: config.protocols,
            discovery: config.discovery.map(|options| DiscoveryOptions {
                topic: options.topic,
                beacon_interval_ms: options.beacon_interval_ms,
                peer_ttl_ms: options.peer_ttl_ms,
                auto_dial: options.auto_dial,
            }),
            mdns: config.mdns.map(|options| MdnsOptions {
                enable_ipv6: options.enable_ipv6,
                ttl_ms: options.ttl_ms,
                query_interval_ms: options.query_interval_ms,
                max_packet_bytes: options.max_packet_bytes,
                max_announced_addrs: options.max_announced_addrs,
                interface_refresh_ms: options.interface_refresh_ms,
                auto_dial: options.auto_dial,
            }),
        }
    }
}

/// Whole milliseconds of a non-negative JS time reading.
#[expect(
    clippy::cast_sign_loss,
    reason = "clamped to non-negative; the float-to-int cast saturates"
)]
fn millis(value: f64) -> u64 {
    value.max(0.0) as u64
}

fn js_result<T: Serialize>(value: Result<T, FfiError>) -> Result<JsValue, JsValue> {
    value
        .map_err(|error| js_error(&error))
        .and_then(|value| to_js(&value))
}

/// The serde shape as napi-rs hands it: `u64` as `bigint`, `None` as `null`.
fn to_js<T: Serialize + ?Sized>(value: &T) -> Result<JsValue, JsValue> {
    value
        .serialize(
            &serde_wasm_bindgen::Serializer::new()
                .serialize_large_number_types_as_bigints(true)
                .serialize_missing_as_null(true),
        )
        .map_err(JsValue::from)
}

/// A JS `Error` tagged as the Node addon tags it: `code` (the variant),
/// `detail`, and an `InvalidConfig`'s `capability`.
fn js_error(error: &FfiError) -> JsValue {
    let js = js_sys::Error::new(&error.to_string());
    let set = |key: &str, value: &str| {
        drop(js_sys::Reflect::set(&js, &key.into(), &value.into()));
    };
    set("code", error.code());
    if let Some(detail) = error.detail() {
        set("detail", detail);
    }
    if let Some(capability) = error.capability() {
        set("capability", capability.as_str());
    }
    js.into()
}
