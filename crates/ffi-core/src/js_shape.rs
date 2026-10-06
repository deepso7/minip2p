//! The JavaScript-facing serde representation, behind the `serde` feature.
//!
//! The event, path and snapshot types serialize to the one public JS shape
//! the TypeScript SDK consumes:
//!
//! - events and paths are `{ tag, inner }` objects, `tag` being the Rust
//!   variant name; a variant without fields has no `inner`;
//! - fields are camelCase;
//! - `None` fields are omitted rather than `null`, matching optional (`?:`)
//!   TypeScript properties;
//! - byte payloads serialize as bytes, which napi-rs turns into a `Buffer`;
//! - field-less enums are their variant name as a string;
//! - `u64` values stay lossless: napi-rs emits a `number` up to `u32::MAX`
//!   and a `bigint` above it.

/// Serializes owned bytes as a byte string instead of a sequence of numbers.
pub(crate) fn bytes<S: serde::Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_bytes(value)
}

/// [`bytes`] for an optional payload; `None` fields are skipped beforehand.
pub(crate) fn optional_bytes<S: serde::Serializer>(
    value: &Option<Vec<u8>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => serializer.serialize_bytes(value),
        None => serializer.serialize_none(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::{
        ConnectionInfo, DiscoverySource, EndpointErrorKind, IdentifyInfo, KnownPeerInfo,
        OpenStreamResult, P2pEvent, PathKind, Reachability, RelayReservationInfo,
    };

    fn js<T: serde::Serialize>(value: &T) -> serde_json::Value {
        serde_json::to_value(value).expect("the JS shape always serializes")
    }

    #[test]
    fn events_are_tagged_with_camel_case_inner_fields() {
        assert_eq!(
            js(&P2pEvent::ConnectionReplaced {
                peer_id: "peer".into(),
                old_conn_id: 1,
                new_conn_id: 2,
            }),
            json!({
                "tag": "ConnectionReplaced",
                "inner": { "peerId": "peer", "oldConnId": 1, "newConnId": 2 },
            })
        );
    }

    #[test]
    fn absent_optionals_are_omitted_and_enums_are_names() {
        assert_eq!(
            js(&P2pEvent::EndpointError {
                kind: EndpointErrorKind::OpenStreamFailed,
                peer_id: Some("peer".into()),
                conn_id: None,
                stream_id: None,
                detail: "refused".into(),
            }),
            json!({
                "tag": "EndpointError",
                "inner": { "kind": "OpenStreamFailed", "peerId": "peer", "detail": "refused" },
            })
        );
        assert_eq!(
            js(&P2pEvent::ReachabilityChanged {
                previous: Reachability::Unknown,
                current: Reachability::Private,
                confirmed_addrs: vec![],
            }),
            json!({
                "tag": "ReachabilityChanged",
                "inner": { "previous": "Unknown", "current": "Private", "confirmedAddrs": [] },
            })
        );
        assert_eq!(
            js(&P2pEvent::DiscoveryProtocolViolation {
                peer_id: None,
                source: DiscoverySource::SignedBeacon,
                reason: "bad".into(),
                suppressed: 0,
            }),
            json!({
                "tag": "DiscoveryProtocolViolation",
                "inner": { "source": "SignedBeacon", "reason": "bad", "suppressed": 0 },
            })
        );
    }

    #[test]
    fn large_ids_stay_lossless() {
        assert_eq!(
            js(&P2pEvent::StreamData {
                peer_id: "peer".into(),
                conn_id: u64::MAX,
                stream_id: 4,
                data: vec![0, 255],
            }),
            json!({
                "tag": "StreamData",
                "inner": {
                    "peerId": "peer",
                    "connId": 18_446_744_073_709_551_615_u64,
                    "streamId": 4,
                    "data": [0, 255],
                },
            })
        );
    }

    #[test]
    fn paths_nest_as_tagged_values() {
        assert_eq!(
            js(&P2pEvent::PathUpgraded {
                connect_id: 7,
                peer_id: "peer".into(),
                from: PathKind::Relayed {
                    relay_peer_id: "relay".into(),
                },
                to: PathKind::DirectPunched,
            }),
            json!({
                "tag": "PathUpgraded",
                "inner": {
                    "connectId": 7,
                    "peerId": "peer",
                    "from": { "tag": "Relayed", "inner": { "relayPeerId": "relay" } },
                    "to": { "tag": "DirectPunched" },
                },
            })
        );
    }

    #[test]
    fn identify_info_carries_optional_bytes() {
        let info = IdentifyInfo {
            public_key: Some(vec![8, 1]),
            listen_addrs: vec!["/ip4/127.0.0.1/udp/1/quic-v1".into()],
            protocols: vec!["/ipfs/id/1.0.0".into()],
            observed_addr: None,
            protocol_version: Some("ipfs/0.1.0".into()),
            agent_version: None,
        };
        assert_eq!(
            js(&info),
            json!({
                "publicKey": [8, 1],
                "listenAddrs": ["/ip4/127.0.0.1/udp/1/quic-v1"],
                "protocols": ["/ipfs/id/1.0.0"],
                "protocolVersion": "ipfs/0.1.0",
            })
        );
        assert_eq!(
            js(&IdentifyInfo {
                public_key: None,
                ..info
            })
            .get("publicKey"),
            None
        );
    }

    #[test]
    fn snapshots_share_the_shape() {
        assert_eq!(
            js(&KnownPeerInfo {
                peer_id: "peer".into(),
                addrs: vec![],
                beacon_addrs: vec![],
                mdns_addrs: vec![],
                beacon_last_seen_age_ms: Some(5),
                mdns_last_seen_age_ms: None,
                connected: true,
            }),
            json!({
                "peerId": "peer",
                "addrs": [],
                "beaconAddrs": [],
                "mdnsAddrs": [],
                "beaconLastSeenAgeMs": 5,
                "connected": true,
            })
        );
        assert_eq!(
            js(&RelayReservationInfo {
                relay_peer_id: "relay".into(),
                expires_unix_secs: None,
            }),
            json!({ "relayPeerId": "relay" })
        );
        assert_eq!(
            js(&ConnectionInfo {
                conn_id: 3,
                remote_addr: None,
                ready_protocols: Some(vec![]),
            }),
            json!({ "connId": 3, "readyProtocols": [] })
        );
        assert_eq!(
            js(&OpenStreamResult {
                conn_id: 3,
                stream_id: 9,
            }),
            json!({ "connId": 3, "streamId": 9 })
        );
    }
}
