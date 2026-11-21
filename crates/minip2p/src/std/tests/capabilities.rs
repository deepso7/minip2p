use super::*;

#[cfg(any(feature = "discovery", feature = "mdns"))]
#[test]
fn discovery_clock_is_present_only_for_an_active_source() {
    let mut inactive = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind plain endpoint");
    assert_eq!(inactive.discovery_now_ms(), None);

    let builder = Endpoint::builder();
    #[cfg(feature = "discovery")]
    let builder = builder.discovery();
    #[cfg(all(feature = "mdns", not(feature = "discovery")))]
    let builder = builder.mdns();
    let mut active = builder
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind discovery endpoint");
    let first = active.discovery_now_ms().expect("discovery clock");
    let second = active.discovery_now_ms().expect("discovery clock");
    assert!(second >= first);
}

#[cfg(feature = "mdns")]
#[test]
fn mdns_config_is_rejected_before_binding() {
    let config = MdnsConfig {
        max_packet_bytes: 4_097,
        ..MdnsConfig::default()
    };
    assert!(matches!(
        Endpoint::builder()
            .mdns_config(config)
            .listen_on(UNBINDABLE_QUIC)
            .expect("quic listen address")
            .bind()
            .err(),
        Some(BindError::Mdns(
            crate::MdnsConfigError::InvalidMaxPacketBytes
        ))
    ));
}

#[cfg(feature = "mdns")]
#[test]
fn mdns_shutdown_is_idempotent_and_leaves_quic_usable() {
    let mut endpoint = Endpoint::builder()
        .mdns()
        .peer_discovery_config(PeerDiscoveryConfig {
            auto_dial: false,
            ..PeerDiscoveryConfig::default()
        })
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind mDNS endpoint");
    endpoint.listen().expect("QUIC listens");
    endpoint.shutdown_mdns().expect("first mDNS shutdown");
    endpoint.shutdown_mdns().expect("second mDNS shutdown");
    assert!(
        endpoint.poll().is_ok(),
        "QUIC remains usable after shutdown"
    );
}

#[cfg(feature = "discovery")]
#[test]
fn discovery_topic_cannot_be_unsubscribed_independently() {
    let topic = "/minip2p/test/discovery";
    let config = BeaconConfig {
        topic: topic.into(),
        ..BeaconConfig::default()
    };
    let mut endpoint = Endpoint::builder()
        .discovery_config(config)
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind discovery endpoint");

    assert!(matches!(
        endpoint.unsubscribe(topic),
        Err(GossipsubError::DiscoveryTopicReserved)
    ));
    assert!(matches!(
        endpoint.publish(topic, b"not a beacon".to_vec()),
        Err(GossipsubError::DiscoveryTopicReserved)
    ));
}
