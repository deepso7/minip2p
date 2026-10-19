//! WebTransport addresses route to QUIC but are not natively dialable yet: a
//! connect that mixes them with `/quic-v1` candidates connects over QUIC.

#![cfg(feature = "quic")]

use std::time::{Duration, Instant};

use minip2p::{ConnectOutcome, Endpoint, EndpointEvent, Multiaddr, PeerAddr};

#[path = "../../../tests/support/endpoint.rs"]
mod endpoint_support;
use endpoint_support::NextEvent;

/// Failure backstop, not a budget the test has to fit in.
const BACKSTOP: Duration = Duration::from_secs(10);

fn bind() -> Endpoint {
    Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("listen address")
        .bind()
        .expect("bind loopback")
}

#[test]
fn connect_skips_webtransport_candidates_and_connects_over_quic_v1() {
    let mut a = bind();
    let mut b = bind();
    let b_quic = b.listen().expect("b listens");
    let b_webtransport = PeerAddr::new(
        format!(
            "{}/webtransport/certhash/uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g",
            b_quic.transport()
        )
        .parse::<Multiaddr>()
        .expect("webtransport multiaddr"),
        b_quic.peer_id().clone(),
    )
    .expect("peer addr");

    // The WebTransport candidate comes first, so its refusal must not end
    // the attempt.
    let id = a
        .connect(vec![b_webtransport, b_quic.clone()])
        .expect("connect starts");

    let deadline = Instant::now() + BACKSTOP;
    let outcome = loop {
        assert!(Instant::now() < deadline, "connect never settled");
        if let Some(EndpointEvent::ConnectSettled {
            connect_id,
            outcome,
            ..
        }) = a.next_event(Duration::from_millis(5)).expect("a drives")
            && connect_id == id
        {
            break outcome;
        }
        let _ = b.next_event(Duration::from_millis(5)).expect("b drives");
    };

    let ConnectOutcome::Connected { conn_id, .. } = outcome else {
        panic!("expected Connected, got {outcome:?}");
    };
    let info = a.connection_info(conn_id).expect("connection info");
    assert_eq!(&info.remote_addr, b_quic.transport());
}
