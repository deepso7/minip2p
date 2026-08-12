//! Regression coverage for listener state retention when dialers connect and
//! drop without an explicit disconnect.

use std::time::{Duration, Instant};

use minip2p::{Endpoint, QuicLimits};

const CHURN_ROUNDS: usize = 50;

fn short_idle_limits() -> QuicLimits {
    QuicLimits {
        idle_timeout_ms: 500,
        ..QuicLimits::default()
    }
}

fn default_idle_limits() -> QuicLimits {
    QuicLimits::default()
}

fn wait_peer_ready(
    listener: &mut Endpoint,
    dialer: &mut Endpoint,
    listener_peer: &minip2p::PeerId,
    dialer_peer: &minip2p::PeerId,
) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !listener.is_peer_ready(dialer_peer) || !dialer.is_peer_ready(listener_peer) {
        assert!(Instant::now() < deadline, "peer ready timed out");
        let _ = listener.next_event(Duration::from_millis(10));
        let _ = dialer.next_event(Duration::from_millis(10));
    }
}

fn settle_listener(listener: &mut Endpoint, within: Duration) {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline && !listener.connected_peers().is_empty() {
        let _ = listener.next_event(Duration::from_millis(10));
    }
}

#[test]
fn listener_reclaims_state_after_dialer_drop_without_disconnect() {
    let limits = short_idle_limits();
    let mut listener = Endpoint::builder()
        .quic_limits(default_idle_limits())
        .bind_quic("127.0.0.1:0")
        .expect("bind listener");
    let listener_addr = listener.listen().expect("listener listens");
    let listener_peer = listener.peer_id().clone();

    for round in 0..CHURN_ROUNDS {
        let mut dialer = Endpoint::builder()
            .quic_limits(limits.clone())
            .bind_quic("127.0.0.1:0")
            .expect("bind dialer");
        let dialer_peer = dialer.peer_id().clone();
        dialer.dial(&listener_addr).expect("dial listener");

        wait_peer_ready(
            &mut listener,
            &mut dialer,
            &listener_peer,
            &dialer_peer,
        );

        // Exercise one ping so identify/ping streams are opened before drop.
        dialer.ping(&listener_peer).expect("queue ping");
        let ping_deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < ping_deadline {
            let _ = listener.next_event(Duration::from_millis(10));
            let _ = dialer.next_event(Duration::from_millis(10));
            if listener.peer_info(&dialer_peer).is_some()
                && dialer.peer_info(&listener_peer).is_some()
            {
                break;
            }
        }

        // Drop the dialer without an explicit disconnect, as spar does.
        drop(dialer);

        settle_listener(&mut listener, Duration::from_millis(500));

        assert!(
            listener.connected_peers().is_empty(),
            "round {round}: listener still tracks connected peers {:?}",
            listener.connected_peers()
        );
        assert!(
            listener.peer_info(&dialer_peer).is_none(),
            "round {round}: listener retained identify state for {dialer_peer}"
        );
        assert!(
            listener.swarm().core().conn_for(&dialer_peer).is_none(),
            "round {round}: listener retained a transport connection for {dialer_peer}"
        );
    }
}
