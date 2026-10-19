//! `WebTransportClient` backpressure end to end, over the test-only quinn
//! client against a real `QuicTransport` listener: `Full` and
//! `StreamWritable` on the client's writes, and its receive window gating
//! the server's.

use std::sync::LazyLock;
use std::time::{Duration, Instant};

use minip2p_core::platform::{Clock, Now, StdClock, StdEntropy};
use minip2p_core::{Multiaddr, PeerAddr};
use minip2p_identity::Ed25519Keypair;
use minip2p_quic::{QuicNodeConfig, QuicTransport};
use minip2p_transport::{Bytes, ConnectionId, StreamId, Transport, TransportError, TransportEvent};
use minip2p_webtransport::{WebTransportClient, WebTransportLimits};

#[path = "common/wt_client.rs"]
mod wt_client;
use wt_client::{Options, QuinnIo};

type Client = WebTransportClient<QuinnIo, StdEntropy>;

static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

fn now() -> Now {
    StdClock::with_epoch(*EPOCH).now()
}

const WINDOW: usize = 16 * 1024;

/// A connected server and client, with their connection ids.
struct Pair {
    server: QuicTransport,
    client: Client,
    server_conn: ConnectionId,
    client_conn: ConnectionId,
    started: Instant,
}

impl Pair {
    /// Small client caps and window, so a few hundred KiB exercise them.
    fn connect() -> Self {
        let addrs: Vec<Multiaddr> = [
            "/ip4/127.0.0.1/udp/0/quic-v1",
            "/ip4/127.0.0.1/udp/0/quic-v1/webtransport",
        ]
        .iter()
        .map(|addr| addr.parse().expect("multiaddr"))
        .collect();
        let mut server = QuicTransport::bind(QuicNodeConfig::generate(), &addrs).expect("bind");
        server.listen_on_bound_addrs().expect("listen");
        let target: PeerAddr = server
            .local_peer_addrs()
            .expect("peer addrs")
            .into_iter()
            .find(|addr| addr.transport().is_webtransport())
            .expect("a WebTransport address");
        let limits = WebTransportLimits {
            max_pending_bytes_per_stream: 32 * 1024,
            max_pending_connection_bytes: 128 * 1024,
            control_stream_reserve_bytes: 16 * 1024,
            stream_receive_window: WINDOW,
            ..WebTransportLimits::default()
        };
        let mut client = WebTransportClient::with_limits(
            QuinnIo::new(Options::default()),
            Ed25519Keypair::generate(),
            StdEntropy::new(),
            limits,
        )
        .expect("limits");
        let client_conn = client.dial(&target).expect("dial");
        let mut pair = Self {
            server,
            client,
            server_conn: ConnectionId::new(0),
            client_conn,
            started: Instant::now(),
        };
        let (mut server_up, mut client_up) = (None, false);
        while server_up.is_none() || !client_up {
            let (server, client) = pair.pump("both ends connected");
            server_up = server_up.or(server.iter().find_map(|event| match event {
                TransportEvent::Connected { id, .. } => Some(*id),
                _ => None,
            }));
            client_up |= client
                .iter()
                .any(|event| matches!(event, TransportEvent::Connected { .. }));
        }
        pair.server_conn = server_up.expect("server connected");
        pair
    }

    /// One round: both ends polled once.
    fn pump(&mut self, what: &str) -> (Vec<TransportEvent>, Vec<TransportEvent>) {
        assert!(
            self.started.elapsed() < Duration::from_secs(10),
            "timed out waiting for {what}"
        );
        std::thread::sleep(Duration::from_millis(1));
        let server = self.server.poll(now()).expect("server poll");
        let client = self.client.poll(now()).expect("client poll");
        (server, client)
    }
}

/// Sends `tail` on `transport`, keeping what comes back `Full`. Returns
/// whether it was `Full`.
fn send(
    transport: &mut impl Transport,
    conn: ConnectionId,
    stream: StreamId,
    tail: &mut Option<Bytes>,
) -> bool {
    let Some(data) = tail.take() else {
        return false;
    };
    match transport.send_stream(conn, stream, data) {
        Ok(()) => false,
        Err(TransportError::Full { unsent, .. }) => {
            *tail = Some(unsent);
            true
        }
        other => {
            other.expect("send");
            false
        }
    }
}

/// Bytes `events` delivered on `stream`.
fn data_len(events: &[TransportEvent], stream: StreamId) -> usize {
    events
        .iter()
        .map(|event| match event {
            TransportEvent::StreamData {
                stream_id, data, ..
            } if *stream_id == stream => data.len(),
            _ => 0,
        })
        .sum()
}

#[test]
fn client_writes_report_full_and_resume_on_stream_writable() {
    const TOTAL: usize = 512 * 1024;
    let mut pair = Pair::connect();
    let stream = pair.client.open_stream(pair.client_conn).expect("open");
    let mut tail = Some(Bytes::from(vec![9u8; TOTAL]));
    let (conn, server_conn) = (pair.client_conn, pair.server_conn);
    assert!(
        send(&mut pair.client, conn, stream, &mut tail),
        "512 KiB exceed the 32 KiB stream cap"
    );
    let (mut fulls, mut wakes, mut received) = (1, 0, 0);
    let mut inbound = None;
    while received < TOTAL {
        let (server, client) = pair.pump("every byte through");
        for event in &server {
            if let TransportEvent::IncomingStream { stream_id, .. } = event {
                inbound = Some(*stream_id);
            }
        }
        if let Some(inbound) = inbound {
            let len = data_len(&server, inbound);
            received += len;
            pair.server
                .ack_stream(server_conn, inbound, len)
                .expect("ack");
        }
        let woken = client.iter().any(|event| {
            matches!(event, TransportEvent::StreamWritable { stream_id, .. } if *stream_id == stream)
        });
        if woken {
            assert!(tail.is_some(), "a Writable only follows a Full");
            wakes += 1;
            fulls += usize::from(send(&mut pair.client, conn, stream, &mut tail));
        }
    }
    assert!(tail.is_none());
    assert!(
        fulls > 2 && wakes >= fulls - 1,
        "fulls {fulls}, wakes {wakes}"
    );
}

#[test]
fn the_client_receive_window_gates_the_server() {
    const TOTAL: usize = 256 * 1024;
    let mut pair = Pair::connect();
    let (conn, server_conn) = (pair.client_conn, pair.server_conn);
    let stream = pair.server.open_stream(server_conn).expect("open");
    let mut tail = Some(Bytes::from(vec![3u8; TOTAL]));
    let mut inbound = None;
    let mut unacked = 0;
    let mut received = 0;
    let mut stalled_rounds = 0;
    // Nothing acknowledged: delivery stops at the window.
    while stalled_rounds < 200 {
        let (server, client) = pair.pump("the window to fill");
        if tail.is_some()
            && (server
                .iter()
                .any(|event| matches!(event, TransportEvent::StreamWritable { .. }))
                || received == 0)
        {
            send(&mut pair.server, server_conn, stream, &mut tail);
        }
        for event in &client {
            if let TransportEvent::IncomingStream { stream_id, .. } = event {
                inbound = Some(*stream_id);
            }
        }
        let len = inbound.map_or(0, |inbound| data_len(&client, inbound));
        unacked += len;
        received += len;
        assert!(unacked <= WINDOW, "{unacked} delivered past the window");
        if unacked == WINDOW {
            stalled_rounds += 1;
        }
    }
    assert_eq!(received, WINDOW);

    // Acknowledging as it arrives lets the rest through.
    let inbound = inbound.expect("incoming");
    while received < TOTAL {
        pair.client.ack_stream(conn, inbound, unacked).expect("ack");
        let (server, client) = pair.pump("the rest");
        if server
            .iter()
            .any(|event| matches!(event, TransportEvent::StreamWritable { .. }))
        {
            send(&mut pair.server, server_conn, stream, &mut tail);
        }
        unacked = data_len(&client, inbound);
        assert!(unacked <= WINDOW);
        received += unacked;
    }
}
