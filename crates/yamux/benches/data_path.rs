use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use minip2p_yamux::{FLAG_SYN, Frame, HEADER_LEN, YamuxOutput, YamuxRole, YamuxSession};

const PAYLOAD_LEN: usize = 64 * 1024;
const QUEUED_LEN: usize = 256 * 1024;
const WINDOW_STEP: u32 = 16 * 1024;

fn assert_payload_frame(output: YamuxOutput, payload: &[u8]) {
    match output {
        YamuxOutput::Outbound(bytes) => {
            assert_eq!(bytes.len(), HEADER_LEN + payload.len());
            assert_eq!(bytes.get(1), Some(&0), "frame type must be data");
            assert_eq!(bytes.get(HEADER_LEN..), Some(payload));
        }
        unexpected => assert!(
            matches!(unexpected, YamuxOutput::Outbound(_)),
            "expected outbound data frame"
        ),
    }
}

fn yamux_data_path(c: &mut Criterion) {
    let payload = vec![0x5a; PAYLOAD_LEN];
    let inbound = Frame::data(1, FLAG_SYN, payload.clone())
        .expect("valid frame")
        .encode();

    let mut verified_sender = YamuxSession::new(YamuxRole::Client);
    let stream = verified_sender.open_stream().expect("open stream");
    verified_sender
        .send(stream, payload.clone())
        .expect("send payload");
    assert_payload_frame(
        verified_sender.poll_output().expect("outbound payload"),
        &payload,
    );

    let mut verified_receiver = YamuxSession::new(YamuxRole::Server);
    verified_receiver
        .handle_data(&inbound)
        .expect("receive payload");
    assert!(matches!(
        verified_receiver.poll_output(),
        Some(YamuxOutput::IncomingStream { stream: 1 })
    ));
    assert!(matches!(
        verified_receiver.poll_output(),
        Some(YamuxOutput::Data { stream: 1, data }) if data == payload
    ));

    let mut group = c.benchmark_group("yamux/64KiB");
    group.bench_function("session_send_and_drain", |b| {
        b.iter_batched(
            || {
                let mut session = YamuxSession::new(YamuxRole::Client);
                let stream = session.open_stream().expect("open stream");
                (session, stream, payload.clone())
            },
            |(mut session, stream, data)| {
                session.send(stream, data).expect("send");
                black_box(session.poll_output())
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function("session_receive_and_drain", |b| {
        b.iter_batched(
            || (YamuxSession::new(YamuxRole::Server), inbound.clone()),
            |(mut session, bytes)| {
                session.handle_data(&bytes).expect("receive");
                black_box(session.poll_output());
                black_box(session.poll_output())
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();

    // A stream whose window is exhausted queues a whole chunk, then drains it
    // across many small window updates: the partial-send path.
    let updates = (0..QUEUED_LEN / WINDOW_STEP as usize)
        .flat_map(|_| {
            Frame::window_update(1, 0, WINDOW_STEP)
                .expect("valid frame")
                .encode()
        })
        .collect::<Vec<u8>>();
    let mut group = c.benchmark_group("yamux/256KiB");
    group.bench_function("queued_send_16KiB_window_updates", |b| {
        b.iter_batched(
            || (window_exhausted_sender(), vec![0x5a; QUEUED_LEN]),
            |((mut session, stream), data)| {
                session.send(stream, data).expect("send");
                session.handle_data(&updates).expect("window updates");
                while let Some(output) = session.poll_output() {
                    black_box(output);
                }
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

/// A client stream that has spent its whole initial send window.
fn window_exhausted_sender() -> (YamuxSession, u32) {
    let mut session = YamuxSession::new(YamuxRole::Client);
    let stream = session.open_stream().expect("open stream");
    session
        .send(stream, vec![0; QUEUED_LEN])
        .expect("fill window");
    while session.poll_output().is_some() {}
    (session, stream)
}

criterion_group!(benches, yamux_data_path);
criterion_main!(benches);
