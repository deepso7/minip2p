use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use minip2p_yamux::{FLAG_SYN, Frame, HEADER_LEN, YamuxOutput, YamuxRole, YamuxSession};

const PAYLOAD_LEN: usize = 64 * 1024;

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
}

criterion_group!(benches, yamux_data_path);
criterion_main!(benches);
