use gungraun::prelude::*;
use minip2p_core::Bytes;
use minip2p_yamux::{
    FLAG_SYN, Frame, FrameDecoder, FrameType, YamuxOutput, YamuxRole, YamuxSession,
};
use std::hint::black_box;

const PAYLOAD_LEN: usize = 64 * 1024;

fn sender() -> (YamuxSession, u32, Vec<u8>) {
    let mut session = YamuxSession::new(YamuxRole::Client);
    let stream = session.open_stream().expect("open stream");
    (session, stream, vec![0x5a; PAYLOAD_LEN])
}

#[library_benchmark]
#[bench::session_send_and_drain(sender())]
fn session_send_and_drain(input: (YamuxSession, u32, Vec<u8>)) {
    let (mut session, stream, data) = input;
    session.send(stream, Bytes::from(data)).expect("send");
    black_box(session.poll_output());
}

fn receiver() -> (YamuxSession, Vec<u8>) {
    let inbound = Frame::data(1, FLAG_SYN, vec![0x5a; PAYLOAD_LEN])
        .expect("valid frame")
        .encode();
    (YamuxSession::new(YamuxRole::Server), inbound)
}

#[library_benchmark]
#[bench::session_receive_and_drain(receiver())]
fn session_receive_and_drain(input: (YamuxSession, Vec<u8>)) {
    let (mut session, bytes) = input;
    session.handle_data(&bytes).expect("receive");
    black_box(session.poll_output());
    black_box(session.poll_output());
}

const QUEUED_LEN: usize = 256 * 1024;
const WINDOW_STEP: u32 = 16 * 1024;

/// A client stream that has spent its whole initial send window.
fn window_exhausted_sender() -> (YamuxSession, u32) {
    let mut session = YamuxSession::new(YamuxRole::Client);
    let stream = session.open_stream().expect("open stream");
    session
        .send(stream, Bytes::from(vec![0; QUEUED_LEN]))
        .expect("fill window");
    while session.poll_output().is_some() {}
    (session, stream)
}

/// Drains `session` and concatenates the payloads of its outbound data frames.
fn drained_data(session: &mut YamuxSession) -> Vec<u8> {
    let mut decoder = FrameDecoder::new(u32::MAX);
    while let Some(output) = session.poll_output() {
        if let YamuxOutput::Outbound(bytes) = output {
            decoder.push(&bytes);
        }
    }
    let mut data = Vec::new();
    while let Some(frame) = decoder.next_frame().expect("valid frame") {
        if frame.frame_type() == FrameType::Data {
            data.extend_from_slice(frame.payload());
        }
    }
    data
}

/// A window-exhausted stream, a chunk to queue, and the updates that drain it.
/// Setup (unmeasured) first checks the updates frame the whole chunk.
fn queued_sender() -> (YamuxSession, u32, Vec<u8>, Vec<u8>) {
    let (mut session, stream) = window_exhausted_sender();
    let updates: Vec<u8> = (0..QUEUED_LEN / WINDOW_STEP as usize)
        .flat_map(|_| {
            Frame::window_update(stream, 0, WINDOW_STEP)
                .expect("valid frame")
                .encode()
        })
        .collect();
    let queued = vec![0x5a; QUEUED_LEN];
    session
        .send(stream, Bytes::from(queued.clone()))
        .expect("send");
    session.handle_data(&updates).expect("window updates");
    assert!(
        drained_data(&mut session) == queued,
        "window updates must frame the whole queued chunk"
    );

    let (session, stream) = window_exhausted_sender();
    (session, stream, queued, updates)
}

#[library_benchmark]
#[bench::queued_send_16kib_window_updates(queued_sender())]
fn queued_send_16kib_window_updates(input: (YamuxSession, u32, Vec<u8>, Vec<u8>)) {
    let (mut session, stream, data, updates) = input;
    session.send(stream, Bytes::from(data)).expect("send");
    session.handle_data(&updates).expect("window updates");
    while let Some(output) = session.poll_output() {
        black_box(output);
    }
}

library_benchmark_group!(
    name = benches;
    benchmarks = session_send_and_drain, session_receive_and_drain, queued_send_16kib_window_updates
);
gungraun::main!(library_benchmark_groups = benches);
