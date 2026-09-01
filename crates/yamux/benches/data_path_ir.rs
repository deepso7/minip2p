use gungraun::prelude::*;
use minip2p_yamux::{FLAG_SYN, Frame, YamuxRole, YamuxSession};
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
    session.send(stream, data).expect("send");
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

library_benchmark_group!(name = benches; benchmarks = session_send_and_drain, session_receive_and_drain);
gungraun::main!(library_benchmark_groups = benches);
