use gungraun::prelude::*;
use minip2p_core::Multiaddr;
use std::hint::black_box;

const TEXT: &str = "/dns4/example.com/udp/443/quic-v1";

#[library_benchmark]
fn parse_text() -> Multiaddr {
    black_box(TEXT).parse().expect("parse")
}

fn parsed() -> Multiaddr {
    TEXT.parse().expect("benchmark address")
}

#[library_benchmark]
#[bench::encode_binary(parsed())]
fn encode_binary(value: Multiaddr) -> Vec<u8> {
    black_box(value).to_bytes()
}

fn encoded() -> Vec<u8> {
    parsed().to_bytes()
}

#[library_benchmark]
#[bench::decode_binary(encoded())]
fn decode_binary(value: Vec<u8>) -> Multiaddr {
    Multiaddr::from_bytes(black_box(&value)).expect("decode")
}

library_benchmark_group!(name = benches; benchmarks = parse_text, encode_binary, decode_binary);
gungraun::main!(library_benchmark_groups = benches);
