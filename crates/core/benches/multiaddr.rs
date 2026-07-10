use criterion::{Criterion, criterion_group, criterion_main};
use minip2p_core::Multiaddr;
use std::hint::black_box;

fn multiaddr(c: &mut Criterion) {
    const TEXT: &str = "/dns4/example.com/udp/443/quic-v1";
    let parsed: Multiaddr = TEXT.parse().expect("benchmark address");
    let encoded = parsed.to_bytes();

    c.bench_function("multiaddr/parse_text", |b| {
        b.iter(|| black_box(TEXT).parse::<Multiaddr>().expect("parse"));
    });
    c.bench_function("multiaddr/encode_binary", |b| {
        b.iter(|| black_box(&parsed).to_bytes());
    });
    c.bench_function("multiaddr/decode_binary", |b| {
        b.iter(|| Multiaddr::from_bytes(black_box(&encoded)).expect("decode"));
    });
}

criterion_group!(benches, multiaddr);
criterion_main!(benches);
