//! Wire-level interop pin: a floodsub RPC frame captured byte-for-byte from
//! go-libp2p-pubsub (StrictSign, Ed25519 identity) must decode and verify.
//! See `testdata/README.md` for the pinned upstream versions and the capture
//! harness.

use minip2p_pubsub::{FrameDecode, Rpc, decode_frame};

fn decode_hex(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    assert!(hex.len().is_multiple_of(2), "odd hex length");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex digit"))
        .collect()
}

#[test]
fn go_libp2p_signed_message_decodes_and_verifies() {
    let bytes = decode_hex(include_str!("testdata/go_signed_message_rpc.hex"));

    let FrameDecode::Complete { payload, consumed } = decode_frame(&bytes) else {
        panic!("captured frame must decode completely");
    };
    assert_eq!(consumed, bytes.len(), "no trailing bytes in the fixture");

    let rpc = Rpc::decode(payload).expect("go RPC must decode");
    assert_eq!(rpc.publish.len(), 1, "one published message");
    let message = &rpc.publish[0];

    // go emits exactly one topic and omits the key field (inline Ed25519).
    assert_eq!(message.topic_ids, vec!["minip2p-golden".to_string()]);
    assert!(message.key.is_none(), "go inlines the key in from");
    assert_eq!(message.data.as_deref(), Some(&b"golden"[..]));

    // StrictSign verification against go's actual signature: this is the
    // canonical-re-encode rule proving out end to end.
    let (from, _seqno, signed) = message
        .verify(false)
        .expect("go-signed message must pass strict verification");
    assert!(signed);
    let expected = include_str!("testdata/go_peer_id.txt");
    assert_eq!(from.to_base58(), expected.trim());
}
