use minip2p_yamux::{FLAG_FIN, FLAG_SYN, FrameDecoder, FrameType, YamuxError};

const FIXTURE: &str = include_str!("fixtures/yamux-0.13.8.txt");

#[test]
fn decodes_and_reencodes_pinned_upstream_transcript() {
    assert_eq!(value("producer"), "yamux-0.13.8");
    let transcript = hex(value("client_transcript"));
    let mut decoder = FrameDecoder::new(1024);
    decoder.push(&transcript);

    let opening = decoder.next_frame().unwrap().expect("opening frame");
    assert_eq!(opening.frame_type(), FrameType::Data);
    assert_eq!(opening.flags(), FLAG_SYN);
    assert_eq!(opening.stream_id(), 1);
    assert_eq!(opening.payload(), b"fixture-data");

    let close = decoder.next_frame().unwrap().expect("stream close frame");
    assert_eq!(close.frame_type(), FrameType::Data);
    assert_eq!(close.flags(), FLAG_FIN);
    assert_eq!(close.stream_id(), 1);
    assert!(close.payload().is_empty());

    let go_away = decoder.next_frame().unwrap().expect("GoAway frame");
    assert_eq!(go_away.frame_type(), FrameType::GoAway);
    assert_eq!(go_away.value(), 0);
    assert_eq!(decoder.next_frame().unwrap(), None);

    let encoded = [opening.encode(), close.encode(), go_away.encode()].concat();
    assert_eq!(encoded, transcript);
}

fn value(name: &str) -> &str {
    FIXTURE
        .lines()
        .filter_map(|line| line.split_once('='))
        .find_map(|(field, value)| (field == name).then_some(value))
        .unwrap_or_else(|| panic!("missing fixture field {name}"))
}

fn hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "hex fixture has an odd length");
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = core::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

#[test]
fn fixture_decoder_limit_is_enforced() {
    let mut decoder = FrameDecoder::new(4);
    decoder.push(&hex(value("client_transcript")));
    assert!(matches!(
        decoder.next_frame(),
        Err(YamuxError::FrameTooLarge { .. })
    ));
}
