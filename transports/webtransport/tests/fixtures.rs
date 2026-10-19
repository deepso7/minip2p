//! Decodes byte captures from Chrome, Firefox and webtransport-go, so the
//! codec is checked against implementations other than itself. See
//! `tests/fixtures/README.md` for how each capture was made.

use minip2p_webtransport::h3::{
    Capsule, CapsuleDecoder, Frame, FrameDecoder, Settings, UniStreamHeaderDecoder, UniStreamType,
    setting, varint,
};
use minip2p_webtransport::qpack::QpackDecoder;

const CHROME_CONTROL: &[u8] = include_bytes!("fixtures/chrome_control_stream.bin");
const CHROME_CONNECT: &[u8] = include_bytes!("fixtures/chrome_connect_headers.bin");
const CHROME_CLOSE: &[u8] = include_bytes!("fixtures/chrome_close_capsule.bin");
const FIREFOX_CONTROL: &[u8] = include_bytes!("fixtures/firefox_control_stream.bin");
const FIREFOX_CONNECT: &[u8] = include_bytes!("fixtures/firefox_connect_headers.bin");
const FIREFOX_CLOSE: &[u8] = include_bytes!("fixtures/firefox_close_capsule.bin");
const GO_CONTROL: &[u8] = include_bytes!("fixtures/webtransport_go_server_control_stream.bin");
const GO_200: &[u8] = include_bytes!("fixtures/webtransport_go_200_headers.bin");

/// Every frame on a stream, with DATA chunks kept as owned bytes.
#[derive(Debug, PartialEq)]
enum Owned {
    Data(Vec<u8>),
    Headers(Vec<u8>),
    Settings(Settings),
    Other(String),
}

fn frames(mut input: &[u8]) -> Vec<Owned> {
    let mut decoder = FrameDecoder::new();
    let mut frames = Vec::new();
    while let Some(frame) = decoder.decode(&mut input).expect("valid frames") {
        frames.push(match frame {
            Frame::Data(chunk) => Owned::Data(chunk.to_vec()),
            Frame::Headers(block) => Owned::Headers(block),
            Frame::Settings(settings) => Owned::Settings(settings),
            other => Owned::Other(format!("{other:?}")),
        });
    }
    assert!(decoder.is_at_frame_boundary(), "stream ends mid-frame");
    frames
}

/// The SETTINGS on a control stream; any frames after it (GREASE) are
/// skipped by the decoder.
fn control_settings(mut input: &[u8]) -> Vec<(u64, u64)> {
    assert_eq!(
        UniStreamHeaderDecoder::new().decode(&mut input),
        Some(UniStreamType::Control)
    );
    match frames(input).as_slice() {
        [Owned::Settings(settings)] => Some(settings.iter().collect()),
        _ => None,
    }
    .expect("exactly one SETTINGS frame")
}

fn header_fields(frame: &[u8]) -> Vec<(String, String)> {
    let frames = frames(frame);
    let block = match frames.as_slice() {
        [Owned::Headers(block)] => Some(block),
        _ => None,
    }
    .expect("exactly one HEADERS frame");
    let mut decoder = QpackDecoder::new();
    let section = decoder.decode(block).expect("valid field section");
    section
        .iter()
        .map(|field| {
            (
                String::from_utf8_lossy(field.name).into_owned(),
                String::from_utf8_lossy(field.value).into_owned(),
            )
        })
        .collect()
}

fn pairs(fields: &[(&str, &str)]) -> Vec<(String, String)> {
    fields
        .iter()
        .map(|&(name, value)| (name.into(), value.into()))
        .collect()
}

/// Every capsule in a stream of DATA frames.
fn capsules(frame: &[u8]) -> Vec<Capsule> {
    let mut decoder = CapsuleDecoder::new();
    let mut capsules = Vec::new();
    for owned in frames(frame) {
        let Owned::Data(chunk) = owned else {
            continue;
        };
        let mut input: &[u8] = &chunk;
        while let Some(capsule) = decoder.decode(&mut input).expect("valid capsules") {
            capsules.push(capsule);
        }
    }
    assert!(decoder.is_at_capsule_boundary());
    capsules
}

#[test]
fn chrome_control_stream_settings() {
    assert_eq!(
        control_settings(CHROME_CONTROL),
        [
            (setting::QPACK_MAX_TABLE_CAPACITY, 65_536),
            (setting::MAX_FIELD_SECTION_SIZE, 16_384),
            (setting::QPACK_BLOCKED_STREAMS, 100),
            (setting::H3_DATAGRAM, 1),
            (0xff_d277, 1), // pre-RFC H3_DATAGRAM
            (setting::ENABLE_WEBTRANSPORT, 1),
            (0x1b_4f7f_0738, 0xcb5d_05f4), // GREASE
        ]
    );
}

#[test]
fn firefox_control_stream_settings() {
    assert_eq!(
        control_settings(FIREFOX_CONTROL),
        [
            (setting::QPACK_MAX_TABLE_CAPACITY, 65_536),
            (setting::QPACK_BLOCKED_STREAMS, 20),
            (setting::ENABLE_WEBTRANSPORT, 1),
            (0xff_d277, 1),
            (setting::H3_DATAGRAM, 1),
            (setting::ENABLE_CONNECT_PROTOCOL, 1),
        ]
    );
}

#[test]
fn webtransport_go_control_stream_settings() {
    assert_eq!(
        control_settings(GO_CONTROL),
        [
            (setting::MAX_FIELD_SECTION_SIZE, 1_048_576),
            (setting::H3_DATAGRAM, 1),
            (setting::ENABLE_CONNECT_PROTOCOL, 1),
            (setting::ENABLE_WEBTRANSPORT, 1),
            (0x2c7c_f000, 1), // draft-15+ WT_ENABLED
            (setting::WT_MAX_SESSIONS, varint::MAX),
        ]
    );
}

#[test]
fn chrome_connect_request() {
    assert_eq!(
        header_fields(CHROME_CONNECT),
        pairs(&[
            (":scheme", "https"),
            (":method", "CONNECT"),
            (":authority", "127.0.0.1:4433"),
            (":path", "/.well-known/libp2p-webtransport?type=noise"),
            (":protocol", "webtransport"),
            ("sec-webtransport-http3-draft02", "1"),
            ("origin", "http://127.0.0.1:8409"),
        ])
    );
}

#[test]
fn firefox_connect_request() {
    assert_eq!(
        header_fields(FIREFOX_CONNECT),
        pairs(&[
            (":method", "CONNECT"),
            (":scheme", "https"),
            (":authority", "127.0.0.1:4433"),
            (":path", "/.well-known/libp2p-webtransport?type=noise"),
            (":protocol", "webtransport"),
            (
                "user-agent",
                "Mozilla/5.0 (X11; Linux x86_64; rv:158.0) Gecko/20100101 Firefox/158.0",
            ),
            ("accept", "*/*"),
            ("accept-language", "en-US,en;q=0.9"),
            ("accept-encoding", "gzip, deflate, br, zstd"),
            ("sec-webtransport-http3-draft02", "1"),
            ("origin", "http://127.0.0.1:8409"),
            ("sec-fetch-dest", "webtransport"),
            ("sec-fetch-mode", "no-cors"),
            ("sec-fetch-site", "same-site"),
            ("priority", "u=4"),
            ("pragma", "no-cache"),
            ("cache-control", "no-cache"),
        ])
    );
}

#[test]
fn webtransport_go_200_response() {
    assert_eq!(
        header_fields(GO_200),
        pairs(&[
            (":status", "200"),
            ("date", "Mon, 19 Oct 2026 01:35:30 GMT")
        ])
    );
}

#[test]
fn browser_close_capsules() {
    let expected = Capsule::CloseSession {
        code: 7,
        reason: "bye".into(),
    };
    assert_eq!(capsules(CHROME_CLOSE), std::slice::from_ref(&expected));
    assert_eq!(capsules(FIREFOX_CLOSE), [expected]);
}
