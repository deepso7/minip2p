#![no_main]

use libfuzzer_sys::fuzz_target;
use minip2p_autonat::{AutoNatClient, AutoNatClientInput, AutoNatServer, AutoNatServerInput};
use minip2p_core::{Multiaddr, PeerId, SansIoProtocol};
use minip2p_dcutr::{FrameDecode as DcutrFrame, HolePunch};
use minip2p_identify::{IdentifyConfig, IdentifyInput, IdentifyMessage, IdentifyProtocol};
use minip2p_multistream_select::{MultistreamInput, MultistreamSelect};
use minip2p_relay::{FrameDecode as RelayFrame, HopMessage, StopMessage};
use minip2p_transport::StreamId;

fuzz_target!(|data: &[u8]| {
    let _ = Multiaddr::from_bytes(data);
    if let Ok(text) = core::str::from_utf8(data) {
        let _ = text.parse::<Multiaddr>();
    }

    fuzz_multistream(data);
    fuzz_identify(data);
    fuzz_autonat(data);

    if let RelayFrame::Complete { payload, .. } = minip2p_relay::decode_frame(data) {
        let _ = HopMessage::decode(payload);
        let _ = StopMessage::decode(payload);
    }
    if let DcutrFrame::Complete { payload, .. } = minip2p_dcutr::decode_frame(data) {
        let _ = HolePunch::decode(payload);
    }
});

/// Feeds the input to both negotiation roles so `decode_message` and the
/// per-state handlers see attacker-controlled bytes.
fn fuzz_multistream(data: &[u8]) {
    let machines = [
        MultistreamSelect::dialer("/ipfs/ping/1.0.0"),
        MultistreamSelect::listener(["/ipfs/ping/1.0.0".to_string()]),
    ];
    for mut machine in machines {
        let _ = machine.handle_input(MultistreamInput::Start);
        let _ = machine.handle_input(MultistreamInput::Data(data.to_vec()));
        while machine.poll_output().is_some() {}
        let _ = machine.take_remaining_buffer();
    }
}

/// Exercises both the raw message decoder and the state-machine path that
/// runs the private length-prefixed framing decoder.
fn fuzz_identify(data: &[u8]) {
    let _ = IdentifyMessage::decode(data);

    let peer_id = fuzz_peer_id();
    let stream_id = StreamId::new(1);
    let mut identify = IdentifyProtocol::new(IdentifyConfig {
        protocol_version: "fuzz/1.0.0".into(),
        agent_version: "minip2p-fuzz/0.0.0".into(),
        protocols: vec!["/ipfs/id/1.0.0".into()],
        public_key: b"fuzz-public-key".to_vec(),
    });
    let _ = identify.handle_input(IdentifyInput::RegisterInboundStream {
        peer_id: peer_id.clone(),
        stream_id,
    });
    let _ = identify.handle_input(IdentifyInput::StreamData {
        peer_id: peer_id.clone(),
        stream_id,
        data: data.to_vec(),
    });
    // Closing the remote write side decodes the buffered length-prefixed
    // message.
    let _ = identify.handle_input(IdentifyInput::StreamRemoteWriteClosed { peer_id, stream_id });
    while identify.poll_output().is_some() {}
}

/// Runs the frame decoder plus both state machines so the message-level
/// `read_len_delimited` path sees the decoded payload.
fn fuzz_autonat(data: &[u8]) {
    let _ = minip2p_autonat::decode_frame(data);

    let mut server = AutoNatServer::new();
    let _ = server.handle_input(AutoNatServerInput::Data(data.to_vec()));
    while server.poll_output().is_some() {}

    let mut client = AutoNatClient::new(&fuzz_peer_id(), &[]);
    let _ = client.handle_input(AutoNatClientInput::Data(data.to_vec()));
    while client.poll_output().is_some() {}
}

fn fuzz_peer_id() -> PeerId {
    PeerId::from_public_key_protobuf(b"minip2p-fuzz-peer")
}
