#![no_main]

use libfuzzer_sys::fuzz_target;
use minip2p_core::Multiaddr;
use minip2p_dcutr::{FrameDecode as DcutrFrame, HolePunch};
use minip2p_identify::IdentifyMessage;
use minip2p_relay::{FrameDecode as RelayFrame, HopMessage, StopMessage};

fuzz_target!(|data: &[u8]| {
    let _ = Multiaddr::from_bytes(data);
    if let Ok(text) = core::str::from_utf8(data) {
        let _ = text.parse::<Multiaddr>();
    }
    let _ = IdentifyMessage::decode(data);

    if let RelayFrame::Complete { payload, .. } = minip2p_relay::decode_frame(data) {
        let _ = HopMessage::decode(payload);
        let _ = StopMessage::decode(payload);
    }
    if let DcutrFrame::Complete { payload, .. } = minip2p_dcutr::decode_frame(data) {
        let _ = HolePunch::decode(payload);
    }

    let _ = minip2p_autonat::decode_frame(data);
});
