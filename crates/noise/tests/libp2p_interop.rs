use core::str::FromStr;

use minip2p_core::SansIoProtocol;
use minip2p_identity::{Ed25519Keypair, PeerId};
use minip2p_noise::{NoiseConfig, NoiseInput, NoiseOutput, NoiseRole, NoiseSession};

const FIXTURE: &str = include_str!("fixtures/libp2p-noise-0.46.1.txt");

#[test]
fn responder_completes_pinned_rust_libp2p_initiator_transcript() {
    assert_eq!(value("producer"), "libp2p-noise-0.46.1");
    let expected_peer = PeerId::from_str(value("initiator_peer")).unwrap();
    let mut responder = NoiseSession::new(NoiseConfig {
        role: NoiseRole::Responder,
        identity: Ed25519Keypair::from_secret_key_bytes(array("responder_identity_secret")),
        static_secret: array("responder_static_secret"),
        ephemeral_secret: array("responder_ephemeral_secret"),
        expected_peer: Some(expected_peer.clone()),
    });
    responder.handle_input(NoiseInput::Start).unwrap();
    responder
        .handle_input(NoiseInput::Data(hex(value("message1"))))
        .unwrap();
    assert_eq!(
        responder.poll_output(),
        Some(NoiseOutput::Outbound(hex(value("message2"))))
    );
    responder
        .handle_input(NoiseInput::Data(hex(value("message3"))))
        .unwrap();
    match responder.poll_output().expect("handshake completion") {
        NoiseOutput::HandshakeComplete { peer, identity_key } => {
            assert_eq!(peer, expected_peer);
            assert_eq!(PeerId::from_public_key(&identity_key), expected_peer);
        }
        output => panic!("expected handshake completion, got {output:?}"),
    }
}

fn value(name: &str) -> &str {
    FIXTURE
        .lines()
        .filter_map(|line| line.split_once('='))
        .find_map(|(field, value)| (field == name).then_some(value))
        .unwrap_or_else(|| panic!("missing fixture field {name}"))
}

fn array(name: &str) -> [u8; 32] {
    hex(value(name)).try_into().expect("32-byte fixture value")
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
