use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use futures::io::{AsyncRead, AsyncWrite};
use futures::task::noop_waker;
use libp2p_core::upgrade::OutboundConnectionUpgrade;
use minip2p_core::SansIoProtocol;
use minip2p_identity::Ed25519Keypair;
use minip2p_noise::{NoiseConfig, NoiseInput, NoiseOutput, NoiseRole, NoiseSession};

// This utility is deliberately a standalone workspace. It is run only when a
// maintainer explicitly regenerates the checked-in transcript; its producer
// dependencies never enter minip2p's workspace or CI graph.

#[derive(Default)]
struct Buffers {
    incoming: VecDeque<u8>,
    outgoing: Vec<u8>,
    reader: Option<Waker>,
}

#[derive(Clone, Default)]
struct CaptureIo(Arc<Mutex<Buffers>>);

impl CaptureIo {
    fn push_incoming(&self, bytes: &[u8]) {
        let mut buffers = self.0.lock().unwrap();
        buffers.incoming.extend(bytes);
        if let Some(waker) = buffers.reader.take() {
            waker.wake();
        }
    }

    fn take_outgoing(&self) -> Vec<u8> {
        std::mem::take(&mut self.0.lock().unwrap().outgoing)
    }
}

impl AsyncRead for CaptureIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut buffers = self.0.lock().unwrap();
        if buffers.incoming.is_empty() {
            buffers.reader = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let count = destination.len().min(buffers.incoming.len());
        for slot in &mut destination[..count] {
            *slot = buffers.incoming.pop_front().unwrap();
        }
        Poll::Ready(Ok(count))
    }
}

impl AsyncWrite for CaptureIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.lock().unwrap().outgoing.extend_from_slice(source);
        Poll::Ready(Ok(source.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn main() {
    let libp2p_identity =
        libp2p_identity::Keypair::ed25519_from_bytes([11; 32]).expect("identity key");
    let libp2p_peer = libp2p_identity.public().to_peer_id();
    let config = libp2p_noise::Config::new(&libp2p_identity).expect("Noise config");
    let io = CaptureIo::default();
    let mut future = config.upgrade_outbound(io.clone(), "/noise");

    assert!(matches!(poll_once(&mut future), Poll::Pending));
    let message1 = io.take_outgoing();

    let mut responder = NoiseSession::new(NoiseConfig {
        role: NoiseRole::Responder,
        identity: Ed25519Keypair::from_secret_key_bytes([21; 32]),
        static_secret: [22; 32],
        ephemeral_secret: [23; 32],
        expected_peer: None,
    });
    responder.handle_input(NoiseInput::Start).unwrap();
    responder
        .handle_input(NoiseInput::Data(message1.clone()))
        .unwrap();
    let message2 = take_outbound(&mut responder);

    let responder_identity = Ed25519Keypair::from_secret_key_bytes([21; 32]);
    let static_public = x25519_public([22; 32]);
    let mut signed = b"noise-libp2p-static-key:".to_vec();
    signed.extend_from_slice(&static_public);
    let mut payload = Vec::new();
    protobuf_bytes(
        1,
        &responder_identity.public_key().encode_protobuf(),
        &mut payload,
    );
    protobuf_bytes(2, &responder_identity.sign(&signed), &mut payload);
    let params = "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
    let mut snow = snow::Builder::new(params)
        .local_private_key(&[22; 32])
        .fixed_ephemeral_key_for_testing_only(&[23; 32])
        .build_responder()
        .unwrap();
    let mut scratch = [0; 65535];
    snow.read_message(&message1[2..], &mut scratch).unwrap();
    let size = snow.write_message(&payload, &mut scratch).unwrap();
    let mut snow_message2 = Vec::from((size as u16).to_be_bytes());
    snow_message2.extend_from_slice(&scratch[..size]);
    assert_eq!(message2, snow_message2);

    io.push_incoming(&message2);
    let result = poll_once(&mut future);
    assert!(matches!(result, Poll::Ready(Ok(_))), "{result:?}");
    let message3 = io.take_outgoing();

    responder
        .handle_input(NoiseInput::Data(message3.clone()))
        .unwrap();
    let verified_peer = match responder.poll_output().unwrap() {
        NoiseOutput::HandshakeComplete { peer, .. } => peer,
        output => panic!("unexpected output: {output:?}"),
    };
    assert_eq!(verified_peer.to_string(), libp2p_peer.to_string());

    println!("producer=libp2p-noise-0.46.1");
    println!("initiator_identity_secret={}", encode_hex(&[11; 32]));
    println!("initiator_noise_static_secret={}", encode_hex(&[31; 32]));
    println!("initiator_noise_rng_seed={}", encode_hex(&[32; 32]));
    println!("responder_identity_secret={}", encode_hex(&[21; 32]));
    println!("responder_static_secret={}", encode_hex(&[22; 32]));
    println!("responder_ephemeral_secret={}", encode_hex(&[23; 32]));
    println!("initiator_peer={libp2p_peer}");
    println!("message1={}", encode_hex(&message1));
    println!("message2={}", encode_hex(&message2));
    println!("message3={}", encode_hex(&message3));
}

fn poll_once<F: std::future::Future + ?Sized>(future: &mut Pin<Box<F>>) -> Poll<F::Output> {
    let waker = noop_waker();
    let mut context = Context::from_waker(&waker);
    future.as_mut().poll(&mut context)
}

fn take_outbound(session: &mut NoiseSession) -> Vec<u8> {
    match session.poll_output().expect("outbound message") {
        NoiseOutput::Outbound(bytes) => bytes,
        output => panic!("unexpected output: {output:?}"),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").unwrap();
    }
    output
}

fn protobuf_bytes(field: u8, value: &[u8], output: &mut Vec<u8>) {
    output.push((field << 3) | 2);
    protobuf_uvarint(value.len() as u64, output);
    output.extend_from_slice(value);
}

fn protobuf_uvarint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn x25519_public(secret: [u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    PublicKey::from(&StaticSecret::from(secret)).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::protobuf_bytes;

    #[test]
    fn protobuf_bytes_varint_encodes_multibyte_lengths() {
        let value = vec![0xaa; 128];
        let mut encoded = Vec::new();

        protobuf_bytes(2, &value, &mut encoded);

        assert_eq!(&encoded[..3], &[0x12, 0x80, 0x01]);
        assert_eq!(&encoded[3..], value);
    }
}
