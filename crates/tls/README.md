# minip2p-tls

libp2p TLS certificate generation and verification for minip2p.

Implements the [libp2p TLS spec](https://github.com/libp2p/specs/blob/master/tls/tls.md) for peer authentication over TLS 1.3. Transport-agnostic: reusable by QUIC, TCP, WebSocket, and future transport adapters.

## What it does

- **Certificate generation**: creates a self-signed X.509 certificate with an ephemeral ECDSA P-256 signing key and a libp2p Public Key Extension (OID `1.3.6.1.4.1.53594.1.1`) carrying the Ed25519 host identity.
- **Certificate verification**: parses a peer's DER-encoded certificate, verifies the self-signature and the extension's host-key signature, and derives the remote peer's `PeerId`.
- **PEM helpers**: converts DER-encoded certificates and private keys to PEM. Works in both `std` and `no_std + alloc` (the `std` build uses `der::EncodePem` for `cert_to_pem`; `no_std` uses a hand-written base64 encoder producing identical RFC 7468 PEM).

## `no_std` support

Verification, generation, and PEM encoding all work in `no_std + alloc`. The core generation function accepts caller-provided `Validity` and `CryptoRng`:

```rust
use minip2p_tls::{generate_certificate_with_rng, Validity};

let (cert_der, key_der) = generate_certificate_with_rng(&keypair, validity, &mut rng)?;
```

The `std` feature adds a convenience wrapper that uses OS randomness and a default validity window:

```rust
use minip2p_tls::generate_certificate;

let (cert_der, key_der) = generate_certificate(&keypair)?;
```

```sh
# Verify no_std builds (verification + generation + PEM)
cargo check -p minip2p-tls --no-default-features
```

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `std`   | yes     | OS randomness convenience wrapper, `der::EncodePem` for `cert_to_pem` |
