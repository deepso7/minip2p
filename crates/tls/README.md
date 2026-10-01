# minip2p-tls

libp2p TLS certificate generation and verification for minip2p.

Implements the [libp2p TLS spec](https://github.com/libp2p/specs/blob/master/tls/tls.md) for peer authentication over TLS 1.3. Transport-agnostic: reusable by QUIC, TCP, WebSocket, and future transport adapters.

## What it does

- **Certificate generation**: creates a self-signed X.509 certificate with an ephemeral ECDSA P-256 signing key and a libp2p Public Key Extension (OID `1.3.6.1.4.1.53594.1.1`) carrying the Ed25519 host identity. The `std` wrapper backdates NotBefore by one hour, so a verifier whose clock runs slightly behind still accepts a fresh certificate.
- **Certificate verification**: parses a peer's DER-encoded certificate, verifies the self-signature, and derives the remote peer's `PeerId` from the extension's host-key signature. It rejects a certificate that is expired or not yet valid, carries the libp2p extension more than once, or carries any other critical extension. Each rejection is a distinct `TlsError` variant.

The crate reads no clock, so the caller passes the current time:

```rust
use minip2p_tls::verify_libp2p_certificate;

// `now` is a `core::time::Duration` since the Unix epoch.
let peer_id = verify_libp2p_certificate(&cert_der, now)?;
```

The spec also forbids certificate chains. The verifier sees one certificate, so the transport must reject a peer that presents more than one (the QUIC transport does).

### Host key types

| Key type | Verified |
| --- | --- |
| Ed25519 | yes |
| ECDSA P-256 | yes |
| ECDSA on other curves | no, `TlsError::UnsupportedKeyType` |
| secp256k1 | no, deferred (would need a `k256` dependency); `TlsError::UnsupportedKeyType` |
| RSA | no, optional in the spec; `TlsError::UnsupportedKeyType` |

## `no_std` support

Verification and generation both work in `no_std + alloc`. The core generation function accepts caller-provided `Validity` and `CryptoRng`:

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
# Verify no_std builds (verification + generation)
cargo check -p minip2p-tls --no-default-features
```

## Features

| Feature | Default | Description |
| --- | --- | --- |
| `std` | yes | OS randomness convenience wrapper (`generate_certificate`) |
