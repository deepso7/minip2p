# minip2p-identity

Small, `no_std`-friendly libp2p identity crate focused on public key protobuf encoding, peer ID derivation, and feature-gated Ed25519 key generation.

## Features

- Deterministic protobuf encoding/decoding for `PublicKey` (`Type`, then `Data`).
- Key type enum values matching libp2p: `RSA`, `Ed25519`, `Secp256k1`, `ECDSA`.
- Peer ID derivation from protobuf-encoded public keys:
  - `identity` multihash for encoded key length `<= 42` bytes.
  - `sha2-256` multihash for encoded key length `> 42` bytes.
- Peer ID string support:
  - Legacy base58btc multihash form (`Qm...`, `12D3Koo...`).
  - CIDv1 with `libp2p-key` multicodec (`0x72`) in base32 multibase (`b...`).
- Typed multihash API via `PeerMultihash` (`multihash::Multihash<64>`).
- Ed25519 keypair generation (`ed25519` feature, enabled by default) with:
  - `generate()` for `std` users.
  - `generate_with_rng(...)` for `no_std` users.
- Ed25519 signatures (`ed25519` feature):
  - `Ed25519Keypair::sign(...)` for message signing.
  - `PublicKey::verify(...)` for signature verification with typed errors.
  - `SignedBytes` helper for bundled `{ public_key, payload, signature }` verification.

## Usage

Quick start (default features / `std`):

```rust
use minip2p_identity::Ed25519Keypair;

let keypair = Ed25519Keypair::generate();
let peer_id = keypair.peer_id();

println!("peer id (base58): {}", peer_id.to_base58());
println!("peer id (cidv1): {}", peer_id.to_cid_base32());
```

Recover from secret key bytes:

```rust
use minip2p_identity::Ed25519Keypair;

let generated = Ed25519Keypair::generate();
let restored = Ed25519Keypair::from_secret_key_bytes(generated.secret_key_bytes());

assert_eq!(restored.public_key_bytes(), generated.public_key_bytes());
assert_eq!(restored.peer_id(), generated.peer_id());
```

Generate in `no_std` by supplying your own CSPRNG (`ed25519` feature):

```rust
use minip2p_identity::Ed25519Keypair;
use rand_core::CryptoRngCore;

fn generate_with_rng<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Ed25519Keypair {
    Ed25519Keypair::generate_with_rng(rng)
}
```

Sign and verify messages:

```rust
use minip2p_identity::{Ed25519Keypair, VerifyError};

let keypair = Ed25519Keypair::from_secret_key_bytes([42u8; 32]);
let message = b"payload";
let signature = keypair.sign(message);

keypair.public_key().verify(message, &signature)?;

// Recommended for protocol payloads: sign a domain-separated byte string,
// e.g. b"/minip2p/ping/1" || payload.
# Ok::<(), VerifyError>(())
```

Sign and verify a bundled payload:

```rust
use minip2p_identity::{Ed25519Keypair, SignedBytes};

let keypair = Ed25519Keypair::from_secret_key_bytes([7u8; 32]);
let signed = SignedBytes::sign_ed25519(&keypair, b"payload");

signed.verify()?;
# Ok::<(), minip2p_identity::VerifyError>(())
```

## Error semantics

`PeerId` parsing returns typed errors (`PeerIdError`) with context useful for callers:

- `UnsupportedMultibase(char)`: CID text had an unsupported multibase prefix.
- `InvalidBase58Character { character, index }`: base58 decode failed with exact character position.
- `InvalidBase32Character { character, index }`: base32 decode failed with exact character position.
- `InvalidCidVersionVarint(..)`: failed to decode CID version varint.
- `InvalidCidMulticodecVarint(..)`: failed to decode CID multicodec varint.
- `UnsupportedCidVersion(u64)` / `UnsupportedMulticodec(u64)`: CID decoded but did not match required libp2p values.
- `InvalidMultihash(String)`: multihash parser rejected bytes (includes parser message).
- `InvalidSha256DigestLength { actual }`: SHA2-256 code was present with a non-32-byte digest.

`PublicKey` decoding returns `PublicKeyError` for deterministic protobuf violations
(wrong tags/order, invalid varints, unknown key type, or mismatched data length).

Example caller-side error handling:

```rust
use minip2p_identity::{PeerId, PeerIdError, VarintError};

fn parse_peer_id(input: &str) -> Result<PeerId, String> {
    match input.parse::<PeerId>() {
        Ok(peer_id) => Ok(peer_id),
        Err(PeerIdError::InvalidBase58Character { character, index }) => {
            Err(format!("base58 error at index {index}: '{character}'"))
        }
        Err(PeerIdError::InvalidBase32Character { character, index }) => {
            Err(format!("base32 error at index {index}: '{character}'"))
        }
        Err(PeerIdError::InvalidCidVersionVarint(VarintError::BufferTooShort)) => {
            Err("cid version is truncated".to_string())
        }
        Err(other) => Err(other.to_string()),
    }
}
```

`no_std`-friendly classification (no formatting/allocation in the handler):

```rust
use minip2p_identity::{PeerId, PeerIdError, VarintError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseClass {
    InvalidBase58Char { character: char, index: usize },
    InvalidBase32Char { character: char, index: usize },
    TruncatedCidVersion,
    Other,
}

fn classify_peer_id_error(err: PeerIdError) -> ParseClass {
    match err {
        PeerIdError::InvalidBase58Character { character, index } => {
            ParseClass::InvalidBase58Char { character, index }
        }
        PeerIdError::InvalidBase32Character { character, index } => {
            ParseClass::InvalidBase32Char { character, index }
        }
        PeerIdError::InvalidCidVersionVarint(VarintError::BufferTooShort) => {
            ParseClass::TruncatedCidVersion
        }
        _ => ParseClass::Other,
    }
}

fn parse_peer_id_no_std(input: &str) -> Result<PeerId, ParseClass> {
    input.parse::<PeerId>().map_err(classify_peer_id_error)
}
```

Mapping classes to stable numeric codes (useful for embedded telemetry):

```rust
fn parse_class_code(class: ParseClass) -> u16 {
    match class {
        ParseClass::InvalidBase58Char { .. } => 1001,
        ParseClass::InvalidBase32Char { .. } => 1002,
        ParseClass::TruncatedCidVersion => 1003,
        ParseClass::Other => 1999,
    }
}
```

## no_std

Disable default features:

```toml
[dependencies]
minip2p-identity = { path = "crates/identity", default-features = false }
```

Enable Ed25519 key generation in `no_std`:

```toml
[dependencies]
minip2p-identity = { path = "crates/identity", default-features = false, features = ["ed25519"] }
rand_core = { version = "0.6.4", default-features = false }
```

## Scope

This crate covers key container encoding and peer ID computation/parsing.
It includes feature-gated Ed25519 key generation and signature primitives
(`ed25519`, enabled by default).
