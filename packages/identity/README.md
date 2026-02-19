# minip2p-identity

Small, `no_std`-friendly libp2p identity crate focused on public key protobuf encoding and peer ID derivation.

## Features

- Deterministic protobuf encoding/decoding for `PublicKey` (`Type`, then `Data`).
- Key type enum values matching libp2p: `RSA`, `Ed25519`, `Secp256k1`, `ECDSA`.
- Peer ID derivation from protobuf-encoded public keys:
  - `identity` multihash for encoded key length `<= 42` bytes.
  - `sha2-256` multihash for encoded key length `> 42` bytes.
- Peer ID string support:
  - Legacy base58btc multihash form (`Qm...`, `12D3Koo...`).
  - CIDv1 with `libp2p-key` multicodec (`0x72`) in base32 multibase (`b...`).

## Usage

```rust
use minip2p_identity::{KeyType, PeerId, PublicKey};

let public_key = PublicKey::new(KeyType::Ed25519, vec![0u8; 32]);
let peer_id = PeerId::from_public_key(&public_key);

let legacy = peer_id.to_base58();
let cid = peer_id.to_cid_base32();

let parsed_legacy: PeerId = legacy.parse().unwrap();
let parsed_cid: PeerId = cid.parse().unwrap();

assert_eq!(parsed_legacy, peer_id);
assert_eq!(parsed_cid, peer_id);
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
minip2p-identity = { path = "packages/identity", default-features = false }
```

## Scope

This crate currently covers key container encoding and peer ID computation/parsing. It does not yet include key generation or signature primitives.
