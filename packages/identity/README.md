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

## no_std

Disable default features:

```toml
[dependencies]
minip2p-identity = { path = "packages/identity", default-features = false }
```

## Scope

This crate currently covers key container encoding and peer ID computation/parsing. It does not yet include key generation or signature primitives.
