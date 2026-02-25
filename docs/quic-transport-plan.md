# QUIC transport plan (quiche + BoringSSL)

This document captures the implementation plan for adding a libp2p-aligned QUIC transport to this workspace.

## Scope for this milestone

- Transport engine: `quiche` (RFC 9000 / QUIC v1).
- TLS backend: BoringSSL path via quiche.
- API shape: Sans-IO transport core (host runtime owns UDP sockets and timers).
- libp2p alignment:
  - ALPN set to `libp2p`.
  - Peer authentication via libp2p TLS certificate extension.
  - Multiaddr support for `/quic-v1` only.
- Identity support in this milestone: Ed25519 host keys.

## Explicit non-goals (this milestone)

- No `/quic` (draft-29) support.
- No host key support beyond Ed25519 (ECDSA / secp256k1 / RSA postponed).
- No async runtime coupling (Tokio/async-std specific transport implementation).

## Spec references

- libp2p QUIC spec: `quic/README.md` (ALPN `libp2p`, QUIC-v1, peer auth via TLS spec).
- libp2p TLS spec: `tls/tls.md`.

## Architecture outline

### Auth placement (recommended split)

Authentication is logically part of the QUIC/TLS handshake, but the code does
not need to live only inside the transport implementation.

- Keep handshake enforcement in transport:
  - transport must block readiness until peer auth succeeds,
  - transport must fail the connection on auth failure.
- Extract reusable auth logic into a separate module/crate:
  - libp2p TLS cert generation,
  - cert extension encode/decode,
  - cert verification,
  - peer-id extraction and expected-peer checks.

This split keeps transport focused on packet/state flow and makes the auth logic
reusable for other transports or tests.

### 1) Identity primitives (`packages/identity`)

- Ensure Ed25519 keypair operations are available for:
  - key generation,
  - signature generation,
  - signature verification,
  - protobuf public key encoding/decoding.
- Keep `PeerId` derivation sourced from the libp2p public key encoding.
- Return clear `UnsupportedKeyType` style errors for non-Ed25519 where applicable.

### 2) libp2p TLS certificate/auth layer (`transports/quic`)

- Implement cert extension OID: `1.3.6.1.4.1.53594.1.1`.
- Implement `SignedKey` ASN.1 payload:
  - `publicKey: OCTET STRING` (protobuf-encoded libp2p public key),
  - `signature: OCTET STRING`.
- Signature message format:
  - `"libp2p-tls-handshake:" || certificate_subject_public_key_info_der`.
- Generate self-signed X.509 cert + ephemeral certificate keypair.
- Verification rules:
  - exactly one cert,
  - cert validity window includes now,
  - self-signature valid,
  - required libp2p extension present,
  - unknown critical extensions rejected,
  - SignedKey signature valid against embedded libp2p public key.
- Derive authenticated remote `PeerId` from extension public key.

### 3) QUIC transport core (`transports/quic/src/lib.rs`)

- Build `quiche::Config` for client/server with:
  - ALPN = `libp2p`,
  - transport params defaults suitable for libp2p use,
  - BoringSSL-backed TLS wiring.
- Provide Sans-IO core methods:
  - ingest inbound UDP datagrams,
  - drain outbound packets with destination/source metadata,
  - expose timeout instant/duration,
  - process timeout events,
  - open/send/recv stream data.
- Gate connection readiness on successful peer authentication.
- Client-side optional expected-peer check:
  - if expected `PeerId` is set, it MUST match cert-derived peer id.

### 4) Multiaddr handling

- Accept `/ip4|ip6/.../udp/<port>/quic-v1`.
- Reject `/quic` with explicit unsupported-version error.

## Error model

Add transport errors for at least:

- ALPN mismatch,
- missing peer certificate,
- invalid libp2p extension,
- invalid cert validity/self-signature,
- SignedKey signature mismatch,
- expected peer mismatch,
- unsupported host key type,
- unsupported QUIC multiaddr version (`/quic`).

## Milestones

1. Identity + TLS certificate primitives
   - Ed25519 signing/verification plumbing,
   - cert generation and extension encode/decode,
   - cert verification helpers and peer-id extraction.
2. QUIC core integration
   - `quiche` config and connection wrappers,
   - Sans-IO packet/timer interfaces,
   - stream send/recv surface,
   - auth gate and lifecycle events.
3. Validation and tests
   - TLS extension parse/verify tests (valid + invalid vectors),
   - handshake success/failure cases,
   - ALPN mismatch test,
   - expected peer mismatch test,
   - multiaddr parse accept/reject tests.

## Testing strategy

- Unit tests for certificate parsing and signature verification.
- Integration-style handshake tests with client/server pair.
- Negative tests for every required verification failure path.
- Keep tests deterministic and independent of external network.

## Follow-up milestones

- Add support for non-Ed25519 host key types.
- Add broader interoperability matrix/testing against other libp2p implementations.
- Evaluate optional legacy compatibility mode for `/quic` only if needed.
