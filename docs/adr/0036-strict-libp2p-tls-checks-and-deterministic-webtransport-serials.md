# libp2p TLS certificate checks and WebTransport certificate serials

Decisions in `minip2p-tls` beyond what the libp2p TLS spec spells out:

- **`verify_self_signature` requires the outer `signatureAlgorithm` and the TBS `signature` field to be identical** (RFC 5280 §4.1.1.2), and rejects a mismatch as `InvalidSelfSignature` even when the signature would verify.
- **`decode_signed_key` is strict DER:** trailing bytes after the `SignedKey` SEQUENCE are rejected, because this path authenticates the peer's identity.
- **The verifier's tests use the libp2p spec's test vectors** (https://github.com/libp2p/specs/blob/master/tls/tls.md), so they double as an interop check.
- **WebTransport certificates get a distinct, deterministic serial.** `webtransport_certificate` gives every certificate the same self-issued name, and NSS (Firefox) refuses a certificate whose issuer and serial match one it already holds. The serial is therefore 16 bytes, `0x01` (keeping it positive) followed by the first 15 bytes of SHA-256 over the period's public key: it differs per node and per period yet stays deterministic, as the derived certificate must be (same key and period give the same certhash across restarts).
