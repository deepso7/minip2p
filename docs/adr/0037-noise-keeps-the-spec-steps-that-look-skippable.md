# Noise handshake follows the spec where shortcuts break interop

`minip2p-secure-mux`'s Noise implementation keeps several spec steps that look skippable:

- `SymmetricState` initialisation always runs `mix_hash(prologue)`, even for an empty prologue. Hashing `h || []` is not a no-op, and libp2p peers expect it.
- XX message 1 has an empty payload, but the initiator still runs `EncryptAndHash` over it, because that advances the handshake hash.
- `CipherState` increments its nonce only after a successful encrypt or decrypt. Noise requires this for DECRYPT; on encrypt it is safe because no ciphertext is emitted on failure, so the nonce can be reused on retry.
- Noise extensions (`NoiseExtensions`, WebTransport certhashes) are sent only by WebTransport. `SecureMuxSession` (TCP and circuit) sets `local_extensions: None` and ignores any it receives, so its wire bytes stay identical to plain libp2p Noise.
