# minip2p-noise

`minip2p-noise` is a small, caller-driven implementation of libp2p's Noise
security protocol. It implements `Noise_XX_25519_ChaChaPoly_SHA256`, including
libp2p identity binding, cryptographic peer-ID verification, and the two-byte
libp2p framing used for both handshake and transport messages.

The crate is Sans-I/O and supports `no_std + alloc`. Callers provide fresh
X25519 static and ephemeral secrets for every session, feed received bytes into
the state machine, and write the emitted outbound bytes using their own I/O
adapter. The crate does not own randomness, sockets, clocks, or timers.

Transport plaintext is automatically segmented at 65,519 bytes so every
encrypted message, including its 16-byte authentication tag, fits the 65,535
byte wire-frame limit.
