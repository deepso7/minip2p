# Bytes coalesced behind DCUtR and relay handshakes

Reads can coalesce protocol frames with the bytes that follow them. The NAT machines never parse past their last frame and never buffer input they will not use:

- **DCUtR stops at its last frame.** `DcutrResponder` stops decoding at SYNC and `DcutrInitiator` at the CONNECT reply; bytes behind them belong to the application, which drains them with `take_trailing_data` (the initiator only after SYNC has been flushed).
- **Later DCUtR input is dropped, not buffered.** Once the initiator has consumed the CONNECT reply, the stream carries no further DCUtR frames toward it, so later bytes are dropped, including in `ReadyToSync`, where a misbehaving peer could otherwise grow the buffer without bound. On a decode error the machine fails and drops its buffer, retaining no attacker-controlled input or its allocation.
- **Secure-mux bytes behind a relay STATUS go with the bridge.** Bytes the relay pipelined behind HOP STATUS:OK (`Attempt`) or behind STOP CONNECT (`InboundCircuit`) belong to the circuit's Noise/Yamux handshake and are handed to the circuit transport with the bridge as `pending_data`. DCUtR runs later on the promoted connection (ADR 0006), never on the raw bridge.
