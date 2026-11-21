# WebTransport session close and stream teardown

How `WtSession` ends a session:

- **Our resets are never acknowledged, so the Closing phase's deadline lets them out.** When the CONNECT stream's send side is reset (by trailing data after a close capsule, or by the client's STOP_SENDING), the session waits out the Closing deadline instead of an acknowledgement; an acknowledgement of our FIN read in the same poll does not change that. A close capsule already received keeps its code. Once our FIN is acknowledged there is no send half left to reset, and STOP_SENDING carries the code alone.
- **Data after a close capsule resets the CONNECT stream with `H3_MESSAGE_ERROR`.** Draft-14 §6 lets a client send the capsule, FIN and STOP_SENDING together; the session's streams are still reset with `WT_SESSION_GONE`.
- **The teardown leaves before QUIC closes.** Our FIN on the CONNECT stream and the session's stream resets are sent before CONNECTION_CLOSE; a close in the same service would otherwise discard them. Stopping the CONNECT stream marks our side done at once, and the resets still go out.
- **Stream codes by draft.** Draft-14 names `WT_SESSION_GONE` for the streams of a closed session; draft-02 names no code, so its streams end like any other minip2p reset, with application error 0.
- **Noise stream.** The FIN waits for the last byte of the reply; once Noise is done, anything further on that stream is ignored.
