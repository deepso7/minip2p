# WebTransport draft negotiation and settings

`WtSession` (in `minip2p-quic`) serves draft-02 (Chrome, Firefox) and draft-13/14 (Safari) on one listener (ADR 0023):

- **Our SETTINGS offer both drafts together**, as webtransport-go sends them, and no QPACK settings: the dynamic table stays at capacity 0, so the decoder is static-only.
- **The highest draft both sides speak wins**: 13/14, else 02. Both need HTTP/3 datagrams, in SETTINGS (`H3_DATAGRAM`) and as the QUIC DATAGRAM transport parameter (draft-14 §3.1, draft-02 §3.1); every browser sends both, and a client missing either is refused.
- **Draft-14 session flow control is on once both sides ask for it**: more than one session (`WT_MAX_SESSIONS`) or a nonzero initial limit (draft-14 §5.1). Our own limits are 2^60, so only the client's limits ever bind, and a limit it omits is 0. Draft-02 has no session flow control, so the same settings limit nothing there.
- **A refusal ends the session.** A non-200 response (400 for a missing or unsupported offer, including draft-15+) finishes the CONNECT stream, enters the Closing phase, and the connection closes once the status is through.
