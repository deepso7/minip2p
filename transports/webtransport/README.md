# minip2p-webtransport

`minip2p-webtransport` is the sans-I/O HTTP/3 and QPACK codec behind libp2p WebTransport, and the client side of libp2p WebTransport. The QUIC listener (`minip2p-quic`) and the native test client use the codec to speak to browsers; browsers bring their own HTTP/3 stack, and run `WebTransportClient` over it.

It owns no streams, sockets or clocks. A caller feeds the bytes of one QUIC stream, in order, into a decoder and gets back frames, a stream header, capsules, or `None` for "need more". Every decoder is bounded by explicit caps, so an unauthenticated peer cannot make it allocate more than a few KiB. `no_std + alloc`; disable default features for embedded targets.

## `h3`

- `varint`: QUIC variable-length integers.
- `FrameDecoder`: DATA, HEADERS, SETTINGS, GOAWAY, CANCEL_PUSH and MAX_PUSH_ID frames. DATA payloads stream through as borrowed chunks; HEADERS (16 KiB), SETTINGS (4 KiB) and the single-id frames are buffered whole within their caps, checked before allocating. The push frames are reported, not skipped, so a caller can confine them to the control stream and check their ids. Unknown and reserved (GREASE) frame types are skipped without buffering; HTTP/2-only types and PUSH_PROMISE are rejected. A WebTransport bidi stream's `0x41` + session id prefix decodes as `Frame::WebTransportStream`, after which the stream carries application data.
- `Settings`: SETTINGS encode and decode, rejecting repeated and HTTP/2-only identifiers. `setting` names the identifiers WebTransport uses.
- `UniStreamHeaderDecoder`: control, push, QPACK encoder and decoder, and WebTransport (`0x54` + session id) uni streams, or the unknown type for the caller to refuse.
- `CapsuleDecoder` and `Capsule`: capsules reassembled across DATA frames. `CLOSE_WEBTRANSPORT_SESSION`, `WT_MAX_DATA` and `WT_MAX_STREAMS` are decoded; other capsules up to 64 KiB are skipped without buffering.
- `webtransport_code_to_h3` and `h3_code_to_webtransport`: the draft's mapping between WebTransport application error codes and HTTP/3 codes.

Each decoding `Error` carries the HTTP/3 code to close with (`Error::code`); the `code` module lists the HTTP/3 and QPACK codes.

```rust
use minip2p_webtransport::h3::{Frame, FrameDecoder, UniStreamHeaderDecoder, UniStreamType};

// A client control stream: the stream type, then SETTINGS.
let mut stream: &[u8] = &[0x00, 0x04, 0x02, 0x08, 0x01];
assert_eq!(UniStreamHeaderDecoder::new().decode(&mut stream), Some(UniStreamType::Control));
let mut frames = FrameDecoder::new();
let Some(Frame::Settings(settings)) = frames.decode(&mut stream)? else {
    panic!("expected SETTINGS");
};
assert_eq!(settings.get(0x08), Some(1));
# Ok::<(), minip2p_webtransport::Error>(())
```

## `qpack`

The listener advertises a QPACK table capacity of 0, so peers may only use the static table. `QpackDecoder` accepts exactly that: Required Insert Count 0 with a nonnegative Base, indexed static entries, and literals with RFC 7541 Huffman decoding. Any dynamic-table reference fails with `QPACK_DECOMPRESSION_FAILED`, as does a field section that decodes past 8 KiB (counted as `name + value + 32` per field, per RFC 9114) or 64 fields, however few encoded bytes produced it. It decodes into one buffer allocated up front and reused.

`DecoderStreamReader` checks the peer's QPACK decoder stream incrementally for an encoder that never inserts: Stream Cancellation passes, while a Section Acknowledgment or Insert Count Increment (even of 0) fails with `QPACK_DECODER_STREAM_ERROR`.

`encode_field_section` writes the same subset without Huffman: indexed static entries where they match exactly, static name references, and plain literals. `:status 200` encodes to `00 00 d9`.

```rust
use minip2p_webtransport::qpack::{QpackDecoder, encode_field_section};

let mut block = Vec::new();
encode_field_section([(&b":status"[..], &b"200"[..])], &mut block);
assert_eq!(block, [0x00, 0x00, 0xd9]);

let mut decoder = QpackDecoder::new();
let section = decoder.decode(&block)?;
assert_eq!(section.get(b":status"), Some(&b"200"[..]));
# Ok::<(), minip2p_webtransport::Error>(())
```

## `WebTransportIo` and `WebTransportClient`

`WebTransportIo` is the seam to a platform's WebTransport API: in a browser, TypeScript around the `WebTransport` object. It is caller-driven like the rest of minip2p. Calls return at once (`connect` with the URL and certhashes, `open_stream`, `write`, `close_write`, `reset`, `stop`, `grant_read`, `close`), and what the platform learns later comes back as `IoEvent`s from `poll_event`: `SessionReady`, `SessionClosed` (an orderly close, with its code), `SessionFailed` (never came up, or lost to an error), `StreamOpened`, `IncomingStream`, `Data`, `Fin`, `Reset`, `StopSending` and `WriteCompleted`. `write` copies what it accepts, and a short write is backpressure that a later `WriteCompleted` releases. `Data` never exceeds what `grant_read` allowed. Stream codes cross the seam as WebTransport application codes, as a browser reports them; the platform maps them to and from HTTP/3's range (`webtransport_code_to_h3`). `close` sends a close capsule and finishes the CONNECT stream, as `WebTransport.close()` does, and the server closes QUIC.

`WebTransportClient<Io, E>` is the libp2p WebTransport dialer over it, as a `minip2p_transport::Transport` (connection ids in `ConnectionNamespace::WEBTRANSPORT`). `dial` takes `/ip4|ip6|dns*/…/udp/<port>/quic-v1/webtransport[/certhash/…]/p2p/…`:

1. connect to `https://<host>:<port>/.well-known/libp2p-webtransport?type=noise` (`webtransport_url`; IPv6 hosts are bracketed and names pass through), trusting exactly the address's certhashes or, with none, a CA-signed certificate the platform verifies for the host (WebPKI; dial a `/dns*` address, since the certificate names the domain);
2. on `SessionReady`, open the first stream and run Noise XX as initiator, requiring the `/p2p` peer;
3. require every dialed certhash in the server's Noise extensions, or close with an `Error` reason (a dial without certhashes accepts any list, or none);
4. finish the Noise stream and emit `Connected`, with the Noise handshake hash as the connection token, once message three and the FIN are with the platform. Until then the handshake and its timeout stay pending, and a `StopSending` or `Reset` on the Noise stream fails it.

Every later stream maps 1:1 onto a WebTransport stream; `reset_stream` sends code 0, and a peer's stop code reaches `StreamWriteStopped` unchanged, matching the QUIC server's mapping. `listen` is `Unsupported`.

The client honours the full transport contract within `WebTransportLimits` (`WebTransportClient::with_limits`; `new` uses the defaults), mirroring the QUIC transport's limits: `max_connections`, `max_streams_per_connection` (per direction; the server's streams past it are reset with no event), `max_pending_bytes_per_stream`, `max_pending_connection_bytes`, `control_stream_reserve_bytes`, `stream_receive_window`, and `handshake_timeout_ms` (default 10 s, from the first poll that sees the dial, reported through `next_deadline`; expiry closes with `TimedOut`). Every byte sits in exactly one bounded place:

- **Pending writes**: from `send_stream` until their `WriteCompleted`, whether queued in Rust or copied into the platform's in-flight writes. Both count against the stream and connection caps (`minip2p_transport::SendCaps`, shared with the QUIC transport), so the connection cap covers the platform's in-flight bytes too. That is where `Full` and `StreamWritable` come from. Each `WriteCompleted` releases exactly its own bytes. The Noise handshake's own writes are not counted. A queued tail shorter than half the payload it was sliced from is copied out (`minip2p_core::retain_slice`, ADR 0012), so it pins at most twice its bytes.
- **Granted reads**: `grant_read` is issued only for `window − unacked − outstanding grant`.
- **Delivered, unacknowledged bytes**: held per stream until `ack_stream`. A connection that ends with some becomes an unsettled connection (`UnsettledConnections`) that keeps its slot until `ack_stream` or `reset_stream` settles them.

A reset, `StopSending`, `SessionClosed`, `SessionFailed` or `close` frees the affected queues and grants at once. A peer's reset also resets the client's side of the platform stream, as the QUIC transport does. A `StopSending` after `StreamClosed` is not reported but still releases writes the platform will never complete. A write the platform refuses fails `send_stream` with `StreamSendFailed`; one refused later, from the queue, stops the write side with `StreamWriteStopped` (code 0). Handles are never reused, so a late event for a handle that is gone is ignored. Dropping the client closes every session it still holds, pending dials included.

## Tests

Unit tests use the RFC 9000, RFC 7541 and RFC 9204 vectors. `tests/fixtures.rs` decodes byte captures from Chrome, Firefox and webtransport-go (provenance in `tests/fixtures/README.md`), so the listener and the test client cannot share one mistake. Every decoder has a `wire_inputs` fuzz entry. `tests/client.rs` checks the client's limits, byte ownership and certhash-free dials over a fake `WebTransportIo`. `WebTransportClient` is tested end to end in `minip2p-quic`'s `tests/webtransport.rs` and `tests/webtransport_backpressure.rs`, over a test-only quinn-proto `WebTransportIo` against the real listener.
