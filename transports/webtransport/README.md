# minip2p-webtransport

`minip2p-webtransport` is the sans-I/O HTTP/3 and QPACK codec behind libp2p WebTransport, and the client side of libp2p WebTransport. The QUIC listener (`minip2p-quic`) and the native test client use the codec to speak to browsers; browsers bring their own HTTP/3 stack, and run `WebTransportClient` over it.

It owns no streams, sockets or clocks. A caller feeds the bytes of one QUIC stream, in order, into a decoder and gets back frames, a stream header, capsules, or `None` for "need more". Every decoder is bounded by explicit caps, so an unauthenticated peer cannot make it allocate more than a few KiB. `no_std + alloc`; disable default features for embedded targets.

## `h3`

- `varint`: QUIC variable-length integers.
- `FrameDecoder`: DATA, HEADERS, SETTINGS and GOAWAY frames. DATA payloads stream through as borrowed chunks; HEADERS (16 KiB), SETTINGS (4 KiB) and GOAWAY are buffered whole within their caps, checked before allocating. Unknown and reserved (GREASE) frame types are skipped without buffering; HTTP/2-only types and PUSH_PROMISE are rejected. A WebTransport bidi stream's `0x41` + session id prefix decodes as `Frame::WebTransportStream`, after which the stream carries application data.
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

The listener advertises a QPACK table capacity of 0, so peers may only use the static table. `QpackDecoder` accepts exactly that: Required Insert Count 0, indexed static entries, and literals with RFC 7541 Huffman decoding. Any dynamic-table reference fails with `QPACK_DECOMPRESSION_FAILED`, as does a field section that decodes past 8 KiB (counted as `name + value + 32` per field, per RFC 9114) or 64 fields, however few encoded bytes produced it. It decodes into one buffer allocated up front and reused.

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

`WebTransportIo` is the seam to a platform's WebTransport API: in a browser, TypeScript around the `WebTransport` object. It is caller-driven like the rest of minip2p. Calls return at once (`connect` with the URL and certhashes, `open_stream`, `write`, `close_write`, `reset`, `stop`, `grant_read`, `close`), and what the platform learns later comes back as `IoEvent`s from `poll_event`: `SessionReady`, `SessionClosed`, `StreamOpened`, `IncomingStream`, `Data`, `Fin`, `Reset`, `StopSending` and `WriteCompleted`. `write` copies what it accepts, and a short write is backpressure that a later `WriteCompleted` releases. `Data` never exceeds what `grant_read` allowed.

`WebTransportClient<Io, E>` is the libp2p WebTransport dialer over it, as a `minip2p_transport::Transport` (connection ids in `ConnectionNamespace::WEBTRANSPORT`). `dial` takes `/ip4|ip6|dns*/…/udp/<port>/quic-v1/webtransport/certhash/…/p2p/…`:

1. connect to `https://<host>:<port>/.well-known/libp2p-webtransport?type=noise` (`webtransport_url`; IPv6 hosts are bracketed and names pass through), trusting exactly the address's certhashes;
2. on `SessionReady`, open the first stream and run Noise XX as initiator, requiring the `/p2p` peer;
3. require every dialed certhash in the server's Noise extensions, or close with an `Error` reason;
4. finish the Noise stream and emit `Connected`, with the Noise handshake hash as the connection token.

Every later stream maps 1:1 onto a WebTransport stream. `listen` and dials without a `/certhash` are `Unsupported`. This first cut queues writes without a bound and grants each stream a fixed 256 KiB read window; the client's limits (`Full`, connection caps, unsettled connections, the handshake deadline) come later.

## Tests

Unit tests use the RFC 9000, RFC 7541 and RFC 9204 vectors. `tests/fixtures.rs` decodes byte captures from Chrome, Firefox and webtransport-go (provenance in `tests/fixtures/README.md`), so the listener and the test client cannot share one mistake. Every decoder has a `wire_inputs` fuzz entry. `WebTransportClient` is tested end to end in `minip2p-quic`'s `tests/webtransport.rs`, over a test-only quinn-proto `WebTransportIo` against the real listener.
