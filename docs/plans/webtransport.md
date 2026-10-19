# Plan: libp2p WebTransport (native server + browser SDK)

> **Status:** Proposed, after three rounds of review with gpt-6.1-sol (high):
>
> - round 1: 12 findings, 7 of them high;
> - round 2: 7 findings, 1 high, plus 6 round-1 fixes judged insufficient;
> - round 3: "ready with changes" (3 findings, 1 high).
>
> Every finding was checked against the code and fixed, apart from the Identify Push deferral that round 2 accepted. The round-3 fixes were not re-reviewed. Research and sources: [WebTransport research](../research/webtransport.md).

## Goal

Browsers can talk to native minip2p nodes:

- A native `Endpoint` listening on `/ip4/0.0.0.0/udp/4001/quic-v1/webtransport` accepts browsers over libp2p WebTransport, on the same UDP socket and the same quinn `Endpoint` that serve `quic-v1`.
- A new browser SDK, `@minip2p/web`, ships wasm-compiled minip2p (`PortableEndpoint`) behind the same `@minip2p/core` API as `@minip2p/node` and `@minip2p/react-native`. It dials `/…/quic-v1/webtransport/certhash/…/p2p/…` addresses.
- After connecting, everything above the `Transport` trait works unchanged: identify, ping, custom protocols, gossipsub. Relay reservations from the browser come in the last PR.

Non-goals:

- **No async in Rust.** Browser I/O lives in TypeScript; Rust stays caller-driven (Decision 9).
- **No native WebTransport dialer** in the shipped API. Native nodes keep using `quic-v1` with each other. A test-only native client exists (Decision 11) and makes a real dialer a short follow-up.
- **No WebRTC and no WebSocket.** Browser-to-browser traffic goes over a relay circuit in PR 6, not direct.
- **No hole punching, listening, mDNS, signed discovery or AutoNAT from the browser.** The web config rejects them with `InvalidConfigError`.
- **No CA-signed certificate mode** (a WebTransport listener without `/certhash`).
- **No change to `quic-v1` wire behaviour** for libp2p peers on `quic-v1`-only sockets. On a socket that also serves WebTransport, libp2p peers additionally see the datagram parameter and a uni-stream limit of 3 (Decision 3).

## Outcome

- Chrome and Firefox, from a page on `localhost`, connect to a native node, ping it, and echo a custom protocol stream. This runs in CI under Playwright. Chromium is required; Firefox is required if its headless build supports `serverCertificateHashes`, and best-effort otherwise.
- Safari 26.4+ is best-effort and tested by hand (Decision 6).
- A browser running a third-party libp2p stack can dial our server, recorded by hand in PR 3: js-libp2p, or rust-libp2p's `webtransport-websys` client.
- `@minip2p/web` can dial a go-libp2p WebTransport listener, recorded by hand in PR 5.
- `just test`, `just clippy`, `just check-nostd` and `just fuzz` cover every new decoder. A new `just check-wasm` builds the browser crates for `wasm32-unknown-unknown`.

## Background (short)

See the research doc for sources. The facts that drive the design:

- **Browsers** speak WebTransport over HTTP/3. Chrome uses draft-02 settings. Firefox uses draft-02 settings and also requires the QUIC datagram transport parameter. Safari 26.4+ also wants the draft-13/14 settings `WT_MAX_SESSIONS` and `WT_INITIAL_MAX_*`. One server SETTINGS frame can satisfy all three.
- **libp2p WebTransport:**
  - The browser sends `CONNECT /.well-known/libp2p-webtransport?type=noise`, then opens the first bidi stream and runs Noise XX on it as **initiator**.
  - The server (responder) sends `NoiseExtensions.webtransport_certhashes` in message 2. The client checks that all of its dialed certhashes are in that list.
  - The Noise keys are then discarded: every later WebTransport stream is a plain libp2p stream (multistream-select, no yamux).
- **Certificates:** self-signed ECDSA P-256, total validity ≤ 14 days, identified by `sha2-256(DER)` multihashes in the address.

## Decisions

1. **Address model.**
   - Add `Protocol::WebTransport` (code 465) and `Protocol::Certhash(Multihash)` (code 466) to `crates/core`. Binary form: the raw multihash bytes, with sha2-256 and a 32-byte digest required. Text form: parse any multibase prefix among base58btc `z`, base64url `u`, base32 `b`/`B` and base16 `f`; print canonical base64url `u…`, as rust-libp2p and js-libp2p do.
   - Multibase codecs: base64url uses `base64ct` (no_std, already in the lockfile). base58btc and base32 reuse identity's existing private codecs, exposed as a documented public `minip2p_identity::multibase` module (`decode_base58btc`, `decode_base32_lower`, and so on). `crates/core` already depends on identity, so no new dependency is needed.
   - **Shapes:**
     - `Multiaddr::is_webtransport()` accepts `[host, Udp, QuicV1, WebTransport, Certhash*]`.
     - `is_quic_transport()` stays exact for `[host, Udp, QuicV1]`. NAT, DCUtR and hole punching keep using it, so they never treat a WebTransport address as punchable.
   - **Routing:** `transport_kind()` returns `TransportKind::Quic` for both shapes. WebTransport _is_ QUIC, the server side has to share the QUIC socket, and this keeps `TransportSet` at one member per kind with no routing changes.
   - **Dialing:** each transport rejects the shape it cannot dial synchronously, with `TransportError::Unsupported` and an actionable reason:
     - `QuicTransport::dial` rejects WebTransport ("native WebTransport dialing is not supported; dial the peer's /quic-v1 address").
     - The browser transport rejects plain `quic-v1` ("browsers can only dial /webtransport/certhash addresses").
     - PR 1 confirms that the connect engine treats a synchronous dial error as a failed candidate and moves on.
   - **Connection metadata.**
     - `admit` builds every inbound `ConnectionEndpoint` as `/…/udp/…/quic-v1`. Once ALPN is known to be `h3`, the endpoint is rewritten to `/…/udp/…/quic-v1/webtransport`, with no certhash because it is the browser's address, before `Connected`.
     - So Identify's observed address and `active_inbound_connection_sources` see a WebTransport shape, which `is_quic_transport()` correctly excludes from hole punching and NAT candidates.
     - Tests check observed-address and inbound-source classification for a WebTransport connection.
   - Fuzzing: `fuzz_multiaddr` round-trips and its oracle `expected_transport_kind` gain both shapes.

2. **Listening on WebTransport.**
   - A `/…/udp/<port>/quic-v1/webtransport` listen address (no certhash) enables WebTransport on the QUIC socket bound for that address.
   - A socket can serve `quic-v1`, WebTransport, or both, depending on which shapes were listened on. `local_addresses()` reports only the shapes that were listened on. WebTransport addresses always include the current certhashes (Decision 5).
   - **Endpoint wiring:**
     - `bind_transports` passes the listen addresses of both shapes to `QuicTransport::bind`, which groups them by socket: a socket serves WebTransport because a `/webtransport` address names it (ADR 0023), with no separate flag in `QuicNodeConfig`.
     - `listen()` on the swarm's re-listen path (`listen_on_bound_addrs`) accepts a WebTransport address carrying a certhash and matches it to its socket, ignoring the hashes.
     - `default_listen_quic_addrs` is unchanged, so WebTransport is opt-in.
   - Node and React Native SDK users get WebTransport by putting the address in `listen`; no new config field is needed.

3. **TLS: one socket, two ALPNs, chosen per connection.**
   - **Per-socket server config.** Each listening socket gets its own `Arc<ServerConfig>`: ALPN `["libp2p"]`, `["h3"]`, or `["libp2p", "h3"]`. `admit` passes it to `endpoint.accept(.., Some(config))`, quinn's per-connection override, chosen by the receiving socket.
   - **Certificate resolver.** It is ALPN-aware: `ClientHello::alpn()` containing `libp2p` gets today's libp2p certificate, `h3` gets the current WebTransport certificate. The certificate is swapped on rotation behind an `RwLock<Arc<CertifiedKey>>`.
   - **Client auth becomes optional** (`client_auth_mandatory = false`) on sockets that serve h3, because browsers send no client certificate. A presented certificate is still fully verified by `Libp2pVerifier`.
   - **The libp2p requirement moves into `on_connected`.** It reads the negotiated ALPN from `conn.handshake_data()`:
     - `libp2p` without a verified peer certificate → `fail_connection`, before any `Connected`. Today this path already ends in `fail_connection`, so libp2p peers see no change.
     - `h3` → enters the WebTransport handshake phase (Decision 4) and ignores any client certificate.
   - **Application events are gated on authentication.** Only connections in `ConnectionState::Connected` (authenticated) surface stream events. Today `accept_streams`, `scan` and the stopped handlers don't check connection state, and quinn keeps queued stream events after `Connection::close`. So:
     - In `Connecting`, peer bidi streams on a `libp2p` connection are not admitted. Their data is never read and they are dropped with the connection. On an `h3` connection they go only to the internal `WtSession` (the CONNECT, Noise and early streams).
     - In `Closing` (a local `close`, a failed authentication, or the WebTransport Closing phase), new peer streams are refused: bidi streams with stop and reset, uni streams with `STOP_SENDING` only (see the refusal rule below). Data and terminal events on existing streams are discarded without events, except that the CONNECT stream keeps being processed internally so the closing handshake can finish.
     - This applies to `quic-v1` too. It is the transport contract ("`Closed` follows, then no more events for that id") made explicit for the case where QUIC stays open briefly.
     - Tests:
       - an anonymous `libp2p` handshake whose client queued a bidi stream with data in the same flight yields no `IncomingStream` or `StreamData`, then `Closed`;
       - `close` racing an incoming stream and data yields only `Closed`;
       - during the WebTransport Closing phase, a new browser stream is refused and nothing is surfaced.
   - **Why this is safe.** Session resumption stays disabled (`NoServerSessionStorage`, no tickets), so every handshake verifies afresh. A presented certificate is still fully checked inside the handshake. An anonymous `libp2p` connection never reaches `Connected`, so it can produce no stream or established events. The ALPN is read from `crypto_session().handshake_data()`.
   - **Transport parameters.** h3-serving configs carry their own `TransportConfig`. It differs from the libp2p one in two ways, both set in the initial transport parameters, because RFC 9114 §6.2 requires the parameters themselves to allow the peer's control and QPACK streams:
     - `max_concurrent_uni_streams = 3`;
     - the QUIC datagram parameter, which Firefox requires, with a small `datagram_receive_buffer_size`. Received datagrams are drained and dropped.
   - **Refusal rule for peer-initiated streams.** A peer-initiated **uni** stream has no local send half, and quinn-proto 0.11's `Connection::send_stream` asserts `dir == Bi || initiator == local` (`connection/mod.rs:441`). Resetting one would let a peer trigger a panic. So:
     - uni streams are refused with `recv_stream(id).stop(code)` only;
     - only bidi streams also get `send_stream(id).reset(code)`.

     This one helper is used by every refusal path: dual-ALPN libp2p uni streams, unknown H3 uni types, WT uni streams, and the Closing gate. Tests drive each path with a peer-opened uni stream and assert no panic and a delivered STOP_SENDING.

   - **Recorded parameter-level change.** On a dual-ALPN socket, libp2p connections see these parameters too, because the server config is chosen before ALPN. A libp2p peer that opens a uni stream there gets `STOP_SENDING` only, and nothing is surfaced. `quic-v1`-only sockets keep today's parameters exactly.

4. **WebTransport server phase inside `QuicConnection`.**
   - A new `WtSession` sans-I/O state machine sits beside the existing stream logic in `transports/quic/src/webtransport.rs`. It uses the codec from Decision 8 and runs these phases:
     1. **H3 setup.** Open the server control uni stream: type `0x00`, then SETTINGS:
        - `0x08`=1
        - `0x33`=1
        - `0x2b603742`=1
        - `0x14e9cd29`=1
        - `0x2b61` / `0x2b64` / `0x2b65` = 2^60
        - QPACK settings left at their default 0

        Then read the client's uni streams, validating them per the matrix below.

     2. **CONNECT.** The first client bidi stream that carries a HEADERS frame is the CONNECT stream.
        - Decode it with the static-table QPACK decoder (Huffman included).
        - Require exactly one each of `:method CONNECT`, `:protocol`, `:scheme https`, `:authority` and `:path`, with no other pseudo-headers and no pseudo-header after a regular field.
        - `:path` must be exactly `/.well-known/libp2p-webtransport?type=noise`. `origin` is ignored, as go-libp2p does; authentication is Noise.
        - **Draft selection.** Wait for the client's SETTINGS, check them per draft, and pick the highest version both sides support:
          - **Legality first.** Boolean settings (`ENABLE_WEBTRANSPORT` `0x2b603742`, `ENABLE_CONNECT_PROTOCOL` `0x08`, `H3_DATAGRAM` `0x33`) must be 0 or 1. Any other value is a connection error, `H3_SETTINGS_ERROR`, before version selection, even when another draft is validly offered.
          - **draft-13/14** (Safari): `WT_MAX_SESSIONS` (`0x14e9cd29`) ≥ 1. This enables session flow control (below).
          - **draft-02** (Chrome, Firefox): `ENABLE_WEBTRANSPORT` == 1. 0 means not offered.

          `:protocol` must then be exactly `webtransport`, the token both drafts use. `webtransport-h3` (draft-15+) is rejected with 400, because we don't implement that generation's requirements (RESET_STREAM_AT, `WT_ENABLED`). No supported draft → 400. In both cases the session closes afterwards.

          Our SETTINGS advertise only drafts 02 and 13/14; the draft-15+ `0x2c7cf000` is never sent. Tests: `ENABLE_WEBTRANSPORT = 2` alone and alongside a valid draft-14 offer (both `H3_SETTINGS_ERROR`), zero values, `webtransport-h3` with each draft, and both drafts offered (14 is chosen).

          **Draft-13/14 is a compatibility subset, not full compliance.** Those drafts already require RESET_STREAM_AT, so that a reset stream still delivers its session prefix. quinn-proto 0.11 has no RESET_STREAM_AT, so our resets are plain RESET_STREAM. A reset that races the prefix leaves the client unable to associate the stream, which it discards; nothing is misdelivered. This targets what Safari 26.4 accepts in practice (webtransport-go ships the same subset). It is verified by hand, recorded as a deviation in ADR 0023 and the research doc, and Safari stays best-effort (Decision 6). Full compliance waits for RESET_STREAM_AT support in quinn (see Follow-ups).

        - Reply `:status 200` (`01 03 00 00 D9`). Reply 404 for a wrong path and 400 for a wrong query or malformed request, then close the session (see Close).
        - The session id is the CONNECT stream id.
        - **Capsules (RFC 9297 §3.1).** The CONNECT stream keeps HTTP/3 framing after the 2xx. Capsules are the concatenated payloads of its DATA frames, reassembled incrementally across DATA-frame boundaries. Outbound capsules are wrapped in DATA frames. HEADERS (trailers) or unknown frames are ignored or rejected per RFC 9114.

        **Validation matrix**, each case with a malformed-peer test:

        | Peer behaviour | Result |
        | --- | --- |
        | A second control stream, or a second QPACK encoder or decoder stream | Connection error `H3_STREAM_CREATION_ERROR` |
        | A critical stream (control or QPACK) closed or reset | `H3_CLOSED_CRITICAL_STREAM` |
        | First frame on control is not SETTINGS, a SETTINGS repeat, or DATA/HEADERS on control | `H3_MISSING_SETTINGS` / `H3_FRAME_UNEXPECTED` |
        | Duplicate setting id, or an HTTP/2-only setting | `H3_SETTINGS_ERROR` |
        | Client SETTINGS without a supported WebTransport draft | 400 on CONNECT, then close |
        | Any QPACK encoder-stream instruction (the table capacity is 0, so every insert is illegal) | `QPACK_ENCODER_STREAM_ERROR` |
        | A field section with required insert count ≠ 0, or a dynamic or post-base reference | `QPACK_DECOMPRESSION_FAILED` |
        | Unknown uni stream type | `STOP_SENDING(H3_STREAM_CREATION_ERROR)` on that stream only |
        | GOAWAY from the client | Treated as session close |

     3. **Noise.** The first `0x41 + session id` bidi stream runs `NoiseSession` as responder. Its extensions carry the certhashes of the previous, current and next certificates. On `HandshakeComplete`:
        - set the peer id;
        - set the connection token to the Noise `handshake_hash()`, which both ends compute;
        - emit `Connected`;
        - FIN the Noise stream. It is never surfaced to the swarm.
     4. **Established.** Every later bidi stream with the prefix `0x41 + session id` is surfaced as `IncomingStream` once its prefix is parsed. A bidi stream with another session id is refused with stop and reset. A WT uni stream (`0x54`) is refused with `STOP_SENDING` only. libp2p uses neither.
   - **Stream prefixes are internal.**
     - Inbound prefix bytes are read before admission and never count against the receive budget (ADR 0012).
     - Outbound streams queue the prefix ahead of any caller bytes. It is not counted in `send_room` and is never part of a `Full { unsent }`.
     - `open_stream` before `Connected` stays `InvalidState`, as today.
   - **Early streams.** Streams that arrive before the session is established, such as the Noise stream racing the 2xx, are held. The cap is 4 streams and 16 KiB in total; past that the connection fails.
   - **Stream error codes.**
     - minip2p's reset and stop code 0 is sent as the WT application error 0, mapped to `0x52e4a40fa8db` by the draft formula.
     - Inbound H3 codes are mapped back into WT codes for `StreamWriteStopped { error_code }`. Codes outside the WT range pass through unchanged.
     - Browsers cut codes to 8 bits, so minip2p only ever sends 0.
   - **Session flow control (needed for Safari).** When both sides sent `WT_INITIAL_MAX_*`, server-opened streams and bytes count against the client's WT stream and data credit. The parser reads `WT_MAX_STREAMS` (`0x190b4d3f`) and `WT_MAX_DATA` capsules on the CONNECT stream, and the existing `pending_opens` and send queue simply wait for that credit. The server's own limits are 2^60, so it never sends credit capsules.
   - **Close.**
     - **Local `close(id)`** enters a `Closing` phase rather than closing QUIC at once. quinn's `Connection::close` drops undelivered stream data, so an immediate close would lose the capsule.
       1. Send a `CLOSE_WEBTRANSPORT_SESSION` capsule (`0x2843`, code 0) in a DATA frame.
       2. FIN the CONNECT stream.
       3. Reset the open WT streams.
       4. Wait until the peer FINs or resets its side of the CONNECT stream, or until a bounded deadline passes (`max(3 × RTT, 500 ms)`, capped at 2 s).
       5. Close QUIC with `H3_NO_ERROR` (`0x100`).

       The transport contract is unchanged: `Closed` is emitted once QUIC drains, as today. No stream events follow `close`.

     - **Peer-initiated close.** A peer capsule, a FIN on the CONNECT stream, or a reset of it ends the session. The server FINs its side of the CONNECT stream, then closes QUIC with `H3_NO_ERROR` after the same bounded delay. The browser initiated the close, so it already treats the session as closed.
     - **Refused requests.** The 400 and 404 replies use the same `Closing` path, so the status reaches the browser.
     - `on_lost` counts `H3_NO_ERROR` as orderly on h3 connections, so no `Error` event is raised.
     - Tests: a native-initiated close in Playwright (PR 5) asserts that the browser's `transport.closed` promise _fulfills_ with code 0; the native test client (Decision 11) asserts that the capsule arrived before the QUIC close.
   - **Pre-auth limits.** These are enforced before allocation and bound each connection's pre-auth state once ALPN is `h3` (there is no memory budget, ADR 0022):
     - Encoded caps: HEADERS frames 16 KiB, the SETTINGS frame 4 KiB, a single capsule 64 KiB. Capsule bodies other than CLOSE are parsed as they stream, so the 64 KiB bound only applies to CLOSE messages (1 KiB max) and to skipping unknown capsules, which is done without buffering.
     - Decoded caps: the QPACK decoder stops with `QPACK_DECOMPRESSION_FAILED` once the decoded field section passes **8 KiB** (the RFC 9114 `name + value + 32` per-field accounting) or **64 fields**. That bound applies no matter how few encoded bytes produced it, which covers repeated static-index expansion. The decoder writes into one preallocated 8 KiB buffer, so there is no per-field allocation.
     - Early streams: as above, 4 streams and 16 KiB in total.
     - A WebTransport handshake deadline, `QuicLimits::webtransport_handshake_timeout_ms` (default 10 s), runs from QUIC Connected to Noise complete and feeds `next_deadline`.
     - Admission, the connection cap and Retry are unchanged: quinn admits the connection before ALPN is known, as today. The h3 state is set up at ALPN time, and a peer past any cap gets the connection closed with `H3_EXCESSIVE_LOAD`.
     - Fixtures: a 2 KiB HEADERS frame of repeated static indexes that would expand past 8 KiB is rejected; a field count of 65 is rejected.

5. **WebTransport certificates and rotation.**
   - **Generation.** `crates/tls` gets a `webtransport` module (no_std + alloc) built on the existing `x509-cert` / `p256` builder:
     - `webtransport_certificate(host: &Ed25519Keypair, period: u64) -> (cert_der, pkcs8_key)`, with no libp2p extension;
     - `certhash(cert_der) -> Multihash`.
   - **Deterministic.** The P-256 key comes from HKDF-SHA256 over the host secret key, with salt = `period` (big-endian) and info = `"minip2p webtransport certificate"`. A scalar outside range retries with a counter. ECDSA signing is RFC 6979 deterministic. The same key and period therefore give the same hash across restarts, so published addresses survive a restart. go-libp2p does the same for the same reason.
   - **Periods.**
     - Period length is `L = 13 days`, and period `k` starts at `k·L` unix seconds.
     - Certificate `k` is valid from `start_k − 1 h` to `start_k − 1 h + 14 d`, so total validity is exactly 14 days. That leaves a 1 h margin for client clock skew at the start and 23 h at the end.
     - During period `k` the server presents certificate `k` and advertises `{k, k+1}` in its addresses. The Noise list is `{k−1, k, k+1}`, so an address learned in the previous period still verifies.
     - An address therefore stays dialable for 13 to 26 days after it was learned.
   - **Rotation** is driven by the host's wall clock: `Now::unix_seconds`, falling back to system time as `HostTime` does today.
     - `next_deadline` includes the next period boundary.
     - On rotation the transport swaps the resolver's certificate, recomputes the certhashes, bumps `local_addresses_revision`, and emits `Listening` for each new WebTransport address.
     - Live connections are unaffected, because certificates only matter during a TLS handshake.
   - **Address propagation.** Today a revision bump only refreshes the swarm's snapshot, used by later Identify replies. The swarm ignores `Listening`, and ffi-core's `listen_addrs` is cached when the endpoint is built. So:
     - **Poll order.** `SwarmCore::drive` calls `refresh_local_addresses` before `transport.poll`, but rotation happens inside the transport poll. The refresh moves to just after `transport.poll` returns, before its events are handled, so the boundary poll itself sees the new addresses. Identify replies built from those events use the new set. Test: one poll at the boundary on an otherwise idle swarm reports the change.
     - **Two sets, kept apart.**
       - The _advertised_ set (transport addresses plus external and NAT addresses) feeds Identify, as today.
       - The _listen_ set is what `listenAddrs()` promises: bound listen addresses as peer multiaddresses with `/p2p/<local>`, the shape `listen_all()` returns today.
     - **New event.** When the listen set changes, the swarm emits `SwarmEvent::ListenAddressesChanged { addrs: Vec<PeerAddr> }`, surfaced as `EndpointEvent::ListenAddressesChanged`, `P2pEvent::ListenAddressesChanged` and the TS `listenAddressesChanged` event. External-address changes don't trigger it.
     - **ffi-core.** `listen_addrs()` reads a snapshot the driver updates from that event, instead of the build-time cache.
     - Test: an external-address change leaves `listenAddrs()` and the event untouched, while rotation updates both with the `/p2p` suffix preserved.
     - **Identify Push (`/ipfs/id/push/1.0.0`) is not added.** Already-connected peers learn new addresses on their next Identify, at reconnect. Their old addresses stay dialable for at least 13 more days (Periods). The addresses browsers dial come out of band (bootstrap lists, the app, a relay's own reservation), and the new event is what lets an app republish them. Identify Push is a follow-up if long-lived native peers turn out to need it.
     - Tests:
       - a mocked period boundary emits exactly one `ListenAddressesChanged` with the new hashes;
       - `listenAddrs()` in the Node SDK returns them;
       - a peer connected before the boundary gets the new set from a fresh Identify after reconnect;
       - a wall-clock jump forward or back across several periods recomputes from the clock, with no stepwise catch-up;
       - a restart exactly at a boundary yields the same hashes as a node that kept running.
   - A per-node period offset (go-libp2p uses one to stagger rotations) is not done; see Follow-ups.

6. **Browser support target.** Chrome and Firefox are required, Safari is best-effort.
   - The SETTINGS and session flow control above are what webtransport-go sends for Safari 26.4 compatibility.
   - Without a Safari test in CI, it is verified by hand per release and listed as best-effort in the README.
   - Draft-07 (`0xc671706a`) is never advertised, so Chrome stays on draft-02.

7. **Noise extensions (`crates/secure-mux`).**
   - A typed `NoiseExtensions { webtransport_certhashes: Vec<Multihash>, stream_muxers: Vec<String> }` with encode and decode in `noise/payload.rs`, using the protobuf wire vocabulary in `crates/core`.
   - `NoiseConfig` gains `local_extensions: Option<NoiseExtensions>`.
   - `NoiseOutput::HandshakeComplete` gains `remote_extensions: Option<NoiseExtensions>`.
   - `SecureMuxSession` passes `None` and ignores them, so TCP and circuit stay byte-identical on the wire.
   - The certhash check belongs to the WebTransport client (Decision 10), not to Noise.
   - Fuzzing: `fuzz_noise` decodes `NoiseExtensions`.

8. **A shared sans-I/O H3/WebTransport codec: new crate `transports/webtransport` (`minip2p-webtransport`, no_std + alloc).**
   - `h3` module:
     - QUIC varint;
     - frame header (DATA, HEADERS, SETTINGS, GOAWAY; unknown frame types skipped);
     - SETTINGS encode and decode;
     - uni stream type and WT stream prefix parsing;
     - capsules (CLOSE_WEBTRANSPORT_SESSION, WT_MAX_STREAMS, WT_MAX_DATA; unknown ones skipped);
     - WT ↔ H3 error-code mapping.
   - `qpack` module: a decoder limited to the static table, required insert count 0, literal and indexed field lines, and the RFC 7541 Huffman decoder. An encoder with indexed static entries and non-Huffman literals is enough for our requests and responses.
   - Every decoder is incremental (feed bytes, get frames or "need more"), bounded by explicit size caps, and fuzzed in `wire_inputs`.
   - The QUIC server (Decision 4) and the test client (Decision 11) both use it. The browser client does not, because the browser speaks H3 itself.

9. **Browser I/O seam: TypeScript owns WebTransport and Rust owns the protocol.**
   - **The seam.** `minip2p-webtransport` also defines a `WebTransportIo` provider trait, shaped like `TcpProvider`:

     ```rust
     pub trait WebTransportIo {
         fn connect(&mut self, url: &str, certhashes: &[Multihash]) -> Result<SessionHandle, IoError>;
         fn open_stream(&mut self, session: SessionHandle) -> Result<StreamHandle, IoError>;   // bidi
         fn write(&mut self, stream: StreamHandle, data: &[u8]) -> Result<usize, IoError>;     // copies; short write = backpressure
         fn close_write(&mut self, stream: StreamHandle);
         fn reset(&mut self, stream: StreamHandle, code: u8);   // abort() + cancel()
         fn stop(&mut self, stream: StreamHandle, code: u8);    // cancel() only
         fn grant_read(&mut self, stream: StreamHandle, bytes: usize); // pull: read at most this much more
         fn close(&mut self, session: SessionHandle, code: u32, reason: &str);
         fn poll_event(&mut self) -> Option<IoEvent>;
         // IoEvent: SessionReady, SessionClosed{reason}, StreamOpened, IncomingStream,
         //          Data{stream, bytes}, Fin, Reset{code}, StopSending{code},
         //          WriteCompleted{stream, bytes}
     }
     ```

   - **Reads.** `grant_read` maps to a BYOB reader with a view of at most the granted size. Granted bytes are exactly the ADR 0012 receive budget, so the browser's own stream flow control pushes back on the remote when the app stops acking.
   - **Writes.** `write` accepts up to the stream's free in-flight room (a 64 KiB cap) and **copies the accepted prefix synchronously**, into a fresh `Uint8Array`, before returning. A queued browser write therefore never holds a view into wasm memory, which may move or grow.
     - Each `writer.write()` resolution reports `WriteCompleted { stream, bytes }` with that write's own byte count. Several writes may be outstanding per stream. Rust releases exactly `bytes` from the stream's and the connection's in-flight accounting, and that is what eventually drives `StreamWritable`.
     - A rejected write (reset or session close) reports nothing. Its bytes are released by the terminal event.
     - Tests: interleaved partial completions release exactly their bytes; a pending write's bytes stay intact after wasm memory grows or the Rust buffer is reused.
   - **No async on either side of the seam.** The TS implementation turns promise callbacks into queued events and calls a wake function. Rust drains the queue in `poll`.

10. **Browser client transport: `WebTransportClient<Io: WebTransportIo>` in `minip2p-webtransport`, implementing `Transport`.**
    - **Dial** takes `/ip4|ip6|dns*/…/udp/<port>/quic-v1/webtransport/certhash/…`:
      1. build `https://<host>:<port>/.well-known/libp2p-webtransport?type=noise` (IPv6 hosts are bracketed; DNS names pass through to the browser, which resolves them);
      2. `connect` with the address's certhashes;
      3. on `SessionReady`, `open_stream` and run `NoiseSession` as initiator with `expected_peer` from `/p2p`;
      4. on `HandshakeComplete`, require every dialed certhash to be in `remote_extensions.webtransport_certhashes`; otherwise emit `Error` then `Closed`;
      5. FIN the Noise stream and emit `Connected`, with the token set to the handshake hash.
    - A dial without a certhash is rejected with `Unsupported` (no CA mode).
    - **Streams.** Streams map 1:1. The full transport contract follows, using the same limits and helpers as the TCP and QUIC transports.
    - **`WebTransportLimits`** mirrors `QuicLimits` where meaningful:
      - `max_connections`, `max_streams_per_connection`;
      - `max_pending_bytes_per_stream`, `max_pending_connection_bytes`, `control_stream_reserve_bytes`;
      - `stream_receive_window`;
      - `handshake_timeout_ms` (default 10 s).

      Incoming streams over the stream cap are refused with `reset` and no event, as in QUIC's `admit_remote_stream`.

    - **Byte ownership.** Every byte is in exactly one place, and each place is bounded:
      - **Rust send queue**, bounded by `send_room` (min of stream and connection caps, plus the control reserve, via the same `SendCaps` logic). This is where `Full` and `StreamWritable` come from.
      - **JS in-flight writes**: bytes `Io::write` accepted and copied, and whose `WriteCompleted` hasn't arrived. The JS side caps them at 64 KiB per stream, and completions are byte-counted (Decision 9). They count against the connection's pending bytes until resolved, so the connection cap covers Rust queue plus JS in-flight.
      - **Granted reads**: `grant_read` is issued only for `window − unacked − outstanding_grant`. `outstanding_grant` is what JS may still deliver, and drops as `Data` arrives. JS never holds a read result beyond its grant, and at most one BYOB read is outstanding per stream.
      - **Delivered, unacked bytes** are tracked per stream exactly as in QUIC (`unacked`). When a connection ends with unacked streams, they move to `UnsettledConnections` (`crates/transport/src/unsettled.rs`), as QUIC's `remove_connection` does. `reset_stream` and `ack_stream` on an ended connection settle them.
      - **Terminal callbacks.** On reset, `SessionClosed` or `close`, the Rust side frees the queues and grants immediately. JS cancels pending reads and drops pending writes, and late promise results for a dead handle are ignored by handle generation.
    - **Other limits.** The handshake deadline feeds `next_deadline`. `listen` → `Unsupported` ("browsers cannot listen; use a relay reservation to be reachable").
    - Tests, with a fake `Io`:
      - stream churn without acks stays within the stream cap times `stream_receive_window`;
      - reconnect churn with unacked data leaves unsettled entries until `ack_stream` or `reset_stream`;
      - grants never exceed the window, with outstanding grants counted;
      - the connection cap covers JS in-flight bytes;
      - late callbacks after reset or close are ignored.
    - Because it is portable and generic, it is tested natively with a fake `Io` and with the test client (Decision 11).

11. **A test-only native WebTransport client.**
    - `transports/quic/tests/common/wt_client.rs` implements `WebTransportIo` over raw quinn-proto: ALPN `h3`, a rustls verifier that checks the certhash, and an H3 client written with `minip2p-webtransport`'s codec.
    - It drives `WebTransportClient` against a real `QuicTransport` in CI, so the server and the client protocol logic are tested end to end without a browser.
    - It is not exported. Turning it into a real native dialer is a follow-up.

12. **Host layer reuse: split `crates/ffi-core` into a thread-free host core and the std driver.**
    - **Thread-free core:**
      - `Carry`, `ingest` and `take_delivery`;
      - `P2pEvent` and the `convert_*` functions;
      - `js_shape`, the config, error and connect-target types, and the key helpers.

      These compile without the std `Endpoint`. `convert_endpoint_event` takes a `path` lookup closure instead of `&minip2p::Endpoint`.

    - **`StreamWriter`** moves from `crates/minip2p/src/std/writer.rs` to a portable module that works on the shared `Engine`, so `Endpoint` and `PortableEndpoint` both expose it.
    - **Features.** The std-only parts (`P2pEndpoint`, the driver thread, the doorbell thread, DNS) go behind a default `driver` feature. `crates/nodejs` and `crates/ffi` keep the default and see no behaviour change. `crates/web` uses `default-features = false, features = ["serde"]`.

13. **The wasm shell: `crates/web` (`minip2p-web`, wasm-bindgen, `publish = false`).**
    - `WebEndpoint` exposes the same native surface as `NodeEndpoint`: `new(secretKey, config)`, `start(doorbell)`, `drainEvents(limit)`, the getters, `sendStream`, `streamConsumed`, `closeStreamWrite`, `resetStream`, `abandonStream`, `connect`, `cancelConnect`, `disconnect`, `close`, `ping`, pubsub, and `addProtocol`.
    - Internally it is a `PortableEndpoint<WebTransportClient<JsIo>, WebEntropy>`.
    - **Pump.** The driver is a single-threaded pump with no thread and no blocking:
      - any API call or `JsIo` wake schedules one coalesced `queueMicrotask(pump)`;
      - `pump` samples `Now` (`performance.now()` and `Date.now()`), calls `poll` until the next deadline is no longer `IMMEDIATE` (at most N rounds, then it yields with `setTimeout(0)`), ingests into the `Carry`, rings the doorbell on empty → non-empty, and re-arms a single `setTimeout` for `next_deadline`.
    - **Entropy** comes from `crypto.getRandomValues`, through getrandom's `wasm_js` feature, which needs no RUSTFLAGS in 0.4.
    - **No std clock.** `StdClock` is never compiled in, because `Instant` panics on wasm32.
    - **Panics.** On wasm32 a panic aborts the instance, so `catch_unwind` does not apply. The TS adapter catches the wasm `RuntimeError`, fails the endpoint with `DriverFailedError`, and every later call throws `ClosedError`.
    - **Config.** Web-specific `InvalidConfig` errors cover `listen`, `mdns`, `discovery` and `autonatServers`, each with a detail that says why. `relays` and `forceRelay` are rejected until PR 6 ("relay support for browsers lands in a later release").

14. **TypeScript package `@minip2p/web` (`bindings/ts/web`).**
    - `WebBackend implements Minip2pBackend` over `WebEndpoint`. It reuses `EventDrain` (scheduler `queueMicrotask`), `resolveEndpointConfig`, `ConnectionIdMap` and `typedFfiError`. `Minip2p extends Minip2pBase`, with `generateSecretKey`, `peerIdFromSecretKey` and `circuitAddress`.
    - **Same API as node, two entry points:**
      - `@minip2p/web` initialises the wasm with top-level `await` (wasm-bindgen `--target web`, with the `.wasm` resolved via `new URL(…, import.meta.url)`). `Minip2p.create(config)` stays synchronous and identical to node.
      - `@minip2p/web/manual` exports the same API plus `initMinip2p({ wasm })`, and does no automatic fetch. It is for hosts that serve the `.wasm` themselves (a CDN, or a strict CSP). `Minip2p.create` before `initMinip2p` resolves throws an actionable error.
      - Both entries share one implementation module, and only the default entry imports the auto-init module.
      - Test: importing `@minip2p/web/manual` with the default `.wasm` URL returning 404 succeeds, then `initMinip2p({ wasm: bytes })` works.
    - **`JsIo`** (`web/src/io.ts`) is the TS `WebTransportIo` implementation: one `WebTransport` per session with `serverCertificateHashes` and no pooling, BYOB readers, writers with in-flight accounting, error codes cut to `u8`, and `closed` and `ready` promises mapped to events. It is unit-tested against a fake `WebTransport`.
    - **Contract tests.** `describeAdapterContract("Web", …)` from `@minip2p/test-fixtures`, with a fake native.
    - **No Effect.** The rest of `bindings/ts` doesn't use Effect, and the SDK should stay consistent; that is reconsidered across all packages, not here.

15. **ADR and terms.**
    - New **ADR 0023 "libp2p WebTransport: server inside the QUIC transport, browser I/O behind a TypeScript seam"**. It records Decisions 1, 3, 9 and 12 and the rejected alternatives:
      - a separate WebTransport transport with its own socket;
      - a Rust `web-sys` and `wasm-bindgen-futures` client;
      - the async `h3` / `wtransport` crates;
      - WebSocket first.
    - `GLOSSARY.md` has **Certhash**, **WebTransport session** and **Certificate period**, and **Connection token** covers WebTransport (added before ticketing).

## PR stack

### PR 1 — `core: webtransport and certhash multiaddrs`

- `Protocol::WebTransport` and `Protocol::Certhash(Multihash)`: codes, binary and text codecs, and multibase decoding (base58btc, base64url, base32, base16). Canonical output is base64url.
- `Multiaddr::is_webtransport()`, `certhashes()` and `without_certhashes()`. `transport_kind()` returns `Quic` for both shapes. `is_quic_transport()` stays exact. `candidates`, discovery and mDNS keep accepting by kind.
- `QuicTransport::dial` and `listen` reject WebTransport shapes with `Unsupported` and an actionable reason, until PR 3.
- Check the connect engine: a synchronous `Unsupported` from dial fails that candidate only. If it doesn't, fix that here, with a test that mixes `quic-v1` and `webtransport` candidates.
- Tests:
  - text and binary round-trips using fixtures from rust-libp2p and go-libp2p strings (base58btc and base64url);
  - rejection of non-sha256 and wrong-length hashes;
  - classification.
- Fuzzing: `fuzz_multiaddr` covers the new protocols, and its oracle is updated.
- Docs: `crates/core` README.

### PR 2 — `secure-mux, tls: noise extensions and webtransport certificates`

- `NoiseExtensions`, plus the `NoiseConfig` and `HandshakeComplete` plumbing (Decision 7).
  - Unit tests: a responder's certhashes reach the initiator, and payloads without extensions still interoperate.
  - Fuzzing: `fuzz_noise` covers the extensions decoder.
- `crates/tls::webtransport` (Decision 5). Unit tests:
  - deterministic DER for the same key and period;
  - different hashes for different periods or keys;
  - validity exactly 14 days, starting 1 h before the period start;
  - a P-256 key;
  - no RSA path;
  - the certhash equals sha256(DER);
  - the period and boundary arithmetic (`period_at(unix)`, `next_boundary`).

### PR 3 — `quic: libp2p WebTransport listener`

The biggest PR, organised as reviewable commits.

- **3a. `transports/webtransport` crate, codec only** (Decision 8): varint, frames, SETTINGS, stream prefixes, capsules, error-code mapping, and the QPACK static decoder and encoder with Huffman. Unit tests use RFC 9204 and RFC 7541 vectors. **Independent wire fixtures** guard against the server and test client sharing one mistake, because both use this codec. These are byte captures, checked in under `transports/webtransport/tests/fixtures/` with their provenance noted:
  - Chrome's and Firefox's client control-stream SETTINGS and CONNECT HEADERS, from `chrome://net-export` and Firefox HTTP logging;
  - a browser's `CLOSE_WEBTRANSPORT_SESSION` capsule inside its DATA frame;
  - webtransport-go's server SETTINGS and its 200 response.

  Every decoder gets a `wire_inputs` entry.

- **3b. TLS and ALPN** (Decision 3): per-socket server configs passed to `accept`, the ALPN-aware resolver, optional client auth on h3 sockets, the ALPN check in `on_connected`, the per-connection uni limit, and the datagram parameter with drained datagrams. Tests:
  - a libp2p peer without a client certificate on a dual-ALPN socket still never gets `Connected`;
  - a `quic-v1`-only socket still offers only `libp2p`;
  - an `h3` client on a `quic-v1`-only socket fails ALPN negotiation;
  - a client offering both `libp2p` and `h3` with no certificate is negotiated as `libp2p` (server preference order) and rejected;
  - a client presenting an invalid libp2p certificate under `h3` is rejected inside the handshake.
- **3c. `WtSession`** (Decision 4) wired into `QuicConnection`: phases, prefix handling, early-stream cap, error-code mapping, session flow-control gating of opens and sends, close capsule, handshake deadline, and pre-auth caps.
- **3d. Rotation** (Decision 5): resolver swap, revision bump, `Listening`, and the boundary deadline. Endpoint wiring (Decision 2): `bind_transports`, `validate_listen_multiaddr`, `push_listen_addr`, and certhash-tolerant re-listen.
- **3e. `WebTransportClient`** (Decision 10, so the server can be tested end to end) and the test client (Decision 11). Tests, all with the real `QuicTransport`:
  - connect, then identify and ping via `SwarmCore` on both sides;
  - stream echo with FIN;
  - reset in both directions (the codes arrive mapped);
  - STOP_SENDING → `StreamWriteStopped`;
  - backpressure: `Full`, `StreamWritable`, and the receive window gating the browser side;
  - a stream prefix split across packets;
  - the Noise stream racing the 2xx;
  - wrong path → 404 and close; wrong `type` → 400;
  - a certhash mismatch fails on the client side;
  - a wrong `/p2p` peer fails;
  - handshake timeout (CONNECT never sent, Noise never finished) → `Closed` with no `Connected`;
  - the early-stream cap;
  - an orderly close in each direction gives no `Error`;
  - rotation across a mocked period boundary: new hashes, the revision bumped, an old-period address still dials, a live connection survives;
  - Retry with `require_address_validation` before an h3 handshake;
  - session flow control with a client that advertises a small `WT_INITIAL_MAX_STREAMS_BIDI`: server opens queue until `WT_MAX_STREAMS`;
- **3f. relay-server example:** `--webtransport` listens WebTransport on the QUIC port and prints the certhash address. The `--announce` handling learns the shape.
- **3g. Address propagation** (Decision 5): the refresh moves after `transport.poll`, and `SwarmEvent::ListenAddressesChanged` goes through `EndpointEvent`, `P2pEvent` and the TS event map. ffi-core's `listen_addrs` reads a live snapshot of bound addresses.
- **Release wiring for the new crate:** add `minip2p-webtransport` to `publish.yml`'s explicit crate publication order, before `minip2p-quic`, along with its registry verification and `scripts/release.sh`'s version bump and checks, so the first release after PR 3 can publish `minip2p-quic`.
- **Docs:** `transports/quic` README (ALPN dispatch, WebTransport phase, rotation, limits), `transports/webtransport` README, and ADR 0023.
- **Exit criteria:**
  - `just test`, `just clippy`, `just fmt` and `just check-nostd` (the new crate is in the no_std list) are green;
  - `just fuzz 30` runs clean with the new entries;
  - QUIC throughput is unchanged for `quic-v1` (`endpoint_throughput/quic` on the same host before and after);
  - **recorded by hand:** Chrome stable and Firefox stable dial the relay-server example from a localhost page running a small js-libp2p or rust-libp2p websys page, then ping. Safari 26.4 is attempted, with the result recorded.

### PR 4 — `ffi-core: thread-free host core` (no behaviour change)

- Decision 12. Node and RN tests pass unchanged. The ffi-core unit tests for `Carry` and conversion run without the `driver` feature.
- A `just check-wasm` recipe and CI step: `cargo check --target wasm32-unknown-unknown` for `minip2p-ffi-core --no-default-features --features serde`, `minip2p-webtransport` and `minip2p-rs --no-default-features --features pubsub`.

### PR 5 — `web: @minip2p/web browser SDK`

- `crates/web` (Decision 13) and `bindings/ts/web` (Decision 14).
- `examples/web`: a Vite page that connects to a printed address, pings, and runs an echo protocol. It also documents the matching Rust peer (`examples/peer` with a WebTransport listen address).
- **Browser e2e in CI** (`bindings.yml`): Playwright with Chromium (required) and Firefox (required if headless supports `serverCertificateHashes`, otherwise allowed to fail with a tracking issue).
  - The page is served from `localhost` so Chrome's Local Network Access check doesn't prompt.
  - The fixture spawns the relay-server example with `--webtransport` and passes the address in.
  - Tests:
    - connect, ping, open a stream, echo with FIN, reset;
    - `waitPeerReady`;
    - a large transfer to exercise backpressure;
    - `close` with the native side seeing an orderly close;
    - reconnect after the native side restarts, using the same certhash because certificates are deterministic.
- **Release wiring:** `scripts/release.sh`, `publish.yml` (a wasm build job, `package-typescript`, `publish-typescript`), `verify-release-packages.mjs` (manifest, exports, and a size cap on the `.wasm`), `smoke-release-install.mjs`, `publish.test.mjs`, `pnpm-workspace.yaml`, and the `bindings/ts` README and FEATURES. The npm trusted publisher for `@minip2p/web` is registered by hand; a wizard step covers it.
- **Recorded by hand:** `@minip2p/web` dials a go-libp2p WebTransport listener and pings.
- Docs: a docs-site TypeScript page for web, covering what works and the browser limits.

### PR 6 — `web: relay reservations and browser-to-browser over circuits`

Today, portable relays require `force_relay = true` (`validate_nat`, `crates/minip2p/src/portable/mod.rs:1001`). `force_relay` also disables direct racing (`crates/nat/src/attempt.rs:182`), so a browser that has relays configured could never dial a native peer's WebTransport address directly. This PR splits the two concerns.

- **`NatConfig` gets `dcutr: bool`** (default `true`), separate from `force_relay`.
  - `force_relay` keeps its meaning: no direct racing and no DCUtR.
  - `dcutr = false` keeps direct racing and the relay leg, but never starts an upgrade:
    - **outbound** (`ConnectAttempt`): no upgrade or start deadlines (`attempt.rs:1209`), and `accepts_dcutr` returns `false`;
    - **inbound** (the reservation holder, `crates/nat/src/inbound.rs:427`): it settles as `done` after `InboundPathEstablished`, as with `force_relay`, with no `start_round` and no upgrade deadline.

    Both guards check `force_relay || !dcutr`.

  - `validate_nat` for portable endpoints requires `!dcutr || force_relay` instead of `force_relay`. The error text is updated to match.
- **Circuit composition.** `crates/web` builds `CircuitTransport<WebTransportClient<JsIo>>` with `build_with_circuits` and the `portable-relay` feature. The web config accepts `relays` (→ `dcutr = false`) and `forceRelay`. `autonatServers` stays rejected.
- **Paths.** A browser connecting to a native peer races the direct WebTransport dial against the relay leg, as native does with QUIC. `path` is `directDialed` or `relayed`, and never `directPunched`.
- **Reachability.** With a reservation, a browser is dialable at its `/p2p-circuit` address.
- **Tests:**
  - `crates/nat`:
    - outbound: `dcutr = false` races direct and relay legs and never opens a DCUtR stream;
    - inbound: a reservation holder with `dcutr = false` gets an inbound relayed connection, time advances past `upgrade_timeout_ms` and `dcutr_start_timeout_ms`, and there is no DCUtR stream, no punch action and no deadline.
  - Playwright, two pages and one relay-server with `--webtransport`:
    - A reserves, then B connects via the circuit and echoes;
    - a native peer dials A through the circuit;
    - B, with relays configured, connects to a native peer that has a WebTransport address and lands on `directDialed` (the combined case);
    - the same with the native peer's direct address unreachable lands on `relayed`.

## Follow-ups (separate issues)

- A native WebTransport dialer: promote the test client's `WebTransportIo` to a real std provider and export it.
- Joining libp2p/test-plans transport-interop as a WebTransport listener, so the Chromium-rust, Chromium-js and Firefox-js dialers test us.
- RESET_STREAM_AT for full draft-13/14 (and later) compliance, once quinn-proto supports it.
- Identify Push, if long-lived native peers need certhash rotations pushed to them (Decision 5).
- A per-node period offset, to stagger certificate rotation across a fleet.
- A CA-certificate mode (no certhash) for nodes that have a domain.
- Safari in CI, once a runner with Safari 26.4+ and WebDriver is available.
- WebRTC-direct and browser-to-browser WebRTC.
- A WebSocket transport for older browsers.

## Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Browser drafts move (Chrome turns on draft-07 or later; Safari's behaviour isn't public) | Send the union SETTINGS used by webtransport-go, never advertise draft-07, accept both `:protocol` values, run Playwright on current stable, keep the research doc's draft table current |
| Making client auth optional weakens libp2p authentication | Only on h3-serving sockets. The libp2p ALPN still requires a verified certificate before `Connected`, enforced in `on_connected`, with a test |
| Unauthenticated h3 state used for DoS | Existing admission and Retry; a handshake deadline; capped HEADERS, SETTINGS, capsules and early streams |
| Server clock skew > 1 h makes browsers reject the certificate | 1 h backdate as go-libp2p does; documented; the next certificate is already advertised |
| Stream prefix bytes break ADR 0012 accounting | Prefixes are parsed before admission and queued outside `send_room`; split-prefix and backpressure tests |
| Safari sends `:protocol webtransport-h3` (unknown; see research) and gets a 400 | Safari is best-effort; the manual check in PR 3 records which token it sends. If it is `webtransport-h3`, implementing the draft-15+ requirements becomes a follow-up rather than accepting the token loosely |
| Safari session flow control blocks server-opened streams | WT credit gating plus a `WT_MAX_STREAMS` test; Safari marked best-effort |
| wasm size and startup time | Size cap in `verify-release-packages`; measure in PR 5; `wasm-opt -Oz` |
| wasm panics kill the endpoint | Mapped to `DriverFailedError`; fuzzing on every decoder; no `unwrap` on wire paths |
| Chrome Local Network Access prompts when a public page dials a private IP | Documented; CI serves from `localhost`; production nodes are dialed on public addresses |
| quinn-proto has no RESET_STREAM_AT, which drafts 13/14 already require | Draft-02 (Chrome, Firefox) does not need it. The draft-14 path is a documented compatibility subset (Decision 4) and Safari is best-effort. Follow-up: RESET_STREAM_AT once quinn supports it |

## Rollback

- PRs 1–4 are independent reverts. PR 1 and PR 2 only add types; PR 4 is a refactor.
- PR 3 is opt-in: only a `/webtransport` listen address turns it on. A revert removes the shape, and `quic-v1` sockets are unaffected because they keep the libp2p-only server config.
- PR 5 and PR 6 add a new package. Unpublishing isn't needed; a revert stops new releases.

## Resolved questions (round 1)

1. **One `TransportKind::Quic` for both shapes.** One adapter owns the socket and both protocols, so a separate kind would add routing with no present need. `is_quic_transport()` stays strict.
2. **The libp2p certificate requirement moves into `on_connected`, on h3-serving sockets only.** The conditions are in Decision 3.
3. **13-day periods** with `{k, k+1}` in addresses and `{k−1, k, k+1}` in Noise. go-libp2p's exact schedule is not needed for interop.
4. **`WebTransportIo` lives in `minip2p-webtransport`**, next to the portable client and the native test provider. Browser types, promises, timers and wasm dependencies stay in `crates/web` and TypeScript.
