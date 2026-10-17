# libp2p WebTransport server + browser client: research notes (2026-10-17)

Sources were read at these revisions (all fetched 2026-10-17): libp2p/specs `c750236d`, go-libp2p `3c2c9021`, quic-go/webtransport-go `0480526e` (2026-10-13), google/quiche `c7ee5a06` (2026-10-16), chromium/chromium `12f020e3`, mozilla/neqo `98041a45`, mozilla-firefox/firefox `d0e0fc69`, WebKit `03413005`, w3c/webtransport `151578f7`, rust-libp2p `2fed78f0`, js-libp2p `2d4c93ed`, libp2p/test-plans `f5a41770`, quinn `9d729c1b`, draft-ietf-webtrans-http3-16 (2026-07-06).

Confidence tags: **[verified]** means I read it in the source. **[inferred]** means I reasoned it from the source. **[uncertain]** means I could not confirm it.

---

## TL;DR for the minip2p server

1. **What each browser negotiates today.**
   - **Chrome** negotiates **draft-02** only. Draft-07 support exists but is behind `kEnableWebTransportDraft07`, which is `FEATURE_DISABLED_BY_DEFAULT`.
   - **Firefox (neqo)** speaks draft-02-style settings: `0x2b603742`, plus H3_DATAGRAM, ENABLE_CONNECT_PROTOCOL and the QUIC datagram transport parameter.
   - **Safari 26.4+** needs `SETTINGS_WT_MAX_SESSIONS` (`0x14e9cd29`, the draft-13/14 codepoint) set to at least 1, plus nonzero `WT_INITIAL_MAX_*` settings.

   None of the three uses draft-15/16 `webtransport-h3` / `SETTINGS_WT_ENABLED` yet, as far as the source shows.

2. **Server SETTINGS that work for all three** (this is what webtransport-go and go-libp2p send):
   - `0x08`=1
   - `0x33`=1
   - `0x2b603742`=1
   - `0x14e9cd29`=N≥1
   - `0x2b61` / `0x2b64` / `0x2b65` = large nonzero values
   - optionally `0x2c7cf000`=1 (draft-15/16)
   - QPACK settings `0x01`=0 and `0x07`=0 (these are the defaults, so they can be omitted)

   Also set the QUIC transport parameter `max_datagram_frame_size` > 0 and ALPN `h3`. Do **not** send `0xc671706a` (draft-07) unless you implement draft-07.

3. **CONNECT request.** Accept `:method CONNECT` with `:protocol` = `webtransport` (Chrome, Firefox, older drafts) **or** `webtransport-h3` (draft-15+), and `:scheme https`. Check `:path` = `/.well-known/libp2p-webtransport?type=noise`. Ignore `origin` (go-libp2p accepts every origin). Reply `:status 200`. The QPACK block for that is the 3 bytes `00 00 D9`. No extra response headers are needed.
4. **Streams.**
   - Bidi: varint `0x41` + varint session id, then payload.
   - Uni: varint `0x54` + varint session id, then payload.
   - The session id is the QUIC stream id of the CONNECT stream (always 0 mod 4).
5. **libp2p handshake.**
   - The browser opens the first bidi stream and is the Noise XX **initiator**. The server is the **responder**.
   - The server puts `NoiseExtensions.webtransport_certhashes` (multihash bytes, sha2-256) in **message 2**.
   - The client checks that all of its dialed certhashes are a subset of that list, and checks the server's peer ID against `/p2p/` in the address.
   - The prologue is empty. No `stream_muxers` extension is sent.
   - After the handshake the client closes the stream. The Noise transport keys are **not used**: every later WebTransport stream is a plain libp2p stream that runs multistream-select.
6. **Certificates.** Self-signed ECDSA P-256, validity ≤ 14 days, never RSA. Advertise the current and next cert hashes. Use go-libp2p's deterministic HKDF scheme if you want the same hashes across restarts.
7. **quinn-proto.** It has no RESET_STREAM_AT support (no match in quinn `main`). **Correction (plan review):** drafts 13 and 14 already require RESET_STREAM_AT (draft-13 §3.1/§4.3), not only draft-15+. minip2p's draft-14 path is therefore a compatibility subset; see the plan's Decision 4. Draft-15+ requires RESET_STREAM_AT, but no browser enforces it today: Firefox explicitly falls back to RESET_STREAM, and Chrome draft-02 predates it.

---

## 1. libp2p WebTransport spec

Spec: https://github.com/libp2p/specs/blob/master/webtransport/README.md. Status: Candidate Recommendation, r0, 2022-10-12. The spec has no separate security-considerations section.

- **Multiaddr** **[verified]**: a QUIC multiaddr + `/webtransport` + zero or more `/certhash/<multibase(multihash)>` components.
  - Spec examples use `/quic/`. Every current implementation requires `/quic-v1/`: go-libp2p's `IsWebtransportMultiaddr` state machine looks for `P_QUIC_V1`, and rust-libp2p's websys tests use `/quic-v1/webtransport/certhash/...`.
  - Protocol codes (https://github.com/multiformats/multiaddr/blob/master/protocols.csv): `quic-v1`=461, `webtransport`=465, `certhash`=466 (variable length).
  - Binary form: the certhash value is the raw multihash, `0x12 0x20 <32 bytes>`.
  - String form: any multibase. go-libp2p emits base58btc `z…` (`multiaddr.go` `addrComponentForCert`). rust and js tests use base64url `u…`. Parsers must accept any multibase.
- **Certhash semantics** **[verified]**:
  - Nodes with a CA-signed cert MAY use it, and SHOULD NOT advertise `/certhash`, because certhash forces hash verification.
  - Self-signed certs must have validity of at most 14 days and must not use RSA.
  - Recommended rotation: at boot, create cert A (14 days starting now) and cert B (14 days starting at A's expiry). Advertise both. When A expires, switch to B, create C, and re-advertise.
- **URL** **[verified]**:
  - Path MUST be `/.well-known/libp2p-webtransport`. The handshake MUST be signalled with `?type=noise`.
  - Example: `https://192.0.2.0:1443/.well-known/libp2p-webtransport?type=noise`.
  - go-libp2p returns 400 unless the query has exactly one `type` value equal to `noise` (`listener.go` `httpHandler`).
  - IPv6 hosts are bracketed: rust-libp2p uses `https://[::1]:port/...` (`webtransport-websys/src/endpoint.rs`).
- **Security handshake** (spec, "Security Handshake" section) **[verified]**:
  - The **first stream the client opens** runs Noise (https://github.com/libp2p/specs/tree/master/noise). The client SHOULD start Noise right after sending CONNECT, without waiting for the response.
  - The **server MUST include** in `webtransport_certhashes`:
    - the hash of the current cert;
    - the hashes of all future certs it has already advertised;
    - and SHOULD include recently expired certs.
  - **Client MUST verify** that the hash of the cert actually used is in the server's list. Browser clients cannot tell which cert was used, so they MUST verify that **all** their dial hashes are in the list. On failure, abort.
  - Completion: the client is done after sending the last Noise message (msg 3). The server is done after processing it.
- **Noise details** (https://github.com/libp2p/specs/blob/master/noise/README.md) **[verified]**:
  - Pattern and suite: `Noise_XX_25519_ChaChaPoly_SHA256`.
  - Framing: 2-byte big-endian length prefix per message.
  - Extensions go in the first message that guarantees secrecy:
    - the **responder sends its extensions in message 2**;
    - the initiator sends its extensions in message 3, and MUST NOT send any in message 1.
  - Payload schema: `NoiseHandshakePayload { identity_key=1, identity_sig=2, extensions=4 }` and `NoiseExtensions { repeated bytes webtransport_certhashes = 1; repeated string stream_muxers = 2; }`.
  - Signature: `identity_sig` signs `"noise-libp2p-static-key:" || static_pubkey`.
  - Prologue: the spec defines none, so it is empty. go-libp2p uses `noise.New(noise.ID, key, nil)` with no prologue option, and rust-libp2p's default is an empty prologue. **[verified for go and rust defaults]**
- **Who is initiator?** The client (dialer/browser) is the initiator.
  - go: `SecureOutbound(ctx, str, p)` on the dialer and `SecureInbound(ctx, str, "")` on the listener (`transport.go` `upgrade`, `listener.go` `handshake`).
  - The server sends certhashes through the early-data "sender" handler with `pb.NoiseExtensions{WebtransportCerthashes: certManager.SerializedCertHashes()}`. These are multihash-encoded bytes, ordered `[last?, current, next]`.
- **stream_muxers**: this extension is for inlined muxer negotiation over TCP-like transports. It is not used on WebTransport, because WebTransport streams are native.
  - js-libp2p passes `skipStreamMuxerNegotiation: true` (`packages/transport-webtransport/src/index.ts`).
  - go's listener sends only certhashes.
  - So the server should send no `stream_muxers`, and should ignore any the client sends. **[verified]**
- **Is the first stream closed after the handshake?** Yes, on the client side.
  - go dialer: `defer str.Close()` and `defer c.Close()`.
  - js: `await messages.close()` ("We're done with this authentication stream").
  - rust websys drops the Noise output `_io`.

  The Noise session keys are never used for traffic. After the handshake, every new WebTransport bidi stream is a libp2p stream that negotiates its protocol with multistream-select. **[verified client close; server-side close inferred]** Recommendation: the server should FIN its own side and stop reading once the handshake completes.

- **Peer ID verification**:
  - The client knows the expected peer ID from `/p2p/<id>`. Noise's `identity_key` gives the remote's public key, and the client checks that the derived PeerId matches. go passes `p` to `SecureOutbound`; rust compares the result to `remote_peer` and returns `Error::UnknownRemotePeerId` on mismatch.
  - The server learns the client's peer ID from message 3. There is no prior expectation.
  - The certhash check binds the TLS cert to the Noise-authenticated peer, which prevents a MITM using a different cert.
  - rust-libp2p requires the dialed hashes to be a subset of the received ones (`transports/noise/src/io/handshake.rs`, "Expected WebTransport certhashes must be a strict subset"). go uses the same subset check (`transport.go` `upgrade`).
- **go-libp2p server behaviour**:
  - Noise handshake timeout: 10 s.
  - Session closes with code 1 on handshake failure.
  - Session closes with `0x47415445` ("GATE") when the connection gater rejects.
  - Stream reset code is 0.

  Files: https://github.com/libp2p/go-libp2p/blob/3c2c902122cb6fae3897f729a3dbb9d4665ae90d/p2p/transport/webtransport/listener.go and `transport.go`, `stream.go`.

## 2. W3C `serverCertificateHashes`

Source: https://github.com/w3c/webtransport/blob/main/index.bs (published at https://w3c.github.io/webtransport/).

- **IDL** **[verified]**:
  - `dictionary WebTransportHash { required DOMString algorithm; required BufferSource value; }`
  - `serverCertificateHashes` is a `sequence<WebTransportHash>` in `WebTransportOptions`.
  - Only supported for dedicated connections. Using it together with `allowPooling: true` throws `NotSupportedError`.
  - Hashes with unknown algorithms are ignored.
- **Hash** **[verified]**: SHA-256 of the DER `Certificate` of the **leaf** (the first cert in the chain). The algorithm string is matched against `"sha-256"` case-insensitively. SHA-256 is the only algorithm the spec defines.
- **Custom certificate requirements** **[verified]**:
  - X.509v3.
  - The current time must be inside the validity period.
  - **Total validity period ≤ two weeks**.
  - Allowed key algorithms are implementation-defined, but **MUST include ECDSA secp256r1 (P-256)** and **MUST NOT include RSA**.
- **Chrome**:
  - Max validity is `kCustomCertificateMaxValidityDays = 14`; quiche adds 1 s of slack (`max_validity_days*86400 + 1`).
  - Allowed keys: P-256, P-384, Ed25519. RSA is rejected by Chromium's override.
  - Only `sha-256` hashes of length 32 are accepted.
  - A certificate whose validity starts in the future is rejected.

  Sources: https://github.com/chromium/chromium/blob/main/net/quic/dedicated_web_transport_http3_client.cc (lines ~52, ~118-160) and https://github.com/google/quiche/blob/main/quiche/quic/core/crypto/web_transport_fingerprint_proof_verifier.cc. **[verified]**

- **Safari (WebKit)**:
  - Computes SHA-256 of the leaf, compares it only against `"sha-256"` entries, and rejects validity ≤ 0 or > two weeks.
  - Source: https://github.com/WebKit/WebKit/blob/main/Source/WebKit/NetworkProcess/webtransport/cocoa/NetworkTransportSessionCocoa.mm (`leafCertificateMatchesWebTransportHash`).
  - The key-type policy is not visible in WebKit; it may be enforced inside Network.framework. **[uncertain]**
- **Firefox**: I did not locate its key-type policy. **[uncertain]** Use ECDSA P-256 for portability.
- **Validity timing**:
  - go-libp2p backdates `NotBefore` by 1 h for clock skew, and switches certs 1 h before expiry.
  - A cert valid for exactly 14 days passes Chrome (with its +1 s slack) and WebKit (`> twoWeeks` fails, so exactly two weeks is accepted).

## 3. HTTP/3 WebTransport: drafts, SETTINGS and wire format

### Codepoints across drafts

I extracted these from https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-NN.txt. **[verified]**

| Draft | Upgrade token | Enable / version setting | Max-sessions setting | Flow-control settings |
| --- | --- | --- | --- | --- |
| 02–03 (Oct 2021) | `webtransport` | `ENABLE_WEBTRANSPORT` 0x2b603742 | — | — |
| 04–05 | `webtransport` | 0x2b603742 | `WEBTRANSPORT_MAX_SESSIONS` 0x2b603743 | — |
| 06 | `webtransport` | 0x2b603742 | 0x3c48d522 | — |
| 07–11 (07: Jun 2023) | `webtransport` | (removed) | 0xc671706a | — |
| 12 | `webtransport` | — | 0xc671706a | 0x2b61 / 0x2b64 / 0x2b65 |
| 13 (Jul 2025), 14 (Oct 2025) | `webtransport` | — | `WT_MAX_SESSIONS` **0x14e9cd29** | `SETTINGS_WT_INITIAL_MAX_DATA` 0x2b61, `_STREAMS_UNI` 0x2b64, `_STREAMS_BIDI` 0x2b65 |
| 15 (Mar 2026), 16 (Jul 2026, current) | **`webtransport-h3`** | **`SETTINGS_WT_ENABLED` 0x2c7cf000** (draft-specific; value must be 1, a value above 1 is an error) | removed | 0x2b61 / 0x2b64 / 0x2b65 |

Draft-02 through 05 also define the request header `Sec-Webtransport-Http3-Draft02: 1` and the response header `sec-webtransport-http3-draft: draft02` (`h3-02.txt` around line 541).

### Draft-16 requirements

Source: https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-16.html §3.1. **[verified]**

- **The server sends:**
  - `SETTINGS_WT_ENABLED`=1
  - `SETTINGS_ENABLE_CONNECT_PROTOCOL` (0x08)=1
  - `SETTINGS_H3_DATAGRAM` (0x33)=1
  - transport parameter `max_datagram_frame_size` > 0
  - an empty `reset_stream_at` transport parameter
- **The client sends:** H3_DATAGRAM, `max_datagram_frame_size`, `reset_stream_at`, and (for drafts) `WT_ENABLED`.
- **Version negotiation (§7.1):** each draft has its own `WT_ENABLED` codepoint, and the highest common version wins. While the protocol is still a draft, the server MUST NOT process WT requests until it has the client's SETTINGS. The client MUST wait for the server's SETTINGS before sending CONNECT.
- **CONNECT (§3.2):**
  - `:protocol` is `webtransport-h3`, `:scheme` is `https`, and both `:authority` and `:path` must be set.
  - Browsers MUST send `Origin`. The server MUST verify Origin, and SHOULD answer 403 when verification fails.
  - 2xx accepts the session. 405 means the resource does not support WebTransport. Clients must not follow 3xx.
  - The `capsule-protocol` header is not needed.
  - Bytes that arrive on the CONNECT stream before the 2xx must not be parsed as capsules.
- **Session ID:** the stream ID of the CONNECT stream.
- **Streams (§4.2, §4.3):**
  - Uni: `0x54`, Session ID (varint), data.
  - Bidi: `0x41` (`WT_STREAM`), Session ID, data.
  - `0x41` is only valid as the very first bytes of a request stream; anywhere else it is `H3_FRAME_ERROR`.
  - Server-initiated bidi streams are allowed once the server has received the CONNECT.
- **Buffering (§4.6):** streams or datagrams can arrive before the session exists. Buffer them, with a limit. When over the limit, reset or stop-sending with `WT_BUFFERED_STREAM_REJECTED` 0x3994bd84.
- **Error mapping (§4.4):**
  - App codes are u32 in draft ≥ 07. In draft-02 they are **u8**, mapped to 0x52e4a40fa8db..0x52e4a40fa9e2.
  - Mapping: `h = 0x52e4a40fa8db + n + n/0x1e`.
  - Reverse: reject values outside `[0x52e4a40fa8db, 0x52e5ac983162]` and values where `(h-0x21) % 0x1f == 0` (reserved GREASE points). Otherwise `shifted = h - first; n = shifted - shifted/0x1f`.
  - A code outside the range means "reset with no app code". Chrome treats it as 0 (`Http3ErrorToWebTransportOrDefault`).
  - Draft-16 says to reset with RESET_STREAM_AT, with reliable size at least the WT header length.
- **Other codes:**
  - `WT_SESSION_GONE` 0x170d7b68: reset all of a session's streams with this code when the session ends.
  - `WT_FLOW_CONTROL_ERROR` 0x045d4487.
  - `WT_ALPN_ERROR` 0x0817b3dd.
  - `WT_REQUIREMENTS_NOT_MET` 0x212c0d48.
- **Close (§6):**
  - Capsule `WT_CLOSE_SESSION` (formerly `CLOSE_WEBTRANSPORT_SESSION`) has type **0x2843** and body `{u32 code, UTF-8 message ≤ 1024 bytes}`.
  - The sender MUST FIN the CONNECT stream immediately after the capsule.
  - Closing the CONNECT stream cleanly without the capsule is the same as code 0 with an empty message.
  - Before sending CONNECTION_CLOSE, wait for the peer to close its CONNECT streams.
  - 0x2843 and these semantics are already in draft-02 (`h3-02.txt` around lines 471-520).
- **Drain:**
  - `WT_DRAIN_SESSION` 0x78ae, zero length (§4.7). It is advisory, and GOAWAY has the same meaning. It is not in draft-02.
  - Chrome does not expose `draining` (MDN BCD: `chrome=false`).
- **Flow control (§5.1):** it is enabled only if **both** sides send a nonzero `WT_INITIAL_MAX_*`. Without it the client must not open more than one session per connection. Capsules:
  - `WT_MAX_DATA` 0x190b4d3d
  - `WT_MAX_STREAMS` 0x190b4d3f (bidi) / 0x190b4d40 (uni)
  - `WT_DATA_BLOCKED` 0x190b4d41
  - `WT_STREAMS_BLOCKED` 0x190b4d43 / 0x190b4d44

  Source: draft-16 §9.6 and https://github.com/quic-go/webtransport-go/blob/master/capsule.go.

- **Datagrams:** libp2p does not need them, but **the setting and the transport parameter are required by browsers** (see below). An HTTP datagram is `QuarterStreamID(varint) + payload` (§4.5). It is fine to never send datagrams and to drop any you receive.

### What browsers actually do

**Chrome** (quiche + `//net`) **[verified]**:

- Supported versions are `kDraft02` and `kDraft07`. Chrome's `LocallySupportedWebTransportVersions()` returns `{kDraft02}`, and adds `kDraft07` only if `features::kEnableWebTransportDraft07` is enabled. That feature is `BASE_FEATURE(kEnableWebTransportDraft07, base::FEATURE_DISABLED_BY_DEFAULT)` in https://github.com/chromium/chromium/blob/main/net/base/features.cc. **[uncertain]** whether a Finch field trial enables it for some users.
- The version is the highest common one, from the bitmask `(local & peer).Max()` (`quic_spdy_session.h`).
  - The peer is marked draft-02 when it sends `0x2b603742`=1. On the client, that alone also sets `allow_extended_connect_`.
  - The peer is marked draft-07 when it sends `0xc671706a` > 0.
- Chrome sends `SETTINGS_H3_DATAGRAM` 0x33 **and** 0xffd277 (draft-04), plus `0x2b603742`=1, and `0xc671706a` only if draft-07 is enabled. It also sends QPACK settings of 64 KB and 100 blocked streams.
- `SupportsWebTransport()` = H3 datagram negotiated **AND** a WT version negotiated **AND** extended CONNECT allowed. So **Chrome requires the server to send H3_DATAGRAM** (0x33 or 0xffd277).
- If draft-07 is negotiated, Chrome additionally requires `0x08`=1 and RFC (0x33) datagrams (`ValidateWebTransportSettingsConsistency`). I found no check in quiche's HTTP layer for the `max_datagram_frame_size` transport parameter.
- Chrome waits for the server's SETTINGS before sending CONNECT (`OnSettingsReceived` → `DoLoop`).
- CONNECT headers (`DoSendRequest`):
  ```
  :scheme https
  :method CONNECT
  :authority <host:port>
  :path <path?query>
  :protocol webtransport
  sec-webtransport-http3-draft02 1
  origin <serialized page origin>
  ```
  Chrome also sends `wt-available-protocols` (the subprotocol request header) if `protocols` was given.
- Response: any status in 200..299 is accepted. Nothing else is required. Chrome strips `sec-webtransport-http3-draft` if present, and reads the subprotocol header if present (`web_transport_http3.cc` `HeadersReceived`).
- **Error codes:** Blink truncates outgoing app error codes to **u8**: `uint8_t code = exception->streamErrorCode().value_or(0)` in both `outgoing_stream.cc` (abort) and `incoming_stream.cc` (cancel). Incoming codes are delivered as u32. quiche maps with the u32 range.
- QUIC version: RFC v1. ALPN: `h3`.

**Firefox** (neqo + Gecko) **[verified]** (https://github.com/mozilla/neqo `neqo-http3/src/settings.rs`, `features/extended_connect/mod.rs`):

- Settings known: `SETTINGS_ENABLE_WEB_TRANSPORT = 0x2b603742`, `0x33` and `0xffd277` (both sent), and `0x08`.
- neqo knows none of `0xc671706a`, `0x14e9cd29` or `0x2c7cf000`.
- The client enables WebTransport only if **all** of these hold:
  - the peer's `max_datagram_frame_size` > 0;
  - the server sent H3_DATAGRAM=1;
  - the server sent `ENABLE_CONNECT_PROTOCOL`=1;
  - the server sent `ENABLE_WEBTRANSPORT`=1.

  So **Firefox requires H3_DATAGRAM and the QUIC datagram transport parameter**.

- `reset_stream_at` is explicitly _not_ required: "too few servers support it yet… falls back to RESET_STREAM" (neqo #3917).
- `:protocol` is `webtransport`. The neqo server only accepts `webtransport` (`server_connection_events.rs`).
- Stream error codes **[verified, partly]**: Gecko's reset path uses `uint8_t errorCode`, and STOP_SENDING passes u32 (`netwerk/protocol/http/Http3WebTransportStream.cpp`).
- `serverCertificateHashes` has been supported since Firefox 125 (MDN BCD).

**Safari** (Network.framework) **[verified BCD; draft inferred]**:

- WebTransport ships in **Safari 26.4** (macOS and iOS 26.4), including `serverCertificateHashes` (MDN BCD 26.4). Announcement: https://webkit.org/blog/17862/webkit-features-for-safari-26-4/. It also supports HTTP/2 fallback.
- The draft version is not public. Evidence:
  - webtransport-go PR #261 (merged 2026-06-14): "Safari 26.4 requires SETTINGS_WT_MAX_SESSIONS to be present and >= 1". webtransport-go's code comment cites draft-14 and `0x14e9cd29`.
  - webtransport-go issue #355 (open): if `WT_MAX_SESSIONS` is sent without any of the three `WT_INITIAL_MAX_*` settings, Safari refuses before sending CONNECT. On iOS the error is an empty `WebTransportError` after about 50 ms.
  - go-libp2p `listener.go`: without the flow-control settings, "Safari 26 reports the session as ready but never opens a stream on it". go-libp2p therefore sets `MaxIncomingStreams`, `MaxIncomingUniStreams` and `MaxIncomingData` to `1<<60`.
- WebKit itself sets `initial_max_streams_uni/bidi` and adds `origin` and `wt-available-protocols` to the CONNECT.
- So Safari likely sends `WT_INITIAL_MAX_*`, which means **WT flow control becomes enabled** when the server also sends them. Two consequences:
  - The server must respect Safari's stream and data limits for server-opened streams.
  - The server must not let Safari exceed the server's own limits. Huge initial values (as go uses) avoid ever needing `WT_MAX_*` capsules. **[inferred]**
- Whether Safari sends `:protocol webtransport` or `webtransport-h3` is **[uncertain]**. webtransport-go's server accepts both, and so should ours.

**Recommended minimal SETTINGS frame** (server control stream, uni stream type 0x00):

- `0x01`=0
- `0x07`=0
- `0x08`=1
- `0x33`=1
- `0x2b603742`=1
- `0x14e9cd29`=1 (or larger)
- `0x2b61`=large
- `0x2b64`=large
- `0x2b65`=large
- optionally `0x2c7cf000`=1

Optionally add `0x06` (MAX_FIELD_SECTION_SIZE). This mirrors `ConfigureHTTP3Server` in webtransport-go plus go-libp2p's config (https://github.com/quic-go/webtransport-go/blob/master/server.go lines 38-48, `config.go`). Skip `0xffd277`: every browser sends and accepts 0x33. Behaviour: wait for the client's SETTINGS before answering CONNECT (go does this and rejects the session if the client did not advertise H3 datagrams), then reply 200.

**QUIC transport side:**

- ALPN `h3`.
- `max_datagram_frame_size` > 0. In quinn this is `TransportConfig::datagram_receive_buffer_size(Some(n))` (`quinn-proto/src/config/transport.rs`).
- Allow at least 3 peer uni streams (RFC 9114 §6.2: "MUST allow the peer to create at least three unidirectional streams", plus at least 1024 bytes of credit), and add headroom for WT uni streams.
- quinn-proto has no RESET_STREAM_AT (no match in quinn `main`, 0.12.0-dev; the latest crates.io release is 0.11.19).

## 4. QPACK with `QPACK_MAX_TABLE_CAPACITY=0` and `BLOCKED_STREAMS=0`

Sources: RFC 9204 (https://www.rfc-editor.org/rfc/rfc9204) and RFC 9114. **[verified]**

- **Encoder and decoder streams are optional for us.**
  - RFC 9204 §4.2: "An endpoint MAY avoid creating an encoder stream if it will not be used (for example, if its encoder does not wish to use the dynamic table…)" and "MAY avoid creating a decoder stream if its decoder sets the maximum capacity of the dynamic table to zero."
  - So with table capacity 0, and a server encoder that never uses the client's dynamic table, the server only needs its **control stream**.
  - But the server "MUST allow its peer to create an encoder stream and a decoder stream even if the connection's settings prevent their use". Chrome will open both. Accept them, read them, and treat any instructions as errors; closing either one is `H3_CLOSED_CRITICAL_STREAM`.
- **Huffman:** yes, the client can still Huffman-encode string literals. The H bit is per string literal (§4.1.2), and table capacity has no effect on it. **The server's decoder must implement Huffman decoding** (RFC 7541 Appendix B table). Chrome's request will typically Huffman-encode `:authority`, `:path` and `origin`.
- **Static-only, non-Huffman encoding is valid:**
  - Field section prefix: Required Insert Count = 0 (`0x00`) and Base = 0 (`0x00`).
  - `:status 200` is static index 25, so the Indexed Field Line with T=1 is `0xC0|25` = **`0xD9`**.
  - Full HEADERS frame: `01 03 00 00 D9`.
  - Other fields: Literal with Name Reference (`01NT` + static index, §4.5.4), H=0, raw bytes. An encoder may always choose H=0.
- **Request decoding needs:**
  - indexed static lines, e.g. `:method CONNECT` = static 15 and `:scheme https` = 23;
  - literal-with-static-name-ref, e.g. `:authority` = 0 and `:path` = 1;
  - literal-with-literal-name, e.g. `:protocol` and `sec-webtransport-http3-draft02`.

  If Required Insert Count ≠ 0, reject. The client cannot legally use the dynamic table when capacity is 0.

## 5. Implementations and interop

- **go-libp2p** (the only production libp2p WebTransport _server_) cert rotation, from `cert_manager.go` and `crypto.go` **[verified]**:
  - `certValidity = 14 days`, `clockSkewAllowance = 1h`.
  - Certs are **deterministic**:
    - HKDF-SHA256 with IKM = the host private key's raw bytes, salt = `NotBefore` as unix nanoseconds (u64 little-endian), info = `"determinisitic cert"` (sic).
    - From that stream: an 8-byte serial (positive, min 1), then a 24-byte seed → ECDSA P-256 key via `filippo.io/keygen`, then a deterministic ECDSA signature.
    - The template: `IsCA`, `KeyUsage` DigitalSignature|CertSign, `ExtKeyUsage` server+client auth, empty Subject.
  - Start times are bucketed from the unix epoch with period `14d − 2h`. Each node gets an offset of `(LE u16 of pubkey bytes) minutes mod 14d`, so certs survive restarts and network-wide rotation is staggered.
  - At init, `next = bucketStart(now − 1h)`; then `rollConfig` makes `current = next` and `next = [current.End − 2h, +14d]`.
  - Rotation fires at `current.End − 1h`.
  - **Advertised in the multiaddr:** 2 hashes, current and next.
  - **Sent in Noise:** up to 3 hashes, last (expired), current and next.
- **rust-libp2p**:
  - Only a **browser client**: `transports/webtransport-websys`. There is no native WebTransport server in `transports/`.
  - Builds the URL `https://host:port/.well-known/libp2p-webtransport?type=noise`.
  - Passes `serverCertificateHashes` built from the multiaddr.
  - Awaits `session.ready()`, then `createBidirectionalStream()`, then runs Noise as initiator with `with_webtransport_certhashes`, then checks the peer ID.
- **js-libp2p** `@libp2p/webtransport`:
  - Dial only; the README says "does not yet allow listening".
  - Uses `new WebTransport(url + '/.well-known/libp2p-webtransport?type=noise', { serverCertificateHashes: [{algorithm:'sha-256', value: digest}] })`.
  - Runs Noise with `skipStreamMuxerNegotiation: true`, closes the auth stream, then does the subset check.
- **Interop** (https://github.com/libp2p/test-plans/tree/master/transport-interop, `versionsInput.json`) **[verified]**:
  - WebTransport **listeners**: only `go-v0.46`, `go-v0.47` and `go-v0.48`.
  - WebTransport dial-only (`onlyDial: true`): `chromium-rust-v0.53/0.54`, `chromium-js-v1.x/2.x`, `firefox-js-v1.x/2.x`.
  - For webtransport the harness fixes security and muxer (`webtransport` is in the "standalone transports" list in `src/generator.ts`).
  - **How a new implementation joins:**
    1. Add `transport-interop/impl/<name>/<version>/`, with a Makefile that builds a Docker image and writes `image.json`.
    2. Add an entry to `versionsInput.json` with `id`, `transports` (e.g. `"webtransport"`), `secureChannels` and `muxers`.
    3. The binary reads the env vars `transport`, `muxer`, `security`, `is_dialer`, `ip` and `redis_addr`.
    4. As listener: `RPUSH listenerAddr <multiaddr with certhash and /p2p>`, then sleep until killed.
    5. As dialer: `BLPOP listenerAddr`, connect, ping, then print `{"handshakePlusOneRTTMillis":…, "pingRTTMilllis":…}` (sic) to stdout.

    Then open a PR to libp2p/test-plans. Being a listener lets the existing Chromium and Firefox dialers test our server.

## 6. Browser API notes for the wasm client

**W3C interface members** (w3c `index.bs`; MDN BCD https://github.com/mdn/browser-compat-data/blob/main/api/WebTransport.json) **[verified]**:

- Constructor: `new WebTransport(url, { serverCertificateHashes: [{ algorithm: 'sha-256', value: <BufferSource 32 bytes> }] })`.
  - The URL must be `https` with no fragment, otherwise `SyntaxError`.
  - The interface is `SecureContext` only.
  - Chrome also applies CSP `connect-src` (`blink web_transport.cc`).
- `ready: Promise<undefined>` and `closed: Promise<WebTransportCloseInfo{closeCode: u32, reason}>`.
  - `closed` rejects on network error.
  - Detach a handler on `closed`. rust-libp2p does this to avoid "Uncaught in promise" when `close()` is called.
- `close({closeCode, reason})` sends `CLOSE_WEBTRANSPORT_SESSION`.
- `createBidirectionalStream(): Promise<WebTransportBidirectionalStream {readable, writable}>`. The stream is invisible to the server until data is sent on it.
- `incomingBidirectionalStreams: ReadableStream<WebTransportBidirectionalStream>`.
- Backpressure is the standard WHATWG Streams mechanism:
  - `writer.desiredSize` and `await writer.ready`;
  - the spec says the UA buffer "SHOULD have a fixed upper limit, to carry the backpressure information";
  - `writer.close()` sends FIN.
- **Reset and stop-sending:**
  - `writable.abort(new WebTransportError({streamErrorCode: n}))` or `writer.abort(...)` sends RESET_STREAM (spec: RESET_STREAM_AT).
  - `readable.cancel(err)` or `reader.cancel(err)` sends STOP_SENDING.
  - When the peer resets or sends STOP_SENDING, the readable or writable errors with a `WebTransportError` whose `source` is `"stream"` and `streamErrorCode` is a `u32 | null`.
- **Error-code range:** the IDL type is `unsigned long`, but **Chrome truncates outgoing codes to 8 bits** (Blink `uint8_t`), and Firefox's reset path is also `uint8_t`. Keep codes in **0..255** for portability. libp2p uses 0 for reset.
- `congestionControl`: Chrome = not supported (BCD `false`; gated behind `RuntimeEnabledFeatures::WebTransportCongestionControlEnabled`). Firefox 114+ and Safari 26.4+ support it. It is a hint only.
- `allowPooling`: Chrome = not supported (BCD `false`). It must stay `false` when `serverCertificateHashes` is used (spec throws `NotSupportedError`).
- `protocols` / `protocol`: Chrome 143+, Firefox 155+, Safari 26.4+.

**Browser support:** Chrome 97+ (hashes since 100), Firefox 114+ (hashes since 125), Safari 26.4+ (hashes since 26.4). Firefox's `createUnidirectionalStream` returns a plain `WritableStream`.

**IP-literal targets and mixed content:**

- WebTransport is https-only, so mixed content does not apply.
- An IP-literal URL plus `serverCertificateHashes` is the normal libp2p case: hash verification replaces name validation.
- An `http:` page cannot use WebTransport at all (SecureContext), except on localhost, which counts as a secure context.

**Chrome Local Network Access:**

- Shipped for WebTransport in **Chrome 147**: "Restricts the ability to make requests to the user's local network using WebTransport, which is gated behind a permission prompt."
- Scope: requests from a public site to a private/local IP or loopback, and from a local site to loopback. Secure contexts only.
- Source: https://developer.chrome.com/release-notes/147 and MDN BCD `WebTransport.local_network_access` (chrome=147).
- In code: `features::kLocalNetworkAccessChecksWebTransport` is `FEATURE_ENABLED_BY_DEFAULT` (https://github.com/chromium/chromium/blob/main/services/network/public/cpp/features.cc), and the check is applied in `services/network/web_transport.cc` `OnLocalNetworkAccessCheck`.
- Address-space definitions (https://developer.chrome.com/blog/local-network-access):
  - **local**: RFC1918, 169.254/16, fc00::/7, fe80::/10;
  - **loopback**: 127/8 and ::1.
- Enterprise policies: `LocalNetworkAccessAllowedForUrls`, `…BlockedForUrls`, `…RestrictionsTemporaryOptOut`.
- Consequence for us:
  - A public https demo page dialing a LAN or `127.0.0.1` minip2p node will trigger a permission prompt in Chrome 147+.
  - A page served from localhost that dials 127.0.0.1 is loopback to loopback, so there is no prompt. **[inferred from the definition]**
  - Firefox and Safari have no LNA for WebTransport (BCD `false`).

## Open items / uncertain

- Which draft Safari's Network.framework implements, and whether it sends `webtransport` or `webtransport-h3`. The evidence points to draft-13/14 settings.
- Whether a Chrome Finch trial enables `kEnableWebTransportDraft07` for some users. If so, Chrome would only pick draft-07 when the server sends `0xc671706a`, so not sending it keeps Chrome on draft-02.
- The certificate key-type policies of Firefox and Safari. P-256 is the only safe choice.
- The libp2p spec does not say whether the server must close the Noise stream. Implementations close it from the client side.
