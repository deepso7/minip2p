# Replacing quiche with quinn-proto (+ quinn-udp)

Research into swapping the QUIC engine under `minip2p-quic` from Cloudflare's quiche (BoringSSL) to quinn-proto (rustls), with quinn-udp for socket I/O, without introducing async. Pinned to:

- quinn-proto `0.11.19`, quinn-udp `0.6.3`, rustls `0.23.45` with the `ring` provider (ring `0.17.14`);
- quiche `0.29.3` + boring `4.22.0` (the workspace's patched fork);
- minip2p at `1f53757b9`;
- rust-libp2p `0.57.0` for interop.

Everything below was measured or exercised with the spike in [`quinn-proto-spike/`](quinn-proto-spike/): a caller-driven quinn-proto peer (`src/peer.rs`), libp2p TLS on rustls (`src/tls.rs`), throughput harnesses, interop peers and semantics tests. The spike is standalone, not a workspace member.

## Decision

**Viable, and recommended.** quinn-proto fits minip2p's architecture better than quiche. It is a state machine driven by poll/handle calls, owns no I/O, and runs every connection timer on the monotonic time its caller passes in. Its one other clock is a system-time source for Retry token issue and expiry, which can be replaced. Switching removes the C/CMake BoringSSL build and the workspace's patched `boring` fork, and quinn-proto interoperates with rust-libp2p and with today's quiche-based minip2p.

On performance the case is modest. With matched MTU, the engine is ~4% faster on std UDP and ~17% faster with GSO/GRO. The large throughput win comes from quinn-udp's GSO/GRO, which quiche could also use. The cost is a rewrite of the adapter core (~3.5k lines) and its quiche-coupled tests, plus a change to how the Connection token is derived. That change is visible between minip2p versions.

No async is involved anywhere. quinn-proto has no runtime dependency. quinn-udp's `UdpSocketState::{try_send, recv}` are synchronous calls on a non-blocking std socket. The async layer is the separate `quinn` crate, which is not used.

## Measurements

All on one Linux host (8 vCPU), loopback, one 256 MiB one-way stream, client and server each on their own thread. Each row is the range of 2–3 runs of `cargo build --release` binaries from the spike (`quinn_tput`, `raw_quiche_tput`, `quiche_tput`; resolved versions as pinned above). These are **exploratory** numbers from a single host, not a benchmark suite.

### Throughput, same harness

The engine comparison uses matched conditions: both drivers keep polling without waiting while their receive batch hit its cap (mio is edge-triggered), and quinn runs with a fixed 1350-byte payload and no PMTU discovery (`QMTU=1350`), which matches the quiche configuration.

| Stack | MB/s | Rust allocs/MB |
| --- | --: | --: |
| raw quiche, std UDP (no minip2p adapter) | 173–177 | — |
| quinn-proto, std UDP, MTU 1350 | 181–184 | — |
| raw quiche + quinn-udp GSO/GRO | 617–629 | — |
| quinn-proto + quinn-udp, MTU 1350 | 710–756 | — |
| _Other configurations_ |  |  |
| minip2p `QuicTransport` (quiche adapter today) | 146–173 | ~7,000 |
| quinn-proto, std UDP, PMTU discovery (1452 on loopback) | 195–198 | ~2,500 |
| quinn-proto + quinn-udp, PMTU discovery | 746–806 | ~330 |
| quinn-proto + quinn-udp, ms-quantized clock | 372–384 | — |

The quinn spike delivers stream data zero-copy and has no adapter queue, so its allocation numbers are lower bounds. The production adapter copies reads to keep ADR 0012's memory bound (see the plan).

For reference, the `endpoint_throughput` bench on `main` (through the full `Endpoint`, swarm included): TCP 431.6 MB/s, QUIC 175.8 MB/s, relayed 113.6 MB/s, QUIC 9,647 allocs/MB.

Reading the table:

- **The engine is only slightly faster.** With matched MTU, quinn-proto is ~4% faster than quiche on std UDP. Most of the 12–25% gap seen in the first runs came from quinn's PMTU discovery (1452 against 1350) and from the quiche driver sleeping with input still queued.
- **GSO/GRO is the big lever, for either engine.** quinn-udp roughly quadruples throughput. With quiche the adapter has to coalesce same-size packets into GSO trains itself (about 40 lines in `raw_quiche_tput.rs`). quinn-proto emits GSO batches from `poll_transmit(now, max_datagrams, ..)` natively and comes out ~17% ahead at matched MTU.
- **Allocations.** The quiche figure counts only Rust allocations; BoringSSL's go through its own allocator and aren't seen. quinn-proto allocates about once per received datagram (`BytesMut` per receive), and once per GRO batch with quinn-udp.
- **The clock has to stay fine-grained.** quinn-proto with the host's millisecond `Now` (`base + whole ms`) works, but it halves GSO throughput on loopback, because RTT and pacing round to zero. The adapter should keep today's posture: sample `Instant::now()` once per `poll` for the engine, and report deadlines on the host's timeline.

### Build and portability

|  | quiche + boring | quinn-proto + rustls/ring + quinn-udp |
| --- | --- | --- |
| Cold release build of a minimal binary | 37.6 s wall, 127 s CPU | 15.7 s wall, 54 s CPU |
| Stripped minimal binary | 2.53 MB | 2.14 MB |
| Native toolchain needed | CMake + C/C++ compiler (BoringSSL) | C compiler only (ring) |
| `x86_64-unknown-linux-musl` (zig cc) | builds | builds |
| `aarch64-unknown-linux-gnu` (zig cc) | builds | builds |
| `x86_64-pc-windows-gnu` (zig cc) | **fails** (boring-sys CMake) | builds |
| Android allocator issue | workspace patches `boring`/`boring-sys` to a fork (cloudflare/boring#518) | not applicable |

CI builds Windows with MSVC, where boring does work. The row shows that BoringSSL is the component that ties builds to a specific native toolchain.

MSRVs: quinn-proto 1.85, quinn-udp 1.88, rustls 1.71, all below the workspace's 1.91.

### Interop

Every handshake verified the remote `PeerId` from its libp2p certificate.

| Dialer → Listener                                | Result               |
| ------------------------------------------------ | -------------------- |
| quinn spike → rust-libp2p 0.57                   | connected both sides |
| rust-libp2p 0.57 → quinn spike (Retry on)        | connected both sides |
| quinn spike → minip2p `QuicTransport` (quiche)   | connected both sides |
| minip2p `QuicTransport` → quinn spike (Retry on) | connected both sides |
| rust-libp2p → minip2p `QuicTransport` (control)  | connected            |

A mixed fleet (for example, relays still on quiche) therefore keeps working.

### Semantics the adapter relies on (`tests/semantics.rs`, all passing)

- **Read gate (ADR 0012).** An unread stream stops its writer at exactly the 1 MB stream window. Reading half the window returns only that much credit. The tail stays buffered and is readable with no new packet or event.
- **STOP_SENDING** surfaces as `StreamEvent::Stopped { id, error_code }`. Later writes fail with `WriteError::Stopped(code)`, and the read half stays usable.
- **Peer reset** surfaces on read as `ReadError::Reset(code)`.
- **Dead peers still time out with keepalive on.** With a 30 s idle timeout and a 15 s keepalive, a dead peer closes after ~43 s (`TimedOut`). A keepalive restarts the idle timer once per receive (RFC 9000 §10.1), which matches today's quiche behaviour.
- **Connection token.** A TLS exporter value is identical on both ends.

## API fit

| Adapter concern | quiche today | quinn-proto |
| --- | --- | --- |
| Time | reads `Instant::now()` internally | connection timers use the caller-supplied `now: Instant`; Retry tokens use `ServerConfig::time_source`, which defaults to system time and can be replaced |
| Datagram routing | adapter parses headers and keeps CID and reset-token tables (`recv_batch`, `cid_to_connection`, `reset_token_to_connection`) | `Endpoint::handle` routes by CID and detects stateless resets |
| Address validation | hand-rolled HMAC Retry tokens (~150 lines and tests) | `Endpoint::retry` / `Incoming::remote_address_validated()`, with address-bound AEAD tokens and a configurable lifetime |
| Connection admission | drop the Initial when full | `Endpoint::ignore` / `refuse` |
| Pacing | adapter holds a paced packet until `SendInfo::at` | internal pacer: `poll_transmit` returns `None`, and `poll_timeout` includes the pacing time |
| Keepalive | adapter sends a ping at idle/2, one per receive | `TransportConfig::keep_alive_interval` |
| Stream events | scan `readable()`/`writable()` and probe `stream_capacity` for STOP_SENDING | `Event::Stream(Opened, Readable, Writable, Stopped, Finished, Available)` |
| Stream data | copy into a scratch buffer, then `to_vec()` into `Bytes` | `Chunks::next` yields `Bytes`, zero-copy |
| Writes | `stream_send(&[u8])`, bounded by peer credit | `write_chunks(&mut [Bytes])`, bounded by peer credit and `send_window` |
| Flow control | autotunes; the adapter pins windows | fixed windows (`stream_receive_window`, `receive_window`); credit returns on read, as in quiche |
| Multiple sockets | one quiche config per socket; dual-stack is two transports | one `Endpoint` can serve both sockets (`handle(remote, local_ip, ..)`; the transmit's destination selects the socket) |
| Peer certificate | `peer_cert_chain()` | `crypto_session().peer_identity()` downcast to `Vec<CertificateDer>` |
| CIDs | `source_id()` / `destination_id()` | **not exposed** |
| GSO | none (coalesce manually) | `poll_transmit(.., max_datagrams, ..)` returns a GSO train with `segment_size` |

libp2p TLS on rustls takes about 120 lines (`src/tls.rs`). Custom `ServerCertVerifier` and `ClientCertVerifier` implementations require exactly one certificate and run `minip2p_tls::verify_libp2p_certificate`. They check the TLS 1.3 CertificateVerify against the certificate's SubjectPublicKeyInfo with `rustls::crypto::verify_tls13_signature_with_raw_key`, so webpki never parses libp2p's critical extension. The configs are TLS 1.3 only, with ALPN `libp2p`. The certificate and key from `minip2p_tls::generate_certificate` (ECDSA P-256) load unchanged.

## Pros

1. **Sans-I/O fit.** quinn-proto is the same kind of component as minip2p's own crates. It owns no sockets and runs connection timers on caller-supplied time; Retry token time is a pluggable `TimeSource`. The quiche README section that justifies the "dual clock" shrinks to "the adapter samples one `Instant` per poll", and deterministic tests become possible by injecting `Instant`s and a `TimeSource`.
2. **No BoringSSL.** This removes the CMake/C++ build, the patched `boring` fork (an Android allocator fix pending upstream) and the `boring` 4.x/5.x version pinning. Builds are about 2.4× faster, binaries slightly smaller, and the binding matrix (Node, musl, Windows, Android, iOS) becomes simpler.
3. **Less adapter code.** Retry tokens, CID and reset-token routing, header parsing, the paced-packet hold, custom keepalives, the STOP_SENDING probing and the BoringSSL config go away, along with their tests (`pacing_tests.rs`, most of `recv_batch_tests.rs` and `cid_routing.rs`). Stream handling becomes event-driven instead of scan-driven.
4. **Performance, modestly.** The engine is ~4% (std UDP) to ~17% (GSO) faster at matched MTU. PMTU discovery adds more on paths that allow it. With quinn-udp, single-stream throughput reaches ~710–800 MB/s against today's ~170 MB/s; quiche + quinn-udp would reach ~620 MB/s. This serves #243.
5. **Ecosystem.** rust-libp2p's QUIC transport and iroh both run on quinn-proto, so libp2p-shaped use is well trodden and interop is verified.
6. **Pure-Rust TLS.** All TLS and crypto become visible to Rust tooling (allocation counting, fuzzing, sanitizers).
7. **Helps open issues.** It makes #315 moot (no quiche `Header` to allocate), does #243's socket-I/O items (GSO/GRO, batching, PMTU discovery, buffer sizes via quinn-udp), makes #247 natural (one `Endpoint`, one or two sockets), and makes #328 easier (connections only get work when an event or timeout reaches them).

## Cons and risks

1. **Rewrite cost.** The adapter core (`lib.rs` + `connection.rs`, ~3.5k lines) is rewritten. About 3.5k lines of tests reference quiche in places: `two_peer.rs` and `cid_routing.rs` build raw quiche peers, and `stream_send_tests.rs` and `transport_contract.rs` mention quiche capacity behaviour. The public API (`QuicEndpoint`, `QuicNodeConfig`, `QuicLimits`, `STREAM_RECEIVE_WINDOW`) can stay.
2. **The Connection token changes.** quinn-proto doesn't expose connection IDs, so the token moves to a TLS exporter (`export_keying_material`, a minip2p label). That is cryptographically bound and matches how TCP derives it from the Noise hash. But a quinn-based peer and a quiche-based peer compute different tokens for the same connection. The effect is limited to a **same-direction connection race between mixed versions**. The two sides may keep opposite connections and close both. Nothing restarts a settled direct dial (`crates/minip2p/src/connect.rs`), so recovery needs the application or discovery to redial, and a repeat race can fail the same way. A coordinated upgrade avoids it. Keeping the CID scheme is possible by sniffing long headers during the handshake, but it is fragile and not recommended pre-1.0.
3. **Edge-triggered stream events.** quinn emits `Readable` when data arrives, not as a level, and a new remote stream's first frame raises only `Opened`, not `Readable`. The adapter must therefore scan every newly accepted stream, and must remember gated streams (receive budget spent) so it can re-read them on `ack_stream` without an event. 3a. **Semantics quinn leaves to the application.** On STOP_SENDING quinn only records the code and raises an event, so the adapter must `reset` the send half itself, as quiche did internally. quinn's default `TransportConfig` advertises DATAGRAM support, which has to be turned off. Data returned by `Chunks::next` may be a slice of a larger packet allocation, so passing it on zero-copy can pin more memory than ADR 0012's receive budget accounts for.
4. **Stream-count credit.** quinn-proto returns MAX_STREAMS credit when a stream is fully closed and read, which can be before minip2p's reader has acknowledged the delivered bytes. The adapter keeps today's rule of refusing new peer streams beyond `max_streams_per_connection` while slots are held by unsettled streams, by stopping and resetting the extra stream.
5. **Dependency maturity.** quinn-proto is 0.x and has broken its API between minors (0.10→0.11). quiche is also 0.x with frequent breaks, so this is a wash, but plan to pin the version and absorb upgrades deliberately.
6. **`unsafe` in dependencies.** quinn-udp uses `libc` and `unsafe` internally, as `boring` does today. `forbid(unsafe_code)` still holds for minip2p crates.
7. **Clock granularity.** The host's millisecond `Now` is too coarse to feed quinn directly on low-RTT paths (table above). The adapter stays `std`-only and keeps sampling `Instant`, as it does today.
8. **Behaviour drift to re-verify.** quinn-proto defaults differ from today's choices: MTU discovery on (initial 1200, probing up) against a fixed 1350, a CUBIC implementation, an ACK frequency and delay policy, NEW_TOKEN validation tokens, DATAGRAM support advertised, and rate-limited stateless-reset replies to short-header packets with an unknown CID (today such packets are dropped silently). Each needs an explicit setting or a recorded decision.

## Rejected alternatives

- **Stay on quiche, add quinn-udp GSO.** This captures most of the throughput (≈627 MB/s) but keeps BoringSSL, the fork, the internal clock and all the hand-rolled Retry, routing and pacing code. It is worth doing only if the rewrite is deferred for a long time.
- **`quinn` (async) instead of quinn-proto.** Ruled out: it needs an async runtime.
- **aws-lc-rs instead of ring as the rustls provider.** It is rustls's default and FIPS-capable, but heavier, and has historically needed CMake or NASM on some targets. ring needs only a C compiler. aws-lc-rs stays a feature-flag option if FIPS is ever needed.
- **Keep CID-derived Connection tokens by sniffing handshake headers.** Possible, but it ties the adapter back to packet formats that quinn-proto owns. Pre-1.0, the exporter is the cleaner contract.
