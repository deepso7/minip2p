# Native std TCP gets a 1,664 KiB Yamux receive window

Partially supersedes ADR 0022's 256 KiB Yamux window, for native std TCP only. ADR 0022 put every Yamux session back on the specification's 256 KiB window. That window holds TCP to 2.24 MB/s, 19% of the link, on `endpoint_rtt`'s 100 Mbit/s, 100 ms profile, while QUIC reaches 86%. The latency regression ADR 0022 fixed came from circuit sessions advertising multi-megabyte windows to the relay, not from TCP's own sessions.

Originally set to 2,432 KiB (#606) when Yamux returned credit at half the window (`receive_window / 2`), and amended (#610) after `yamux-check` (#611) showed the loaded-ping cost on short links. Returning credit at a quarter of the window (`receive_window / 4`) lets a smaller fixed window fill the primary profile without adding a dynamic RTT/window state machine. We decided:

- **Yamux returns credit at a quarter of the window (`receive_window / 4`).** Full throughput then needs roughly 1.33× the bandwidth-delay product instead of 2×, cutting both loaded queueing delay and worst-case receive memory by about a third.
- **`TcpConfig::std_default()` is the native profile.** It is `TcpConfig::default()` with `yamux.receive_window` set to 1,664 KiB (~1.36× the 1,220 KiB BDP of 100 Mbit/s at 100 ms). The std `EndpointBuilder` (`StdBuilderState::default()`), ffi-core's `resolve_limits` (and so the UniFFI, Node and React Native bindings), and `endpoint_rtt`'s per-PR row all start from it. `EndpointBuilder::tcp_config` replaces it whole, so overrides start from `..TcpConfig::std_default()`.
- **The portable defaults stay at 256 KiB.** `YamuxConfig::default()`, `TcpConfig::default()` and `CircuitLimits::default()` are unchanged. The portable and smoltcp endpoints build TCP from `TcpConfig::default()`, so an embedded heap is sized from the smaller window (`docs/md/docs/rust/embedded-devices.mdx`). Relay circuits keep 256 KiB, the window that set ADR 0022's relayed latency.
- **Attached `StdTcpProvider::send` waits for `WRITABLE` readiness once backpressured.** After a short write or `WouldBlock` arms `Interest::WRITABLE`, `send` returns `0` until readiness fires rather than calling `write()` again and refilling `SO_SNDBUF` past `TCP_NOTSENT_LOWAT`. Proactive yielding before `WouldBlock` was rejected because re-arming `epoll` every 32 KiB cut loopback `endpoint_throughput/tcp` by 27% (498 → 361 MB/s) and doubled allocations per MB.

## Evidence

### Amendment (#610, quarter-window credit return)

Measured with `MINIP2P_RTT_SWEEP=yamux-check` (3 runs per point, 6 at the cutoff; `MINIP2P_RTT_TOTAL_MB=8` on `10m_20ms`), comparing 1,664 KiB with `/ 4` credit return against the original 2,432 KiB with `/ 2` credit return:

| Link | 256 KiB (`/ 4`) | 1,216 KiB (`/ 4`) | **1,664 KiB (`/ 4`, new default)** | 2,432 KiB (`/ 2`, #606) |
| --- | --- | --- | --- | --- |
| `10m_20ms` | 100%, p50 209 ms | 100%, p50 906 ms | **100%, p50 1,261 ms (p99 1,340 ms)** | 100%, p50 1,707 ms |
| `100m_10ms` | 100%, p50 19 ms | 100%, p50 82 ms | **100%, p50 122 ms (p99 135 ms)** | 100%, p50 179 ms |
| `100m_100ms` | 20% (2.35 MB/s), p50 101 ms | 80% (9.31 MB/s), p50 102 ms | **100% (11.68 MB/s), p50 119 ms (p99 137 ms)** | 99% (11.62 MB/s), p50 194 ms (p99 200 ms) |

### Original sweep (#606, half-window credit return)

Measured on rem (12 CPUs) against `eadf3abc`, with `endpoint_rtt`'s in-process userspace link proxy. `endpoint_rtt` prints MB/s with MB = 2^20 bytes; the tables keep its unit.

`scripts/rtt-sweep.sh yamux` on `100m_100ms` (BDP 1,220 KiB), median of 5 runs (10 at the cutoff). The cutoff is 10.51 MB/s, 90% of the 11.68 MB/s reference. Ping is measured on the same link while the transfer runs.

| window        | goodput        | of reference | loaded ping p50 / p99 |
| ------------- | -------------- | ------------ | --------------------- |
| 1,216 KiB     | 7.78 MB/s      | 67%          | 101 / 151 ms          |
| 1,856 KiB     | 10.05 MB/s     | 86%          | 127 / 176 ms          |
| **2,432 KiB** | **11.62 MB/s** | **100%**     | 194 / 200 ms          |
| 3,072 KiB     | 11.68 MB/s     | 100%         | 199 / 353 ms          |
| 4,864 KiB     | 11.68 MB/s     | 100%         | 380 / 399 ms          |

On `1g_20ms` (BDP 2,441 KiB) the sweep picks 4,864 KiB, which reaches 117.24 MB/s (99%). 2,432 KiB reaches 77.97 MB/s (66%), and 3,648 KiB reaches 100.36 MB/s (85%). Gigabit paths with a long RTT still need `receive_window` raised by hand. We size for the primary profile, as ADR 0021 did, rather than double the memory bound for every host.

`endpoint_rtt/tcp/100m_100ms` goes from 2.24 to 11.63 MB/s (19% to 98% of the link). QUIC is unchanged at 10.24 MB/s.

`endpoint_ping_load`'s TCP rows, with the before and after binaries run alternately five times each (median, with the range in parentheses). In these rows the ping probe connects over TCP, so it takes the new default. The relay and pubsub load it runs under is carried over QUIC:

| case | before p50 | after p50 | before p99 | after p99 |
| --- | --- | --- | --- | --- |
| `relay/tcp` | 695 µs (690–722) | 692 µs (686–708) | 1,929 µs (1,185–2,058) | 1,517 µs (1,295–1,658) |
| `pubsub/tcp` | 237 µs (233–263) | 234 µs (228–239) | 385 µs (280–629) | 356 µs (281–393) |

These rows show that a TCP connection with the larger window answers pings no slower under load. No bench yet runs relay legs over TCP. There the outer TCP connections to the relay take the larger window, and a relay's `Forward` queue is bounded by the origin leg's outer receive window (reduced by a third at 1,664 KiB).

## Trade-off

Per connection, received data is bounded by `max_streams` × `receive_window`. With the defaults that is 256 × 1,664 KiB = 416 MiB, against 608 MiB at 2,432 KiB and 64 MiB at 256 KiB. The inbound frame decoder can hold one more partial frame of up to a window, since inbound frames are limited by `receive_window` (ADR 0038). On top of that come the 4 MiB Yamux send cap, which includes the 256 KiB `DEFAULT_CONTROL_STREAM_RESERVE`. The send cap can grow to about twice that while a queued write keeps a slice of its caller's payload (ADR 0012). Finally there is one outbound frame (`max_buffered_send` 0). This is smaller than QUIC's default of about 640 MB (ADR 0022). Transport-wide it is that times `max_connections`. As with QUIC, it is a worst case that a peer reaches only by opening every stream and filling each one while the application does not acknowledge. A host that needs a tighter bound lowers `receive_window`, `max_streams` or `max_connections`. A stream still starts from the specification's 256 KiB credit and is granted the rest with its first window update.

## Rejected alternatives

- **Raising `YamuxConfig::default()`.** It would also raise circuits and smoltcp, which brings back ADR 0022's relayed-latency regression and a multi-hundred-MiB bound on embedded heaps.
- **Keeping 2,432 KiB with half-window credit return.** It holds 46% more unacknowledged data per stream and adds 35–63% more loaded ping delay for no extra throughput on the primary profile.
- **4,864 KiB, the `1g_20ms` pick.** It triples the bound to about 1.2 GiB per connection and triples loaded ping on the primary profile, for a profile we treat as secondary.
- **Growing windows per stream (#610).** Measuring RTT with Yamux PING and growing per-stream windows against a connection-wide growth pool adds an adaptive state machine with subtle loaded-RTT and 1 ms LAN quantization edge cases; both Quinn and Iroh (`noq`) keep static windows for the same simplicity reasons recorded in ADR 0022.
