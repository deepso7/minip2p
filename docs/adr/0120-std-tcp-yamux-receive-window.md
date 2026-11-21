# Native std TCP gets a 2,432 KiB Yamux receive window

Partially supersedes ADR 0022's 256 KiB Yamux window, for native std TCP only. ADR 0022 put every Yamux session back on the specification's 256 KiB window. That window holds TCP to 2.24 MB/s, 19% of the link, on `endpoint_rtt`'s 100 Mbit/s, 100 ms profile, while QUIC reaches 86%. The latency regression ADR 0022 fixed came from circuit sessions advertising multi-megabyte windows to the relay, not from TCP's own sessions. We decided:

- **`TcpConfig::std_default()` is the native profile.** It is `TcpConfig::default()` with `yamux.receive_window` set to 2,432 KiB. The std `EndpointBuilder` (`StdBuilderState::default()`), ffi-core's `resolve_limits` (and so the UniFFI, Node and React Native bindings), and `endpoint_rtt`'s per-PR row all start from it. `EndpointBuilder::tcp_config` replaces it whole, so overrides start from `..TcpConfig::std_default()`.
- **The portable defaults stay at 256 KiB.** `YamuxConfig::default()`, `TcpConfig::default()` and `CircuitLimits::default()` are unchanged. The portable and smoltcp endpoints build TCP from `TcpConfig::default()`, so an embedded heap is sized from the smaller window (`docs/md/docs/rust/embedded-devices.mdx`). Relay circuits keep 256 KiB, the window that set ADR 0022's relayed latency.
- **The value is the sweep's pick.** 2,432 KiB is about twice the bandwidth-delay product of 100 Mbit/s at 100 ms, the same value ADR 0021 measured, and the smallest candidate reaching 90% of a large window's goodput.

## Evidence

Measured on rem (12 CPUs) against `eadf3abc`, with `endpoint_rtt`'s in-process userspace link proxy. `endpoint_rtt` prints MB/s with MB = 2^20 bytes; the tables keep its unit.

`scripts/rtt-sweep.sh yamux` on `100m_100ms` (BDP 1,220 KiB), median of 5 runs (10 at the cutoff). The cutoff is 10.51 MB/s, 90% of the 11.68 MB/s reference. Ping is measured on the same link while the transfer runs.

| window | goodput | of reference | loaded ping p50 / p99 |
| --- | --- | --- | --- |
| 1,216 KiB | 7.78 MB/s | 67% | 101 / 151 ms |
| 1,856 KiB | 10.05 MB/s | 86% | 127 / 176 ms |
| **2,432 KiB** | **11.62 MB/s** | **100%** | 194 / 200 ms |
| 3,072 KiB | 11.68 MB/s | 100% | 199 / 353 ms |
| 4,864 KiB | 11.68 MB/s | 100% | 380 / 399 ms |

On `1g_20ms` (BDP 2,441 KiB) the sweep picks 4,864 KiB, which reaches 117.24 MB/s (99%). 2,432 KiB reaches 77.97 MB/s (66%), and 3,648 KiB reaches 100.36 MB/s (85%). Gigabit paths with a long RTT still need `receive_window` raised by hand. We size for the primary profile, as ADR 0021 did, rather than double the memory bound for every host.

`endpoint_rtt/tcp/100m_100ms` goes from 2.24 to 11.63 MB/s (19% to 98% of the link). QUIC is unchanged at 10.24 MB/s.

`endpoint_ping_load`'s TCP rows, with the before and after binaries run alternately five times each (median, with the range in parentheses). In these rows the ping probe connects over TCP, so it takes the new default. The relay and pubsub load it runs under is carried over QUIC:

| case | before p50 | after p50 | before p99 | after p99 |
| --- | --- | --- | --- | --- |
| `relay/tcp` | 695 µs (690–722) | 692 µs (686–708) | 1,929 µs (1,185–2,058) | 1,517 µs (1,295–1,658) |
| `pubsub/tcp` | 237 µs (233–263) | 234 µs (228–239) | 385 µs (280–629) | 356 µs (281–393) |

These rows show that a TCP connection with the larger window answers pings no slower under load. No bench yet runs relay legs over TCP. There the outer TCP connections to the relay take the larger window, but each circuit's own 256 KiB window still bounds what the circuit has in flight across both legs. So we expect relayed latency to stay where ADR 0022 left it; this is reasoning, not a measurement.

## Trade-off

Per connection, received data is bounded by `max_streams` × `receive_window`. With the defaults that is 256 × 2,432 KiB = 608 MiB, against 64 MiB at 256 KiB. The inbound frame decoder can hold one more partial frame of up to a window, since inbound frames are limited by `receive_window` (ADR 0038). On top of that come the 4 MiB Yamux send cap, which includes the 256 KiB `DEFAULT_CONTROL_STREAM_RESERVE`. The send cap can grow to about twice that while a queued write keeps a slice of its caller's payload (ADR 0012). Finally there is one outbound frame (`max_buffered_send` 0). This is the same order as QUIC's default of about 640 MB (ADR 0022). Transport-wide it is that times `max_connections`. As with QUIC, it is a worst case that a peer reaches only by opening every stream and filling each one while the application does not acknowledge. A host that needs a tighter bound lowers `receive_window`, `max_streams` or `max_connections`. A stream still starts from the specification's 256 KiB credit and is granted the rest with its first window update.

## Rejected alternatives

- **Raising `YamuxConfig::default()`.** It would also raise circuits and smoltcp, which brings back ADR 0022's relayed-latency regression and a multi-hundred-MiB bound on embedded heaps.
- **1,856 KiB, for a 464 MiB bound.** It reaches only 86% of the reference on the primary profile, below the 90% rule.
- **4,864 KiB, the `1g_20ms` pick.** It doubles the bound to about 1.2 GiB per connection and doubles loaded ping on the primary profile, for a profile we treat as secondary.
- **Growing windows.** Rejected for the same reasons as in ADR 0022.
