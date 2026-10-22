# Fewer QUIC ACKs on a receiver that keeps up

The QUIC transport does not try to send fewer ACKs when the receiver drains its socket faster than the sender fills it. It does not negotiate the ACK-frequency extension, and it does not hold back ACK-only output between polls.

## What happens

`QuicTransport::poll` (`transports/quic/src/lib.rs`) reads one receive batch per socket, then services each connection that got input once (`service_due`). That service sends whatever quinn-proto has queued, ACKs included. Without the ACK-frequency extension, quinn-proto wants an immediate ACK once two ack-eliciting packets are pending. So a service that follows N datagrams sends about one ACK per max(N, 2) datagrams.

On Linux and Android, GRO hands the receiver tens of datagrams per poll, and the receiver sends about 7–19 ACKs per MB. On macOS there is no GRO. A fast receiver wakes on every readiness edge and finds about 2.5 datagrams queued, so it sends about 120–160 ACKs per MB, roughly one per 5 data datagrams (measured in `endpoint_throughput` on an M2 Pro, #371/#386).

## Why this is out of scope

- **No cost has been measured.** The extra ACKs are small sends on a receiver that is, by definition, not the bottleneck. Nobody has shown a throughput, CPU, or energy loss.
- **It fixes itself under load.** Once the receiver falls behind, datagrams pile up between polls, and each service covers more of them. The relay's busy leg in the same run sends about 15 ACKs per MB.
- **Frequent ACKs are not pure waste.** They give the sender faster feedback for congestion-window growth and loss detection.
- **Android is unaffected.** quinn-udp enables GRO on `target_os = "android"` just as on Linux.
- **Battery is unlikely to be the cost on mobile.** The ACKs only flow during a bulk transfer, while the radio is already active, so they add CPU per send rather than radio wake-ups.
- **Both fixes are weak or risky:**
  - `TransportConfig::ack_frequency_config` uses a draft IETF extension that both peers must support. In practice it only helps minip2p-to-minip2p connections.
  - Deferring the ACK-only part of a service means changing the poll and service cadence, and that interacts with `max_ack_delay` and loss recovery.

## When to revisit

Revisit if one of these turns up:

- A measured throughput, CPU, or energy cost on a real target.
- An iPhone receiver that shows the macOS-like ACK rate. iOS uses the same Apple datapath as macOS, but its slower CPU may batch on its own, so measure the ACK rate with #371's counters first.

Measure throughput and CPU before and after, with #371's numbers as the baseline. Try `ack_frequency_config` first, because it changes no driver code.

## Prior requests

- #386: "QUIC: a receiver that keeps up ACKs every ~5 datagrams, because each poll services after a few datagrams"
