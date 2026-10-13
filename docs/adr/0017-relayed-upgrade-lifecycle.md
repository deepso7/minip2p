# Relayed upgrade lifecycle and timing

ADR 0006 puts the circuit up first and ADR 0008 has the Connection engine own the attempt's terminal outcome; neither said how long the direct upgrade may take or who retries it. As shipped, DCUtR ran once per relayed session, the dialer repeated its punch window three times while the reservation holder blasted only once, RTT was timed from when CONNECT was queued, and a relayed attempt whose peer never started DCUtR waited for the full connect deadline and could still emit `ConnectFailed` after settling Connected (#327 findings 13 and 14). We decided:

- **The reservation holder retries, with fresh exchanges.** It runs up to three CONNECT/SYNC rounds per relayed session, each with a new RTT measurement and a 3 s punch window on both sides; the dialer's own window repeats go away. This is what the DCUtR spec, rust-libp2p and go-libp2p do: re-measuring keeps one bad RTT from spoiling every round. Roles are unchanged — the circuit dialer dials, the holder sends random UDP.
- **RTT starts when CONNECT is fully written**, held tail included, not when it is queued. The NAT agent holds tails the swarm refuses as Full and starts the clock, at the caller-supplied time, when the stream's Writable drains them.
- **Every wait is bounded.** Defaults, all configurable and clipped to the attempt's connect deadline (30 s): 10 s for the remote to start DCUtR after the Relayed path is usable, 10 s per exchange, 20 s for the whole upgrade. When a budget runs out the Relayed path stays and the attempt settles Connected with a typed upgrade diagnostic; `force_relay` settles immediately.
- **One terminal per attempt.** On any engine terminal, the NAT agent drops the attempt-owned state without closing the selected connection. What happens to that connection afterwards — an upgrade, a disconnect — is reported as connection events and upgrade diagnostics, never as another attempt outcome.
- **Relay acquisition gets 12 s per relay**, clipped by the connect deadline, moving to the next relay on failure, instead of 12 s split across all relays. The relay server's 60 s HOP/STOP timeout stays: it is a cleanup ceiling, not a promise that clients wait that long.

## Rejected alternatives

- **Re-running DCUtR later on a live Relayed path** (on a timer, or when observed addresses change). It would catch NAT mappings that change after the first cycle, but nothing needs it yet; a fresh `connect` after a disconnect does the same.
- **Keeping the dialer-side window repeats.** They re-dial the same addresses after the holder has stopped blasting, so later windows rarely succeed.
