# Behavioural test for the QUIC loss-detection thresholds

`congestion_tuning_reaches_the_engine` in `minip2p-quic` checks that `QuicLimits::packet_threshold` and `QuicLimits::time_threshold` reach quinn-proto by reading the `Debug` output of the built `TransportConfig`. It is not replaced with a test that watches loss detection behave.

## Why this is out of scope

- **The check is deterministic.** quinn-proto writes that `Debug` impl by hand, field by field. The output only changes when quinn changes it, so the test can break on a quinn upgrade, loudly and with the full config in its message. It cannot flake.
- **A behavioural test would be flaky.** quinn's loss delay is the larger of `time_threshold` × RTT and a 1 ms timer granularity. On loopback the 1 ms floor dominates, so the time rule and the packet rule compete. Telling them apart needs held or reordered datagrams and timing, which trades a loud break on upgrade for intermittent failures.
- **The code under test is a pass-through.** `transport_config` hands both values straight to quinn's builder. Wrapping that in a helper and testing its inputs would check nothing.

## When to revisit

Revisit if a quinn upgrade breaks the `Debug` assertion. At that point, drop the threshold half of the assertion rather than rewriting it as a timing test, unless loss detection can be made deterministic in the in-crate `test_peer` harness.

## Prior requests

- #591: "Loss-detection threshold test asserts on quinn's Debug output"
