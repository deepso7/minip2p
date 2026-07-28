# minip2p-platform

Portable clock, deadline, and entropy contracts for minip2p. `no_std` + `alloc` compatible.

Everything in minip2p is caller-driven: protocol agents, transports, and runtimes never read a system clock and never draw randomness themselves. The host samples time once per drive iteration and passes that one value to everything it drives; components that need randomness are handed an entropy source. This crate defines those contracts, so the rest of the workspace stays deterministic and testable and all platform access lives in adapters.

## Features

- `Now`: one time sample, carrying monotonic milliseconds and optional wall-clock seconds.
- `Clock`: the trait adapters implement to produce `Now`.
- `Deadline`: a point on a clock's monotonic timeline, used by caller-driven components to report when they next need attention.
- `EntropySource` and `EntropyError`: cryptographically secure random bytes, with an explicit "this platform has none" error.
- `StdClock` and `StdEntropy` behind the default `std` feature.

## Usage

Sample once, then drive everything with that sample:

```rust
use minip2p_platform::{Clock, Deadline, Now, StdClock};

struct Heartbeat {
    interval_ms: u64,
    next: Deadline,
}

impl Heartbeat {
    fn poll(&mut self, now: Now) -> bool {
        if !self.next.is_expired_at(now) {
            return false;
        }
        self.next = now.deadline_after(self.interval_ms);
        true
    }

    fn next_deadline(&self) -> Option<Deadline> {
        Some(self.next)
    }
}

let mut clock = StdClock::new();
let mut heartbeat = Heartbeat {
    interval_ms: 15_000,
    next: clock.now().as_deadline(),
};

let now = clock.now();
assert!(heartbeat.poll(now));
assert!(!heartbeat.poll(now));

// The host can idle until the earliest deadline across all its subsystems.
let idle_ms = heartbeat
    .next_deadline()
    .map(|deadline| deadline.millis_until(now));
assert_eq!(idle_ms, Some(15_000));
```

## Wall-clock time is optional

`Now::unix_seconds` is `None` on platforms with no wall clock, such as an embedded board without an RTC or NTP sync. Components that need real time — signed beacon freshness, certificate validity — must handle its absence explicitly. Substituting monotonic time is never correct: monotonic epochs are arbitrary and not comparable between peers.

## `no_std`

Build without the `std` feature and supply your own implementations:

```rust
use minip2p_platform::{Clock, EntropyError, EntropySource, Now};

struct BoardClock;

impl Clock for BoardClock {
    fn now(&mut self) -> Now {
        // No RTC on this board, so no wall clock is reported.
        Now::from_millis(ticks_since_boot())
    }
}

struct BoardRng;

impl EntropySource for BoardRng {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        for byte in output.iter_mut() {
            *byte = hardware_rng_byte();
        }
        Ok(())
    }
}
```

## License

MIT
