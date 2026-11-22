# interop apps

minip2p's entries in libp2p's interop matrices, one binary per suite:

| Binary | Suite | Source |
| --- | --- | --- |
| `minip2p-unified-testing` | transport, in both [test-plans](https://github.com/libp2p/test-plans) and [unified-testing](https://github.com/libp2p/unified-testing) | `src/main.rs` |
| `minip2p-relay-interop` | unified-testing [`relay`](https://github.com/libp2p/unified-testing/tree/master/relay) (Circuit Relay v2) | `src/bin/relay.rs` |

`src/redis.rs` is the shared Redis client. The suites disagree on the key type: transport uses a list (`RPUSH` / `BLPOP`), relay a string (`SET` / `GET`).

## transport

Dial, handshake, and ping against every other libp2p implementation, over `tcp` (Noise, Yamux) and `quic-v1`.

One binary serves both harnesses, which agree on the mechanics and differ in three things:

|  | [test-plans](https://github.com/libp2p/test-plans) `transport-interop` | [unified-testing](https://github.com/libp2p/unified-testing) `transport` |
| --- | --- | --- |
| Spec | [`transport-interop/README.md`](https://github.com/libp2p/test-plans/blob/master/transport-interop/README.md) | [`docs/write-a-transport-test-app.md`](https://github.com/libp2p/unified-testing/blob/master/docs/write-a-transport-test-app.md) |
| Settings | `is_dialer`, `transport`, `security`, `muxer`, `redis_addr`, `ip`, `test_timeout_seconds` | `IS_DIALER`, `TRANSPORT`, `SECURE_CHANNEL`, `MUXER`, `REDIS_ADDR`, `TEST_KEY`, `LISTENER_IP` |
| Redis key | `listenerAddr` | `<TEST_KEY>_listener_multiaddr` |
| Result | `{"handshakePlusOneRTTMillis": f, "pingRTTMilllis": f}` | `latency: {handshake_plus_one_rtt, ping_rtt, unit}` |

The harness is picked from whichever dialer flag is set, so neither needs to pass anything extra. For test-plans, `redis_addr` defaults to `redis:6379`, `ip` to `0.0.0.0` and `test_timeout_seconds` to 180, as its spec says; unified-testing always passes its own.

Both read the listener address as a Redis **list** (`RPUSH` / `BLPOP`), which the reference rust-libp2p image also does. test-plans' spec says so; unified-testing's doc describes a string read with `GET`, but its implementations do not.

The directory and binary keep the narrower `unified-testing` name, which predates the second harness: renaming them would move the Dockerfile path that [libp2p/unified-testing#193](https://github.com/libp2p/unified-testing/pull/193) pins.

Standalone crate (own `[workspace]`), so it never touches the workspace lockfile. No Redis client dependency: the two commands it needs are a few lines of RESP.

## Build

From the repository root (the build context both harnesses use):

```sh
docker build -f tests/interop/unified-testing/Dockerfile -t minip2p-transport .
```

## Run without Docker

```sh
docker run -d --rm -p 127.0.0.1:6379:6379 redis:7-alpine
cd tests/interop/unified-testing && cargo build --release
```

test-plans, whose dialer prints JSON and exits 0:

```sh
env='transport=tcp security=noise muxer=yamux redis_addr=127.0.0.1:6379'
env $env is_dialer=false ./target/release/minip2p-unified-testing &
env $env is_dialer=true  ./target/release/minip2p-unified-testing
# {"handshakePlusOneRTTMillis": 2.054, "pingRTTMilllis": 0.284}
```

unified-testing, whose dialer prints YAML and exits 0:

```sh
env='REDIS_ADDR=127.0.0.1:6379 TEST_KEY=deadbeef TRANSPORT=tcp SECURE_CHANNEL=noise MUXER=yamux'
env $env IS_DIALER=false ./target/release/minip2p-unified-testing &
env $env IS_DIALER=true  ./target/release/minip2p-unified-testing
# latency:
#   handshake_plus_one_rtt: 1.313
#   ping_rtt: 0.104
#   unit: ms
```

Timing matches rust-libp2p's `interop-tests`: the clock starts before the dial and stops at the first ping result. `ping_rtt` comes from a second ping on the already negotiated stream, so like rust-libp2p's it covers only the payload echo. It is timed here rather than taken from `PingRttMeasured`, whose whole-millisecond `rtt_ms` reads 0 between containers.

Set `DEBUG=true` for every endpoint event on stderr. The logging is synchronous, so debug runs report slightly higher latencies.

## relay

One image plays all three roles, picked by `ROLE`: `relay` (a minip2p relay server), `listener` (reserves a slot and echoes `/relay-echo/1.0.0`), and `dialer` (reaches the listener through the relay, sends `hello-relay`, and checks the echo). It uses TCP with Noise and Yamux on one flat network. The suite has no written spec, so the contract is the go reference app's, [`relay/images/go/main.go`](https://github.com/libp2p/unified-testing/blob/master/relay/images/go/main.go): string keys `<TEST_KEY>_relay_multiaddr` and `<TEST_KEY>_listener_peer_id`, and `status: pass` / `status: fail` on stdout.

DCUtR is off in every role so the echo can only travel over the circuit. minip2p's DCUtR punches only QUIC targets on public addresses by default, so it would not fire here anyway; the setting keeps the test honest if that changes. The listener reserves with `ReservationPolicy::Always` so the reservation does not depend on the default policy's reachability verdict.

```sh
docker run -d --rm -p 127.0.0.1:6379:6379 redis:7-alpine
cargo build --release
env='REDIS_ADDR=127.0.0.1:6379 TEST_KEY=deadbeef'
env $env ROLE=relay    ./target/release/minip2p-relay-interop &
env $env ROLE=listener ./target/release/minip2p-relay-interop &
env $env ROLE=dialer   ./target/release/minip2p-relay-interop
# status: pass
```
