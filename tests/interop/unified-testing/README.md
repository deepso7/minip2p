# unified-testing transport app

The minip2p entry in [libp2p/unified-testing](https://github.com/libp2p/unified-testing)'s
transport interop matrix: dial, handshake, and ping against every other libp2p
implementation, over `tcp` (Noise, Yamux) and `quic-v1`.

It follows the repo's [transport test-app contract](https://github.com/libp2p/unified-testing/blob/master/docs/write-a-transport-test-app.md),
with one deviation the reference rust-libp2p image also makes: the listener address is
a Redis **list** (`RPUSH` / `BLPOP` on `<TEST_KEY>_listener_multiaddr`), not a string.

Standalone crate (own `[workspace]`), so it never touches the workspace lockfile. No
Redis client dependency: the two commands it needs are a few lines of RESP.

## Build

From the repository root (the build context unified-testing uses):

```sh
docker build -f tests/interop/unified-testing/Dockerfile -t minip2p-transport .
```

## Run without Docker

```sh
docker run -d --rm -p 127.0.0.1:6379:6379 redis:7-alpine
cd tests/interop/unified-testing && cargo build --release
env='REDIS_ADDR=127.0.0.1:6379 TEST_KEY=deadbeef TRANSPORT=tcp SECURE_CHANNEL=noise MUXER=yamux'
env $env IS_DIALER=false ./target/release/minip2p-unified-testing &
env $env IS_DIALER=true  ./target/release/minip2p-unified-testing
```

The dialer prints the result YAML and exits 0:

```yaml
latency:
  handshake_plus_one_rtt: 1.313
  ping_rtt: 0.104
  unit: ms
```

Timing matches rust-libp2p's `interop-tests`: the clock starts before the dial and stops
at the first ping result. `ping_rtt` comes from a second ping on the already negotiated
stream, so like rust-libp2p's it covers only the payload echo. It is timed here rather
than taken from `PingRttMeasured`, whose whole-millisecond `rtt_ms` reads 0 between
containers.

Set `DEBUG=true` for every endpoint event on stderr. The logging is synchronous, so
debug runs report slightly higher latencies.
