# Interop harness: result shape and ping timing match rust-libp2p

`tests/interop/unified-testing` is minip2p's entrypoint for the libp2p unified-testing and test-plans runners:

- **`pingRTTMilllis` keeps three l's.** That is the spelling in the test-plans spec and in every implementation; the runner reads that exact key.
- **Timing matches rust-libp2p's interop-tests**, so the numbers compare: the handshake clock starts before the dial and stops at the first ping result; the first ping also opens and negotiates the ping stream, so the reported RTT comes from a second ping on that stream (rust-libp2p's RTT likewise covers only the payload echo). The harness times the ping itself because `rtt_ms` is whole milliseconds and container RTTs are below that, and it samples before logging so DEBUG output does not inflate the numbers.
- **Runner differences.** unified-testing always passes the Redis address; test-plans leaves it to the compose service name (`redis:6379`) and the listen IP to `0.0.0.0` unless it overrides them, and its Redis key is fixed, not derived from a per-test id. Standalone transports (`quic-v1`) take neither security nor muxer settings. Redis is a global service that can still be starting, so connecting retries.
- **Published address.** A wildcard bind cannot be dialled, so the listener publishes the interface that reaches Redis, which is the one the dialer shares a network with; an IP the harness pinned is used as is.
- **The listener only drives its endpoint**: ping and identify are answered inside the Endpoint until Docker stops the container.
- `tests/interop/rust-relay-client`'s source may dial through a relay address served by another node of a relay mesh with the same relay peer id, exercising mesh forwarding (ADR 0027).
