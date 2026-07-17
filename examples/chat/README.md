# minip2p-chat

Group chat over floodsub with NAT traversal: the "finished product" demo
for the minip2p stack. Peers join a room by dialing one address, the NAT
agent hole-punches direct paths where needed, and messages flood the room
signed end-to-end (libp2p StrictSign).

```text
minip2p-chat host        [--topic <t>] [--nick <n>] [--relay <relay-peer-addr>] [--key <path>] [--listen <quic-multiaddr>]
minip2p-chat join <addr> [--topic <t>] [--nick <n>] [--relay <peer-addr>] [--key <path>] [--listen <quic-multiaddr>]
```

Type lines on stdin to chat; Ctrl-D leaves.

## Quickstart (one machine)

```console
$ cargo run -p minip2p-chat -- host --nick hostess
[host] bound=/ip4/127.0.0.1/udp/54321/quic-v1/p2p/12D3KooW…
…
```

In two more terminals, join with the printed `bound=` address:

```console
$ cargo run -p minip2p-chat -- join /ip4/127.0.0.1/udp/54321/quic-v1/p2p/12D3KooW… --nick alice
$ cargo run -p minip2p-chat -- join /ip4/127.0.0.1/udp/54321/quic-v1/p2p/12D3KooW… --nick bob
```

Lines typed by alice appear at the host and at bob — bob receives them
*through* the host (floodsub star forwarding); alice sees her own line as a
local `[you]` echo only (no self-delivery). This is exactly what the CI
e2e test (`tests/chat.rs`) runs.

## NAT'd host (relay + hole punch)

Give the host a Circuit Relay v2 server; it prints a `circuit=` address
NAT'd joiners can use:

```console
$ minip2p-chat host --relay /ip6/…/udp/4001/quic-v1/p2p/<relay-id>
[host] bound=…
[host] nat-relay-reserved relay=…
[host] circuit=/ip6/…/p2p/<relay-id>/p2p-circuit/p2p/<host-id>
```

A joiner pastes the circuit address; the NAT agent connects through the
relay, runs DCUtR, and the chat starts once the hole punch lands:

```console
$ minip2p-chat join '<circuit-addr>' --nick alice
[join] path=relayed
[join] waiting for the hole punch (chat needs a direct path)
[join] nat-path-upgraded … to=direct-punched
[join] subscribed topic=minip2p-chat nick=alice
```

### Known v1 limitation: no chat over the relay bridge

The relayed path is a raw bridge stream — no multistream negotiation runs
over it, so floodsub cannot open its streams there. If the hole punch
fails, `join` exits with an error instead of silently sitting in a dead
room. A circuit transport that makes relayed paths look like normal
connections is future work at the stack level.

## Message format

The payload is plain UTF-8, `"<nick>: <text>"`, formatted by the sender —
trivially interoperable with any libp2p floodsub peer on the same topic
(go/js sign by default and match this stack's StrictSign; rust-libp2p's
floodsub is unsigned — pass `--allow-unsigned` to chat with it; signed
messages are still verified). Seqnos are implementation-defined opaque
bytes (go: 8 big-endian, rust: 20 random); anything 1..=64 bytes is
accepted.

A quiet room generates no traffic, and the QUIC transport drops
connections after 30 s of silence — the chat loop pings every connected
peer on a 10 s cadence to keep the room (and any relay reservation
connection) alive through idle spells.

## Live-test recipes

The environment mirrors `examples/peer`'s live runs (AWS relay, home
network, mobile hotspot; VPN users: pin `--listen` to a real interface
address if v6 default routes are hijacked).

1. **Open-internet star**: `host --listen /ip4/0.0.0.0/udp/4001/quic-v1`
   on a public box. The printed `bound=` address is rewritten to loopback
   (it is meant for same-host joins); remote joiners build their address
   from the `listen-addr=` line by substituting the machine's public IP:
   `join /ip4/<public-ip>/udp/4001/quic-v1/p2p/<host-peer-id>`. Kill and
   rejoin one peer: the subscription snapshot is resent on reconnect.
2. **NAT'd host**: host behind a NAT with `--relay <aws-relay>`, joiners
   paste the `circuit=` address and hole-punch in.
3. **go-libp2p interop**: a go floodsub peer (Ed25519 identity) on the
   same topic chats both ways in strict mode.
4. **rust-libp2p interop**: a rust-libp2p floodsub peer, with this side
   started with `--allow-unsigned`. The rust peer must include a `ping`
   behaviour (to answer this side's keepalives) or raise its
   `idle_connection_timeout` — by default rust-libp2p closes a
   connection after 10 s when no behaviour keeps it alive, which reads
   as an instant disconnect here.

All four ran green on 2026-07-17: loopback sanity, an AWS-hosted
open-internet star (hotspot + home-network leaves, kill/rejoin,
75 s idle survival), a NAT'd host punched into from a hotspot
(relayed → direct-punched upgrade, then chat over the punched path),
and both interop directions against real go-libp2p and rust-libp2p
peers.
