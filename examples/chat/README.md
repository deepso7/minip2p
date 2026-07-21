# minip2p-chat

Group chat over floodsub with NAT traversal: the "finished product" demo
for the minip2p stack. Peers join a room by dialing one address, the NAT
agent hole-punches direct paths where needed, and messages flood the room
signed end-to-end (libp2p StrictSign).

```text
minip2p-chat host        [--topic <t>] [--nick <n>] [--relay <relay-peer-addr>] [--key <path>] [--listen <quic-multiaddr>] [--no-mesh]
minip2p-chat join <addr> [--topic <t>] [--nick <n>] [--relay <peer-addr>] [--key <path>] [--listen <quic-multiaddr>] [--no-mesh]
```

Type lines on stdin to chat; Ctrl-D leaves. By default peers advertise addresses
on a room-scoped discovery topic and form direct leaf-to-leaf mesh edges. Pass
`--no-mesh` in either mode to preserve the original host-forwarded star.

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

Lines typed by alice appear at the host and at bob. Once discovery settles,
alice and bob have their own direct edge and keep chatting if the host exits;
alice sees her own line as a
local `[you]` echo only (no self-delivery). This is exactly what the CI
e2e test (`tests/chat.rs`) runs.

Discovery filters wildcard listen addresses. For a relay-free mesh, bind an
explicitly dialable address such as `--listen /ip4/127.0.0.1/udp/0/quic-v1`
for local testing (or a real interface address across machines). A node with
only wildcard binds and no AutoNAT-confirmed or relay circuit address can be
present in the room but cannot be automatically dialed.

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
relay and chat starts immediately on the promoted relayed connection while
DCUtR attempts a direct upgrade in the background:

```console
$ minip2p-chat join '<circuit-addr>' --nick alice
[join] path=relayed
[join] subscribed topic=minip2p-chat nick=alice
```

Pass `--relay-only` to skip direct dialing and DCUtR entirely. This gives a
deterministic way to exercise Noise, Yamux, Identify, discovery, and floodsub
over the relay circuit.

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

Two deployment details surfaced during live validation:

- EC2 hairpin NAT can make a chat host colocated with its relay appear at its
  VPC-private address. Remote peers cannot use that address for DCUtR; run the
  chat host and relay on separate boxes, or have peers join the host directly.
- A rust-libp2p relay listening on `/ip6/::/udp/<port>/quic-v1` is IPv6-only;
  it rejects IPv4-mapped traffic. Configure an explicit IPv4 listener as well
  when IPv4 clients must reach the relay.

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
