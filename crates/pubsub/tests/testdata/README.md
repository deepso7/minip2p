# Golden interop fixtures

`go_signed_message_rpc.hex` is a varint-length-prefixed floodsub RPC frame
captured byte-for-byte off the wire from go-libp2p-pubsub — see
`golden-go/main.go` for the capture harness (`go mod tidy && go run .`).

Pinned versions (recorded in `golden-go/go.mod`):

- github.com/libp2p/go-libp2p **v0.48.0**
- github.com/libp2p/go-libp2p-pubsub **v0.15.0**

Facts the capture confirmed about what current go emits:

- exactly **one** topic entry (the singular `topic` incarnation of field 4);
- the `key` field (6) is **omitted** — the Ed25519 key is inlined in `from`;
- `seqno` is 8 big-endian bytes; the signature is 64 bytes (StrictSign,
  go's default).

`go_peer_id.txt` is the publishing host's base58 peer id (fixed seed
`[7u8; 32]`, so re-running the harness reproduces the same identity; the
seqno and therefore the signature bytes differ per run — that's fine, the
Rust test verifies signatures, it does not compare them).

`go_control_rpc.hex` is an unframed RPC body marshaled by the same pinned Go
module. It contains IHAVE, IWANT, GRAFT, and PRUNE, including v1.1 peer
exchange and backoff fields. Unlike the signed publish fixture it is fully
deterministic; the Rust test requires a byte-identical decode/re-encode.
