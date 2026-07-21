// Captures a StrictSign-signed floodsub message exactly as go-libp2p-pubsub
// emits it on the wire, for minip2p's golden-vector interop test
// (crates/pubsub/tests/golden_go.rs).
//
// Host A runs real floodsub with a fixed Ed25519 identity (StrictSign is the
// go default). Host B is a bare libp2p host that advertises
// /floodsub/1.0.0 and dumps every varint-framed RPC it receives. B announces
// a subscription to the topic with a hand-encoded RPC, A publishes once, and
// the RPC frame carrying the signed message is printed as hex.
//
// Run from this directory:
//
//	go mod tidy && go run .
//
// Outputs (stdout):
//
//	control=<hex of the unframed control RPC body>
//	peer=<host A base58 peer id>
//	rpc=<hex of the full varint-length-prefixed publish RPC frame>
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	topicName = "minip2p-golden"
	protoID   = "/floodsub/1.0.0"
	payload   = "golden"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	control, err := proto.Marshal(controlFixture())
	if err != nil {
		return err
	}
	fmt.Printf("control=%s\n", hex.EncodeToString(control))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Fixed seed so the fixture is reproducible.
	seed := bytes.Repeat([]byte{7}, 32)
	priv, _, err := crypto.GenerateEd25519Key(bytes.NewReader(seed))
	if err != nil {
		return err
	}

	hostA, err := libp2p.New(libp2p.Identity(priv), libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		return err
	}
	defer hostA.Close()
	hostB, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		return err
	}
	defer hostB.Close()

	frames := make(chan []byte, 16)
	hostB.SetStreamHandler(protoID, func(s network.Stream) {
		r := bufio.NewReader(s)
		for {
			frame, err := readFrame(r)
			if err != nil {
				return
			}
			frames <- frame
		}
	})

	ps, err := pubsub.NewFloodSub(ctx, hostA)
	if err != nil {
		return err
	}
	topic, err := ps.Join(topicName)
	if err != nil {
		return err
	}

	if err := hostA.Connect(ctx, peer.AddrInfo{ID: hostB.ID(), Addrs: hostB.Addrs()}); err != nil {
		return err
	}

	// B announces its subscription with a hand-encoded RPC:
	// RPC{ subscriptions: [SubOpts{ subscribe: true, topicid: topicName }] }.
	sub, err := hostB.NewStream(ctx, hostA.ID(), protoID)
	if err != nil {
		return err
	}
	if _, err := sub.Write(subscribeFrame(topicName)); err != nil {
		return err
	}

	// Let A ingest the subscription before publishing.
	time.Sleep(500 * time.Millisecond)
	if err := topic.Publish(ctx, []byte(payload)); err != nil {
		return err
	}

	// A sends its own subscription RPC first, then the publish RPC; scan for
	// the frame that carries the payload.
	deadline := time.After(10 * time.Second)
	for {
		select {
		case frame := <-frames:
			if bytes.Contains(frame, []byte(payload)) {
				full := append(varint(uint64(len(frame))), frame...)
				fmt.Printf("peer=%s\n", hostA.ID().String())
				fmt.Printf("rpc=%s\n", hex.EncodeToString(full))
				return nil
			}
		case <-deadline:
			return fmt.Errorf("no publish frame observed within deadline")
		}
	}
}

// controlFixture covers every gossipsub v1.0 control type plus the v1.1
// PeerInfo and backoff additions to ControlPrune.
func controlFixture() *pb.RPC {
	return &pb.RPC{Control: &pb.ControlMessage{
		Ihave: []*pb.ControlIHave{{
			TopicID:    proto.String("minip2p-golden"),
			MessageIDs: []string{"have-1", string([]byte{0xff, 0x00})},
		}},
		Iwant: []*pb.ControlIWant{{MessageIDs: []string{"want-1", "want-2"}}},
		Graft: []*pb.ControlGraft{{TopicID: proto.String("minip2p-golden")}},
		Prune: []*pb.ControlPrune{{
			TopicID: proto.String("minip2p-golden"),
			Peers: []*pb.PeerInfo{{
				PeerID:           []byte{0x00, 0x01, 0x02},
				SignedPeerRecord: []byte{0xaa, 0xbb, 0xcc},
			}},
			Backoff: proto.Uint64(60),
		}},
	}}
}

// readFrame reads one varint-length-prefixed frame.
func readFrame(r *bufio.Reader) ([]byte, error) {
	length, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	if length > 1<<20 {
		return nil, fmt.Errorf("frame too large: %d", length)
	}
	frame := make([]byte, length)
	if _, err := io.ReadFull(r, frame); err != nil {
		return nil, err
	}
	return frame, nil
}

func subscribeFrame(topic string) []byte {
	// SubOpts{ subscribe(1)=true, topicid(2)=topic }
	sub := []byte{0x08, 0x01, 0x12, byte(len(topic))}
	sub = append(sub, topic...)
	// RPC{ subscriptions(1) = sub }
	rpc := append([]byte{0x0a, byte(len(sub))}, sub...)
	return append(varint(uint64(len(rpc))), rpc...)
}

func varint(v uint64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, v)
	return buf[:n]
}
