// Command go-libp2p is the foreign peer used by minip2p's live TCP interop gate.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

const (
	echoProtocol    = "/minip2p/interop/echo/1.0.0"
	echoTimeout     = 10 * time.Second
	maxEchoBytes    = 1 << 20
	maxCommandBytes = 8 * maxEchoBytes
)

type command struct {
	Op      string `json:"op"`
	Addr    string `json:"addr,omitempty"`
	Payload string `json:"payload,omitempty"`
}

type event struct {
	Event   string `json:"event"`
	PeerID  string `json:"peer_id,omitempty"`
	Addr    string `json:"addr,omitempty"`
	Payload string `json:"payload,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

func main() {
	ctx := context.Background()
	node, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		fatal(err)
	}
	defer node.Close()

	node.SetStreamHandler(echoProtocol, func(stream network.Stream) {
		defer stream.Close()
		_, _ = io.Copy(stream, stream)
	})

	if len(node.Addrs()) == 0 {
		fatal(fmt.Errorf("go-libp2p returned no listen address"))
	}
	readyAddr := node.Addrs()[0].Encapsulate(multiaddr.StringCast("/p2p/" + node.ID().String()))
	emit(event{Event: "ready", PeerID: node.ID().String(), Addr: readyAddr.String()})

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), maxCommandBytes)
	for scanner.Scan() {
		var cmd command
		if err := json.Unmarshal(scanner.Bytes(), &cmd); err != nil {
			emit(event{Event: "error", Detail: err.Error()})
			continue
		}
		switch cmd.Op {
		case "echo":
			payload, err := echo(ctx, node, cmd.Addr, cmd.Payload)
			if err != nil {
				emit(event{Event: "error", Detail: err.Error()})
			} else {
				emit(event{Event: "echo", Payload: payload})
			}
		case "stop":
			return
		default:
			emit(event{Event: "error", Detail: "unknown operation: " + cmd.Op})
		}
	}
	if err := scanner.Err(); err != nil {
		fatal(err)
	}
}

func echo(ctx context.Context, node host.Host, address string, payload string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, echoTimeout)
	defer cancel()

	addr, err := multiaddr.NewMultiaddr(address)
	if err != nil {
		return "", err
	}
	info, err := peer.AddrInfoFromP2pAddr(addr)
	if err != nil {
		return "", err
	}
	// Force a fresh connection so this half of the gate exercises go-libp2p
	// as the TCP and Noise initiator, not merely a second stream on the
	// connection minip2p opened earlier.
	if err := node.Network().ClosePeer(info.ID); err != nil {
		return "", fmt.Errorf("closing existing connection: %w", err)
	}
	if err := node.Connect(ctx, *info); err != nil {
		return "", err
	}
	stream, err := node.NewStream(ctx, info.ID, echoProtocol)
	if err != nil {
		return "", err
	}
	defer stream.Close()
	if err := stream.SetDeadline(time.Now().Add(echoTimeout)); err != nil {
		return "", err
	}
	written, err := io.Copy(stream, strings.NewReader(payload))
	if err != nil {
		return "", err
	}
	if written != int64(len(payload)) {
		return "", fmt.Errorf("short stream write: wrote %d of %d bytes", written, len(payload))
	}
	if err := stream.CloseWrite(); err != nil {
		return "", err
	}
	response, err := io.ReadAll(io.LimitReader(stream, maxEchoBytes+1))
	if err != nil {
		return "", err
	}
	if len(response) > maxEchoBytes {
		return "", fmt.Errorf("echo response exceeds %d bytes", maxEchoBytes)
	}
	return string(response), nil
}

func emit(value event) {
	if err := json.NewEncoder(os.Stdout).Encode(value); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	_ = json.NewEncoder(os.Stdout).Encode(event{Event: "error", Detail: err.Error()})
	os.Exit(1)
}
