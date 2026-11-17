package main

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	coreevent "github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	"github.com/multiformats/go-multiaddr"
)

const (
	hopProtocol  = protocol.ID("/libp2p/circuit/relay/0.2.0/hop")
	relayTimeout = 30 * time.Second
)

// relayLimit is the duration and byte limit the relay must advertise on the
// reservation and on both circuit legs.
type relayLimit struct {
	duration time.Duration
	data     uint64
}

// runRelay is the circuit relay v2 client mode, invoked as
//
//	relay <relay-addr> <duration-secs> <byte-limit> [source-relay-addr]
//
// A destination host reserves on relay-addr and a source host dials it
// through source-relay-addr (another node of a relay mesh serving the same
// relay peer id, or by default the same relay). Both then ping each other
// across the circuit. It exits non-zero on the first failure.
func runRelay(args []string) error {
	if len(args) < 3 || len(args) > 4 {
		return fmt.Errorf("usage: relay <relay-addr> <duration-secs> <byte-limit> [source-relay-addr]")
	}
	relay, err := peer.AddrInfoFromString(args[0])
	if err != nil {
		return fmt.Errorf("relay address: %w", err)
	}
	seconds, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil {
		return fmt.Errorf("expected duration: %w", err)
	}
	data, err := strconv.ParseUint(args[2], 10, 64)
	if err != nil {
		return fmt.Errorf("expected byte limit: %w", err)
	}
	want := relayLimit{duration: time.Duration(seconds) * time.Second, data: data}
	sourceRelay := relay
	if len(args) == 4 {
		if sourceRelay, err = peer.AddrInfoFromString(args[3]); err != nil {
			return fmt.Errorf("source relay address: %w", err)
		}
		if sourceRelay.ID != relay.ID {
			return fmt.Errorf("both relay addresses must name the same relay peer id")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), relayTimeout)
	defer cancel()

	// The destination listens on /p2p-circuit so go-libp2p accepts the
	// relay's inbound STOP.
	destination, err := libp2p.New(libp2p.ListenAddrStrings("/p2p-circuit"))
	if err != nil {
		return err
	}
	defer destination.Close()
	identified, err := destination.EventBus().Subscribe(new(coreevent.EvtPeerIdentificationCompleted))
	if err != nil {
		return err
	}
	defer identified.Close()

	if err := destination.Connect(ctx, *relay); err != nil {
		return fmt.Errorf("connecting to the relay: %w", err)
	}
	if err := waitForHop(ctx, identified, relay.ID); err != nil {
		return err
	}
	reservation, err := client.Reserve(ctx, destination, *relay)
	if err != nil {
		return fmt.Errorf("reservation: %w", err)
	}
	got := relayLimit{duration: reservation.LimitDuration, data: reservation.LimitData}
	if got != want {
		return fmt.Errorf("reservation limit %+v, want %+v", got, want)
	}

	// No listeners; unlike libp2p.NoListenAddrs, this keeps the relay
	// transport enabled for the /p2p-circuit dial.
	source, err := libp2p.New(libp2p.ListenAddrStrings())
	if err != nil {
		return err
	}
	defer source.Close()
	circuit := sourceRelay.Addrs[0].
		Encapsulate(multiaddr.StringCast("/p2p/" + relay.ID.String() + "/p2p-circuit"))
	if err := source.Connect(ctx, peer.AddrInfo{ID: destination.ID(), Addrs: []multiaddr.Multiaddr{circuit}}); err != nil {
		return fmt.Errorf("relayed CONNECT: %w", err)
	}

	// Ping both ways, so bytes cross the circuit in each direction on
	// streams each side opened.
	if err := pingOnce(ctx, source, destination.ID()); err != nil {
		return fmt.Errorf("source ping: %w", err)
	}
	if err := pingOnce(ctx, destination, source.ID()); err != nil {
		return fmt.Errorf("destination ping: %w", err)
	}
	if err := checkCircuitLimit(source, destination.ID(), want); err != nil {
		return fmt.Errorf("outbound circuit: %w", err)
	}
	if err := checkCircuitLimit(destination, source.ID(), want); err != nil {
		return fmt.Errorf("inbound circuit: %w", err)
	}

	fmt.Printf("interop ok go-libp2p=v0.48.0 reservation=true identify_hop=true source_ping=true destination_ping=true outbound_limit=true inbound_limit=true duration_limit=%d byte_limit=%d\n", seconds, data)
	return nil
}

// waitForHop waits for Identify to complete with the relay and requires it
// to advertise the HOP protocol.
func waitForHop(ctx context.Context, identified coreevent.Subscription, relay peer.ID) error {
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for the relay's Identify: %w", ctx.Err())
		case value := <-identified.Out():
			completed := value.(coreevent.EvtPeerIdentificationCompleted)
			if completed.Peer != relay {
				continue
			}
			if !slices.Contains(completed.Protocols, hopProtocol) {
				return fmt.Errorf("relay Identify does not advertise %s", hopProtocol)
			}
			return nil
		}
	}
}

func pingOnce(ctx context.Context, node host.Host, target peer.ID) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	result := <-ping.Ping(ctx, node, target)
	return result.Error
}

// checkCircuitLimit requires a limited relayed connection to target whose
// STOP or HOP STATUS carried the expected limit.
func checkCircuitLimit(node host.Host, target peer.ID, want relayLimit) error {
	for _, conn := range node.Network().ConnsToPeer(target) {
		stat := conn.Stat()
		if !stat.Limited {
			continue
		}
		duration, _ := stat.Extra[client.StatLimitDuration].(time.Duration)
		data, _ := stat.Extra[client.StatLimitData].(uint64)
		got := relayLimit{duration: duration, data: data}
		if got != want {
			return fmt.Errorf("limit %+v, want %+v", got, want)
		}
		return nil
	}
	return fmt.Errorf("no limited relayed connection")
}
