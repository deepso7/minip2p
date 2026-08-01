# @minip2p/react-native

React Native bindings for [minip2p](https://minip2p.com), with the platform-neutral `@minip2p/core` API and bundled Android and iOS libraries.

The package is pre-1.0 and may introduce breaking changes between releases.

## Requirements

- React Native 0.85 with the New Architecture and Hermes
- iOS 15.1 or newer
- Android API 24 or newer

Expo Go cannot load custom Rust and C++ native libraries. Expo projects must use a [development build](https://docs.expo.dev/develop/development-builds/introduction/).

## Installation

```sh
pnpm add @minip2p/react-native
```

Rebuild the native app after installing the package.

## Usage

```ts
import { Minip2p, generateSecretKey } from "@minip2p/react-native";

const endpoint = Minip2p.create({
  secretKey: generateSecretKey(),
  mdns: true,
  protocols: ["/example/files/1"],
});

const unsubscribe = endpoint.on("peerReady", ({ peerId }) => {
  console.log("peer ready", peerId);
});

endpoint.subscribe("/example/chat/1");
endpoint.publish("/example/chat/1", "hello");

const path = await endpoint.connectAddr(remoteAddress);
await endpoint.waitPeerReady(path.peerId);
const rttMs = await endpoint.ping(path.peerId);

const stream = await endpoint.openStream(path.peerId, "/example/files/1");
stream.write(new Uint8Array([1, 2, 3]));
stream.closeWrite();

unsubscribe();
endpoint.close();
```

`Minip2p.create` starts the native driver. `useMinip2p` manages an endpoint for a React component, while `bindAppState` keeps its foreground state synchronized.

Configuration defaults to gossipsub with signed messages and no relay or discovery. Set `mdns: true` for local discovery and ensure the host app has local-network and multicast permissions.

## Important behavior

- Operations support timeouts and `AbortSignal` cancellation.
- Native events are delivered FIFO through a bounded queue; handle `queueOverflow` by refreshing queryable state.
- Use a named `stream` handler to claim inbound streams.
- Unsigned pubsub payloads and peer IDs are attacker-controlled.
- `close()` rejects pending work, closes streams, and releases the native endpoint.

## License

MIT
