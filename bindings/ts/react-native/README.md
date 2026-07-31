# @minip2p/react-native

React Native adapter for the platform-neutral `@minip2p/core` SDK, backed by a TurboModule generated with UniFFI and `uniffi-bindgen-react-native`.

The package is pre-1.0. Its JavaScript API, generated types, native ABI, and event variants may change between releases.

## Requirements

- React Native 0.85 with the New Architecture and Hermes
- Node.js 22 or newer
- pnpm 11.18
- Rust with the configured mobile targets
- Android SDK 36 and NDK 28.2.13676358
- Xcode 26 with an iOS deployment target of at least 15.1

The example uses Expo SDK 56 and `expo-dev-client`. Expo Go is not supported: it cannot load this package's Rust and C++ native libraries. Use `expo prebuild` followed by `expo run:android` or `expo run:ios`.

## Installation

```sh
pnpm add @minip2p/react-native
```

The ubrn runtime packages are regular dependencies of this package and are version-locked to the compatible UniFFI 0.31 toolchain.

## Usage

```ts
import { Minip2p, generateSecretKey } from "@minip2p/react-native";

const endpoint = Minip2p.create({
  secretKey: generateSecretKey(),
  mdns: true,
  protocols: ["/example/files/1"],
});

const unsubscribe = endpoint.on("peerReady", ({ peerId, protocols }) => {
  console.log("peer ready", peerId, protocols);
});

endpoint.subscribe("/example/chat/1");
endpoint.publish("/example/chat/1", "hello from React Native");

const result = await endpoint.connectAddr(remoteListenAddr);
await endpoint.waitPeerReady(result.peerId);
const rttMs = await endpoint.ping(result.peerId);
const stream = await endpoint.openStream(result.peerId, "/example/files/1");
stream.write(new Uint8Array([1, 2, 3]));
stream.closeWrite();

// Signal AppState changes before foreground queries or reconnect work.
endpoint.setActive(false);
endpoint.setActive(true);

unsubscribe();
endpoint.close();
```

`Minip2p.create` constructs and starts the native driver. Event buffering, typed waits, Promise operations, Stream handles, and public errors come from `@minip2p/core`; this package owns React Native loading and conversion. `useMinip2p` owns an endpoint for a committed component lifetime and `bindAppState` mirrors the current AppState immediately.

Configuration defaults to gossipsub, signed messages, no relay, and no discovery. Set `pubsubRouter` to `PubsubRouter.Floodsub` when interoperability requires floodsub. mDNS requires local-network/multicast permissions in the host app; Expo Go cannot provide the native module, so use the included Expo development-build workflow.

## Wrapper contracts

- Generated Rust `u64` values are checked before conversion from `bigint` to JavaScript `number`. Values outside the safe integer range throw.
- Native events are delivered FIFO through a bounded host queue. Overflow is a typed `queueOverflow` event; refresh queryable state when it occurs.
- Named event handlers receive flattened payloads. Catch-all handlers receive flattened discriminated events and safe inbound-stream metadata only.
- `handlerError` is queued after fan-out when an event handler throws.
- `path(peerId)` is authoritative for NAT-orchestrated paths and independent of event consumption.
- `close` rejects pending work, closes streams, destroys the UniFFI object, and then fires `onClose` once. A host needing the native stopped barrier can import the generated low-level API from `@minip2p/react-native/native`.
- Unsigned pubsub messages are explicitly untrusted. When `signed` is false, both payload and `fromPeerId` are attacker-controlled.

## Generation

Generated TypeScript, C++, Kotlin, Objective-C++, and React Native Codegen sources are committed. Do not edit them directly.

```sh
pnpm install --frozen-lockfile
pnpm ubrn:ios
pnpm ubrn:android
```

`uniffi`, `uniffi-bindgen-react-native`, and `@ubjs/core` must move together. The current exact versions are `0.31.0`, `0.31.0-3`, and `0.31.0-3`.

The pnpm patch in `patches/` fixes two ubrn 0.31 Android generator issues: package-root resolution under package exports and `jniLibs` resolution when CMake is included by an application.

Native binaries are build outputs and are not committed: `android/src/main/jniLibs/` and `build/*.xcframework`. Release packaging must run both native builds first; `pnpm pack` includes the resulting Android libraries and `build/Minip2pFfi.xcframework`.

Per-PR CI checks the frozen pnpm install, types, Ultracite's Oxlint/Oxfmt rules, package build, and a whole-worktree regeneration diff. A weekly and manually dispatchable native workflow builds both Android ABIs and both iOS slices, validates Android 16 KiB ELF/APK alignment and requires the allocator-hook symbols to be either optimized away or exactly three defined `LOCAL OBJECT` symbols, checks the XCFramework slices, and uploads the artifacts. Native sizes are compared with `native-size-baseline.json`; growth over 20% emits a warning rather than failing the build.

## Example development build

```sh
pnpm example prebuild
pnpm example android
pnpm example ios
```

The example's `android/` and `ios/` directories are generated by Expo and ignored. Its config plugin pins NDK r28c on every prebuild.

The app is an executable smoke suite, not a mock UI. It creates two native endpoints over loopback QUIC and checks:

- path establishment and a reentrant query from a callback;
- Unicode and 60 KiB signed pubsub payloads;
- listener-exception containment and waiter fan-out;
- active, idle, and foreground-transition query latency;
- close during event delivery, 50 create/close cycles, and reverse close order.

Use an Expo development build and Metro:

```sh
pnpm example start --dev-client --lan
```

The suite runs automatically and can be repeated from the app. Expo Go cannot run it because the minip2p TurboModule is compiled into the development build.

## License

MIT
