# react-native-minip2p

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
pnpm add react-native-minip2p
```

The ubrn runtime packages are regular dependencies of this package and are version-locked to the compatible UniFFI 0.31 toolchain.

## Usage

```ts
import {
  MiniP2p,
  generateSecretKey,
  P2pEvent_Tags,
} from "react-native-minip2p";

const endpoint = MiniP2p.create({
  secretKey: generateSecretKey(),
  mdns: true,
  protocols: ["/example/files/1"],
});

const unsubscribe = endpoint.on((event) => {
  if ("type" in event) {
    console.warn(`wrapper queue dropped ${event.dropped} events`);
  } else if (event.tag === P2pEvent_Tags.PeerReady) {
    console.log("peer ready", event.inner.peerId);
  }
});

endpoint.subscribe("/example/chat/1");
endpoint.publish("/example/chat/1", "hello from React Native");

endpoint.ping("remote-peer-id");
const streamId = endpoint.openStream("remote-peer-id", "/example/files/1");
endpoint.sendStream("remote-peer-id", streamId, new Uint8Array([1, 2, 3]));
endpoint.closeStreamWrite("remote-peer-id", streamId);

// Signal AppState changes before foreground queries or reconnect work.
endpoint.setActive(false);
endpoint.setActive(true);

unsubscribe();
endpoint.close();
```

`MiniP2p.create` constructs and starts the native driver. Event buffering, waits, typed errors, and the rest of the public SDK behavior come from `@minip2p/core`; this package owns only React Native loading and conversion. Attach handlers in the same synchronous JavaScript turn; immediate native callbacks are buffered until the next microtask.

Configuration defaults to gossipsub, signed messages, no relay, and no discovery. Set `pubsubRouter` to `PubsubRouter.Floodsub` when interoperability requires floodsub. mDNS requires local-network/multicast permissions in the host app; Expo Go cannot provide the native module, so use the included Expo development-build workflow.

## Wrapper contracts

- Generated Rust `u64` values are checked before conversion from `bigint` to JavaScript `number`. Values outside the safe integer range throw.
- Native events are delivered FIFO through a 4096-entry host queue, in batches of 256. Overflow first coalesces replaceable state, then discards the oldest pubsub-message or stream-data payload, and only then discards another lifecycle event.
- Wrapper overflow is delivered out of band as `{ type: 'queueOverflow', dropped }`. Native `EventsDropped` remains a normal generated event. On either signal, refresh connected peers, known peers, reachability, and the active reservation from queries.
- Path events are advisory because the native API has no per-peer current-path query. Reset path badges to unknown after overflow.
- Event subscribers and `waitFor` observers do not consume events from each other. An exception in one handler does not interrupt other handlers or unwind through the Rust callback.
- `close` rejects pending waits, suppresses queued callbacks, requests native shutdown, and destroys the UniFFI object. A host needing the native stopped barrier can import the generated low-level API from `react-native-minip2p/native`.
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

Per-PR CI checks the frozen pnpm install, types, Ultracite's Oxlint/Oxfmt rules, package build, and a whole-worktree regeneration diff. A weekly and manually dispatchable native workflow builds both Android ABIs and both iOS slices, validates Android 16 KiB ELF/APK alignment and allocator-hook visibility, checks the XCFramework slices, and uploads the artifacts. Native sizes are compared with `native-size-baseline.json`; growth over 20% emits a warning rather than failing the build.

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
