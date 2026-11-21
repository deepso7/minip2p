# Browser e2e harness: localhost, one worker, and the relay pipe

The Playwright suite for `@minip2p/web` (`bindings/ts/web/e2e`, `playwright.config.ts`) runs Chromium and Firefox against native nodes. Its setup follows these constraints:

- **Served from `localhost`.** `e2e/server.mjs` serves the page and the built `@minip2p/core` and `@minip2p/web` (behind an import map) from `localhost`. `localhost` is a secure context, so `WebTransport` is available, and Chrome's Local Network Access never prompts.
- **One worker.** The native peers bind real sockets, so `workers: 1` keeps one browser running at a time.
- **The relay's stdout is drained.** `startRelay` reads the relay-server example's log until it has the addresses, then calls `stdout.resume()`. Without that, the relay blocks once the pipe fills.
- **Native-to-browser circuit connects settle on Identify.** The browser offers no DCUtR with the default config, so a native `connect` to a browser behind a relay settles `Relayed` as soon as Identify arrives instead of waiting out DCUtR's 10 s start timeout. The test asserts it settles in under 5 s.
- **Derived WebTransport certificates are deterministic.** They derive from the node key and the rotation period, so a node restarted with the same key and port advertises the same certhash address. The restart test depends on this.
