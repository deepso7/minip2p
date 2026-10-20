/**
 * `@minip2p/web`: minip2p for the browser, with the same API as
 * `@minip2p/node`. Importing it loads the wasm module (the `.wasm` beside
 * the package, resolved from `import.meta.url`) with top-level `await`, so
 * `Minip2p.create` is ready to call. Use `@minip2p/web/manual` to load the
 * `.wasm` yourself.
 */

import { initMinip2p } from "./sdk.js";

await initMinip2p();

export * from "@minip2p/core";
export {
  Minip2p,
  circuitAddress,
  generateSecretKey,
  peerIdFromSecretKey,
} from "./sdk.js";
