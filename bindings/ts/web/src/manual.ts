/**
 * `@minip2p/web/manual`: the same API as `@minip2p/web`, without loading
 * the wasm module at import. For hosts that serve the `.wasm` themselves (a
 * CDN, a strict CSP): `await initMinip2p({ wasm })` before
 * `Minip2p.create`, which throws until it has resolved.
 */

export * from "@minip2p/core";
export {
  Minip2p,
  circuitAddress,
  generateSecretKey,
  initMinip2p,
  peerIdFromSecretKey,
  type InitMinip2pOptions,
} from "./sdk.js";
export { type WasmSource } from "./wasm.js";
