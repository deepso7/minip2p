/**
 * The minip2p wasm module (`crates/web`) and its one-time initialisation.
 * Nothing here fetches on import: `@minip2p/web` initialises at its own
 * import, `@minip2p/web/manual` when the host calls `initMinip2p`.
 */

import init, * as glue from "../wasm/minip2p_web.js";
import type { InitInput } from "../wasm/minip2p_web.js";

/** Where the `.wasm` comes from: a URL, a `Response`, its bytes, or a compiled module. */
export type WasmSource = InitInput | Promise<InitInput>;

let loading: Promise<void> | undefined;
let loaded = false;

const instantiate = async (source: WasmSource | undefined): Promise<void> => {
  // wasm-bindgen fetches a string or URL only when it is passed directly,
  // so a promised one is awaited here first.
  await init(
    source === undefined ? undefined : { module_or_path: await source }
  );
  loaded = true;
};

/**
 * Instantiates the module once; later calls share the first that succeeds.
 * Without `source`, the `.wasm` beside this package is fetched (resolved
 * from `import.meta.url`). A failed load can be retried, with another source.
 */
export const loadWasm = async (source?: WasmSource): Promise<void> => {
  loading ??= instantiate(source);
  try {
    await loading;
  } catch (error) {
    loading = undefined;
    throw error;
  }
};

/** The initialised module's exports; throws until {@link loadWasm} resolved. */
export const wasm = (): typeof glue => {
  if (!loaded) {
    throw new Error(
      "minip2p's wasm module is not initialised: import @minip2p/web, or await initMinip2p() from @minip2p/web/manual before creating an endpoint"
    );
  }
  return glue;
};
