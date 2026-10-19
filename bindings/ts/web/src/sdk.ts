/* oxlint-disable func-style, max-classes-per-file, no-use-before-define -- Hoisted helpers keep the public entry points first. */

/**
 * The implementation both entry points share: `Minip2p` over the wasm
 * module's `WebEndpoint`, the key helpers, and `initMinip2p`.
 */

import {
  ClosedError,
  DriverFailedError,
  DriverFailureKind,
  Minip2pBase,
} from "@minip2p/core";
import type { Bytes, Minip2pConfig } from "@minip2p/core";
import { resolveEndpointConfig } from "@minip2p/core/backend";
import type { Minip2pBackend } from "@minip2p/core/backend";
import { SerdeBackend, typedNativeCall } from "@minip2p/core/serde-backend";

import { JsIo } from "./io.js";
import { loadWasm, wasm } from "./wasm.js";
import type { WasmSource } from "./wasm.js";

/** Options for {@link initMinip2p}. */
export interface InitMinip2pOptions {
  /**
   * The `.wasm`: a URL, a `Response`, its bytes, or a compiled
   * `WebAssembly.Module`. Defaults to the file beside the package.
   */
  readonly wasm?: WasmSource;
}

/**
 * Loads minip2p's wasm module. `@minip2p/web` calls it at import;
 * `@minip2p/web/manual` leaves it to the host, which must await it before
 * `Minip2p.create`. Safe to call again: later calls share the first load
 * that succeeds, and a failed load can be retried.
 */
export async function initMinip2p(
  options: InitMinip2pOptions = {}
): Promise<void> {
  await loadWasm(options.wasm);
}

/** High-level browser owner for one minip2p endpoint. */
export class Minip2p extends Minip2pBase {
  private constructor(backend: Minip2pBackend, relays: readonly string[]) {
    super(backend, relays);
  }

  /** Constructs and starts a browser endpoint. */
  static create(config: Minip2pConfig): Minip2p {
    return new Minip2p(webBackend(config), config.relays ?? []);
  }
}

/** Generates a new 32-byte Ed25519 secret key with `crypto.getRandomValues`. */
export function generateSecretKey(): Uint8Array {
  return typedNativeCall(() => wasm().generateSecretKey());
}

/** Derives a peer ID from raw Ed25519 secret key material. */
export function peerIdFromSecretKey(secretKey: Bytes): string {
  return typedNativeCall(() =>
    wasm().peerIdFromSecretKey(toUint8Array(secretKey))
  );
}

/** Builds a circuit multiaddress through a direct relay address. */
export function circuitAddress(relayAddress: string, peerId: string): string {
  return typedNativeCall(() => wasm().circuitAddress(relayAddress, peerId));
}

/** Polls a batch of rounds back to back before yielding the event loop. */
const PUMP_ROUNDS = 64;

/**
 * Drives the wasm endpoint on the page's event loop: one coalesced
 * microtask per burst of calls and I/O events, at most {@link PUMP_ROUNDS}
 * polls before yielding with `setTimeout(0)`, and one re-armed timer for
 * the endpoint's next deadline.
 */
class Pump {
  readonly #poll: () => number | undefined;
  #queued = false;
  #timer: ReturnType<typeof setTimeout> | undefined;
  #stopped = false;

  /**
   * `poll` pumps once and returns the delay until the next pump; a throw
   * stops the pump for good.
   */
  constructor(poll: () => number | undefined) {
    this.#poll = poll;
  }

  schedule(): void {
    if (this.#queued || this.#stopped) {
      return;
    }
    this.#queued = true;
    queueMicrotask(() => {
      this.#run();
    });
  }

  stop(): void {
    this.#stopped = true;
    clearTimeout(this.#timer);
  }

  #run(): void {
    this.#queued = false;
    clearTimeout(this.#timer);
    this.#timer = undefined;
    for (let round = 0; round < PUMP_ROUNDS && !this.#stopped; round += 1) {
      let delay: number | undefined;
      try {
        delay = this.#poll();
      } catch {
        // The endpoint failed, and its owner already reported it.
        this.stop();
        return;
      }
      if (delay === undefined) {
        return;
      }
      if (delay > 0) {
        this.#arm(delay);
        return;
      }
    }
    // Still busy: let the page run, then carry on.
    this.#arm(0);
  }

  #arm(delay: number): void {
    if (this.#stopped) {
      return;
    }
    this.#timer = setTimeout(() => {
      this.#timer = undefined;
      this.schedule();
    }, delay);
  }
}

/**
 * Calls into one wasm instance. A trap (`WebAssembly.RuntimeError`, which a
 * Rust panic becomes on wasm32) leaves the instance unusable: the call that
 * hit it throws `DriverFailedError`, `onFail` fails the endpoint, and every
 * later call throws `ClosedError` without touching wasm again.
 */
class WasmCalls {
  readonly #onFail: (detail: string) => void;
  /** Trapped, or the instance was freed. */
  #failed = false;

  constructor(onFail: (detail: string) => void) {
    this.#onFail = onFail;
  }

  call<T>(operation: () => T): T {
    if (this.#failed) {
      throw new ClosedError();
    }
    try {
      return operation();
    } catch (error) {
      if (!(error instanceof WebAssembly.RuntimeError)) {
        throw error;
      }
      this.#failed = true;
      const detail = `the minip2p wasm module trapped: ${error.message}`;
      this.#onFail(detail);
      throw new DriverFailedError(DriverFailureKind.Panic, detail);
    }
  }

  /** Runs `free` unless the instance trapped; later calls throw `ClosedError`. */
  release(free: () => void): void {
    if (!this.#failed) {
      this.#failed = true;
      free();
    }
  }
}

function webBackend(config: Minip2pConfig): Minip2pBackend {
  const module = wasm();
  const calls = new WasmCalls((detail) => {
    pump.stop();
    backend.fail(detail);
  });
  const pump = new Pump(() => calls.call(() => endpoint.pump()));
  const io = new JsIo(() => {
    pump.schedule();
  });
  const endpoint = typedNativeCall(
    () =>
      new module.WebEndpoint(
        toUint8Array(config.secretKey),
        resolveEndpointConfig(config),
        io
      )
  );
  const backend = new SerdeBackend(endpoint, {
    // Every command may queue work (a dial, a write): pump after it.
    call: (operation) => {
      try {
        return calls.call(operation);
      } finally {
        pump.schedule();
      }
    },
    circuitAddress,
    // Closed and drained: stop pumping and free the wasm object, which
    // drops its doorbell and `JsIo`.
    release: () => {
      pump.stop();
      calls.release(() => {
        endpoint.free();
      });
    },
    schedule: (task) => {
      queueMicrotask(task);
    },
  });
  return backend;
}

/** A view wasm-bindgen copies into wasm memory before the call returns. */
function toUint8Array(value: Bytes): Uint8Array {
  return value instanceof Uint8Array ? value : new Uint8Array(value);
}
