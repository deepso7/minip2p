/* oxlint-disable func-style, no-use-before-define -- Hoisted helpers keep the public entry points first. */

import { Minip2pBase } from "@minip2p/core";
import type { Bytes, Minip2pConfig } from "@minip2p/core";
import { resolveEndpointConfig } from "@minip2p/core/backend";
import type { Minip2pBackend } from "@minip2p/core/backend";
import { SerdeBackend, typedNativeCall } from "@minip2p/core/serde-backend";

import { nativeBinding } from "./native.js";

function nodeBackend(config: Minip2pConfig): Minip2pBackend {
  const endpoint = typedNativeCall(
    () =>
      new nativeBinding.NodeEndpoint(
        toUint8Array(config.secretKey),
        resolveEndpointConfig(config)
      )
  );
  return new SerdeBackend(endpoint, {
    circuitAddress,
    // One check-phase turn keeps native callbacks out of the caller's stack
    // without paying the timer granularity for every bounded batch.
    schedule: (task) => {
      setImmediate(task);
    },
  });
}

/** High-level Node.js owner for one native minip2p endpoint. */
export class Minip2p extends Minip2pBase {
  private constructor(backend: Minip2pBackend, relays: readonly string[]) {
    super(backend, relays);
  }

  /** Constructs and starts a Node.js endpoint. */
  static create(config: Minip2pConfig): Minip2p {
    return new Minip2p(nodeBackend(config), config.relays ?? []);
  }
}

/** Generates a new 32-byte Ed25519 secret key. */
export function generateSecretKey(): Uint8Array {
  return nativeBinding.generateSecretKey();
}

/** Derives a peer ID from raw Ed25519 secret key material. */
export function peerIdFromSecretKey(secretKey: Bytes): string {
  return typedNativeCall(() =>
    nativeBinding.peerIdFromSecretKey(toUint8Array(secretKey))
  );
}

/** Builds a circuit multiaddress through a direct relay address. */
export function circuitAddress(relayAddress: string, peerId: string): string {
  return typedNativeCall(() =>
    nativeBinding.circuitAddress(relayAddress, peerId)
  );
}

/** A view napi-rs can read; the addon copies it before the call returns. */
function toUint8Array(value: Bytes): Uint8Array {
  return value instanceof Uint8Array ? value : new Uint8Array(value);
}
