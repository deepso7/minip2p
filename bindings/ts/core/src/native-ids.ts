import { StreamClosedError } from "./errors.js";

/**
 * Converts a native `u64` to a number, throwing when it leaves JavaScript's
 * safe integer range. Native integers arrive as `bigint` (UniFFI) or as
 * `number | bigint` (napi-rs, which only switches to `bigint` above
 * `u32::MAX`).
 */
export const u64ToNumber = (value: bigint | number, name: string): number => {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) {
    throw new RangeError(`${name} exceeds JavaScript's safe integer range`);
  }
  return number;
};

/**
 * Maps native `u64` connection identities to small public numbers.
 *
 * Native connection IDs span the full `u64` range, so they cannot round-trip
 * through a JavaScript `number`. Each endpoint owns one map so a native ID
 * resolves to the same public ID in events and synchronous results. Adapters
 * release an entry once its `ConnectionClosed`, or the `ConnectionReplaced`
 * that retires it, is normalized, which bounds the map by live connections.
 * Public numbers come from a counter that never repeats, so an event arriving
 * after the release gets a fresh number instead of aliasing a live connection.
 */
export class ConnectionIdMap {
  readonly #publicByNative = new Map<bigint, number>();
  readonly #nativeByPublic = new Map<number, bigint>();
  #next = 1;

  toPublic(native: bigint): number {
    const existing = this.#publicByNative.get(native);
    if (existing !== undefined) {
      return existing;
    }
    const publicId = this.#next;
    this.#next += 1;
    this.#publicByNative.set(native, publicId);
    this.#nativeByPublic.set(publicId, native);
    return publicId;
  }

  /**
   * The native ID behind a public one. Stream operations pass it back so
   * native rejects a stream whose connection it already replaced. A released
   * connection throws `StreamClosedError`: its stream operation can run after
   * the release but before the SDK dispatches the ending event.
   */
  toNative(publicId: number): bigint {
    const native = this.#nativeByPublic.get(publicId);
    if (native === undefined) {
      throw new StreamClosedError("The stream's connection ended");
    }
    return native;
  }

  release(publicId: number): void {
    const native = this.#nativeByPublic.get(publicId);
    if (native !== undefined) {
      this.#nativeByPublic.delete(publicId);
      this.#publicByNative.delete(native);
    }
  }
}
