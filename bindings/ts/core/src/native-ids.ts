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

/** How many released connection IDs stay resolvable for late events. */
const RETIRED_LIMIT = 64;

/**
 * Maps native `u64` connection identities to small public numbers.
 *
 * Native connection IDs span the full `u64` range, so they cannot round-trip
 * through a JavaScript `number`. Each endpoint owns one map so a native ID
 * resolves to the same public ID in events and synchronous results. Adapters
 * release an entry once its `ConnectionClosed`, or the `ConnectionReplaced`
 * that retires it, is normalized. Through {@link toPublicOrRetired}, a
 * released ID still resolves to its public number for the last
 * {@link RETIRED_LIMIT} releases, so a path event that names it as
 * `oldConnId` after the replacement (`PathUpgraded`, `InboundDirectUpgrade`)
 * matches the connection the app saw, while stream operations on it throw.
 * That bounds the map by live connections plus the retired window. Public
 * numbers come from a counter that never repeats, so an event arriving after
 * the window gets a fresh number instead of aliasing a live connection.
 */
export class ConnectionIdMap {
  readonly #publicByNative = new Map<bigint, number>();
  readonly #nativeByPublic = new Map<number, bigint>();
  /** Released IDs, oldest first, kept for later events that name them. */
  readonly #retired = new Map<bigint, number>();
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
   * Like {@link toPublic}, but a recently released ID keeps the public number
   * it had. For fields naming a connection that may already be gone
   * (`oldConnId`). A live mapping wins, and {@link toPublic} never reads the
   * retired ones, as native may reuse an ID after its close.
   */
  toPublicOrRetired(native: bigint): number {
    return (
      this.#publicByNative.get(native) ??
      this.#retired.get(native) ??
      this.toPublic(native)
    );
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
    if (native === undefined) {
      return;
    }
    this.#nativeByPublic.delete(publicId);
    this.#publicByNative.delete(native);
    this.#retired.set(native, publicId);
    if (this.#retired.size > RETIRED_LIMIT) {
      const [oldest] = this.#retired.keys();
      if (oldest !== undefined) {
        this.#retired.delete(oldest);
      }
    }
  }
}
