/**
 * Types of the values the native addon returns. `minip2p-ffi-core` derives
 * them with serde (its `js_shape` module pins the representation), and the
 * SDK's backend types describe the same shape, so each native type is the
 * SDK type with napi-rs's value encoding: `u64` arrives as `number`, or as a
 * `bigint` above `u32::MAX`, and bytes arrive as a `Buffer`.
 *
 * The generated `addon.d.ts` imports these names through its header.
 */

import type {
  ConnectionInfo,
  IdentifyInfo,
  KnownPeerInfo,
  RelayReservationInfo,
} from "@minip2p/core";
import type {
  BackendOpenStream,
  P2pEvent,
  PathKind,
} from "@minip2p/core/backend";

/** One SDK backend value as the addon encodes it. */
export type NativeShape<Value> = Value extends ArrayBuffer
  ? Uint8Array
  : Value extends number
    ? number | bigint
    : Value extends string | boolean
      ? Value
      : Value extends readonly (infer Item)[]
        ? readonly NativeShape<Item>[]
        : { readonly [Key in keyof Value]: NativeShape<Value[Key]> };

export type NativeEvent = NativeShape<P2pEvent>;
export type NativeIdentifyInfo = NativeShape<IdentifyInfo>;
export type NativeKnownPeerInfo = NativeShape<KnownPeerInfo>;
export type NativeRelayReservationInfo = NativeShape<RelayReservationInfo>;
export type NativeConnectionInfo = NativeShape<ConnectionInfo>;
export type NativeOpenStream = NativeShape<BackendOpenStream>;
export type NativePathKind = NativeShape<PathKind>;
export type { Reachability } from "@minip2p/core";
