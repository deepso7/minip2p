/**
 * Types of the values the native addon returns: `minip2p-ffi-core`'s serde
 * shape, with napi-rs's value encoding (`u64` as `number`, or `bigint` above
 * `u32::MAX`; bytes as a `Buffer`). The shared serde backend defines them.
 *
 * The generated `addon.d.ts` imports these names through its header.
 */

export type {
  NativeConnectionInfo,
  NativeEvent,
  NativeIdentifyInfo,
  NativeKnownPeerInfo,
  NativeOpenStream,
  NativePathKind,
  NativeRelayReservationInfo,
} from "@minip2p/core/serde-backend";
export type { Reachability } from "@minip2p/core";
