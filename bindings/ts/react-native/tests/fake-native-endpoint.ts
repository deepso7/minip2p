/* oxlint-disable class-methods-use-this -- The fake mirrors the generated endpoint surface; methods no test reaches throw by name. */
/** In-memory stand-in for the UniFFI `P2pEndpoint` used by adapter tests. */

import { vi } from "vitest";

import { CloseOutcome } from "../src/generated/minip2p_ffi_core";
import type {
  ConnectionInfo,
  ConnectTarget,
  OpenStreamResult,
  P2pEndpointLike,
  P2pEvent,
  P2pEventDoorbell,
  Reachability,
} from "../src/native";

/**
 * Hand-written stand-in for a generated event class instance. The adapter
 * only reads `tag` and `inner`, so tests enqueue plain literals. A field-less
 * variant has no `inner`.
 */
export interface FakeEvent {
  readonly tag: string;
  readonly inner?: Readonly<Record<string, unknown>>;
}

const notFaked = (method: keyof P2pEndpointLike): never => {
  throw new Error(`FakeNativeEndpoint does not fake ${method}`);
};

/**
 * Implements the full generated endpoint surface so interface drift fails
 * `typecheck`. Only the methods the adapter tests reach have behavior; the
 * rest throw by name so an unexpected call is loud rather than "not a
 * function".
 */
export class FakeNativeEndpoint implements P2pEndpointLike {
  static latest: FakeNativeEndpoint | undefined;
  /** Error the next constructor call throws, as native config validation would. */
  static constructError: Error | undefined;

  /** Native config passed to the most recent constructor. */
  readonly config: unknown;
  readonly drainLimits: number[] = [];
  /** Native identities returned by the next `openStream` call. */
  nextStream = { connId: 1n, streamId: 1n };
  /** Native verdict returned by `reachability`. */
  nativeReachability: Reachability | undefined = undefined;
  /** Native discovery clock returned by `discoveryNowMs`. */
  discoveryNow: bigint | undefined = undefined;
  /** Targets passed to `connect`, in call order. */
  readonly connectTargets: ConnectTarget[] = [];
  /** Connect IDs passed to `cancelConnect`, in call order. */
  readonly cancelledConnects: bigint[] = [];
  /** Connect ID returned by the next `connect` call. */
  nextConnectId = 30n;
  /** Error thrown by every `publish` call, when set. */
  publishError: Error | undefined = undefined;
  /** Value returned by `connectionInfo` for every peer. */
  connection: ConnectionInfo | undefined = undefined;
  /** When set, `sendStream` rejects every other connection. */
  liveConnId: bigint | undefined = undefined;
  /** Writes `sendStream` accepted, in call order. */
  readonly writes: { connId: bigint; streamId: bigint }[] = [];
  /** Bytes `sendStream` received, in call order. */
  readonly writtenData: Uint8Array[] = [];
  /** `streamConsumed` calls, in call order. */
  readonly consumed: { bytes: number; connId: bigint; streamId: bigint }[] = [];
  /** `abandonStream` calls, in call order. */
  readonly abandoned: { connId: bigint; streamId: bigint }[] = [];
  /** `stop` timeouts in milliseconds, in call order. */
  readonly stopTimeouts: number[] = [];
  /** What the `EndpointClosed` a started endpoint's `stop` queues reports. */
  closeReport: {
    outcome: CloseOutcome;
    unfinished: { connId: bigint; peerId?: string }[];
  } = {
    outcome: CloseOutcome.Drained,
    unfinished: [],
  };
  readonly #batches: FakeEvent[][] = [];
  #doorbell: P2pEventDoorbell | undefined;

  constructor(_secretKey?: Uint8Array, config?: unknown) {
    const error = FakeNativeEndpoint.constructError;
    if (error !== undefined) {
      FakeNativeEndpoint.constructError = undefined;
      throw error;
    }
    this.config = config;
    FakeNativeEndpoint.latest = this;
  }

  /** Returns the endpoint constructed by the most recent `Minip2p.create`. */
  static current(): FakeNativeEndpoint {
    if (FakeNativeEndpoint.latest === undefined) {
      throw new Error("native endpoint was not constructed");
    }
    return FakeNativeEndpoint.latest;
  }

  enqueue(...batches: FakeEvent[][]): void {
    this.#batches.push(...batches);
  }

  ring(): void {
    this.#doorbell?.onEventsReady();
  }

  start(doorbell: P2pEventDoorbell): void {
    this.#doorbell = doorbell;
  }

  drainEvents(limit: number): P2pEvent[] {
    this.drainLimits.push(limit);
    return (this.#batches.shift() ?? []) as unknown as P2pEvent[];
  }

  openStream(): OpenStreamResult {
    return this.nextStream;
  }

  discoveryNowMs(): bigint | undefined {
    return this.discoveryNow;
  }

  /** Queues `closeReport` as the driver's last event, as native does. */
  stop(timeoutMs: bigint): void {
    this.stopTimeouts.push(Number(timeoutMs));
    if (this.#doorbell !== undefined && this.stopTimeouts.length === 1) {
      this.enqueue([{ inner: this.closeReport, tag: "EndpointClosed" }]);
      this.ring();
    }
  }

  uniffiDestroy(): void {
    this.#batches.length = 0;
  }

  abandonStream(connId: bigint, streamId: bigint): void {
    this.abandoned.push({ connId, streamId });
  }

  activeReservation(): never {
    return notFaked("activeReservation");
  }

  addProtocol(): never {
    return notFaked("addProtocol");
  }

  cancelConnect(id: bigint): void {
    this.cancelledConnects.push(id);
  }

  closeStreamWrite(): never {
    return notFaked("closeStreamWrite");
  }

  connect(target: ConnectTarget): bigint {
    this.connectTargets.push(target);
    const id = this.nextConnectId;
    this.nextConnectId += 1n;
    return id;
  }

  connectedPeers(): never {
    return notFaked("connectedPeers");
  }

  connectionInfo(): ConnectionInfo | undefined {
    return this.connection;
  }

  disconnect(): never {
    return notFaked("disconnect");
  }

  isPeerReady(): never {
    return notFaked("isPeerReady");
  }

  isRunning(): never {
    return notFaked("isRunning");
  }

  knownPeers(): never {
    return notFaked("knownPeers");
  }

  listenAddrs(): never {
    return notFaked("listenAddrs");
  }

  path(): never {
    return notFaked("path");
  }

  peerId(): never {
    return notFaked("peerId");
  }

  peerInfo(): never {
    return notFaked("peerInfo");
  }

  ping(): never {
    return notFaked("ping");
  }

  publish(): void {
    throw this.publishError ?? notFaked("publish");
  }

  reachability(): Reachability {
    if (this.nativeReachability === undefined) {
      return notFaked("reachability");
    }
    return this.nativeReachability;
  }

  resetStream(): never {
    return notFaked("resetStream");
  }

  streamConsumed(connId: bigint, streamId: bigint, bytes: bigint): void {
    this.consumed.push({ bytes: Number(bytes), connId, streamId });
  }

  sendStream(connId: bigint, streamId: bigint, data: ArrayBuffer): boolean {
    if (this.liveConnId !== undefined && connId !== this.liveConnId) {
      throw new Error(
        `stream ${streamId} on connection ${connId} is not active`
      );
    }
    this.writes.push({ connId, streamId });
    this.writtenData.push(new Uint8Array(data));
    return true;
  }

  setActive(): never {
    return notFaked("setActive");
  }

  subscribe(): never {
    return notFaked("subscribe");
  }

  unsubscribe(): never {
    return notFaked("unsubscribe");
  }

  waitStopped(): never {
    return notFaked("waitStopped");
  }
}

/** Factory for `vi.mock("../src/native", nativeModuleMock)`. */
export const nativeModuleMock = async () => {
  const generated = await import("../src/generated/minip2p_ffi_core");
  return {
    CloseOutcome: generated.CloseOutcome,
    ConfigCapability: generated.ConfigCapability,
    ConnectTarget: generated.ConnectTarget,
    DiscoverySource: generated.DiscoverySource,
    DriverFailureKind: generated.DriverFailureKind,
    EndpointErrorKind: generated.EndpointErrorKind,
    FfiError_Tags: generated.FfiError_Tags,
    MdnsFailureKind: generated.MdnsFailureKind,
    NatErrorKind: generated.NatErrorKind,
    P2pEndpoint: FakeNativeEndpoint,
    Reachability: generated.Reachability,
    TimeoutLimit: generated.TimeoutLimit,
    WindowLimit: generated.WindowLimit,
    circuitAddress: vi.fn(),
    generateSecretKey: vi.fn(),
    peerIdFromSecretKey: vi.fn(),
  };
};
