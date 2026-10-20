/* oxlint-disable class-methods-use-this, no-empty-function -- A contract-complete native double implements inert endpoint methods directly. */

import type { Reachability } from "../../core/src/index.js";
import type {
  NativeConnectionInfo,
  NativeEvent,
  NativeIdentifyInfo,
  NativeKnownPeerInfo,
  NativeOpenStream,
  NativePathKind,
  SerdeEndpoint,
} from "../../core/src/serde-backend.js";
import type {
  FakeNativeState,
  NativeEventLiteral,
} from "./adapter-contract.js";

/**
 * A scriptable native endpoint in the serde shape, standing in for the Node
 * addon's `NodeEndpoint` or the wasm module's `WebEndpoint` behind the
 * shared serde backend.
 */
export class FakeSerdeEndpoint implements SerdeEndpoint {
  /** The most recently constructed fake. */
  static latest: FakeSerdeEndpoint | undefined;
  /** Error the next constructor call throws, as native validation would. */
  static constructError: Error | undefined;

  readonly config: unknown;
  readonly abandonedStreams: { connId: bigint; streamId: bigint }[] = [];
  readonly writes: { connId: bigint; streamId: bigint }[] = [];
  /** Bytes `sendStream` received, in call order. */
  readonly writtenData: Uint8Array[] = [];
  readonly consumed: { bytes: number; connId: bigint; streamId: bigint }[] = [];
  readonly cancelledConnects: bigint[] = [];
  readonly connectTargets: (string | string[])[] = [];
  readonly drainLimits: number[] = [];
  /** `close` timeouts, in call order. */
  readonly closeTimeouts: number[] = [];
  /** What the `EndpointClosed` a started endpoint's `close` queues reports. */
  closeReport: {
    outcome: string;
    unfinished: { connId: bigint; peerId?: string }[];
  } = { outcome: "Drained", unfinished: [] };
  liveConnId: bigint | undefined;
  connection: NativeConnectionInfo | null = null;
  identify: NativeIdentifyInfo | null = null;
  nextStream: NativeOpenStream = { connId: 10n, streamId: 20n };
  discoveryClock: bigint | null = null;
  abandonError: Error | undefined;
  onDrain: ((call: number) => void) | undefined;
  nextConnectId = 30n;
  readonly #batches: NativeEvent[][] = [];
  #doorbell: (() => void) | undefined;
  #drainCalls = 0;

  constructor(_secretKey: Uint8Array, config: unknown) {
    const error = FakeSerdeEndpoint.constructError;
    if (error !== undefined) {
      FakeSerdeEndpoint.constructError = undefined;
      throw error;
    }
    this.config = config;
    FakeSerdeEndpoint.latest = this;
  }

  /** Queues native drain batches, oldest first. */
  enqueue(...batches: readonly (readonly unknown[])[]): void {
    // Scripted events are deliberately loose, malformed ones included.
    this.#batches.push(...(batches as NativeEvent[][]));
  }

  /** Rings the doorbell the backend registered. */
  ring(): void {
    this.#doorbell?.();
  }

  start(doorbell: () => void): void {
    this.#doorbell = doorbell;
  }

  drainEvents(limit: number): NativeEvent[] {
    this.drainLimits.push(limit);
    this.#drainCalls += 1;
    this.onDrain?.(this.#drainCalls);
    return this.#batches.shift() ?? [];
  }

  /** Queues `closeReport` as the driver's last event, as native does. */
  close(timeoutMs: number): void {
    this.closeTimeouts.push(timeoutMs);
    if (this.#doorbell !== undefined && this.closeTimeouts.length === 1) {
      this.enqueue([{ inner: this.closeReport, tag: "EndpointClosed" }]);
      this.ring();
    }
  }

  discoveryNowMs(): bigint | null {
    return this.discoveryClock;
  }

  activeReservation(): null {
    return null;
  }

  addProtocol(): void {}

  abandonStream(connId: bigint, streamId: bigint): void {
    this.abandonedStreams.push({ connId, streamId });
    if (this.abandonError !== undefined) {
      throw this.abandonError;
    }
  }

  cancelConnect(connectId: bigint): void {
    this.cancelledConnects.push(connectId);
  }

  closeStreamWrite(): void {}

  connect(target: string | string[]): bigint {
    this.connectTargets.push(target);
    const id = this.nextConnectId;
    this.nextConnectId += 1n;
    return id;
  }

  connectedPeers(): string[] {
    return [];
  }

  connectionInfo(): NativeConnectionInfo | null {
    return this.connection;
  }

  disconnect(): void {}

  isPeerReady(): boolean {
    return false;
  }

  isRunning(): boolean {
    return true;
  }

  knownPeers(): NativeKnownPeerInfo[] {
    return [];
  }

  listenAddrs(): string[] {
    return [];
  }

  openStream(): NativeOpenStream {
    return this.nextStream;
  }

  path(): NativePathKind | null {
    return null;
  }

  peerId(): string {
    return "local";
  }

  peerInfo(): NativeIdentifyInfo | null {
    return this.identify;
  }

  ping(): void {}

  publish(): void {}

  reachability(): Reachability {
    return "Private";
  }

  resetStream(): void {}

  streamConsumed(connId: bigint, streamId: bigint, bytes: number): void {
    this.consumed.push({ bytes, connId, streamId });
  }

  sendStream(connId: bigint, streamId: bigint, data: Uint8Array): boolean {
    if (this.liveConnId !== undefined && connId !== this.liveConnId) {
      throw new Error(
        `stream ${streamId} on connection ${connId} is not active`
      );
    }
    this.writes.push({ connId, streamId });
    this.writtenData.push(data);
    return true;
  }

  setActive(): void {}

  subscribe(): boolean {
    return true;
  }

  unsubscribe(): boolean {
    return true;
  }
}

/** The latest fake, for a test that just created an endpoint. */
export const latestFakeSerdeEndpoint = (): FakeSerdeEndpoint => {
  const fake = FakeSerdeEndpoint.latest;
  if (fake === undefined) {
    throw new Error("native endpoint was not constructed");
  }
  return fake;
};

/** The adapter-contract view of a {@link FakeSerdeEndpoint}. */
export const serdeContractNative = (
  fake: FakeSerdeEndpoint
): FakeNativeState => ({
  abandoned: fake.abandonedStreams,
  cancelledConnects: fake.cancelledConnects,
  closeTimeouts: fake.closeTimeouts,
  config: fake.config,
  connectTargets: fake.connectTargets.map((target) =>
    typeof target === "string"
      ? { kind: "peer" as const, peerId: target }
      : { addresses: target, kind: "addresses" as const }
  ),
  consumed: fake.consumed,
  deliver: (events: readonly NativeEventLiteral[]) => {
    // Serde shells hand bytes over as `Uint8Array`s, not `ArrayBuffer`s.
    fake.enqueue(
      events.map(({ inner, tag }) => ({
        inner: Object.fromEntries(
          Object.entries(inner).map(([key, value]) => [
            key,
            value instanceof ArrayBuffer ? new Uint8Array(value) : value,
          ])
        ),
        tag,
      })),
      []
    );
    fake.ring();
  },
  setCloseUnfinished: (unfinished) => {
    fake.closeReport.unfinished = [...unfinished];
  },
  setConnectionInfo: (info) => {
    fake.connection = info;
  },
  setLiveConnection: (connId) => {
    fake.liveConnId = connId;
  },
  setNextStream: (connId, streamId) => {
    fake.nextStream = { connId, streamId };
  },
  writes: fake.writes,
  writtenData: fake.writtenData,
});

/**
 * Makes the next {@link FakeSerdeEndpoint} throw a serde shell's
 * `InvalidConfig { capability: Transport }`.
 */
export const rejectNextSerdeTransportConfig = (detail: string): void => {
  FakeSerdeEndpoint.constructError = Object.assign(
    new Error(`invalid Transport configuration: ${detail}`),
    { capability: "Transport", code: "InvalidConfig", detail }
  );
};
