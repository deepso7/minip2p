/* oxlint-disable func-style, max-lines-per-function, max-statements -- One suite holds the shared runtime contract so both adapters run identical cases. */

import { afterEach, describe, expect, test, vi } from "vitest";

import type { BackendConnectTarget } from "../../core/src/backend.js";
import {
  ConnectCancelledError,
  ConnectResultLostError,
  StreamClosedError,
  TimeoutError,
} from "../../core/src/index.js";
import type { Minip2pBase, Minip2pConfig } from "../../core/src/index.js";

/** A native event literal; both fakes accept `{ tag, inner }` with bigints. */
export interface NativeEventLiteral {
  readonly tag: string;
  readonly inner: Readonly<Record<string, unknown>>;
}

/** Observable state of the fake native endpoint behind one adapter. */
export interface FakeNativeState {
  /** Config handed to the native constructor. */
  readonly config: unknown;
  /** Targets passed to native `connect`, in runtime-neutral form. */
  readonly connectTargets: readonly BackendConnectTarget[];
  /** Connect IDs passed to native `cancelConnect`. */
  readonly cancelledConnects: readonly bigint[];
  /** Makes native `connectionInfo` report `info` for every peer. */
  setConnectionInfo: (info: NativeConnectionInfo) => void;
  /** Makes the next native `openStream` return these identities. */
  setNextStream: (connId: bigint, streamId: bigint) => void;
  /** Queues one native drain batch and rings the doorbell. */
  deliver: (events: readonly NativeEventLiteral[]) => void;
  /**
   * Makes `connId` the peer's only live connection: native `sendStream`
   * then rejects any other connection, as a replacement native has not
   * reported yet would.
   */
  setLiveConnection: (connId: bigint) => void;
  /** Writes native `sendStream` accepted, in call order. */
  readonly writes: readonly NativeStreamRef[];
  /** Native `streamConsumed` calls, in call order. */
  readonly consumed: readonly NativeConsumed[];
}

/** One native `streamConsumed` call, in runtime-neutral form. */
export interface NativeConsumed extends NativeStreamRef {
  readonly bytes: number;
}

/** A native stream identity, in runtime-neutral form. */
export interface NativeStreamRef {
  readonly connId: bigint;
  readonly streamId: bigint;
}

/** A native `connectionInfo` snapshot, in runtime-neutral form. */
export interface NativeConnectionInfo {
  readonly connId: bigint;
  readonly remoteAddr?: string;
  readonly readyProtocols?: string[];
}

/** Adapts one runtime's `Minip2p.create` and native fake to the contract. */
export interface AdapterContractHarness {
  readonly create: (config?: Omit<Minip2pConfig, "secretKey">) => Minip2pBase;
  /** Fake native endpoint behind the most recently created endpoint. */
  readonly native: () => FakeNativeState;
}

const PEER = "12D3KooWPeer";
const QUIC = `/ip4/127.0.0.1/udp/4001/quic-v1/p2p/${PEER}`;
const TCP = `/ip4/127.0.0.1/tcp/4001/p2p/${PEER}`;
// Native connect IDs are small; connection IDs span the full u64 range.
const CONNECT_ID = 30n;
const CONN_ID = 2n ** 63n + 1n;
const NEXT_CONN_ID = 2n ** 63n + 2n;

const pathEstablished = (connectId: bigint): NativeEventLiteral => ({
  inner: {
    connId: CONN_ID,
    connectId,
    path: { tag: "DirectDialed" },
    peerId: PEER,
  },
  tag: "PathEstablished",
});

const drained = async (): Promise<void> => {
  await vi.runAllTimersAsync();
};

/**
 * Registers the behavior every TypeScript runtime must share: Connection
 * targets, Connect IDs, wait/timeout/abort/cancel semantics, delivery loss,
 * State getters, and native config defaults.
 */
export function describeAdapterContract(
  runtime: string,
  harness: AdapterContractHarness
): void {
  describe(`${runtime} adapter contract`, () => {
    afterEach(() => {
      vi.useRealTimers();
    });

    test("Connection targets reach native in one shape", () => {
      const endpoint = harness.create();

      endpoint.startConnect(PEER);
      endpoint.startConnect(QUIC);
      endpoint.startConnect([QUIC, TCP]);

      expect(harness.native().connectTargets).toEqual([
        { kind: "peer", peerId: PEER },
        { addresses: [QUIC], kind: "addresses" },
        { addresses: [QUIC, TCP], kind: "addresses" },
      ]);
      endpoint.close();
    });

    test("Connect IDs round-trip unchanged through events and cancellation", async () => {
      vi.useFakeTimers();
      const endpoint = harness.create();
      const native = harness.native();
      const connectId = endpoint.startConnect(PEER);
      const connecting = endpoint.waitConnectResult(connectId, {
        timeoutMs: 0,
      });

      native.deliver([pathEstablished(CONNECT_ID)]);
      await drained();
      endpoint.cancelConnect(connectId);

      expect(connectId).toBe(Number(CONNECT_ID));
      expect(await connecting).toEqual({
        connectId,
        path: { kind: "directDialed" },
        peerId: PEER,
      });
      expect(native.cancelledConnects).toEqual([CONNECT_ID]);
      endpoint.close();
    });

    test("a timeout ends only the wait; abort cancels and the terminal settles", async () => {
      vi.useFakeTimers();
      const endpoint = harness.create();
      const native = harness.native();
      const connectId = endpoint.startConnect(PEER);

      const timedOut = endpoint.waitConnectResult(connectId, { timeoutMs: 5 });
      const timedOutCheck =
        expect(timedOut).rejects.toBeInstanceOf(TimeoutError);
      await vi.advanceTimersByTimeAsync(5);
      await timedOutCheck;
      expect(native.cancelledConnects).toEqual([]);

      const controller = new AbortController();
      const aborted = endpoint.waitConnectResult(connectId, {
        signal: controller.signal,
        timeoutMs: 0,
      });
      const cancelled = expect(aborted).rejects.toBeInstanceOf(
        ConnectCancelledError
      );
      controller.abort();
      expect(native.cancelledConnects).toEqual([BigInt(connectId)]);

      native.deliver([
        {
          inner: { connectId: CONNECT_ID, peerId: PEER },
          tag: "ConnectCancelled",
        },
      ]);
      await drained();
      await cancelled;
      endpoint.close();
    });

    test("a dropped terminal rejects its wait with a delivery-loss error", async () => {
      vi.useFakeTimers();
      const endpoint = harness.create();
      const native = harness.native();
      const connectId = endpoint.startConnect(PEER);
      const waiting = endpoint.waitConnectResult(connectId, { timeoutMs: 0 });
      const lost = expect(waiting).rejects.toBeInstanceOf(
        ConnectResultLostError
      );

      native.deliver([
        {
          inner: {
            dropped: 1n,
            terminalConnectIds: [CONNECT_ID],
            totalDropped: 1n,
          },
          tag: "EventsDropped",
        },
      ]);
      await drained();

      await lost;
      endpoint.close();
    });

    test("connectionInfo shares the public connection ID of connection events", async () => {
      vi.useFakeTimers();
      const endpoint = harness.create();
      const native = harness.native();
      const opened: number[] = [];
      endpoint.on("connectionEstablished", ({ connId }) => opened.push(connId));
      native.setConnectionInfo({ connId: CONN_ID, remoteAddr: QUIC });

      native.deliver([
        {
          inner: { connId: CONN_ID, peerId: PEER },
          tag: "ConnectionEstablished",
        },
      ]);
      await drained();

      expect(endpoint.connectionInfo(PEER)).toEqual({
        connId: opened[0],
        remoteAddr: QUIC,
      });
      endpoint.close();
    });

    test("ConnectionReplaced moves the peer to the new connection and ends opens on the old one", async () => {
      vi.useFakeTimers();
      const endpoint = harness.create();
      const native = harness.native();
      const established: number[] = [];
      const replaced: {
        readonly oldConnId: number;
        readonly newConnId: number;
      }[] = [];
      endpoint.on("connectionEstablished", ({ connId }) =>
        established.push(connId)
      );
      endpoint.on("connectionReplaced", (event) => replaced.push(event));
      native.deliver([
        {
          inner: { connId: CONN_ID, peerId: PEER },
          tag: "ConnectionEstablished",
        },
      ]);
      await drained();
      native.setNextStream(CONN_ID, 4n);
      const opening = endpoint.openStream(PEER, "/test/1", { timeoutMs: 0 });
      const ended = expect(opening).rejects.toBeInstanceOf(StreamClosedError);

      native.setConnectionInfo({
        connId: NEXT_CONN_ID,
        readyProtocols: ["/test/1"],
      });
      native.deliver([
        {
          inner: { newConnId: NEXT_CONN_ID, oldConnId: CONN_ID, peerId: PEER },
          tag: "ConnectionReplaced",
        },
      ]);
      await drained();

      await ended;
      const current = endpoint.connectionInfo(PEER);
      expect(replaced).toMatchObject([
        { newConnId: current?.connId, oldConnId: established[0] },
      ]);
      expect(current).toEqual({
        connId: replaced[0]?.newConnId,
        readyProtocols: ["/test/1"],
      });
      expect(await endpoint.waitPeerReady(PEER)).toEqual({
        peerId: PEER,
        protocols: ["/test/1"],
      });
      endpoint.close();
    });

    test("a write on a connection native already replaced throws instead of reaching the new one", async () => {
      vi.useFakeTimers();
      const endpoint = harness.create();
      const native = harness.native();
      native.setNextStream(CONN_ID, 4n);
      const opening = endpoint.openStream(PEER, "/test/1");
      native.deliver([
        {
          inner: {
            connId: CONN_ID,
            initiatedLocally: true,
            peerId: PEER,
            protocolId: "/test/1",
            streamId: 4n,
          },
          tag: "StreamReady",
        },
      ]);
      await drained();
      const stream = await opening;
      native.setLiveConnection(CONN_ID);
      await stream.write("before");

      // The new connection reuses stream id 4, and its ConnectionReplaced
      // is not drained yet, so the SDK still treats the stream as open.
      native.setLiveConnection(NEXT_CONN_ID);
      await expect(stream.write("after")).rejects.toThrow();

      expect(native.writes).toEqual([{ connId: CONN_ID, streamId: 4n }]);
      endpoint.close();
    });

    test("a write queued behind a drained replacement throws StreamClosedError", async () => {
      vi.useFakeTimers();
      const endpoint = harness.create();
      const native = harness.native();
      native.setNextStream(CONN_ID, 4n);
      const opening = endpoint.openStream(PEER, "/test/1");
      native.deliver([
        {
          inner: {
            connId: CONN_ID,
            initiatedLocally: true,
            peerId: PEER,
            protocolId: "/test/1",
            streamId: 4n,
          },
          tag: "StreamReady",
        },
      ]);
      await drained();
      const stream = await opening;
      const writeErrors: unknown[] = [];
      stream.on("data", async () => {
        try {
          await stream.write("reply");
        } catch (error) {
          writeErrors.push(error);
        }
      });

      // The adapter drains both events before the SDK dispatches the data,
      // so the reply runs after the old connection's identity is released.
      native.deliver([
        {
          inner: {
            connId: CONN_ID,
            data: new Uint8Array([1]).buffer,
            peerId: PEER,
            streamId: 4n,
          },
          tag: "StreamData",
        },
        {
          inner: { newConnId: NEXT_CONN_ID, oldConnId: CONN_ID, peerId: PEER },
          tag: "ConnectionReplaced",
        },
      ]);
      await drained();

      expect(writeErrors).toHaveLength(1);
      expect(writeErrors[0]).toBeInstanceOf(StreamClosedError);
      expect(native.writes).toEqual([]);
      endpoint.close();
    });

    test("a pull reader acknowledges bytes it reads after the stream closed", async () => {
      vi.useFakeTimers();
      const endpoint = harness.create();
      const native = harness.native();
      native.setNextStream(CONN_ID, 4n);
      const opening = endpoint.openStream(PEER, "/test/1");
      const stream4 = { connId: CONN_ID, peerId: PEER, streamId: 4n };
      native.deliver([
        {
          inner: { ...stream4, initiatedLocally: true, protocolId: "/test/1" },
          tag: "StreamReady",
        },
        {
          inner: { ...stream4, data: new Uint8Array([1, 2, 3]).buffer },
          tag: "StreamData",
        },
        { inner: stream4, tag: "StreamRemoteWriteClosed" },
        { inner: stream4, tag: "StreamClosed" },
      ]);
      await drained();
      const stream = await opening;
      expect(native.consumed).toEqual([]);

      // The closed stream's IDs are retired, yet its unread bytes still
      // hold a native stream slot until this read acknowledges them.
      expect([...((await stream.read()) ?? [])]).toEqual([1, 2, 3]);
      expect(native.consumed).toEqual([
        { bytes: 3, connId: CONN_ID, streamId: 4n },
      ]);
      expect(await stream.read()).toBeUndefined();
      endpoint.close();
    });

    test("a remote stop code past the safe integer range reaches the stream whole", async () => {
      vi.useFakeTimers();
      const endpoint = harness.create();
      const native = harness.native();
      native.setNextStream(CONN_ID, 4n);
      const opening = endpoint.openStream(PEER, "/test/1");
      native.deliver([
        {
          inner: {
            connId: CONN_ID,
            initiatedLocally: true,
            peerId: PEER,
            protocolId: "/test/1",
            streamId: 4n,
          },
          tag: "StreamReady",
        },
      ]);
      await drained();
      const stream = await opening;
      const codes: bigint[] = [];
      stream.on("writeStopped", ({ errorCode }) => codes.push(errorCode));

      // QUIC stop codes are 62-bit varints.
      const errorCode = 2n ** 62n - 1n;
      native.deliver([
        {
          inner: { connId: CONN_ID, errorCode, peerId: PEER, streamId: 4n },
          tag: "StreamWriteStopped",
        },
      ]);
      await drained();

      expect(codes).toEqual([errorCode]);
      await expect(stream.write("late")).rejects.toThrow();
      endpoint.close();
    });

    test("native config carries the shared defaults", () => {
      harness
        .create({
          discovery: { topic: "app" },
          listen: ["/ip4/0.0.0.0/udp/0/quic-v1"],
          mdns: true,
        })
        .close();

      expect(harness.native().config).toMatchObject({
        allowUnsigned: false,
        autonatServers: [],
        discovery: {
          autoDial: true,
          beaconIntervalMs: 10_000n,
          peerTtlMs: 35_000n,
          topic: "app",
        },
        forceRelay: false,
        listen: ["/ip4/0.0.0.0/udp/0/quic-v1"],
        mdns: {
          autoDial: true,
          enableIpv6: false,
          interfaceRefreshMs: 10_000n,
          maxAnnouncedAddrs: 16,
          maxPacketBytes: 1400,
          queryIntervalMs: 300_000n,
          socketPollIntervalMs: 100n,
          ttlMs: 120_000n,
        },
        protocols: [],
        relays: [],
      });

      // Absent listen leaves the choice to the native defaults.
      harness.create().close();
      expect(harness.native().config).toMatchObject({ listen: undefined });

      expect(() =>
        harness.create({ mdns: { maxPacketBytes: 2 ** 32 } })
      ).toThrow(RangeError);
    });
  });
}
