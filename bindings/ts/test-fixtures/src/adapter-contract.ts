/* oxlint-disable func-style, max-lines-per-function, max-statements -- One suite holds the shared runtime contract so both adapters run identical cases. */

import { afterEach, describe, expect, test, vi } from "vitest";

import type { BackendConnectTarget } from "../../core/src/backend.js";
import {
  ConnectCancelledError,
  ConnectResultLostError,
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
  /** Targets passed to native `connectTarget`, in runtime-neutral form. */
  readonly connectTargets: readonly BackendConnectTarget[];
  /** Connect IDs passed to native `cancelConnect`. */
  readonly cancelledConnects: readonly bigint[];
  /** Makes native `connectionInfo` report `connId` for every peer. */
  setConnectionInfo: (connId: bigint, remoteAddr?: string) => void;
  /** Queues one native drain batch and rings the doorbell. */
  deliver: (events: readonly NativeEventLiteral[]) => void;
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
            terminalConnectIdsTruncated: false,
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
      native.setConnectionInfo(CONN_ID, QUIC);

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
      expect(harness.native().config).not.toHaveProperty("quic");

      harness.create().close();
      expect(harness.native().config).toMatchObject({ quic: {} });

      expect(() =>
        harness.create({
          listen: ["/ip4/0.0.0.0/udp/0/quic-v1"],
          transports: { quic: true },
        })
      ).toThrow(/not both/u);
      expect(() =>
        harness.create({ mdns: { maxPacketBytes: 2 ** 32 } })
      ).toThrow(RangeError);
    });
  });
}
