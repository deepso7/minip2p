/* oxlint-disable class-methods-use-this, max-classes-per-file, no-await-in-loop, no-empty-function -- The contract-complete fake backend uses intentionally inert methods, a tiny SDK test subclass, and bounded polling for asynchronous queue drains. */

import assert from "node:assert/strict";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";

import {
  ClosedError,
  ConnectCancelledError,
  DriverFailedError,
  DriverFailureKind,
  MiniP2pBase,
  NatErrorKind,
  P2pEvent_Tags,
  PathKind_Tags,
  PeerDisconnectedError,
  TimeoutError,
} from "../dist/index.js";

class MockBackend {
  listener;
  closed = false;
  published;
  reservation;
  streamCalls = [];

  start(listener) {
    this.listener = listener;
    listener({
      inner: { peerId: "peer", protocols: ["/minip2p/test/1"] },
      tag: P2pEvent_Tags.PeerReady,
    });
  }

  emit(event) {
    this.listener(event);
  }

  close() {
    this.closed = true;
  }

  peerId() {
    return "local-peer";
  }

  listenAddrs() {
    return ["/ip4/127.0.0.1/udp/1/quic-v1/p2p/local-peer"];
  }

  connectedPeers() {
    return [];
  }

  isPeerReady(peerId) {
    return peerId === "peer";
  }

  peerInfo(peerId) {
    return peerId === "peer"
      ? {
          listenAddrs: [],
          protocols: ["/minip2p/test/1"],
        }
      : undefined;
  }

  knownPeers() {
    return [];
  }

  discoveryNowMs() {}

  activeReservation() {
    return this.reservation;
  }

  circuitAddress(relayAddress, peerId) {
    return `${relayAddress}/p2p-circuit/p2p/${peerId}`;
  }

  reachability() {
    return 0;
  }

  isRunning() {
    return !this.closed;
  }

  setActive() {}

  subscribe() {
    return true;
  }

  unsubscribe() {
    return true;
  }

  publish(topic, data) {
    this.published = { data, topic };
  }

  ping() {}

  addProtocol() {}

  openStream() {
    return 3;
  }

  sendStream(peerId, streamId, data) {
    this.streamCalls.push({
      data: [...data],
      operation: "send",
      peerId,
      streamId,
    });
  }

  closeStreamWrite(peerId, streamId) {
    this.streamCalls.push({ operation: "closeWrite", peerId, streamId });
  }

  resetStream(peerId, streamId) {
    this.streamCalls.push({ operation: "reset", peerId, streamId });
  }

  abandonStream(peerId, streamId) {
    this.streamCalls.push({ operation: "abandon", peerId, streamId });
  }

  connect() {
    return 1;
  }

  connectWithAddrs() {
    return 1;
  }

  connectAddr() {
    return 2;
  }

  dial() {
    return [4];
  }

  dialIp4() {
    return 5;
  }

  dialIp6() {
    return 6;
  }

  cancelConnect() {}

  disconnect() {}
}

class TestMiniP2p extends MiniP2pBase {
  constructor(backend) {
    super(backend, []);
  }
}

test("same-tick subscribers receive synchronous backend events", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMiniP2p(backend);
  const events = [];
  endpoint.on((event) => {
    events.push(event);
  });

  await Promise.resolve();

  assert.equal(events.length, 1);
  assert.equal(events[0].tag, P2pEvent_Tags.PeerReady);
  endpoint.close();
});

test("event subscribers and waiters observe the same event", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMiniP2p(backend);
  await Promise.resolve();
  const events = [];
  endpoint.on((event) => {
    events.push(event);
  });
  const waiting = endpoint.waitFor(
    (event) =>
      "tag" in event && event.tag === P2pEvent_Tags.ConnectionEstablished
  );

  backend.emit({
    inner: { connId: 7, peerId: "remote-peer" },
    tag: P2pEvent_Tags.ConnectionEstablished,
  });

  const event = await waiting;
  assert.equal(event.tag, P2pEvent_Tags.ConnectionEstablished);
  assert.equal(events.length, 1);
  endpoint.close();
});

test("matching waiters settle before a handler closes the endpoint", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMiniP2p(backend);
  await Promise.resolve();
  const waiting = endpoint.waitFor(
    (event) =>
      "tag" in event && event.tag === P2pEvent_Tags.ConnectionEstablished
  );
  endpoint.on((event) => {
    if ("tag" in event && event.tag === P2pEvent_Tags.ConnectionEstablished) {
      endpoint.close();
    }
  });

  backend.emit({
    inner: { connId: 7, peerId: "remote-peer" },
    tag: P2pEvent_Tags.ConnectionEstablished,
  });

  const event = await waiting;
  assert.equal(event.tag, P2pEvent_Tags.ConnectionEstablished);
  assert.equal(backend.closed, true);
});

test("typed waits, identify queries, and streams use the shared backend", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMiniP2p(backend);

  const ready = await endpoint.waitPeerReady("peer");
  assert.equal(ready.inner.peerId, "peer");
  assert.equal(endpoint.isPeerReady("peer"), true);
  assert.deepEqual(endpoint.peerInfo("peer").protocols, ["/minip2p/test/1"]);
  assert.equal(endpoint.openStream("peer", "/minip2p/test/1"), 3);
  endpoint.sendStream("peer", 3, "hello");
  endpoint.closeStreamWrite("peer", 3);
  endpoint.resetStream("peer", 3);
  endpoint.abandonStream("peer", 3);
  assert.deepEqual(backend.streamCalls, [
    {
      data: [104, 101, 108, 108, 111],
      operation: "send",
      peerId: "peer",
      streamId: 3,
    },
    { operation: "closeWrite", peerId: "peer", streamId: 3 },
    { operation: "reset", peerId: "peer", streamId: 3 },
    { operation: "abandon", peerId: "peer", streamId: 3 },
  ]);
  endpoint.close();
});

test("waitPeerReady ignores stale Identify snapshots", async () => {
  const backend = new MockBackend();
  backend.isPeerReady = () => false;
  backend.peerInfo = () => ({
    listenAddrs: ["/ip4/127.0.0.1/udp/1/quic-v1"],
    protocols: ["/stale/1"],
  });
  const endpoint = new TestMiniP2p(backend);
  await Promise.resolve();
  const waiting = endpoint.waitPeerReady("peer", 1000);
  let settled = false;
  const observation = (async () => {
    const ready = await waiting;
    settled = true;
    return ready;
  })();

  await Promise.resolve();
  assert.equal(settled, false);
  backend.emit({
    inner: { peerId: "peer", protocols: ["/current/1"] },
    tag: P2pEvent_Tags.PeerReady,
  });

  const ready = await observation;
  assert.deepEqual(ready.inner.protocols, ["/current/1"]);
  endpoint.close();
});

test("waitPeerReady rejects when the peer disconnects first", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMiniP2p(backend);
  await Promise.resolve();
  const waiting = endpoint.waitPeerReady("remote-peer", 1000);

  backend.emit({
    inner: { connId: 7, peerId: "remote-peer" },
    tag: P2pEvent_Tags.ConnectionClosed,
  });

  await assert.rejects(waiting, PeerDisconnectedError);
  endpoint.close();
});

test("waitPeerReady survives a superseded connection closing", async () => {
  const backend = new MockBackend();
  backend.connectedPeers = () => ["remote-peer"];
  const endpoint = new TestMiniP2p(backend);
  await Promise.resolve();
  const waiting = endpoint.waitPeerReady("remote-peer", 1000);

  backend.emit({
    inner: { connId: 7, peerId: "remote-peer" },
    tag: P2pEvent_Tags.ConnectionClosed,
  });
  backend.emit({
    inner: { peerId: "remote-peer", protocols: ["/replacement/1"] },
    tag: P2pEvent_Tags.PeerReady,
  });

  const ready = await waiting;
  assert.deepEqual(ready.inner.protocols, ["/replacement/1"]);
  endpoint.close();
});

test("connection terminal events remain available to late waiters", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMiniP2p(backend);
  await Promise.resolve();
  backend.emit({
    inner: {
      connectId: 42,
      path: { tag: PathKind_Tags.DirectDialed },
      peerId: "remote-peer",
    },
    tag: P2pEvent_Tags.PathEstablished,
  });
  backend.emit({
    inner: {
      connectId: 43,
      detail: "no usable path",
      kind: NatErrorKind.NoPathAvailable,
      peerId: "other-peer",
    },
    tag: P2pEvent_Tags.ConnectFailed,
  });
  await Promise.resolve();

  const result = await endpoint.waitConnectResult(42, 0);
  assert.equal(result.tag, P2pEvent_Tags.PathEstablished);
  assert.equal(result.inner.peerId, "remote-peer");
  const failure = await endpoint.waitConnectResult(43, 0);
  assert.equal(failure.tag, P2pEvent_Tags.ConnectFailed);
  assert.equal(failure.inner.detail, "no usable path");
  endpoint.close();
});

test("cancelConnect rejects its pending result wait and suppresses queued terminals", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMiniP2p(backend);
  await Promise.resolve();
  const waiting = endpoint.waitConnectResult(42, 0);

  backend.emit({
    inner: {
      connectId: 42,
      path: { tag: PathKind_Tags.DirectDialed },
      peerId: "remote-peer",
    },
    tag: P2pEvent_Tags.PathEstablished,
  });
  endpoint.cancelConnect(42);

  await assert.rejects(
    waiting,
    (error) =>
      error instanceof ConnectCancelledError &&
      error.connectId === 42 &&
      error.message === "Connection attempt 42 was cancelled"
  );
  await assert.rejects(
    endpoint.waitConnectResult(42, 0),
    ConnectCancelledError
  );
  endpoint.close();
});

test("cached connection results are consumed and bounded", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMiniP2p(backend);
  await Promise.resolve();
  let delivered = 0;
  endpoint.on((event) => {
    if ("tag" in event && event.tag === P2pEvent_Tags.ConnectFailed) {
      delivered += 1;
    }
  });

  for (let connectId = 0; connectId <= 1024; connectId += 1) {
    backend.emit({
      inner: {
        connectId,
        detail: "no usable path",
        kind: NatErrorKind.NoPathAvailable,
        peerId: "remote-peer",
      },
      tag: P2pEvent_Tags.ConnectFailed,
    });
  }
  await waitUntil(() => delivered === 1025);

  const latest = await endpoint.waitConnectResult(1024, 0);
  assert.equal(latest.inner.connectId, 1024);
  await assert.rejects(endpoint.waitConnectResult(1024, 10), TimeoutError);
  await assert.rejects(endpoint.waitConnectResult(0, 10), TimeoutError);
  endpoint.close();
});

test("DriverFailed rejects waits and permanently closes the SDK", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMiniP2p(backend);
  await Promise.resolve();
  const events = [];
  endpoint.on((event) => {
    events.push(event);
    assert.equal(endpoint.isRunning(), false);
  });
  const waiting = endpoint.waitFor(() => false, 1000);

  backend.emit({
    inner: {
      detail: "native driver stopped",
      kind: DriverFailureKind.Transport,
    },
    tag: P2pEvent_Tags.DriverFailed,
  });

  await assert.rejects(
    waiting,
    (error) =>
      error instanceof DriverFailedError &&
      error.kind === DriverFailureKind.Transport &&
      error.message === "native driver stopped"
  );
  assert.equal(events.at(-1)?.tag, P2pEvent_Tags.DriverFailed);
  assert.equal(backend.closed, true);
  assert.throws(() => endpoint.waitFor(() => true), ClosedError);
  assert.throws(() => endpoint.peerId(), ClosedError);
});

test("bounded queue preserves newest payloads with exact drop accounting", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMiniP2p(backend);
  await Promise.resolve();
  const delivered = [];
  let dropped = 0;
  endpoint.on((event) => {
    if ("tag" in event && event.tag === P2pEvent_Tags.Message) {
      delivered.push(new Uint32Array(event.inner.seqno)[0]);
    } else if (event.type === "queueOverflow") {
      dropped += event.dropped;
    }
  });

  for (let index = 0; index < 5000; index += 1) {
    backend.emit({
      inner: {
        data: new ArrayBuffer(0),
        fromPeerId: "remote-peer",
        seqno: new Uint32Array([index]).buffer,
        signed: true,
        topics: ["/minip2p/test"],
      },
      tag: P2pEvent_Tags.Message,
    });
  }

  await waitUntil(() => delivered.length === 4096);
  assert.equal(dropped, 904);
  assert.equal(delivered[0], 904);
  assert.equal(delivered.at(-1), 4999);
  endpoint.close();
});

test("text publishing uses UTF-8 and close rejects pending waits", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMiniP2p(backend);
  await Promise.resolve();

  endpoint.publish("/test", "héllo");
  assert.equal(backend.published.topic, "/test");
  assert.equal(new TextDecoder().decode(backend.published.data), "héllo");

  const waiting = endpoint.waitFor(() => false);
  endpoint.close();
  await assert.rejects(waiting, ClosedError);
  assert.equal(backend.closed, true);
});

const waitUntil = async (predicate, timeoutMs = 2000) => {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) {
      assert.fail(`condition was not met within ${timeoutMs} ms`);
    }
    await delay(1);
  }
};

test("a backend that fails to start is released", () => {
  const backend = new MockBackend();
  const failure = new Error("start failed");
  backend.start = () => {
    throw failure;
  };

  assert.throws(() => new TestMiniP2p(backend), failure);
  assert.equal(backend.closed, true);
});
