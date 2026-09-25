/* oxlint-disable class-methods-use-this, func-style, max-classes-per-file, no-await-expression-member, no-await-in-loop, no-empty-function, no-plusplus, promise/prefer-await-to-then, require-await -- Contract-complete fake backend methods and Promise race probes are intentionally direct. */

import assert from "node:assert/strict";

import { MockBackend } from "@minip2p/test-fixtures";
import { test } from "vitest";

import { P2pEvent_Tags, PathKind_Tags } from "../src/backend.ts";
import {
  AbortError,
  ClosedError,
  ConnectCancelledError,
  ConnectFailedError,
  ConnectResultLostError,
  ConnectResultUnavailableError,
  DriverFailedError,
  DriverFailureKind,
  EndpointErrorKind,
  EventQueueOverflowError,
  Minip2pBase,
  NatErrorKind,
  OpenStreamError,
  PeerDisconnectedError,
  Stream,
  StreamClosedError,
  TimeoutError,
} from "../src/index.ts";

class TestMinip2p extends Minip2pBase {
  constructor(backend) {
    super(backend, []);
  }
}

async function tick() {
  await Promise.resolve();
  await Promise.resolve();
}

async function remainsPending(promise) {
  return Promise.race([
    promise.then(
      () => false,
      () => false
    ),
    tick().then(() => true),
  ]);
}

test("named and catch-all subscribers receive flattened events", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const named = [];
  const all = [];
  endpoint.on("peerReady", (event) => named.push(event));
  endpoint.on((event) => all.push(event));

  backend.emit({
    inner: { peerId: "peer", protocols: ["/test/1"] },
    tag: P2pEvent_Tags.PeerReady,
  });
  await tick();

  assert.deepEqual(named[0], {
    peerId: "peer",
    protocols: ["/test/1"],
  });
  assert.equal(all[0].type, "peerReady");
  assert.equal("tag" in all[0], false);
  endpoint.close();
});

test("events iteration yields endpoint events in order and ends on close", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const events = [];
  const reading = (async () => {
    for await (const event of endpoint.events()) {
      events.push(event);
    }
  })();

  backend.emit({
    inner: { peerId: "first", protocols: ["/test/1"] },
    tag: P2pEvent_Tags.PeerReady,
  });
  backend.emit({
    inner: { peerId: "second", protocols: ["/test/2"] },
    tag: P2pEvent_Tags.PeerReady,
  });
  await tick();
  endpoint.close();

  await reading;
  assert.deepEqual(events, [
    {
      peerId: "first",
      protocols: ["/test/1"],
      type: "peerReady",
    },
    {
      peerId: "second",
      protocols: ["/test/2"],
      type: "peerReady",
    },
  ]);
});

test("events iteration ends quietly on abort", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const controller = new AbortController();
  const reading = (async () => {
    for await (const _event of endpoint.events({
      signal: controller.signal,
    })) {
      // Wait for cancellation.
    }
  })();

  controller.abort();

  await reading;
  endpoint.close();
});

test("events iteration ends immediately for a pre-aborted signal", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const controller = new AbortController();
  controller.abort();

  const iterator = endpoint.events({ signal: controller.signal });

  assert.equal((await iterator.next()).done, true);
  endpoint.close();
});

function peerReady(peerId) {
  return {
    inner: { peerId, protocols: ["/test/1"] },
    tag: P2pEvent_Tags.PeerReady,
  };
}

test("events iteration drops oldest buffered events and reports the drop", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const iterator = endpoint.events({ bufferCap: 2 });
  const first = iterator.next();
  backend.emit(peerReady("first"));
  assert.equal((await first).value.peerId, "first");

  backend.emit(peerReady("dropped"));
  backend.emit(peerReady("second"));
  backend.emit(peerReady("third"));
  await tick();

  assert.deepEqual((await iterator.next()).value, {
    dropped: 1,
    type: "queueOverflow",
  });
  assert.equal((await iterator.next()).value.peerId, "second");
  assert.equal((await iterator.next()).value.peerId, "third");
  endpoint.close();
  assert.equal((await iterator.next()).done, true);
});

test("events iteration stops immediately on abort while events keep arriving", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const controller = new AbortController();
  const iterator = endpoint.events({ bufferCap: 1, signal: controller.signal });
  const first = iterator.next();
  backend.emit(peerReady("first"));
  await first;

  backend.emit(peerReady("buffered"));
  await tick();
  controller.abort();
  backend.emit(peerReady("after-abort"));
  await tick();

  assert.equal((await iterator.next()).done, true);
  endpoint.close();
});

test("events rejects invalid buffer caps", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);

  await assert.rejects(endpoint.events({ bufferCap: 0 }).next(), RangeError);
  await assert.rejects(
    endpoint.events({ bufferCap: Number.POSITIVE_INFINITY }).next(),
    RangeError
  );
  endpoint.close();
});

test("await using falls back to Symbol.dispose", async () => {
  const backend = new MockBackend();
  assert.equal(Symbol.asyncDispose in Minip2pBase.prototype, false);

  {
    await using endpoint = new TestMinip2p(backend);
    assert.equal(endpoint.peerId(), "local-peer");
  }

  assert.equal(backend.closed, true);
});

test("inbound relayed path events preserve relay provenance", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const events = [];
  endpoint.on("inboundPathEstablished", (event) => events.push(event));

  backend.emit({
    inner: {
      path: {
        inner: { relayPeerId: "relay" },
        tag: PathKind_Tags.Relayed,
      },
      peerId: "peer",
    },
    tag: P2pEvent_Tags.InboundPathEstablished,
  });
  await tick();

  assert.deepEqual(events, [
    {
      path: { kind: "relayed", relayPeerId: "relay" },
      peerId: "peer",
    },
  ]);
  endpoint.close();
});

function streamReady(overrides = {}) {
  return {
    inner: {
      connId: 2,
      initiatedLocally: false,
      peerId: "peer",
      protocolId: "/test/1",
      streamId: 3,
      ...overrides,
    },
    tag: P2pEvent_Tags.StreamReady,
  };
}

test("catch-all stream events expose metadata, while named handlers get handles", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  let handle;
  let caught;
  endpoint.on("stream", (stream) => {
    handle = stream;
  });
  endpoint.on((event) => {
    if (event.type === "inboundStream") {
      caught = event;
    }
  });

  backend.emit(streamReady({ initiatedLocally: false }));
  await tick();

  assert.ok(handle instanceof Stream);
  assert.deepEqual(caught, {
    connId: 2,
    initiatedLocally: false,
    peerId: "peer",
    protocolId: "/test/1",
    streamId: 3,
    type: "inboundStream",
  });
  assert.equal("read" in caught, false);
  assert.equal("write" in caught, false);
  handle.abandon();
  endpoint.close();
});

test("inbound streams are abandoned only when there is no named or waiter claimant", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);

  backend.emit(streamReady({ streamId: 8 }));
  await tick();
  assert.deepEqual(backend.operations.at(-1), ["abandon", "peer", 8]);

  const claimed = endpoint.once("stream", { timeoutMs: 1000 });
  backend.emit(streamReady({ streamId: 9 }));
  const stream = await claimed;
  assert.ok(stream instanceof Stream);
  assert.equal(
    backend.operations.some(
      (operation) => operation[0] === "abandon" && operation[2] === 9
    ),
    false
  );
  stream.abandon();
  endpoint.close();
});

test("handler failures fan out first and enqueue safe handlerError metadata", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const order = [];
  let handlerError;
  endpoint.on("message", () => {
    order.push("throw");
    throw new Error("boom");
  });
  endpoint.on("message", () => order.push("second"));
  endpoint.on("handlerError", (event) => {
    handlerError = event;
    order.push("error");
    throw new Error("nested");
  });

  backend.emit({
    inner: {
      data: new ArrayBuffer(4),
      fromPeerId: "peer",
      seqno: new ArrayBuffer(4),
      signed: true,
      topics: ["/chat"],
    },
    tag: P2pEvent_Tags.Message,
  });
  await tick();
  await tick();

  assert.deepEqual(order, ["throw", "second", "error"]);
  assert.equal(handlerError.eventType, "message");
  assert.deepEqual(handlerError.metadata, {
    fromPeerId: "peer",
    signed: true,
    topics: ["/chat"],
  });
  endpoint.close();
});

test("connect operations resolve paths and advanced results are one-shot", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const established = [];
  endpoint.on("pathEstablished", (event) => established.push(event));
  const connectId = endpoint.startConnect("peer");
  backend.emit({
    inner: {
      connId: 7,
      connectId,
      path: { tag: PathKind_Tags.DirectDialed },
      peerId: "peer",
    },
    tag: P2pEvent_Tags.PathEstablished,
  });
  await tick();

  assert.deepEqual(established, [
    {
      connId: 7,
      connectId,
      path: { kind: "directDialed" },
      peerId: "peer",
    },
  ]);
  const result = await endpoint.waitConnectResult(connectId, { timeoutMs: 0 });
  assert.deepEqual(result, {
    connectId,
    path: { kind: "directDialed" },
    peerId: "peer",
  });
  await assert.rejects(
    endpoint.waitConnectResult(connectId),
    ConnectResultUnavailableError
  );
  endpoint.close();
});

function pathEstablished(connectId, peerId = "peer") {
  return {
    inner: {
      connId: 7,
      connectId,
      path: { tag: PathKind_Tags.DirectDialed },
      peerId,
    },
    tag: P2pEvent_Tags.PathEstablished,
  };
}

function cancelCalls(backend) {
  return backend.operations.filter(([name]) => name === "cancelConnect");
}

test("startConnect shapes peer, address, and address-list targets", () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const quic = "/ip4/127.0.0.1/udp/1/quic-v1/p2p/peer";
  const tcp = "/ip4/127.0.0.1/tcp/1/p2p/peer";

  endpoint.startConnect("peer");
  endpoint.startConnect(quic);
  endpoint.startConnect([quic, tcp]);

  assert.deepEqual(
    backend.operations.filter(([name]) => name === "connectTarget"),
    [
      ["connectTarget", { kind: "peer", peerId: "peer" }],
      ["connectTarget", { addresses: [quic], kind: "addresses" }],
      ["connectTarget", { addresses: [quic, tcp], kind: "addresses" }],
    ]
  );
  endpoint.close();
});

test("connect failure rejects with the terminal's typed error", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const failed = endpoint.connect("peer", { timeoutMs: 1000 });
  backend.emit({
    inner: {
      connectId: 1,
      detail: "no path",
      kind: NatErrorKind.NoPathAvailable,
      peerId: "peer",
    },
    tag: P2pEvent_Tags.ConnectFailed,
  });
  await assert.rejects(failed, (error) => {
    assert.ok(error instanceof ConnectFailedError);
    assert.equal(error.connectId, 1);
    assert.equal(error.peerId, "peer");
    assert.equal(error.kind, NatErrorKind.NoPathAvailable);
    assert.equal(error.message, "no path");
    return true;
  });
  endpoint.close();
});

test("a connect timeout ends only the wait and leaves the attempt running", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const connectId = endpoint.startConnect("peer");

  await assert.rejects(
    endpoint.waitConnectResult(connectId, { timeoutMs: 1 }),
    TimeoutError
  );
  assert.deepEqual(cancelCalls(backend), []);

  backend.emit(pathEstablished(connectId));
  await tick();
  assert.equal(
    (await endpoint.waitConnectResult(connectId, { timeoutMs: 0 })).connectId,
    connectId
  );
  endpoint.close();
});

test("cancelOnTimeout opts into cancelling the attempt", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);

  await assert.rejects(
    endpoint.connect("peer", { cancelOnTimeout: true, timeoutMs: 1 }),
    TimeoutError
  );
  assert.deepEqual(cancelCalls(backend), [["cancelConnect", 1]]);
  endpoint.close();
});

test("aborting a connect wait cancels the attempt, whose terminal stays consumable", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const controller = new AbortController();
  const connectId = endpoint.startConnect("peer");
  const waiting = endpoint.waitConnectResult(connectId, {
    signal: controller.signal,
    timeoutMs: 0,
  });

  controller.abort();
  await assert.rejects(waiting, AbortError);
  assert.deepEqual(cancelCalls(backend), [["cancelConnect", connectId]]);

  backend.emit({
    inner: { connectId, peerId: "peer" },
    tag: P2pEvent_Tags.ConnectCancelled,
  });
  await tick();
  await assert.rejects(
    endpoint.waitConnectResult(connectId, { timeoutMs: 0 }),
    ConnectCancelledError
  );

  const preAborted = endpoint.connect("peer", { signal: controller.signal });
  await assert.rejects(preAborted, AbortError);
  // An already-aborted connect never starts a native attempt.
  assert.equal(
    backend.operations.filter(([name]) => name === "connectTarget").length,
    1
  );
  endpoint.close();
});

test("cancelConnect lets the native terminal settle the pending wait", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const settled = endpoint.startConnect("peer");
  const unsettled = endpoint.startConnect("peer");
  const settledWait = endpoint.waitConnectResult(settled, { timeoutMs: 0 });
  const unsettledWait = endpoint.waitConnectResult(unsettled, {
    timeoutMs: 0,
  });

  endpoint.cancelConnect(settled);
  endpoint.cancelConnect(unsettled);
  assert.equal(await remainsPending(settledWait), true);
  assert.equal(await remainsPending(unsettledWait), true);

  // Cancellation raced a settled attempt: its real outcome still arrives.
  backend.emit(pathEstablished(settled));
  backend.emit({
    inner: { connectId: unsettled, peerId: "peer" },
    tag: P2pEvent_Tags.ConnectCancelled,
  });
  assert.equal((await settledWait).connectId, settled);
  await assert.rejects(unsettledWait, (error) => {
    assert.ok(error instanceof ConnectCancelledError);
    assert.ok(error instanceof AbortError);
    assert.equal(error.connectId, unsettled);
    return true;
  });
  endpoint.close();
});

test("connectCancelled reaches listeners and settles tracked attempts", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const cancelled = [];
  endpoint.on("connectCancelled", (event) => cancelled.push(event));
  const connectId = endpoint.startConnect("peer");
  const waiting = endpoint.waitConnectResult(connectId, { timeoutMs: 0 });

  backend.emit({
    inner: { connectId, peerId: "peer" },
    tag: P2pEvent_Tags.ConnectCancelled,
  });
  await tick();

  assert.deepEqual(cancelled, [{ connectId, peerId: "peer" }]);
  await assert.rejects(waiting, ConnectCancelledError);
  endpoint.close();
});

test("EventsDropped settles pending connect results with a lost error", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const dropped = [];
  endpoint.on("eventsDropped", (event) => dropped.push(event));
  const connectId = endpoint.startConnect("peer");
  const waiting = endpoint.waitConnectResult(connectId, { timeoutMs: 0 });

  backend.emit({
    inner: {
      dropped: 1,
      terminalConnectIds: [connectId],
      terminalConnectIdsTruncated: false,
      totalDropped: 1,
    },
    tag: P2pEvent_Tags.EventsDropped,
  });
  await tick();

  await assert.rejects(waiting, (error) => {
    assert.ok(error instanceof ConnectResultLostError);
    assert.equal(error.connectId, connectId);
    return true;
  });
  assert.deepEqual(dropped, [
    {
      dropped: 1,
      terminalConnectIds: [connectId],
      terminalConnectIdsTruncated: false,
      totalDropped: 1,
    },
  ]);
  endpoint.close();
});

test("EventsDropped stores a lost terminal for results not yet awaited", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const connectId = endpoint.startConnect("peer");

  backend.emit({
    inner: {
      dropped: 1,
      terminalConnectIds: [connectId],
      terminalConnectIdsTruncated: false,
      totalDropped: 1,
    },
    tag: P2pEvent_Tags.EventsDropped,
  });
  await tick();

  await assert.rejects(
    endpoint.waitConnectResult(connectId, { timeoutMs: 0 }),
    (error) => {
      assert.ok(error instanceof ConnectResultLostError);
      assert.equal(error.connectId, connectId);
      return true;
    }
  );
  endpoint.close();
});

test("truncated EventsDropped settles every pending connect result", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const first = endpoint.startConnect("peer");
  const second = endpoint.startConnect("peer");
  const waitingFirst = endpoint.waitConnectResult(first, { timeoutMs: 0 });
  const waitingSecond = endpoint.waitConnectResult(second, { timeoutMs: 0 });

  backend.emit({
    inner: {
      dropped: 1,
      terminalConnectIds: [],
      terminalConnectIdsTruncated: true,
      totalDropped: 1,
    },
    tag: P2pEvent_Tags.EventsDropped,
  });
  await tick();

  for (const [waiting, connectId] of [
    [waitingFirst, first],
    [waitingSecond, second],
  ]) {
    await assert.rejects(waiting, (error) => {
      assert.ok(error instanceof ConnectResultLostError);
      assert.equal(error.connectId, connectId);
      return true;
    });
  }
  endpoint.close();
});

test("a recorded loss stays the attempt's only outcome", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const connectId = endpoint.startConnect("peer");
  backend.emit({
    inner: {
      dropped: 1,
      terminalConnectIds: [],
      terminalConnectIdsTruncated: true,
      totalDropped: 1,
    },
    tag: P2pEvent_Tags.EventsDropped,
  });
  backend.emit(pathEstablished(connectId));
  await tick();

  await assert.rejects(
    endpoint.waitConnectResult(connectId, { timeoutMs: 0 }),
    ConnectResultLostError
  );
  endpoint.close();
});

test("truncated EventsDropped keeps a delivered connect terminal", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const connectId = endpoint.startConnect("peer");

  backend.emit({
    inner: {
      connId: 7,
      connectId,
      path: { tag: PathKind_Tags.DirectDialed },
      peerId: "peer",
    },
    tag: P2pEvent_Tags.PathEstablished,
  });
  backend.emit({
    inner: {
      dropped: 1,
      terminalConnectIds: [],
      terminalConnectIdsTruncated: true,
      totalDropped: 1,
    },
    tag: P2pEvent_Tags.EventsDropped,
  });
  await tick();

  assert.deepEqual(
    await endpoint.waitConnectResult(connectId, { timeoutMs: 0 }),
    {
      connectId,
      path: { kind: "directDialed" },
      peerId: "peer",
    }
  );
  endpoint.close();
});

test("ping coalesces native work while caller abort remains independent", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const controller = new AbortController();
  const first = endpoint.ping("peer", {
    signal: controller.signal,
    timeoutMs: 0,
  });
  const second = endpoint.ping("peer", { timeoutMs: 0 });
  controller.abort();
  await assert.rejects(first, AbortError);
  assert.equal(backend.pingCalls, 1);

  backend.emit({
    inner: { peerId: "peer", rttMs: 7 },
    tag: P2pEvent_Tags.PingRttMeasured,
  });
  assert.equal(await second, 7);
  endpoint.close();
});

test("ping coalescing recovers after its last waiter leaves and rejects on teardown", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  await assert.rejects(endpoint.ping("peer", { timeoutMs: 1 }), TimeoutError);
  const retry = endpoint.ping("peer", { timeoutMs: 1000 });
  assert.equal(backend.pingCalls, 2);
  endpoint.close();
  await assert.rejects(retry, ClosedError);
});

test("queue overflow rejects uncorrelated waits and exactly the lost connects", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const ping = endpoint.ping("peer", { timeoutMs: 0 });
  const lost = endpoint.startConnect("peer");
  const kept = endpoint.startConnect("peer");
  const lostWait = endpoint.waitConnectResult(lost, { timeoutMs: 0 });
  const keptWait = endpoint.waitConnectResult(kept, { timeoutMs: 0 });
  backend.emit(pathEstablished(lost));
  backend.emit(pathEstablished(kept));
  for (let index = 0; index < 4095; index += 1) {
    backend.emit(peerReady(`flood-${index}`));
  }

  await assert.rejects(ping, EventQueueOverflowError);
  await assert.rejects(lostWait, (error) => {
    assert.ok(error instanceof ConnectResultLostError);
    assert.equal(error.connectId, lost);
    return true;
  });
  assert.equal((await keptWait).connectId, kept);
  endpoint.close();
});

test("queue overflow settles connects named by a dropped EventsDropped", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const connectId = endpoint.startConnect("peer");
  backend.emit({
    inner: {
      dropped: 1,
      terminalConnectIds: [connectId],
      terminalConnectIdsTruncated: false,
      totalDropped: 1,
    },
    tag: P2pEvent_Tags.EventsDropped,
  });
  for (let index = 0; index < 4096; index += 1) {
    backend.emit(peerReady(`flood-${index}`));
  }

  await assert.rejects(
    endpoint.waitConnectResult(connectId, { timeoutMs: 0 }),
    ConnectResultLostError
  );
  endpoint.close();
});

test("pending waits leave unrelated events flowing to every subscriber", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const seen = [];
  endpoint.on("peerReady", ({ peerId }) => seen.push(`named:${peerId}`));
  endpoint.on((event) => seen.push(`all:${event.type}`));
  const connectId = endpoint.startConnect("peer");
  const connecting = endpoint.waitConnectResult(connectId, { timeoutMs: 0 });
  const waiting = endpoint.waitFor("peerReady", {
    predicate: ({ peerId }) => peerId === "wanted",
    timeoutMs: 0,
  });

  backend.emit(peerReady("other"));
  backend.emit(pathEstablished(connectId, "other"));
  backend.emit(peerReady("wanted"));

  assert.equal((await connecting).connectId, connectId);
  assert.equal((await waiting).peerId, "wanted");
  assert.deepEqual(seen, [
    "named:other",
    "all:peerReady",
    "all:pathEstablished",
    "named:wanted",
    "all:peerReady",
  ]);
  endpoint.close();
});

test("queue overflow releases the evicted native event", () => {
  const backend = new MockBackend();
  const handled = [];
  backend.eventHandled = (event) => handled.push(event);
  const endpoint = new TestMinip2p(backend);
  const evicted = peerReady("evicted");
  backend.emit(evicted);
  for (let index = 0; index < 4096; index += 1) {
    backend.emit(peerReady(`queued-${index}`));
  }

  assert.deepEqual(handled, [evicted]);
  endpoint.close();
});

test("teardown releases queued native events", () => {
  const backend = new MockBackend();
  const handled = [];
  backend.eventHandled = (event) => handled.push(event);
  const endpoint = new TestMinip2p(backend);
  const queued = peerReady("queued");
  backend.emit(queued);

  endpoint.close();

  assert.deepEqual(handled, [queued]);
});

function streamData(data, streamId) {
  return {
    inner: {
      connId: 2,
      data: data.buffer,
      peerId: "peer",
      streamId,
    },
    tag: P2pEvent_Tags.StreamData,
  };
}

test("stream FIFO counts only queued data and cleans up after terminal", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const opened = endpoint.openStream("peer", "/test/1", { timeoutMs: 1000 });
  backend.emit(streamReady({ initiatedLocally: true, streamId: 3 }));
  const stream = await opened;

  const direct = stream.read();
  backend.emit(streamData(new Uint8Array(2 * 1024 * 1024), 3));
  assert.equal((await direct).byteLength, 2 * 1024 * 1024);

  let overflow;
  stream.on("dataOverflow", (event) => {
    overflow = event;
  });
  backend.emit(streamData(new Uint8Array(2 * 1024 * 1024), 3));
  await tick();
  assert.deepEqual(overflow, {
    droppedBytes: 2 * 1024 * 1024,
    droppedChunks: 1,
  });

  backend.emit({
    inner: { connId: 2, peerId: "peer", streamId: 3 },
    tag: P2pEvent_Tags.StreamClosed,
  });
  await tick();
  assert.throws(() => stream.write("late"), ClosedError);
  stream.closeWrite();
  stream.reset();
  stream.abandon();
  endpoint.close();
});

test("stream async iteration yields chunks in order and ends on remote write close", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const opening = endpoint.openStream("peer", "/test/1", { timeoutMs: 1000 });
  backend.emit(streamReady({ initiatedLocally: true, streamId: 3 }));
  const stream = await opening;
  const chunks = [];
  const reading = (async () => {
    for await (const chunk of stream) {
      chunks.push([...chunk]);
    }
  })();

  backend.emit(streamData(new Uint8Array([1, 2]), 3));
  backend.emit(streamData(new Uint8Array([3]), 3));
  backend.emit({
    inner: { connId: 2, peerId: "peer", streamId: 3 },
    tag: P2pEvent_Tags.StreamRemoteWriteClosed,
  });

  await reading;
  assert.deepEqual(chunks, [[1, 2], [3]]);
  endpoint.close();
});

test("stream reads buffered chunks before EOF when full closure follows remote write close", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const opening = endpoint.openStream("peer", "/test/1", { timeoutMs: 1000 });
  backend.emit(streamReady({ initiatedLocally: true, streamId: 3 }));
  const stream = await opening;

  backend.emit(streamData(new Uint8Array([1, 2]), 3));
  backend.emit(streamData(new Uint8Array([3]), 3));
  backend.emit({
    inner: { connId: 2, peerId: "peer", streamId: 3 },
    tag: P2pEvent_Tags.StreamRemoteWriteClosed,
  });
  backend.emit({
    inner: { connId: 2, peerId: "peer", streamId: 3 },
    tag: P2pEvent_Tags.StreamClosed,
  });
  await tick();

  assert.deepEqual([...(await stream.read())], [1, 2]);
  assert.deepEqual([...(await stream.read())], [3]);
  assert.equal(await stream.read(), undefined);
  endpoint.close();
});

test("stream async iteration keeps half-close EOF final when StreamClosed follows", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const opening = endpoint.openStream("peer", "/test/1", { timeoutMs: 1000 });
  backend.emit(streamReady({ initiatedLocally: true, streamId: 3 }));
  const stream = await opening;
  const reading = (async () => {
    for await (const _chunk of stream) {
      // Wait for read-side EOF.
    }
  })();

  backend.emit({
    inner: { connId: 2, peerId: "peer", streamId: 3 },
    tag: P2pEvent_Tags.StreamRemoteWriteClosed,
  });
  await reading;
  backend.emit({
    inner: { connId: 2, peerId: "peer", streamId: 3 },
    tag: P2pEvent_Tags.StreamClosed,
  });
  await tick();

  endpoint.close();
});

test("stream async iteration rejects when the endpoint closes", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const opening = endpoint.openStream("peer", "/test/1", { timeoutMs: 1000 });
  backend.emit(streamReady({ initiatedLocally: true, streamId: 3 }));
  const stream = await opening;
  const reading = (async () => {
    for await (const _chunk of stream) {
      // Wait for endpoint shutdown.
    }
  })();

  endpoint.close();

  await assert.rejects(reading, ClosedError);
});

test("stream async iteration rejects when the remote stream resets", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const opening = endpoint.openStream("peer", "/test/1", { timeoutMs: 1000 });
  backend.emit(streamReady({ initiatedLocally: true, streamId: 3 }));
  const stream = await opening;
  const reading = (async () => {
    for await (const _chunk of stream) {
      // Wait for the remote terminal event.
    }
  })();

  backend.emit({
    inner: { connId: 2, peerId: "peer", streamId: 3 },
    tag: P2pEvent_Tags.StreamClosed,
  });

  await assert.rejects(reading, StreamClosedError);
  await assert.rejects(stream.read(), StreamClosedError);
  endpoint.close();
});

test("pending stream read rejects when its connection closes", async () => {
  const backend = new MockBackend();
  backend.connected = ["peer"];
  const endpoint = new TestMinip2p(backend);
  const opening = endpoint.openStream("peer", "/test/1", { timeoutMs: 1000 });
  backend.emit(streamReady({ initiatedLocally: true, streamId: 3 }));
  const stream = await opening;
  const reading = stream.read();

  backend.emit({
    inner: { connId: 2, peerId: "peer" },
    tag: P2pEvent_Tags.ConnectionClosed,
  });

  await assert.rejects(reading, PeerDisconnectedError);
  endpoint.close();
});

test("stream async iteration drains buffered data when full closure follows remote write close", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const opening = endpoint.openStream("peer", "/test/1", { timeoutMs: 1000 });
  backend.emit(streamReady({ initiatedLocally: true, streamId: 3 }));
  const stream = await opening;
  const { promise: paused, resolve: resume } = Promise.withResolvers();
  const chunks = [];
  const reading = (async () => {
    for await (const chunk of stream) {
      chunks.push([...chunk]);
      await paused;
    }
  })();

  backend.emit(streamData(new Uint8Array([1]), 3));
  await tick();
  backend.emit(streamData(new Uint8Array([2]), 3));
  backend.emit({
    inner: { connId: 2, peerId: "peer", streamId: 3 },
    tag: P2pEvent_Tags.StreamRemoteWriteClosed,
  });
  backend.emit({
    inner: { connId: 2, peerId: "peer", streamId: 3 },
    tag: P2pEvent_Tags.StreamClosed,
  });
  await tick();
  resume();

  await reading;
  assert.deepEqual(chunks, [[1], [2]]);
  endpoint.close();
});

test("endpoint and connection closure override remote write EOF", async () => {
  for (const failure of ["endpoint", "connection"]) {
    const backend = new MockBackend();
    backend.connected = ["peer"];
    const endpoint = new TestMinip2p(backend);
    const opening = endpoint.openStream("peer", "/test/1", {
      timeoutMs: 1000,
    });
    backend.emit(streamReady({ initiatedLocally: true, streamId: 3 }));
    const stream = await opening;
    backend.emit(streamData(new Uint8Array([1]), 3));
    backend.emit({
      inner: { connId: 2, peerId: "peer", streamId: 3 },
      tag: P2pEvent_Tags.StreamRemoteWriteClosed,
    });
    await tick();

    if (failure === "endpoint") {
      endpoint.close();
      await assert.rejects(stream.read(), ClosedError);
    } else {
      backend.emit({
        inner: { connId: 2, peerId: "peer" },
        tag: P2pEvent_Tags.ConnectionClosed,
      });
      await tick();
      await assert.rejects(stream.read(), PeerDisconnectedError);
      endpoint.close();
    }
  }
});

test("local stream reset and abandon emit closed exactly once", async () => {
  for (const operation of ["reset", "abandon"]) {
    const backend = new MockBackend();
    const endpoint = new TestMinip2p(backend);
    const opening = endpoint.openStream("peer", "/test/1", {
      timeoutMs: 1000,
    });
    backend.emit(streamReady({ initiatedLocally: true, streamId: 3 }));
    const stream = await opening;
    let closed = 0;
    stream.on("closed", () => {
      closed += 1;
      assert.throws(() => stream.write("late"), ClosedError);
      stream.reset();
      stream.abandon();
    });
    const reading = stream.read();

    stream[operation]();
    stream[operation]();

    assert.equal(closed, 1);
    assert.deepEqual(backend.operations, [[operation, "peer", 3]]);
    await assert.rejects(reading, ClosedError);
    await assert.rejects(stream.read(), ClosedError);
    endpoint.close();
  }
});

test("local stream reset and abandon override remote write EOF", async () => {
  for (const operation of ["reset", "abandon"]) {
    const backend = new MockBackend();
    const endpoint = new TestMinip2p(backend);
    const opening = endpoint.openStream("peer", "/test/1", {
      timeoutMs: 1000,
    });
    backend.emit(streamReady({ initiatedLocally: true, streamId: 3 }));
    const stream = await opening;
    backend.emit(streamData(new Uint8Array([1]), 3));
    backend.emit({
      inner: { connId: 2, peerId: "peer", streamId: 3 },
      tag: P2pEvent_Tags.StreamRemoteWriteClosed,
    });
    await tick();

    stream[operation]();

    await assert.rejects(stream.read(), ClosedError);
    endpoint.close();
  }
});

test("abandon tolerates a native close before its event is dispatched", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const opening = endpoint.openStream("peer", "/test/1", { timeoutMs: 1000 });
  backend.emit(streamReady({ initiatedLocally: true, streamId: 3 }));
  const stream = await opening;
  backend.abandonError = new Error("stream is not active");
  backend.emit({
    inner: { connId: 2, peerId: "peer", streamId: 3 },
    tag: P2pEvent_Tags.StreamClosed,
  });

  assert.doesNotThrow(() => stream.abandon());
  assert.throws(() => stream.write("closed"), ClosedError);
  endpoint.close();
});

test("openStream correlates full available identity and abandons late ready", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const opening = endpoint.openStream("peer", "/test/1", {
    timeoutMs: 1000,
  });
  backend.emit({
    inner: {
      connId: 2,
      detail: "wrong peer",
      kind: EndpointErrorKind.UnsupportedProtocol,
      peerId: "other",
      streamId: 3,
    },
    tag: P2pEvent_Tags.EndpointError,
  });
  await tick();
  assert.equal(await remainsPending(opening), true);
  backend.emit({
    inner: {
      connId: 99,
      detail: "wrong connection",
      kind: EndpointErrorKind.UnsupportedProtocol,
      peerId: "peer",
      streamId: 3,
    },
    tag: P2pEvent_Tags.EndpointError,
  });
  await tick();
  assert.equal(await remainsPending(opening), true);
  backend.emit({
    inner: {
      connId: 2,
      detail: "unsupported",
      kind: EndpointErrorKind.UnsupportedProtocol,
      peerId: "peer",
      streamId: 3,
    },
    tag: P2pEvent_Tags.EndpointError,
  });
  await assert.rejects(opening, (error) => {
    assert.ok(error instanceof OpenStreamError);
    assert.equal(error.kind, EndpointErrorKind.UnsupportedProtocol);
    assert.equal(error.connId, 2);
    assert.equal(error.streamId, 3);
    assert.equal(error.detail, "unsupported");
    return true;
  });

  const late = endpoint.openStream("peer", "/test/1", { timeoutMs: 1 });
  await assert.rejects(late, TimeoutError);
  backend.emit(streamReady({ initiatedLocally: true, streamId: 4 }));
  await tick();
  assert.deepEqual(backend.operations.at(-1), ["abandon", "peer", 4]);
  endpoint.close();
});

test("orphaned locally initiated streams are durably abandoned", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  let claimed = 0;
  endpoint.on("stream", () => {
    claimed += 1;
  });

  backend.emit(streamReady({ initiatedLocally: true, streamId: 99 }));
  await tick();

  assert.equal(claimed, 0);
  assert.deepEqual(backend.operations, [["abandon", "peer", 99]]);
  endpoint.close();
});

test("a throwing inbound stream handler does not claim ownership", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  endpoint.on("stream", () => {
    throw new Error("reject stream");
  });

  backend.emit(streamReady({ streamId: 88 }));
  await tick();
  await tick();

  assert.deepEqual(backend.operations, [["abandon", "peer", 88]]);
  endpoint.close();
});

test("openStream preserves timeout when native abandon throws", async () => {
  const backend = new MockBackend();
  backend.abandonError = new Error("native abandon failed");
  const endpoint = new TestMinip2p(backend);

  await assert.rejects(
    endpoint.openStream("peer", "/test/1", { timeoutMs: 1 }),
    TimeoutError
  );
  const controller = new AbortController();
  const aborted = endpoint.openStream("peer", "/test/1", {
    signal: controller.signal,
    timeoutMs: 0,
  });
  controller.abort();
  await assert.rejects(aborted, AbortError);
  endpoint.close();
});

test("openStream rejects an overwritten identity before reusing it", async () => {
  const backend = new MockBackend();
  backend.openResults.push(
    { connId: 2, streamId: 7 },
    { connId: 2, streamId: 7 }
  );
  const endpoint = new TestMinip2p(backend);
  const overwritten = endpoint.openStream("peer", "/test/1", {
    timeoutMs: 1000,
  });
  const replacement = endpoint.openStream("peer", "/test/1", {
    timeoutMs: 1000,
  });

  await assert.rejects(overwritten, (error) => {
    assert.ok(error instanceof OpenStreamError);
    assert.equal(error.kind, "synchronous");
    assert.equal(error.connId, 2);
    assert.equal(error.streamId, 7);
    assert.match(error.detail, /reused an in-flight stream identity/u);
    return true;
  });
  backend.emit(streamReady({ initiatedLocally: true, streamId: 7 }));
  assert.equal((await replacement).streamId, 7);
  endpoint.close();
});

test("unwatched connect terminal cache evicts its oldest result", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const ids = [];
  for (let index = 0; index < 1025; index += 1) {
    const connectId = endpoint.startConnect(`peer-${index}`);
    ids.push(connectId);
    backend.emit({
      inner: {
        connectId,
        path: { tag: PathKind_Tags.DirectDialed },
        peerId: `peer-${index}`,
      },
      tag: P2pEvent_Tags.PathEstablished,
    });
    await tick();
  }

  await assert.rejects(
    endpoint.waitConnectResult(ids[0], { timeoutMs: 0 }),
    ConnectResultUnavailableError
  );
  assert.equal(
    (await endpoint.waitConnectResult(ids.at(-1), { timeoutMs: 0 })).connectId,
    ids.at(-1)
  );
  endpoint.close();
});

test("openStream uses full identity for concurrent native stream ids", async () => {
  const backend = new MockBackend();
  backend.openResults.push(
    { connId: 2, streamId: 7 },
    { connId: 3, streamId: 7 }
  );
  const endpoint = new TestMinip2p(backend);
  const first = endpoint.openStream("peer-a", "/test/1", { timeoutMs: 1000 });
  const second = endpoint.openStream("peer-b", "/test/1", { timeoutMs: 1000 });

  backend.emit(
    streamReady({
      connId: 3,
      initiatedLocally: true,
      peerId: "peer-b",
      streamId: 7,
    })
  );
  assert.equal((await second).peerId, "peer-b");
  assert.equal(await remainsPending(first), true);
  backend.emit(
    streamReady({
      connId: 2,
      initiatedLocally: true,
      peerId: "peer-a",
      streamId: 7,
    })
  );
  assert.equal((await first).peerId, "peer-a");
  endpoint.close();
});

test("openStream rejects close and disconnect before ready", async () => {
  const backend = new MockBackend();
  backend.connected = ["peer"];
  const endpoint = new TestMinip2p(backend);
  const closed = endpoint.openStream("peer", "/test/1", { timeoutMs: 1000 });
  backend.emit({
    inner: { connId: 2, peerId: "peer", streamId: 3 },
    tag: P2pEvent_Tags.StreamClosed,
  });
  await assert.rejects(closed, StreamClosedError);

  const disconnected = endpoint.openStream("peer", "/test/1", {
    timeoutMs: 1000,
  });
  backend.emit({
    inner: { connId: 2, peerId: "peer" },
    tag: P2pEvent_Tags.ConnectionClosed,
  });
  await assert.rejects(disconnected, PeerDisconnectedError);
  endpoint.close();
});

test("connection close rejects only opens on that connection", async () => {
  const backend = new MockBackend();
  backend.connected = ["peer"];
  backend.openResults.push(
    { connId: 2, streamId: 7 },
    { connId: 3, streamId: 8 }
  );
  const endpoint = new TestMinip2p(backend);
  const closed = endpoint.openStream("peer", "/test/1", { timeoutMs: 1000 });
  const live = endpoint.openStream("peer", "/test/1", { timeoutMs: 1000 });

  backend.emit({
    inner: { connId: 2, peerId: "peer" },
    tag: P2pEvent_Tags.ConnectionClosed,
  });

  await assert.rejects(closed, PeerDisconnectedError);
  assert.equal(await remainsPending(live), true);
  backend.emit(
    streamReady({
      connId: 3,
      initiatedLocally: true,
      streamId: 8,
    })
  );
  assert.equal((await live).connId, 3);
  endpoint.close();
});

test("waitPeerReady ignores a superseded connection but rejects final disconnect", async () => {
  const backend = new MockBackend();
  backend.connected = ["peer"];
  const endpoint = new TestMinip2p(backend);
  const ready = endpoint.waitPeerReady("peer", { timeoutMs: 1000 });
  backend.emit({
    inner: { connId: 1, peerId: "peer" },
    tag: P2pEvent_Tags.ConnectionClosed,
  });
  assert.equal(await remainsPending(ready), true);
  backend.emit({
    inner: { peerId: "peer", protocols: ["/test/1"] },
    tag: P2pEvent_Tags.PeerReady,
  });
  assert.deepEqual(await ready, {
    peerId: "peer",
    protocols: ["/test/1"],
  });

  const disconnected = endpoint.waitPeerReady("peer", { timeoutMs: 1000 });
  backend.connected = [];
  backend.emit({
    inner: { connId: 2, peerId: "peer" },
    tag: P2pEvent_Tags.ConnectionClosed,
  });
  await assert.rejects(disconnected, PeerDisconnectedError);
  endpoint.close();
});

test("onClose fires once after teardown and swallows listener errors", () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  const reasons = [];
  endpoint.onClose((reason) => {
    assert.equal(backend.closed, true);
    reasons.push(reason);
    throw new Error("ignored");
  });
  endpoint.onClose((reason) => reasons.push(reason));

  assert.doesNotThrow(() => endpoint.close());
  endpoint.close();
  assert.deepEqual(reasons, [{ reason: "close" }, { reason: "close" }]);
});

test("driver failure rejects work and reports a distinct close reason", async () => {
  const backend = new MockBackend();
  const endpoint = new TestMinip2p(backend);
  let reason;
  endpoint.onClose((value) => {
    reason = value;
  });
  const waiting = endpoint.once("peerReady", { timeoutMs: 1000 });
  backend.emit({
    inner: {
      detail: "driver stopped",
      kind: DriverFailureKind.Transport,
    },
    tag: P2pEvent_Tags.DriverFailed,
  });

  await assert.rejects(waiting, DriverFailedError);
  assert.equal(reason.reason, "driverFailed");
  assert.ok(reason.error instanceof DriverFailedError);
});
