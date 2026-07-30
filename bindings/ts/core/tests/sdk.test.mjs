/* oxlint-disable class-methods-use-this, max-classes-per-file, no-empty-function -- The contract-complete fake backend uses intentionally inert methods and a tiny SDK test subclass. */

import assert from "node:assert/strict";
import test from "node:test";

import { ClosedError, MiniP2pBase, P2pEvent_Tags } from "../dist/index.js";

class MockBackend {
  listener;
  closed = false;
  published;
  reservation;

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

  knownPeers() {
    return [];
  }

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

  connect() {
    return 1;
  }

  connectAddr() {
    return 2;
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

test("a backend that fails to start is released", () => {
  const backend = new MockBackend();
  const failure = new Error("start failed");
  backend.start = () => {
    throw failure;
  };

  assert.throws(() => new TestMiniP2p(backend), failure);
  assert.equal(backend.closed, true);
});
