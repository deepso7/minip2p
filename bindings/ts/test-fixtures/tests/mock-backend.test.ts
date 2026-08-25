import { describe, expect, test, vi } from "vitest";

import { P2pEvent_Tags } from "../../core/src/backend.js";
import { MockBackend } from "../src/index.js";

describe("MockBackend", () => {
  test("injects events only after a listener starts", () => {
    const backend = new MockBackend();
    const event = {
      inner: { peerId: "peer", protocols: ["/test/1"] },
      tag: P2pEvent_Tags.PeerReady,
    };

    expect(() => backend.emit(event)).toThrow(
      "MockBackend.start() must be called before emit()"
    );

    const listener = vi.fn();
    backend.start(listener);
    backend.emit(event);
    expect(listener).toHaveBeenCalledOnce();
    expect(listener).toHaveBeenCalledWith(event);
  });

  test("uses queued stream results before monotonic fallback identities", () => {
    const backend = new MockBackend();
    backend.openResults.push(
      { connId: 8, streamId: 13 },
      { connId: 9, streamId: 21 }
    );

    expect(backend.openStream("peer", "/test/1")).toEqual({
      connId: 8,
      streamId: 13,
    });
    expect(backend.openStream("peer", "/test/1")).toEqual({
      connId: 9,
      streamId: 21,
    });
    expect(backend.openStream("peer", "/test/1")).toEqual({
      connId: 2,
      streamId: 3,
    });
    expect(backend.openStream("peer", "/test/1")).toEqual({
      connId: 2,
      streamId: 4,
    });
  });

  test("shares connection IDs and records abandonment before throwing", () => {
    const backend = new MockBackend();

    expect(backend.connect("peer")).toBe(1);
    expect(backend.connectWithAddrs("peer", ["/test"])).toBe(2);
    expect(backend.connectAddr("/test")).toBe(3);

    backend.abandonError = new Error("abandon failed");
    expect(() => backend.abandonStream("peer", 7)).toThrow("abandon failed");
    expect(backend.operations).toEqual([["abandon", "peer", 7]]);
  });
});
