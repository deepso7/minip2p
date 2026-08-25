import { describe, expect, test } from "vitest";

import { MockBackend } from "../src/index.js";

describe("MockBackend", () => {
  test("records scriptable operations", () => {
    const backend = new MockBackend();

    backend.sendStream("peer", 7, new Uint8Array([1, 2]));
    backend.cancelConnect(4);

    expect(backend.operations).toEqual([
      ["write", "peer", 7, [1, 2]],
      ["cancelConnect", 4],
    ]);
  });
});
