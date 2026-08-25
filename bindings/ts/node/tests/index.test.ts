import { MockBackend } from "@minip2p/test-fixtures";
import { describe, expect, test } from "vitest";

import { Minip2pBase } from "../src/index.js";

class TestMinip2p extends Minip2pBase {
  constructor(backend: MockBackend) {
    super(backend, []);
  }
}

describe("@minip2p/node", () => {
  test("re-exports the source SDK contract", () => {
    const backend = new MockBackend();
    const endpoint = new TestMinip2p(backend);

    expect(endpoint.peerId()).toBe("local-peer");
    endpoint.close();
    expect(backend.closed).toBe(true);
  });
});
