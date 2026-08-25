import * as coreSdk from "@minip2p/core";
import { describe, expect, test } from "vitest";

import * as nodeSdk from "../src/index.js";

describe("@minip2p/node", () => {
  test("re-exports every runtime SDK value by identity", () => {
    for (const [name, value] of Object.entries(coreSdk)) {
      expect(nodeSdk, `missing @minip2p/core export ${name}`).toHaveProperty(
        name
      );
      expect(Reflect.get(nodeSdk, name)).toBe(value);
    }
  });
});
