import { describe, expect, it } from "vitest";

import { resolveEndpointConfig } from "../src/config.js";

describe("inbound stream limits", () => {
  const secretKey = new Uint8Array(32);

  it("keeps omitted limits empty and forwards limits for additional protocols", () => {
    expect(resolveEndpointConfig({ secretKey }).inboundStreamLimits).toEqual(
      {}
    );
    const inboundStreamLimits = { "/chat/1": 4, "/files/1": 0xff_ff_ff_ff };
    const resolved = resolveEndpointConfig({ inboundStreamLimits, secretKey });
    expect(resolved.inboundStreamLimits).toEqual(inboundStreamLimits);
    expect(resolved.inboundStreamLimits).not.toBe(inboundStreamLimits);
  });

  it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 0x1_00_00_00_00])(
    "rejects invalid limit %s with its protocol named",
    (limit) => {
      expect(() =>
        resolveEndpointConfig({
          inboundStreamLimits: { "/chat/1": limit },
          secretKey,
        })
      ).toThrow(/inboundStreamLimits\["\/chat\/1"\]/u);
    }
  );
});
