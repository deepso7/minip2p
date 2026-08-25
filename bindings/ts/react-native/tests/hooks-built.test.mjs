import { ClosedError } from "@minip2p/core";
import { test } from "vitest";

import {
  bindAppStateSource,
  mountEndpointLifecycle,
} from "../lib/module/hook-lifecycle.js";
import { verifyHookLifecycle } from "./hook-lifecycle.contract.mjs";

test("built hook lifecycle satisfies its contract", () => {
  verifyHookLifecycle({
    ClosedError,
    bindAppStateSource,
    mountEndpointLifecycle,
  });
});
