/* oxlint-disable func-style, no-use-before-define, promise/avoid-new -- Child-process readiness and timeout helpers are callback-backed promises. */

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

const fixture = fileURLToPath(
  new URL("fixtures/lifecycle.mjs", import.meta.url)
);

describe("@minip2p/node process lifecycle", () => {
  test("a started endpoint keeps Node alive", async () => {
    const child = spawn(process.execPath, [fixture, "hold"]);
    try {
      await waitForOutput(child, "started");
      await new Promise((resolve) => {
        setTimeout(resolve, 200);
      });
      expect(child.exitCode).toBeNull();
    } finally {
      child.kill();
      await waitForExit(child);
    }
  });

  test("close is non-blocking and releases the event loop", async () => {
    const child = spawn(process.execPath, [fixture, "close"]);
    const output = await collectOutput(child);
    const closeMs = Number(
      /closeMs=(?<milliseconds>[\d.]+)/u.exec(output)?.groups?.milliseconds
    );
    const averageCallMs = Number(
      /averageCallMs=(?<milliseconds>[\d.]+)/u.exec(output)?.groups
        ?.milliseconds
    );

    expect(output).toContain("started");
    expect(closeMs).toBeLessThan(50);
    expect(averageCallMs).toBeLessThan(1);
    expect(child.exitCode).toBe(0);
  });
});

function waitForOutput(
  child: ReturnType<typeof spawn>,
  expected: string
): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`Child did not print ${expected}`));
    }, 5000);
    child.stdout.on("data", (chunk: Buffer) => {
      if (chunk.toString().includes(expected)) {
        clearTimeout(timer);
        resolve();
      }
    });
    child.once("error", reject);
    child.once("exit", (code) => {
      reject(
        new Error(`Child exited with ${code} before printing ${expected}`)
      );
    });
  });
}

function waitForExit(child: ReturnType<typeof spawn>): Promise<void> {
  if (child.exitCode !== null) {
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    child.once("exit", () => resolve());
  });
}

async function collectOutput(child: ReturnType<typeof spawn>): Promise<string> {
  let output = "";
  child.stdout.on("data", (chunk: Buffer) => {
    output += chunk.toString();
  });
  child.stderr.on("data", (chunk: Buffer) => {
    output += chunk.toString();
  });
  let timer: ReturnType<typeof setTimeout>;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      child.kill();
      reject(new Error(`Child did not exit. Output:\n${output}`));
    }, 5000);
  });
  try {
    await Promise.race([waitForExit(child), timeout]);
  } finally {
    clearTimeout(timer);
  }
  return output;
}
