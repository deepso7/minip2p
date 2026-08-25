import { describe, expect, test, vi } from "vitest";

import { EventDrain } from "../src/event-drain";

const settle = async (): Promise<void> => {
  await vi.runAllTimersAsync();
};

describe("EventDrain", () => {
  test("drains to empty in bounded batches and yields between them", async () => {
    vi.useFakeTimers();
    const batches = [[1, 2], [3], []];
    const delivered: number[] = [];
    const drain = vi.fn(() => batches.shift() ?? []);
    const events = new EventDrain(drain, (event) => delivered.push(event), 2);

    events.ring();
    expect(drain).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(0);
    expect(delivered).toEqual([1, 2]);
    expect(drain).toHaveBeenCalledTimes(1);

    await settle();
    expect(delivered).toEqual([1, 2, 3]);
    expect(drain).toHaveBeenCalledTimes(3);
    expect(drain).toHaveBeenCalledWith(2);
    vi.useRealTimers();
  });

  test("a re-ring while draining starts another drain-to-empty pass", async () => {
    vi.useFakeTimers();
    const batches = [[1], [], [2], []];
    const drain = vi.fn(() => batches.shift() ?? []);
    const delivered: number[] = [];
    const events = new EventDrain(
      drain,
      (event) => {
        delivered.push(event);
        if (event === 1) {
          events.ring();
        }
      },
      8
    );

    events.ring();
    await settle();

    expect(delivered).toEqual([1, 2]);
    expect(drain).toHaveBeenCalledTimes(4);
    vi.useRealTimers();
  });

  test("coalesces an event flood into one scheduled drain", async () => {
    vi.useFakeTimers();
    const drain = vi.fn(() => [] as number[]);
    const events = new EventDrain(drain, () => null, 32);

    for (let index = 0; index < 10_000; index += 1) {
      events.ring();
    }
    await settle();

    expect(drain).toHaveBeenCalledTimes(1);
    vi.useRealTimers();
  });
});
