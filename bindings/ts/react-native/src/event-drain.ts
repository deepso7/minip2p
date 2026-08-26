/* oxlint-disable no-await-in-loop, promise/avoid-new -- Each bounded batch intentionally yields one event-loop turn before the next synchronous native drain. */

const DEFAULT_BATCH_LIMIT = 256;

type Scheduler = (task: () => void) => void;

const scheduleOnNextTurn: Scheduler = (task) => {
  setTimeout(task, 0);
};

/** Coalesces native doorbells and drains bounded event batches off the callback stack. */
export class EventDrain<Event> {
  readonly #drain: (limit: number) => Event[];
  readonly #deliver: (event: Event) => void;
  readonly #limit: number;
  readonly #schedule: Scheduler;
  #pending = false;
  #running = false;
  #stopped = false;

  constructor(
    drain: (limit: number) => Event[],
    deliver: (event: Event) => void,
    limit = DEFAULT_BATCH_LIMIT,
    schedule: Scheduler = scheduleOnNextTurn
  ) {
    this.#drain = drain;
    this.#deliver = deliver;
    this.#limit = limit;
    this.#schedule = schedule;
  }

  ring(): void {
    if (this.#stopped) {
      return;
    }
    this.#pending = true;
    if (!this.#running) {
      this.#running = true;
      this.#schedule(() => {
        void this.#run();
      });
    }
  }

  stop(): void {
    this.#stopped = true;
    this.#pending = false;
  }

  async #run(): Promise<void> {
    try {
      while (!this.#stopped && this.#pending) {
        this.#pending = false;
        let batch = this.#drain(this.#limit);
        while (!this.#stopped && batch.length > 0) {
          for (const event of batch) {
            try {
              this.#deliver(event);
            } catch {
              // Application callbacks cannot break native event delivery.
            }
          }
          await new Promise<void>((resolve) => {
            this.#schedule(resolve);
          });
          if (this.#stopped) {
            break;
          }
          batch = this.#drain(this.#limit);
        }
      }
    } finally {
      this.#running = false;
      if (this.#pending && !this.#stopped) {
        this.ring();
      }
    }
  }
}
