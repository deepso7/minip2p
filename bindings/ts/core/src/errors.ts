/* oxlint-disable max-classes-per-file -- The small public SDK error family is intentionally colocated and exported from one module. */

/** The native pubsub queue rejected work because it is full. */
export class BackpressureError extends Error {
  constructor() {
    super("The native pubsub queue is full");
    this.name = "BackpressureError";
  }
}

/** The payload exceeds the native pubsub protocol limit. */
export class MessageTooLargeError extends Error {
  constructor() {
    super("The message exceeds the native pubsub size limit");
    this.name = "MessageTooLargeError";
  }
}

/** A valid operation was rejected by endpoint policy. */
export class NotPermittedError extends Error {
  constructor(message = "The operation is not permitted") {
    super(message);
    this.name = "NotPermittedError";
  }
}

/** A bounded SDK wait elapsed without a matching event. */
export class TimeoutError extends Error {
  constructor(timeoutMs: number) {
    super(`Timed out after ${timeoutMs} ms`);
    this.name = "TimeoutError";
  }
}

/** The SDK was closed before an operation could complete. */
export class ClosedError extends Error {
  constructor() {
    super("The minip2p endpoint is closed");
    this.name = "ClosedError";
  }
}
