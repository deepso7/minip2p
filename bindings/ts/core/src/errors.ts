/* oxlint-disable max-classes-per-file -- The small public SDK error family is intentionally colocated and exported from one module. */

import type { DriverFailureKind } from "./types.js";

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

/** A connection-result wait was cancelled by the host. */
export class ConnectCancelledError extends Error {
  readonly connectId: number;

  constructor(connectId: number) {
    super(`Connection attempt ${connectId} was cancelled`);
    this.name = "ConnectCancelledError";
    this.connectId = connectId;
  }
}

/** The native background driver terminated with a fatal failure. */
export class DriverFailedError extends Error {
  readonly kind: DriverFailureKind;

  constructor(kind: DriverFailureKind, detail: string) {
    super(detail.length > 0 ? detail : "The minip2p driver failed");
    this.name = "DriverFailedError";
    this.kind = kind;
  }
}

/** A peer disconnected before the awaited operation could complete. */
export class PeerDisconnectedError extends Error {
  readonly peerId: string;

  constructor(peerId: string) {
    super(`Peer ${peerId} disconnected before becoming ready`);
    this.name = "PeerDisconnectedError";
    this.peerId = peerId;
  }
}
