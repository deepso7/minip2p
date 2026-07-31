/* oxlint-disable max-classes-per-file -- Public error types are intentionally colocated. */

import type {
  DriverFailureKind,
  EndpointErrorKind,
  NatErrorKind,
} from "./types.js";

/** Pubsub rejected a publish because its bounded native queue is full. */
export class BackpressureError extends Error {
  constructor() {
    super("The native pubsub queue is full");
    this.name = "BackpressureError";
  }
}

/** A payload exceeds the native protocol size limit. */
export class MessageTooLargeError extends Error {
  constructor() {
    super("The message exceeds the native pubsub size limit");
    this.name = "MessageTooLargeError";
  }
}

/** Native policy rejected an otherwise valid operation. */
export class NotPermittedError extends Error {
  constructor(message = "The operation is not permitted") {
    super(message);
    this.name = "NotPermittedError";
  }
}

/** Platform-neutral operation cancellation error. */
export class AbortError extends Error {
  constructor(message = "The operation was aborted") {
    super(message);
    this.name = "AbortError";
  }
}

/** A Promise-based SDK operation exceeded its configured timeout. */
export class TimeoutError extends Error {
  /** Configured timeout in milliseconds, when known. */
  readonly timeoutMs?: number;

  constructor(timeoutMs?: number) {
    super(
      timeoutMs === undefined
        ? "The operation timed out"
        : `Timed out after ${timeoutMs} ms`
    );
    this.name = "TimeoutError";
    this.timeoutMs = timeoutMs;
  }
}

/** The endpoint or stream is already closed. */
export class ClosedError extends Error {
  constructor() {
    super("The minip2p endpoint is closed");
    this.name = "ClosedError";
  }
}

/** The native background driver stopped unexpectedly. */
export class DriverFailedError extends Error {
  /** Native subsystem that caused the terminal failure. */
  readonly kind: DriverFailureKind;

  constructor(kind: DriverFailureKind, detail: string) {
    super(detail.length > 0 ? detail : "The minip2p driver failed");
    this.name = "DriverFailedError";
    this.kind = kind;
  }
}

/** A NAT-orchestrated connection attempt ended without a usable path. */
export class ConnectFailedError extends Error {
  /** Endpoint-local connection-attempt identifier. */
  readonly connectId: number;
  /** Target peer ID. */
  readonly peerId: string;
  /** Machine-readable terminal failure category. */
  readonly kind: NatErrorKind;

  constructor(
    connectId: number,
    peerId: string,
    kind: NatErrorKind,
    detail: string
  ) {
    super(detail.length > 0 ? detail : `Connection to ${peerId} failed`);
    this.name = "ConnectFailedError";
    this.connectId = connectId;
    this.peerId = peerId;
    this.kind = kind;
  }
}

/** A connection result is unknown, already awaited, or already consumed. */
export class ConnectResultUnavailableError extends Error {
  readonly connectId: number;

  constructor(connectId: number) {
    super(`Connection result ${connectId} is unknown or already consumed`);
    this.name = "ConnectResultUnavailableError";
    this.connectId = connectId;
  }
}

/** A peer disconnected before an operation could complete. */
export class PeerDisconnectedError extends Error {
  readonly peerId: string;
  readonly operation?: string;

  constructor(peerId: string, operation?: string) {
    super(
      operation === undefined
        ? `Peer ${peerId} disconnected`
        : `Peer ${peerId} disconnected during ${operation}`
    );
    this.name = "PeerDisconnectedError";
    this.peerId = peerId;
    this.operation = operation;
  }
}

/** Outbound stream opening or protocol negotiation failed. */
export class OpenStreamError extends Error {
  /** Machine-readable native error category, or a synchronous adapter error. */
  readonly kind: EndpointErrorKind | "synchronous";
  /** Target peer ID. */
  readonly peerId: string;
  /** Connection carrying the attempted stream, when allocated. */
  readonly connId?: number;
  /** Native stream identifier, when allocated. */
  readonly streamId?: number;
  /** Human-readable native or adapter diagnostic. */
  readonly detail: string;

  constructor(options: {
    kind: EndpointErrorKind | "synchronous";
    peerId: string;
    connId?: number;
    streamId?: number;
    detail: string;
  }) {
    super(options.detail || `Opening a stream to ${options.peerId} failed`);
    this.name = "OpenStreamError";
    this.kind = options.kind;
    this.peerId = options.peerId;
    this.connId = options.connId;
    this.streamId = options.streamId;
    this.detail = options.detail;
  }
}

/** A stream closed before outbound negotiation completed. */
export class StreamClosedError extends Error {
  constructor(message = "The stream closed before it became ready") {
    super(message);
    this.name = "StreamClosedError";
  }
}

/** Native event loss made an in-flight operation's result unknowable. */
export class EventQueueOverflowError extends Error {
  constructor() {
    super("The native event queue overflowed before the operation completed");
    this.name = "EventQueueOverflowError";
  }
}
