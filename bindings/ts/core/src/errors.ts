/* oxlint-disable max-classes-per-file -- Public error types are intentionally colocated. */

import type {
  DriverFailureKind,
  EndpointErrorKind,
  NatErrorKind,
} from "./types.js";

export class BackpressureError extends Error {
  constructor() {
    super("The native pubsub queue is full");
    this.name = "BackpressureError";
  }
}

export class MessageTooLargeError extends Error {
  constructor() {
    super("The message exceeds the native pubsub size limit");
    this.name = "MessageTooLargeError";
  }
}

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

export class TimeoutError extends Error {
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

export class ClosedError extends Error {
  constructor() {
    super("The minip2p endpoint is closed");
    this.name = "ClosedError";
  }
}

export class DriverFailedError extends Error {
  readonly kind: DriverFailureKind;

  constructor(kind: DriverFailureKind, detail: string) {
    super(detail.length > 0 ? detail : "The minip2p driver failed");
    this.name = "DriverFailedError";
    this.kind = kind;
  }
}

export class ConnectFailedError extends Error {
  readonly connectId: number;
  readonly peerId: string;
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

export class ConnectResultUnavailableError extends Error {
  readonly connectId: number;

  constructor(connectId: number) {
    super(`Connection result ${connectId} is unknown or already consumed`);
    this.name = "ConnectResultUnavailableError";
    this.connectId = connectId;
  }
}

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

export class OpenStreamError extends Error {
  readonly kind: EndpointErrorKind | "synchronous";
  readonly peerId: string;
  readonly connId?: number;
  readonly streamId?: number;
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

export class StreamClosedError extends Error {
  constructor(message = "The stream closed before it became ready") {
    super(message);
    this.name = "StreamClosedError";
  }
}
