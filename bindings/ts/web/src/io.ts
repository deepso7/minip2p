/* oxlint-disable func-style, max-classes-per-file, no-empty-function, no-use-before-define, promise/prefer-await-to-callbacks, promise/prefer-await-to-then, promise/prefer-catch -- Promise callbacks become queued events here by design: nothing awaits, so the wasm side stays caller-driven, and a rejection the end of a stream or session already reports is dropped on purpose. */

/**
 * `JsIo`: the `WebTransportIo` seam of `minip2p-webtransport` over the
 * browser's `WebTransport` API. Rust owns the protocol and calls these
 * methods synchronously; every outcome the browser learns later (a session
 * coming up, a read, a write resolving, a reset) is queued as an
 * {@link IoEvent} and handed back by {@link JsIo.pollEvent}, and `wake`
 * asks the host to pump.
 *
 * The rules Rust relies on:
 *
 * - `write` copies what it accepts before returning, so a queued browser
 *   write never views wasm memory, and caps each stream's in-flight bytes;
 *   each accepted write reports exactly one `writeCompleted` with its own
 *   length, and a write the browser rejects reports nothing.
 * - Reads are pulled: `grantRead` is additive, at most one read is
 *   outstanding per stream, and `data` never exceeds what was granted.
 * - Handles are never reused, and events for a reset stream or an ended
 *   session are dropped. A stream whose read side ended and whose write
 *   side finished (every accepted write reported first) or was stopped is
 *   retired, so finished streams hold nothing.
 * - Stream error codes are WebTransport application codes cut to `u8`
 *   (minip2p only sends 0); a missing code is 0.
 * - Only `connect`, `openStream` and `write` may throw (Rust catches those
 *   as `IoError`s). An exception escaping any other method would unwind
 *   through Rust and leave the `WebEndpoint` borrowed for good, so they
 *   swallow everything.
 */

/** In-flight write bytes each stream may hold in the browser. */
export const MAX_IN_FLIGHT_BYTES = 64 * 1024;
/** The largest single read requested from the browser. */
const MAX_READ_BYTES = 64 * 1024;

/** One outcome for Rust, the shape `crates/web/src/io.rs` decodes. */
export type IoEvent =
  | { readonly kind: "sessionReady"; readonly session: number }
  | {
      readonly kind: "sessionClosed";
      readonly session: number;
      readonly code: number;
      readonly reason: string;
    }
  | { readonly kind: "streamOpened"; readonly stream: number }
  | {
      readonly kind: "incomingStream";
      readonly session: number;
      readonly stream: number;
    }
  | {
      readonly kind: "data";
      readonly stream: number;
      readonly bytes: Uint8Array;
    }
  | { readonly kind: "fin"; readonly stream: number }
  | { readonly kind: "reset"; readonly stream: number; readonly code: number }
  | {
      readonly kind: "stopSending";
      readonly stream: number;
      readonly code: number;
    }
  | {
      readonly kind: "writeCompleted";
      readonly stream: number;
      readonly bytes: number;
    };

/** The part of a browser `WebTransport` that `JsIo` uses. */
export type WebTransportSession = Pick<
  WebTransport,
  | "close"
  | "closed"
  | "createBidirectionalStream"
  | "incomingBidirectionalStreams"
  | "ready"
>;

/** Opens one session; the browser's `new WebTransport(url, options)`. */
export type OpenSession = (
  url: string,
  options: WebTransportOptions
) => WebTransportSession;

interface Session {
  readonly transport: WebTransportSession;
  readonly streams: Set<number>;
}

/** A stream's read side: BYOB when the browser offers it. */
interface ChunkReader {
  readonly closed: Promise<void>;
  read: (max: number) => Promise<ReadableStreamReadResult<Uint8Array>>;
  cancel: (reason?: unknown) => Promise<void>;
}

class Stream {
  writer: WritableStreamDefaultWriter<Uint8Array> | undefined;
  reader: ChunkReader | undefined;
  inFlight = 0;
  granted = 0;
  reading = false;
  /** Fin, reset or a local stop: no more `data`. */
  readEnded = false;
  /** Finished after its last write, or stopped by the peer. */
  writeEnded = false;
  /** Reset locally or its session ended: no more events at all. */
  dead = false;
  /** A `stop` that arrived before the stream finished opening. */
  pendingStop: number | undefined;
  readonly session: number;

  constructor(session: number) {
    this.session = session;
  }
}

const defaultOpenSession = (): OpenSession | undefined =>
  typeof WebTransport === "function"
    ? (url, options) => new WebTransport(url, options)
    : undefined;

/** The browser `WebTransportIo` behind one `WebEndpoint`. */
export class JsIo {
  readonly #wake: () => void;
  readonly #openSession: OpenSession | undefined;
  readonly #events: IoEvent[] = [];
  readonly #sessions = new Map<number, Session>();
  readonly #streams = new Map<number, Stream>();
  #nextSession = 1;
  #nextStream = 1;

  /**
   * `wake` runs whenever an event is queued; `openSession` defaults to the
   * global `WebTransport`.
   */
  constructor(wake: () => void, openSession = defaultOpenSession()) {
    this.#wake = wake;
    this.#openSession = openSession;
  }

  /** Starts a session trusting exactly the certificates `certhashes` name. */
  connect(url: string, certhashes: Uint8Array<ArrayBuffer>[]): number {
    if (this.#openSession === undefined) {
      throw new Error(
        "this browser has no WebTransport; minip2p needs a WebTransport-capable browser"
      );
    }
    const transport = this.#openSession(url, {
      serverCertificateHashes: certhashes.map((value) => ({
        algorithm: "sha-256",
        value,
      })),
    });
    const id = this.#nextSession;
    this.#nextSession += 1;
    const session: Session = { streams: new Set(), transport };
    this.#sessions.set(id, session);
    transport.ready.then(
      () => {
        if (this.#sessions.get(id) === session) {
          this.#push({ kind: "sessionReady", session: id });
          void this.#acceptIncoming(id, session);
        }
      },
      // `closed` rejects too and reports it.
      () => {}
    );
    transport.closed.then(
      (info) => {
        this.#endSession(id, info.closeCode ?? 0, info.reason ?? "");
      },
      (error: unknown) => {
        this.#endSession(id, 0, errorMessage(error));
      }
    );
    return id;
  }

  /** Opens a bidirectional stream; `streamOpened` follows. */
  openStream(sessionId: number): number {
    const session = this.#sessions.get(sessionId);
    if (session === undefined) {
      throw new Error(`session ${sessionId} is closed`);
    }
    const id = this.#addStream(sessionId, session);
    const stream = this.#streams.get(id);
    session.transport.createBidirectionalStream().then(
      (bidi) => {
        if (stream === undefined || stream.dead) {
          abandon(bidi);
          return;
        }
        this.#attach(id, stream, bidi);
        this.#push({ kind: "streamOpened", stream: id });
      },
      () => {
        if (stream !== undefined && !stream.dead) {
          this.#forget(id, stream);
          this.#push({ code: 0, kind: "reset", stream: id });
        }
      }
    );
    return id;
  }

  /** Copies and queues a prefix of `data`; a short write is backpressure. */
  write(streamId: number, data: Uint8Array): number {
    const stream = this.#streams.get(streamId);
    const writer = stream?.writer;
    if (stream === undefined || writer === undefined) {
      throw new Error(`stream ${streamId} is not writable`);
    }
    const accepted = Math.min(
      MAX_IN_FLIGHT_BYTES - stream.inFlight,
      data.length
    );
    if (accepted <= 0) {
      return 0;
    }
    // `data` views wasm memory, which may move: copy before returning.
    const copy = data.slice(0, accepted);
    stream.inFlight += accepted;
    writer.write(copy).then(
      () => {
        if (!stream.dead) {
          stream.inFlight -= accepted;
          this.#push({
            bytes: accepted,
            kind: "writeCompleted",
            stream: streamId,
          });
        }
      },
      // A rejected write reports nothing: the stream's end releases it.
      () => {}
    );
    return accepted;
  }

  /** Finishes the write side after every accepted write. */
  closeWrite(streamId: number): void {
    quietly(() => {
      const stream = this.#streams.get(streamId);
      // Resolves once every accepted write has resolved, and been reported.
      stream?.writer?.close().then(
        () => {
          stream.writeEnded = true;
          this.#retireIfDone(streamId, stream);
        },
        // Stopped or reset: `writer.closed` or the reset covers it.
        () => {}
      );
    });
  }

  /** Resets the stream both ways (`abort()` and `cancel()`). */
  reset(streamId: number, code: number): void {
    quietly(() => {
      const stream = this.#streams.get(streamId);
      if (stream === undefined) {
        return;
      }
      this.#forget(streamId, stream);
      stream.writer?.abort(streamError(code)).catch(() => {});
      stream.reader?.cancel(streamError(code)).catch(() => {});
    });
  }

  /** Asks the peer to stop sending (`cancel()` only). */
  stop(streamId: number, code: number): void {
    quietly(() => {
      const stream = this.#streams.get(streamId);
      if (stream === undefined) {
        return;
      }
      stream.readEnded = true;
      if (stream.reader === undefined) {
        stream.pendingStop = code;
        return;
      }
      stream.reader.cancel(streamError(code)).catch(() => {});
      this.#retireIfDone(streamId, stream);
    });
  }

  /** Lets the stream deliver up to `bytes` more. */
  grantRead(streamId: number, bytes: number): void {
    quietly(() => {
      const stream = this.#streams.get(streamId);
      if (stream === undefined) {
        return;
      }
      stream.granted += bytes;
      this.#read(streamId, stream);
    });
  }

  /** Closes the session with a close capsule, as `WebTransport.close()` does. */
  close(sessionId: number, code: number, reason: string): void {
    quietly(() => {
      const session = this.#sessions.get(sessionId);
      if (session === undefined) {
        return;
      }
      // Rust forgets the session's streams with it.
      for (const id of session.streams) {
        const stream = this.#streams.get(id);
        if (stream !== undefined) {
          this.#forget(id, stream);
        }
      }
      // Throws once already closed, when `closed` reports the end anyway.
      session.transport.close({ closeCode: code, reason });
    });
  }

  /** The next queued event, if any. */
  pollEvent(): IoEvent | undefined {
    return this.#events.shift();
  }

  #push(event: IoEvent): void {
    this.#events.push(event);
    this.#wake();
  }

  #addStream(sessionId: number, session: Session): number {
    const id = this.#nextStream;
    this.#nextStream += 1;
    this.#streams.set(id, new Stream(sessionId));
    session.streams.add(id);
    return id;
  }

  /** Forgets a stream once both of its sides are done. */
  #retireIfDone(id: number, stream: Stream): void {
    if (!stream.dead && stream.readEnded && stream.writeEnded) {
      this.#forget(id, stream);
    }
  }

  #forget(id: number, stream: Stream): void {
    stream.dead = true;
    this.#streams.delete(id);
    this.#sessions.get(stream.session)?.streams.delete(id);
  }

  #attach(
    id: number,
    stream: Stream,
    bidi: WebTransportBidirectionalStream
  ): void {
    stream.writer = bidi.writable.getWriter();
    stream.reader = chunkReader(bidi.readable);
    // The peer's STOP_SENDING errors the write side.
    stream.writer.closed.catch((error: unknown) => {
      const code = peerStreamCode(error);
      if (!stream.dead && code !== undefined) {
        stream.writeEnded = true;
        this.#push({ code, kind: "stopSending", stream: id });
        this.#retireIfDone(id, stream);
      }
    });
    // The peer's RESET_STREAM errors the read side, read pending or not.
    stream.reader.closed.catch((error: unknown) => {
      this.#readFailed(id, stream, error);
    });
    if (stream.pendingStop !== undefined) {
      stream.reader.cancel(streamError(stream.pendingStop)).catch(() => {});
      return;
    }
    this.#read(id, stream);
  }

  #read(id: number, stream: Stream): void {
    const { reader } = stream;
    if (
      reader === undefined ||
      stream.reading ||
      stream.readEnded ||
      stream.dead ||
      stream.granted <= 0
    ) {
      return;
    }
    stream.reading = true;
    reader.read(Math.min(stream.granted, MAX_READ_BYTES)).then(
      ({ done, value }) => {
        stream.reading = false;
        if (stream.dead || stream.readEnded) {
          return;
        }
        if (done) {
          stream.readEnded = true;
          this.#push({ kind: "fin", stream: id });
          this.#retireIfDone(id, stream);
          return;
        }
        if (value.byteLength > 0) {
          stream.granted -= value.byteLength;
          this.#push({ bytes: value, kind: "data", stream: id });
        }
        this.#read(id, stream);
      },
      (error: unknown) => {
        stream.reading = false;
        this.#readFailed(id, stream, error);
      }
    );
  }

  /**
   * A read side errored: a peer reset, its session going away (which
   * `closed` reports too), or an error with no WebTransport code (Firefox
   * errors the read side so when the peer stops our sending as it closes).
   * Each ends the read side as a reset, so nothing waits on it.
   */
  #readFailed(id: number, stream: Stream, error: unknown): void {
    if (stream.dead || stream.readEnded) {
      return;
    }
    stream.readEnded = true;
    this.#push({ code: peerStreamCode(error) ?? 0, kind: "reset", stream: id });
    this.#retireIfDone(id, stream);
  }

  async #acceptIncoming(id: number, session: Session): Promise<void> {
    const reader = session.transport.incomingBidirectionalStreams.getReader();
    try {
      for (;;) {
        // oxlint-disable-next-line no-await-in-loop -- One stream at a time, in arrival order.
        const { done, value } = await reader.read();
        if (done || this.#sessions.get(id) !== session) {
          if (!done) {
            abandon(value);
          }
          return;
        }
        const stream = this.#addStream(id, session);
        const state = this.#streams.get(stream);
        if (state !== undefined) {
          this.#attach(stream, state, value);
          this.#push({ kind: "incomingStream", session: id, stream });
        }
      }
    } catch {
      // The session ended; `closed` reports it.
    } finally {
      reader.releaseLock();
    }
  }

  #endSession(id: number, code: number, reason: string): void {
    const session = this.#sessions.get(id);
    if (session === undefined) {
      return;
    }
    for (const streamId of session.streams) {
      const stream = this.#streams.get(streamId);
      if (stream !== undefined) {
        this.#forget(streamId, stream);
      }
    }
    this.#sessions.delete(id);
    this.#push({ code, kind: "sessionClosed", reason, session: id });
  }
}

function chunkReader(readable: ReadableStream<Uint8Array>): ChunkReader {
  try {
    const byob = readable.getReader({ mode: "byob" });
    return {
      cancel: (reason) => byob.cancel(reason),
      closed: byob.closed,
      read: (max) => byob.read(new Uint8Array(max)),
    };
  } catch {
    // Not a byte stream: split default chunks to the grant instead.
  }
  const reader = readable.getReader();
  let rest: Uint8Array | undefined;
  return {
    cancel: (reason) => reader.cancel(reason),
    closed: reader.closed,
    read: async (max) => {
      if (rest === undefined) {
        const result = await reader.read();
        if (result.done) {
          return result;
        }
        rest = result.value;
      }
      const value = rest.subarray(0, max);
      rest = rest.byteLength > max ? rest.subarray(max) : undefined;
      return { done: false, value };
    },
  };
}

/**
 * The reason a reset or stop passes, carrying its code: none for 0 (what
 * the browser sends by default), else a `WebTransportError`, in the spec's
 * `(message, options)` form or the `(init)` form Chrome implements.
 */
function streamError(code: number): unknown {
  if (code === 0 || typeof WebTransportError !== "function") {
    return undefined;
  }
  try {
    return new WebTransportError("minip2p stream error", {
      streamErrorCode: code,
    });
  } catch {
    // Chrome's constructor takes one init dictionary.
  }
  try {
    const init: unknown = {
      message: "minip2p stream error",
      streamErrorCode: code,
    };
    return Reflect.construct(WebTransportError, [init]) as unknown;
  } catch {
    return undefined;
  }
}

/** Runs a `JsIo` call Rust makes without catching, swallowing any throw. */
function quietly(operation: () => void): void {
  try {
    operation();
  } catch {
    // See the module rules: nothing may unwind into Rust from here.
  }
}

/**
 * The WebTransport code of an error the peer caused on one stream (a
 * `WebTransportError` with `source: "stream"`), cut to `u8`; `undefined`
 * for anything else, such as the session ending.
 */
function peerStreamCode(error: unknown): number | undefined {
  if (
    error === null ||
    typeof error !== "object" ||
    Reflect.get(error, "source") !== "stream"
  ) {
    return undefined;
  }
  const code: unknown = Reflect.get(error, "streamErrorCode");
  return typeof code === "number" ? Math.min(Math.max(code, 0), 0xff) : 0;
}

function abandon(bidi: WebTransportBidirectionalStream): void {
  bidi.writable.abort().catch(() => {});
  bidi.readable.cancel().catch(() => {});
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
