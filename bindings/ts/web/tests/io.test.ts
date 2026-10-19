/* oxlint-disable max-classes-per-file, promise/avoid-new -- The fake WebTransport exposes the browser's promise-and-stream surface, settled by the test. */

import { afterEach, describe, expect, test, vi } from "vitest";

import { JsIo, MAX_IN_FLIGHT_BYTES } from "../src/io.js";
import type { IoEvent, WebTransportSession } from "../src/io.js";

/** A `WebTransportError`-shaped stream error, as browsers raise it. */
const peerStreamError = (streamErrorCode: number | null) =>
  Object.assign(new Error("stream error"), {
    source: "stream",
    streamErrorCode,
  });

/** The server's end of one fake bidirectional stream. */
class FakeStream {
  readonly written: Uint8Array[] = [];
  /** Settles the oldest write still waiting in the fake sink. */
  readonly #pendingWrites: (() => void)[] = [];
  readable: ReadableStreamDefaultController | undefined;
  #reads: ReadableByteStreamController | undefined;
  #writes: WritableStreamDefaultController | undefined;
  closedWrite = false;
  aborted = false;
  abortReason: unknown;
  cancelled = false;

  readonly bidi: WebTransportBidirectionalStream = {
    readable: new ReadableStream({
      cancel: () => {
        this.cancelled = true;
      },
      start: (controller) => {
        this.#reads = controller;
      },
      type: "bytes",
    }),
    writable: new WritableStream<Uint8Array>({
      abort: (reason) => {
        this.aborted = true;
        this.abortReason = reason;
      },
      close: () => {
        this.closedWrite = true;
      },
      start: (controller) => {
        this.#writes = controller;
      },
      write: async (chunk) => {
        this.written.push(chunk);
        await new Promise<void>((resolve) => {
          this.#pendingWrites.push(resolve);
        });
      },
    }),
  } as unknown as WebTransportBidirectionalStream;

  /** The peer sends bytes. */
  send(bytes: number[]): void {
    this.#reads?.enqueue(new Uint8Array(bytes));
  }

  /** The peer finishes its side. */
  fin(): void {
    this.#reads?.close();
  }

  /** The peer resets its side. */
  reset(code: number | null): void {
    this.#reads?.error(peerStreamError(code));
  }

  /** The browser errors the read side without a WebTransport code. */
  failRead(): void {
    this.#reads?.error(new TypeError("Error in input stream"));
  }

  /** The peer asks us to stop sending. */
  stopSending(code: number): void {
    this.#writes?.error(peerStreamError(code));
  }

  /** The browser finishes the oldest write in flight. */
  completeWrite(): void {
    this.#pendingWrites.shift()?.();
  }
}

class FakeWebTransport implements WebTransportSession {
  readonly ready: Promise<undefined>;
  readonly closed: Promise<WebTransportCloseInfo>;
  readonly incomingBidirectionalStreams: ReadableStream<WebTransportBidirectionalStream>;
  readonly opened: FakeStream[] = [];
  readonly closeCalls: WebTransportCloseInfo[] = [];
  #accept:
    | ReadableStreamDefaultController<WebTransportBidirectionalStream>
    | undefined;
  #ready: (() => void) | undefined;
  #closed: ((info: WebTransportCloseInfo) => void) | undefined;

  readonly url: string;
  readonly options: WebTransportOptions;

  constructor(url: string, options: WebTransportOptions) {
    this.url = url;
    this.options = options;
    this.ready = new Promise((resolve) => {
      this.#ready = () => {
        resolve();
      };
    });
    this.closed = new Promise((resolve) => {
      this.#closed = resolve;
    });
    this.incomingBidirectionalStreams = new ReadableStream({
      start: (controller) => {
        this.#accept = controller;
      },
    });
  }

  createBidirectionalStream(): Promise<WebTransportBidirectionalStream> {
    const stream = new FakeStream();
    this.opened.push(stream);
    return Promise.resolve(stream.bidi);
  }

  close(info: WebTransportCloseInfo = {}): void {
    this.closeCalls.push(info);
  }

  /** The CONNECT succeeds. */
  open(): void {
    this.#ready?.();
  }

  /** The session ends, as `closed` reports it. */
  end(info: WebTransportCloseInfo): void {
    this.#closed?.(info);
  }

  /** The server opens a stream. */
  incoming(): FakeStream {
    const stream = new FakeStream();
    this.#accept?.enqueue(stream.bidi);
    return stream;
  }
}

/** Lets every queued promise callback run. */
const flush = async (): Promise<void> => {
  for (let turn = 0; turn < 20; turn += 1) {
    // oxlint-disable-next-line no-await-in-loop -- Each turn drains one promise hop.
    await Promise.resolve();
  }
  await new Promise((resolve) => {
    setTimeout(resolve, 0);
  });
};

/** A `JsIo` over fake sessions, with its wakes counted. */
const harness = () => {
  const sessions: FakeWebTransport[] = [];
  let wakes = 0;
  const io = new JsIo(
    () => {
      wakes += 1;
    },
    (url, options) => {
      const session = new FakeWebTransport(url, options);
      sessions.push(session);
      return session;
    }
  );
  const events = (): IoEvent[] => {
    const all: IoEvent[] = [];
    for (
      let event = io.pollEvent();
      event !== undefined;
      event = io.pollEvent()
    ) {
      all.push(event);
    }
    return all;
  };
  return { events, io, sessions, wakes: () => wakes };
};

/** A ready session with one opened stream. */
const openedStream = async () => {
  const setup = harness();
  const session = setup.io.connect("https://192.0.2.1:4001/x", []);
  setup.sessions[0]?.open();
  await flush();
  const stream = setup.io.openStream(session);
  await flush();
  setup.events();
  const fake = setup.sessions[0]?.opened[0];
  if (fake === undefined) {
    throw new Error("no stream opened");
  }
  return { ...setup, fake, session, stream };
};

describe("JsIo", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  test("a session trusts exactly the dialed certhashes and reports ready", async () => {
    const { events, io, sessions, wakes } = harness();
    const digest = new Uint8Array(32).fill(7);

    const session = io.connect(
      "https://192.0.2.1:4001/.well-known/libp2p-webtransport?type=noise",
      [digest]
    );
    expect(events()).toEqual([]);
    sessions[0]?.open();
    await flush();

    expect(sessions[0]?.options).toEqual({
      serverCertificateHashes: [{ algorithm: "sha-256", value: digest }],
    });
    expect(events()).toEqual([{ kind: "sessionReady", session }]);
    expect(wakes()).toBe(1);
  });

  test("writes copy what they accept, cap in-flight bytes and complete with their own lengths", async () => {
    const { events, fake, io, stream } = await openedStream();
    const source = new Uint8Array(MAX_IN_FLIGHT_BYTES).fill(1);

    expect(io.write(stream, source.subarray(0, 1000))).toBe(1000);
    expect(io.write(stream, source)).toBe(MAX_IN_FLIGHT_BYTES - 1000);
    expect(io.write(stream, source)).toBe(0);
    // The caller's buffer (wasm memory) changes; queued writes keep their bytes.
    source.fill(9);
    await flush();

    fake.completeWrite();
    await flush();
    expect(events()).toEqual([{ bytes: 1000, kind: "writeCompleted", stream }]);
    expect(io.write(stream, source)).toBe(1000);
    fake.completeWrite();
    await flush();
    expect(events()).toEqual([
      { bytes: MAX_IN_FLIGHT_BYTES - 1000, kind: "writeCompleted", stream },
    ]);
    expect(fake.written[0]?.every((byte) => byte === 1)).toBe(true);
    expect(fake.written[1]?.every((byte) => byte === 1)).toBe(true);
  });

  test("reads deliver no more than granted, then FIN", async () => {
    const { events, fake, io, stream } = await openedStream();
    fake.send([1, 2, 3, 4, 5, 6]);
    await flush();
    expect(events()).toEqual([]);

    io.grantRead(stream, 4);
    await flush();
    const first = events();
    io.grantRead(stream, 10);
    fake.fin();
    await flush();
    const rest = events();

    const delivered = [...first, ...rest].flatMap((event) =>
      event.kind === "data" ? [...event.bytes] : []
    );
    expect(
      first.every(
        (event) => event.kind === "data" && event.bytes.byteLength <= 4
      )
    ).toBe(true);
    expect(delivered).toEqual([1, 2, 3, 4, 5, 6]);
    expect(rest.at(-1)).toEqual({ kind: "fin", stream });
  });

  test("a peer reset and STOP_SENDING arrive with codes cut to u8", async () => {
    const { events, fake, stream } = await openedStream();

    fake.reset(300);
    fake.stopSending(7);
    await flush();

    expect(events()).toEqual(
      expect.arrayContaining([
        { code: 255, kind: "reset", stream },
        { code: 7, kind: "stopSending", stream },
      ])
    );
  });

  test("a read side failing without a stream code ends as a reset", async () => {
    // Firefox does this when the peer stops our sending as it closes.
    const { events, fake, io, stream } = await openedStream();
    io.grantRead(stream, 10);

    fake.failRead();
    await flush();

    expect(events()).toEqual([{ code: 0, kind: "reset", stream }]);
  });

  test("a locally reset stream reports nothing more", async () => {
    const { events, fake, io, stream } = await openedStream();
    io.write(stream, new Uint8Array([1]));
    await flush();

    io.reset(stream, 0);
    fake.completeWrite();
    fake.reset(1);
    await flush();

    expect(fake.aborted).toBe(true);
    expect(events()).toEqual([]);
    expect(() => io.write(stream, new Uint8Array([2]))).toThrow(
      /not writable/u
    );
  });

  test("a reset carries its code through Chrome's WebTransportError, and never throws into Rust", async () => {
    // Chrome takes one init dictionary where the spec takes (message, options).
    class ChromeWebTransportError extends Error {
      readonly streamErrorCode: number;

      constructor(init: unknown) {
        super("stream error");
        this.name = "ChromeWebTransportError";
        if (typeof init !== "object" || init === null) {
          throw new TypeError(
            "The provided value is not of type 'WebTransportErrorInit'."
          );
        }
        this.streamErrorCode = Number(Reflect.get(init, "streamErrorCode"));
      }
    }
    const { fake, io, stream } = await openedStream();
    vi.stubGlobal("WebTransportError", ChromeWebTransportError);

    expect(() => {
      io.reset(stream, 3);
    }).not.toThrow();
    await flush();

    expect(fake.abortReason).toMatchObject({ streamErrorCode: 3 });
  });

  test("server streams are announced, and a session end drops its streams", async () => {
    const { events, io, sessions, session } = await openedStream();
    const incoming = sessions[0]?.incoming();
    await flush();
    const [announced] = events();
    expect(announced).toMatchObject({ kind: "incomingStream", session });

    io.close(session, 0, "bye");
    incoming?.send([1]);
    sessions[0]?.end({ closeCode: 0, reason: "" });
    await flush();

    expect(sessions[0]?.closeCalls).toEqual([{ closeCode: 0, reason: "bye" }]);
    expect(events()).toEqual([
      { code: 0, kind: "sessionClosed", reason: "", session },
    ]);
  });

  test("connect without WebTransport says what is missing", () => {
    const io = new JsIo(() => {}, undefined);
    expect(() => io.connect("https://192.0.2.1:1/", [])).toThrow(
      /no WebTransport/u
    );
  });
});
