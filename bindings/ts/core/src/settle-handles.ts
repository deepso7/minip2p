import { P2pEvent_Tags } from "./types.js";
import type { P2pEvent } from "./types.js";

/** The public stream a backend event names, when it names one. */
export const eventStream = (
  event: P2pEvent
): { readonly connId: number; readonly streamId: number } | undefined => {
  switch (event.tag) {
    case P2pEvent_Tags.StreamReady:
    case P2pEvent_Tags.StreamData:
    case P2pEvent_Tags.StreamWriteAccepted:
    case P2pEvent_Tags.StreamWriteStopped:
    case P2pEvent_Tags.StreamRemoteWriteClosed:
    case P2pEvent_Tags.StreamClosed: {
      return event.inner;
    }
    default: {
      return undefined;
    }
  }
};

/**
 * Native identities of streams whose events the SDK has not finished
 * handling: the acknowledgement-only handle that outlives a stream's
 * connection (ADR 0012).
 *
 * An adapter releases a connection's public ID as soon as it normalizes the
 * event that ends it, so stream operations behind that event fail. Bytes the
 * stream already delivered still hold the ended connection's native slot
 * until they are acknowledged or abandoned, though, and the SDK may only get
 * to them afterwards: dispatching a late `StreamReady`, discarding data for
 * a stream it no longer tracks, or reading bytes kept after a FIN. Each
 * normalized stream event holds its stream's handle until `eventHandled`, so
 * those paths still reach native; a stream consumer captured while it was
 * held keeps working after. With no event left in flight, the handle goes.
 */
export class SettleHandles<Native> {
  readonly #handles = new Map<
    number,
    Map<number, { native: Native; held: number }>
  >();

  /** Holds `native` for the stream of one normalized event. */
  hold(connId: number, streamId: number, native: Native): void {
    let streams = this.#handles.get(connId);
    if (streams === undefined) {
      streams = new Map();
      this.#handles.set(connId, streams);
    }
    const handle = streams.get(streamId);
    if (handle === undefined) {
      streams.set(streamId, { held: 1, native });
    } else {
      handle.held += 1;
    }
  }

  /** Releases one event's hold, once the SDK handled it. */
  release(connId: number, streamId: number): void {
    const streams = this.#handles.get(connId);
    const handle = streams?.get(streamId);
    if (streams === undefined || handle === undefined) {
      return;
    }
    handle.held -= 1;
    if (handle.held === 0) {
      streams.delete(streamId);
      if (streams.size === 0) {
        this.#handles.delete(connId);
      }
    }
  }

  get(connId: number, streamId: number): Native | undefined {
    return this.#handles.get(connId)?.get(streamId)?.native;
  }
}
