/* tslint:disable */
/* eslint-disable */

/**
 * A minip2p endpoint in the browser, dialing over WebTransport.
 *
 * It is driven by its TypeScript owner: every call returns at once, and
 * `pump` polls the endpoint, which the owner schedules after each call, each
 * `JsIo` event, and at the deadline `pump` returns.
 */
export class WebEndpoint {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Resets and relinquishes a stream.
     */
    abandonStream(conn_id: bigint, stream_id: bigint): void;
    /**
     * The relay reservation currently held, or `null`.
     */
    activeReservation(): any;
    /**
     * Registers an application protocol.
     */
    addProtocol(protocol_id: string): void;
    /**
     * Cancels a Connection attempt.
     */
    cancelConnect(id: bigint): void;
    /**
     * Half-closes a stream's write side.
     */
    closeStreamWrite(conn_id: bigint, stream_id: bigint): void;
    /**
     * Closes the endpoint; `EndpointClosed` is the last event drained.
     *
     * The timeout is ignored in the browser: every session closes at once
     * (`WebTransport.close()` sends the close capsule), so there is no
     * drain for it to bound.
     */
    close(_timeout_ms: number): void;
    /**
     * Starts one Connection attempt: a peer ID string, or an array of peer
     * addresses naming one peer. Returns the Connect ID.
     */
    connect(target: any): bigint;
    /**
     * Connected peer IDs.
     */
    connectedPeers(): string[];
    /**
     * A snapshot of a peer's connection, or `null`.
     */
    connectionInfo(peer_id: string): any;
    /**
     * Disconnects one peer.
     */
    disconnect(peer_id: string): void;
    /**
     * The discovery clock (always `null` in a browser).
     */
    discoveryNowMs(): any;
    /**
     * Pulls a bounded batch of events.
     */
    drainEvents(limit: number): any;
    /**
     * Whether Identify completed for a peer.
     */
    isPeerReady(peer_id: string): boolean;
    /**
     * Whether the endpoint is started and not closed.
     */
    isRunning(): boolean;
    /**
     * The discovery book (always empty in a browser).
     */
    knownPeers(): any;
    /**
     * The listen set; empty, since browsers do not listen.
     */
    listenAddrs(): string[];
    /**
     * Validates the key and config and builds the endpoint over `io`,
     * without driving it yet.
     */
    constructor(secret_key: Uint8Array, config: any, io: any);
    /**
     * Starts opening an application stream.
     */
    openStream(peer_id: string, protocol_id: string): any;
    /**
     * The path of a peer's connection, or `null`.
     */
    path(peer_id: string): any;
    /**
     * The local peer ID.
     */
    peerId(): string;
    /**
     * The latest Identify snapshot, or `null`.
     */
    peerInfo(peer_id: string): any;
    /**
     * Starts one ping.
     */
    ping(peer_id: string): void;
    /**
     * Publishes one pubsub payload.
     */
    publish(topic: string, data: Uint8Array): void;
    /**
     * Polls the endpoint once and returns the milliseconds until it needs
     * polling again (`0` at once), or `undefined` when nothing is
     * scheduled.
     */
    pump(): number | undefined;
    /**
     * The reachability verdict (always `Unknown` in a browser).
     */
    reachability(): any;
    /**
     * Resets a stream.
     */
    resetStream(conn_id: bigint, stream_id: bigint): void;
    /**
     * Sends bytes on a stream: `true` once all are accepted, `false` while
     * the tail is held and `StreamWriteAccepted` is still to come.
     */
    sendStream(conn_id: bigint, stream_id: bigint, data: Uint8Array): boolean;
    /**
     * Ignored in the browser, kept for the shared SDK surface: there is no
     * background driver whose cadence it could change. The page's own
     * timers pump the endpoint.
     */
    setActive(_active: boolean): void;
    /**
     * Starts driving; `doorbell` is called when events become ready to drain.
     */
    start(doorbell: Function): void;
    /**
     * Acknowledges `bytes` of a stream's received data as consumed.
     */
    streamConsumed(conn_id: bigint, stream_id: bigint, bytes: number): void;
    /**
     * Subscribes to a pubsub topic.
     */
    subscribe(topic: string): boolean;
    /**
     * Unsubscribes from a pubsub topic.
     */
    unsubscribe(topic: string): boolean;
}

/**
 * Builds a circuit address through a direct relay address.
 */
export function circuitAddress(relay_address: string, peer_id: string): string;

/**
 * Generates a 32-byte Ed25519 secret key from `crypto.getRandomValues`.
 */
export function generateSecretKey(): Uint8Array;

/**
 * Derives a peer ID from raw Ed25519 secret key material.
 */
export function peerIdFromSecretKey(secret_key: Uint8Array): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_webendpoint_free: (a: number, b: number) => void;
    readonly circuitAddress: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly generateSecretKey: () => [number, number, number, number];
    readonly peerIdFromSecretKey: (a: number, b: number) => [number, number, number, number];
    readonly webendpoint_abandonStream: (a: number, b: bigint, c: bigint) => [number, number];
    readonly webendpoint_activeReservation: (a: number) => [number, number, number];
    readonly webendpoint_addProtocol: (a: number, b: number, c: number) => [number, number];
    readonly webendpoint_cancelConnect: (a: number, b: bigint) => [number, number];
    readonly webendpoint_close: (a: number, b: number) => void;
    readonly webendpoint_closeStreamWrite: (a: number, b: bigint, c: bigint) => [number, number];
    readonly webendpoint_connect: (a: number, b: any) => [bigint, number, number];
    readonly webendpoint_connectedPeers: (a: number) => [number, number, number, number];
    readonly webendpoint_connectionInfo: (a: number, b: number, c: number) => [number, number, number];
    readonly webendpoint_disconnect: (a: number, b: number, c: number) => [number, number];
    readonly webendpoint_discoveryNowMs: (a: number) => [number, number, number];
    readonly webendpoint_drainEvents: (a: number, b: number) => [number, number, number];
    readonly webendpoint_isPeerReady: (a: number, b: number, c: number) => [number, number, number];
    readonly webendpoint_isRunning: (a: number) => number;
    readonly webendpoint_knownPeers: (a: number) => [number, number, number];
    readonly webendpoint_listenAddrs: (a: number) => [number, number];
    readonly webendpoint_new: (a: number, b: number, c: any, d: any) => [number, number, number];
    readonly webendpoint_openStream: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly webendpoint_path: (a: number, b: number, c: number) => [number, number, number];
    readonly webendpoint_peerId: (a: number) => [number, number];
    readonly webendpoint_peerInfo: (a: number, b: number, c: number) => [number, number, number];
    readonly webendpoint_ping: (a: number, b: number, c: number) => [number, number];
    readonly webendpoint_publish: (a: number, b: number, c: number, d: number, e: number) => [number, number];
    readonly webendpoint_pump: (a: number) => [number, number];
    readonly webendpoint_reachability: (a: number) => [number, number, number];
    readonly webendpoint_resetStream: (a: number, b: bigint, c: bigint) => [number, number];
    readonly webendpoint_sendStream: (a: number, b: bigint, c: bigint, d: number, e: number) => [number, number, number];
    readonly webendpoint_setActive: (a: number, b: number) => void;
    readonly webendpoint_start: (a: number, b: any) => [number, number];
    readonly webendpoint_streamConsumed: (a: number, b: bigint, c: bigint, d: number) => [number, number];
    readonly webendpoint_subscribe: (a: number, b: number, c: number) => [number, number, number];
    readonly webendpoint_unsubscribe: (a: number, b: number, c: number) => [number, number, number];
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __externref_drop_slice: (a: number, b: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
