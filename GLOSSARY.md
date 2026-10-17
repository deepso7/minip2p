# minip2p

A minimal libp2p implementation in Rust with sans-I/O cores, transport adapters, and foreign-runtime bindings.

## Language

### Bindings

**FFI core**: The binding-agnostic embedding layer (`minip2p-ffi-core`): the detached driver thread, event flattening, and endpoint lifecycle that every binding shell builds on.

**Binding shell**: A thin crate adapting the FFI core to one foreign toolchain — UniFFI for React Native (`minip2p-ffi`), napi-rs for Node (`minip2p-nodejs`), PyO3 for Python (`minip2p-python`). Shells hold no driver or lifecycle logic of their own. _Avoid_: wrapper

**Backend contract**: The synchronous `Minip2pBackend` interface in `@minip2p/core` that each JS binding implements; the TypeScript-facing seam shared by React Native and Node.

**Platform package**: A binary-only npm package (`@minip2p/node-<target>`) carrying one prebuilt Node binding binary, selected at install time through `optionalDependencies`. Holds nothing but the binary and its manifest.

**Carry buffer**: The FFI driver's single event queue. Stream and connection-end events never drop and adjacent stream data coalesces, except that a peer-opened stream, or any connection, that ends without carrying data before the binding took any of its events leaves the carry whole (an unseen connection that is replaced folds into its successor); past 4096 other events it drops gossipsub messages first, then the oldest (`EventsDropped` diagnostic). The only place events wait or drop between the driver and a binding.

**Doorbell**: The coalesced, edge-triggered ready signal a binding registers with the FFI core; rung only when the carry buffer goes empty→non-empty. Replaces per-event push through the listener seam.

**Drain**: A binding's synchronous `drain_events(limit)` command pulling a batch from the carry buffer in order. A binding that hears the doorbell must drain until empty.

### SDKs

**TypeScript SDK**: The one TypeScript API minip2p presents on every JS runtime: the `@minip2p/core` API plus a runtime's binding package. Documented as a single "TypeScript" docs section. _Avoid_: Node SDK, React Native SDK (they are the same SDK on different runtimes)

**Python SDK**: minip2p's asyncio-first Python API: the pure-Python `minip2p` package over the PyO3 binding shell, mirroring the TypeScript SDK's concepts with Pythonic names. Documented as a single "Python" docs section. _Avoid_: Python bindings (that is the binding shell)

**Runtime**: The host a TypeScript SDK app runs on — Node.js or React Native. Runtimes differ in setup and a short list of one-sided extras; the API is otherwise shared. Distinct from the binding shell that serves it.

### Connections

**Connection replacement**: A newer connection to a peer taking the single per-peer connection slot from an older one. The peer never counts as disconnected. Everything that belonged to the old connection ends with it, including its streams, its readiness, and any writes it had accepted but not yet sent: acceptance is local, never delivery. The newest connection wins, except in a connection race: when two direct connections to one peer register within the simultaneous-dial window (`SIMULTANEOUS_DIAL_WINDOW_MS`, 5 s by default) of each other, both peers keep the same one whatever order each sees them in. In opposite directions (a simultaneous dial) that is the one dialed by the lower peer ID; in the same direction (two of one peer's candidate dials) it is the one with the lower Connection token, falling back to the newest when either has none. A winner arriving second replaces the other as usual (`ConnectionReplaced`); a loser arriving second is closed unannounced, and if that dial was our own it completes as a dial failure. Both peers agree only once each has seen both connections, so a Connection attempt keeps its other direct dials open for the window instead of aborting them. The side that sees both first closes the loser at once, so when the loser was the other side's only connection so far, that side sees it close before the winner establishes there: a disconnect, not a Connection replacement. _Avoid_: supersede, reconnect

**Connection token**: A value both ends of one connection compute identically from its handshake (QUIC: a TLS exporter value; TCP: the Noise handshake hash), carried on the transport's `Connected` endpoint. It lets both peers make the same choice in a same-direction connection race without exchanging anything. It is not a secret and identifies nothing outside that comparison.

**Connection close reason**: Why one connection ended, carried on its close event: we closed it, the peer closed it (with its code), the peer went silent (timed out), the peer stopped reading (stalled), or an error. A Connection replacement is not a close. _Avoid_: close reason (unqualified), disconnect reason

**Endpoint close reason**: Why a binding's endpoint stopped: the application closed it, or its driver failed. Distinct from a Connection close reason. _Avoid_: close reason (unqualified)

**Peer readiness**: A peer's current connection has completed Identify, so its protocols are known. Readiness belongs to a connection: after a Connection replacement the peer becomes ready again once the new connection is identified.

### NAT traversal

**Connection attempt**: One application-level effort to reach a peer. It may start several Transport dials, establish a provisional Relayed path, and later upgrade that path, but it has one identity and ends with exactly one terminal outcome: connected, failed, or cancelled. _Avoid_: dial

**Transport dial**: One mechanism-level attempt to establish a transport connection to one peer address. Several Transport dials may belong to one Connection attempt. _Avoid_: connection attempt

**Connect ID**: The endpoint-local identity of a Connection attempt. It remains the same across candidate Transport dials, relay fallback, and direct-path upgrades.

**Connection target**: What an application supplies to start a Connection attempt: a peer ID, one complete peer address, or a non-empty set of complete peer addresses that all name the same peer. Each address retains its transport shape and peer ID so it can be copied as advertised.

**Name resolution**: The Endpoint step that turns a `/dns*` candidate of a Connection attempt into concrete `/ip4`/`/ip6` candidates. It runs beside the attempt, never on the driver: other candidates and the relay leg race while it is pending, and a failed lookup is one failed candidate. Transports never resolve names. _Avoid_: expansion

**Endpoint event stream**: The endpoint's single public, ordered source of connection, protocol, discovery, and diagnostic events. Applications correlate events with operation IDs and build selective waits above this stream; the endpoint does not expose competing focused queues or waits.

**Endpoint wait outcome**: Why a blocking endpoint wait returned: an Endpoint event, the caller's deadline, or an explicit interruption. Deadline and interruption are control outcomes, not competing event sources.

**State snapshot**: An authoritative getter over durable current endpoint state, such as active connections, selected paths, known peer addresses, or listener addresses. State changes before its event is queued, so separate getters may be ahead of the Endpoint event stream and are not one cross-getter atomic snapshot.

**Circuit**: The hop/stop bridged byte pipe through a Circuit Relay v2 hop, before Noise and Yamux have turned it into a Relayed path. _Avoid_: connection (until that upgrade finishes)

**Relayed path**: A swarm connection whose transport is a circuit. Identify, ping, and application streams use it like any other connection. _Avoid_: fallback connection

**DCUtR**: The `/libp2p/dcutr` protocol that coordinates a hole punch over an existing Relayed path. It is an upgrade, not the circuit handshake. _Avoid_: using DCUtR as the Noise barrier

**Relay leg**: The NAT-owned part of a Connection attempt: relay dial, HOP CONNECT, bridge promotion, DCUtR. Keyed by the attempt's Connect ID; never decides the attempt's terminal outcome.

**Observed address**: The address a trusted relay or AutoNAT server reports, through Identify, as where it sees us on one connection. It belongs to that connection and ends with it, so one reporter vouches for only the family it is currently connected over. Feeds hole-punch candidates and AutoNAT probes; distinct from a confirmed public address. _Avoid_: external address (that is AutoNAT-confirmed)

**Path**: How a peer's current connection was established: Direct (dialed or accepted), Punched (by DCUtR), or Relayed through a named relay. Every established connection has one. _Avoid_: route, origin

**force_relay**: Keep the selected path Relayed: no direct candidate dials and no hole punch. The circuit upgrade is the same as without the flag.

### Wire codecs

**Protobuf wire vocabulary**: The shared field-framing helpers in `minip2p-core` (tags, varints, length-delimited reads, unknown-field skipping, `WireError`). Protocol crates wrap these failures in contextual errors and keep their own message semantics. Distinct from stream length-prefix framing (`encode_frame` / `decode_frame`).

**Payload**: The bytes of one stream read or write, held as a shared handle so fan-out and forwarding clone the handle, not the bytes.

### Backpressure

**Full**: A stream write that did not fit the stream's send capacity. It is retryable, not a fault; the caller keeps the unsent tail and retries. _Avoid_: send failure, buffer overflow

**Unsent tail**: The suffix of a payload a Full write did not accept, handed back to the caller. It is the whole payload when nothing fit. _Avoid_: rejected payload, remainder

**Control stream**: A stream the swarm uses for its own protocols: every stream while multistream negotiates it, and ping and Identify streams after. It may write into a reserve of the connection's send cap that application streams cannot fill, so they cannot starve it. The swarm marks it; transports never inspect protocols. _Avoid_: priority stream, system stream

**Writable**: The one-shot notice that a stream which reported Full can again accept at least half of its smallest send limit. A Full arms it; it fires once, and never if the stream's write side ends first. _Avoid_: ready, drain event

**Stream writer**: The opt-in holder of an application's unsent tails: one pending write per stream, retried on Writable, with a write-side close that waits for it. Its completion means the whole payload was accepted, never delivered. The Rust Endpoint and the FFI core share one. _Avoid_: buffered stream, write queue

**Receive budget**: The most unacknowledged bytes a stream will deliver to its reader. Acknowledging consumed bytes replenishes it, which is what lets the sender continue. _Avoid_: read buffer, window (the transport's own term)

**Unsettled stream**: A stream whose delivered bytes are not yet all acknowledged or abandoned. It keeps its stream slot even after closing, and after its connection ends, so stream churn cannot grow retained receive data. Acknowledging or abandoning its bytes still settles it after the connection is gone. _Avoid_: zombie stream, lingering stream

**Unsettled connection**: A connection that has ended while some of its streams are still unsettled. It keeps its connection slot (a circuit keeps its circuit slot) until every one of those streams settles, so close-and-reconnect churn cannot grow retained receive data either; a transport whose slots are all held refuses new connections rather than forgetting what was delivered. Only its accounting and ownership survive. _Avoid_: closing connection, draining connection (draining is QUIC's own close phase)

**Memory budget**: The bytes one transport (QUIC, TCP, or the circuit transport) may commit to its connections and streams, across all its sockets. Every connection and stream holds a memory reservation against it, so the budget caps the transport's worst-case retained payload; each transport has its own, named after it ("QUIC memory budget"). _Avoid_: send budget, memory limit, quota

**Memory reservation**: The share of a memory budget that a connection or stream holds from admission until its bytes are released, which for delivered data means acknowledged or abandoned. A connection or stream whose reservation does not fit is refused, not queued. Distinct from a relay reservation. _Avoid_: reservation (unqualified), allocation, quota

**Manual acknowledgement**: A protocol registration whose stream data the application acknowledges itself (`stream_consumed`) once it has really consumed the bytes, instead of the Endpoint acknowledging data as its event is pulled. Every protocol registered through FFI uses it; the SDK acknowledges when `read()` returns a chunk or a `data` listener returns. _Avoid_: manual read, flow control mode

### Errors

**Bind error**: A failure turning Endpoint options into a running Endpoint, before any event is polled. It names what failed (a transport, the relay server, gossipsub, mDNS, or the options themselves) and carries that part's typed cause. Never describes something that fails later. _Avoid_: config error, InvalidConfig

**Capability failure event**: A runtime change in one capability's failure state, such as mDNS or a relay server address source, reported on the Endpoint event stream while the endpoint keeps running. A failure is reported once per change, and a recovery is reported if the capability later recovers; a failure while the capability is being shut down is final. Meanwhile the capability keeps its last accepted state. _Avoid_: poll error, runtime error
