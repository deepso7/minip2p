# minip2p-circuit

`minip2p-circuit` turns an already-negotiated relay bridge stream into a
regular minip2p `Transport` connection. It is fully Sans-I/O: multistream
selection, Noise, and Yamux are driven over the bridge while the wrapped
transport remains responsible for actual I/O.

The wrapper assigns circuit connections IDs with the high bit set, leaving
wrapped transport IDs unchanged. Callers adopt HOP/STOP bridge streams with
`CircuitTransport::adopt_bridge` and then use the ordinary `Transport` API.

Default features enable OS entropy. Disable default features for
`no_std + alloc` and provide an `EntropySource` explicitly.
