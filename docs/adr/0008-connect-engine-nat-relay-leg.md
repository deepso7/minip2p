# Connection-attempt engine coordinates; NatAgent provides the relay leg

The Connection-attempt engine owns identity, direct racing, deadline, the provisional Relayed path, the terminal outcome, and cancellation. `NatAgent` is a relay-leg provider keyed by the engine's `ConnectId`: relay session dial, HOP CONNECT, bridge promotion, and DCUtR. Direct candidate racing left `NatAgent`.

Rejected: moving `attempt.rs` into the engine (would drag `Shared` into the application crate). Rejected: delegating the whole attempt to `NatAgent` when NAT is configured (two direct-racing implementations; builds without NAT would not share the engine).

Consequences: `ConnectId` lives in `minip2p-core`; `NatConfig::connect_deadline_ms` is gone (engine 30 s); `PathEstablished { Relayed }` is provisional until `ConnectSettled`.
