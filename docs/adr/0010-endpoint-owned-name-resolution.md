# Endpoint-owned name resolution; transports accept only IP addresses

A blocking `/dns*` lookup on the driver thread stalled every connection on the endpoint (#238). The std Endpoint now resolves `/dns*` candidates off the driver, one detached thread per distinct in-flight name, and feeds each result back to the Connection attempt as a late-joining direct candidate or a failed candidate. The QUIC and TCP transports reject `/dns*` addresses and accept only `/ip4`/`/ip6`.

We rejected making hosts pre-resolve: the discovery sweep and advertised addresses reach `connect` without passing through host code, and every binding would need its own resolver. We also rejected a public resolver trait, because no one has asked for custom DNS. We rejected keeping blocking resolution in the transports as a convenience, because it would leave a way to stall the driver.

## Consequences

- There is no DNS-specific timeout: the attempt deadline bounds resolution, and a result that arrives after the attempt settles is dropped. `getaddrinfo` cannot be cancelled, so a dead resolver holds one thread per distinct name until the OS gives up. At most 32 names are looked up at once; a candidate past that cap is a failed candidate with a reason saying so.
- Direct `Transport` users, including `send_datagram` callers, must pass resolved addresses.

## Amendments: implementation details

- **A parked dial whose flight already ended starts no lookup.** `NatDriver::expand_parked` skips a dial whose attempt was cancelled or expired before it was expanded (`NatAgent::deferred_dial_wanted`): a lookup cannot be cancelled and would hold one of the capped resolver slots for nothing.
- **An IP literal in a `/dns*` component is refused**, not looked up and not dialed as an address. The std `Resolver` refuses it rather than routing an address down the path meant for names.
- **A resolving candidate is racing.** A `/dns*` candidate still resolving is a direct candidate in the race: the Connection attempt does not fail at admission for lack of a dial, and while it resolves the attempt counts as racing direct, so the relay leg waits out its stagger (`NatConfig::relay_stagger_ms`) before it parks the relay dial.
- **A `/dns*` dial target must carry a `/tcp` or `/udp` port.** Without one there is nothing to dial, and guessing a default would dial a service the caller never named; the candidate is refused at validation.
- **One target per address family.** `answer_for` dials only the first answer of each family, in the order they arrived: two dials over the same socket kind to the same peer are a wasted connection, not a second path.
