# Endpoint-owned name resolution; transports accept only IP addresses

A blocking `/dns*` lookup on the driver thread stalled every connection on the endpoint (#238). The std Endpoint now resolves `/dns*` candidates off the driver, one detached thread per distinct in-flight name, and feeds each result back to the Connection attempt as a late-joining direct candidate or a failed candidate. The QUIC and TCP transports reject `/dns*` addresses and accept only `/ip4`/`/ip6`.

We rejected making hosts pre-resolve: the discovery sweep and advertised addresses reach `connect` without passing through host code, and every binding would need its own resolver. We also rejected a public resolver trait, because no one has asked for custom DNS. We rejected keeping blocking resolution in the transports as a convenience, because it would leave a way to stall the driver.

## Consequences

- There is no DNS-specific timeout: the attempt deadline bounds resolution, and a result that arrives after the attempt settles is dropped. `getaddrinfo` cannot be cancelled, so a dead resolver holds one thread per distinct name until the OS gives up. At most 32 names are looked up at once; a candidate past that cap is a failed candidate with a reason saying so.
- Direct `Transport` users and `send_raw_udp` callers must pass resolved addresses.
