# PollSource detach

`PollSource` has no `detach`. A `TransportSet` whose attach failed partway
through is dropped, not attached again.

## Why this is out of scope

`TransportSet::attach` attaches its members one at a time. A member that
fails cleans up its own registrations: TCP through
`StdTcpProvider::deregister_all`, QUIC by deregistering its socket clones,
and `MdnsSockets` the same way. Members attached before the failing one stay
registered, and the set records no attachment, so attaching the same set
again fails with "already registered".

That is the documented contract (see the `# Errors` section on
`impl PollSource for TransportSet` in `crates/transport/src/set.rs`): drop a
set whose attach failed. Dropping it closes the sockets and their
registrations go with them. Every host already does this. `Swarm`
(`crates/swarm/src/driver.rs`) and `Endpoint` (`crates/minip2p/src/std/mod.rs`)
treat a failed attach as fatal and tear the transport down.

Making attach all-or-nothing across a set would mean adding a required
`fn detach(&mut self)` to a public trait. Every source would then have to
implement it: `StdTcpProvider`, `TcpTransport`, `QuicTransport`,
`TransportSet`, `MdnsSockets`, the `Box<S>` forward, the circuit wrapper, and
about half a dozen test doubles. All of that would fix a failure no host can
reach. Under the project's YAGNI preference, the drop-on-failure contract is
the simpler design.

## When to revisit

Revisit when a host needs to retry an attach without rebuilding its
transports, for example an FFI or mobile host that rebinds after a network
change and wants to keep its transports. The design in #348 still holds then:
add a required `detach`, have `TransportSet::attach` detach the members it
already attached before it returns the error, and test a set whose second
member fails to attach followed by a successful re-attach.

## Prior requests

- #348: "PollSource: add detach so a TransportSet attach is all-or-nothing"
