# Generic mDNS carrier on `PortableEndpoint`

`PortableEndpoint<T, E>` does not take the mDNS carrier as a type parameter. When `mdns` (or `smoltcp`, which enables it) is compiled in, the carrier is stored as a `Box<dyn MdnsIo>`. In that build no `PortableEndpoint` is `Send`, including ones that never call `.mdns(..)`.

## Why this is out of scope

The fix would be a third public parameter, `PortableEndpoint<T, E, M = NoMdns>`, with `PortableEndpointBuilder::mdns(io, config)` changing the builder's carrier type. That parameter would then show up in every signature that names the endpoint or its builder, and in the smoltcp constructors, docs, and READMEs.

Very few callers would gain anything from it:

- The std `Endpoint` is unaffected: it holds concrete `MdnsSockets`, which are `Send`. Since #432 there is one `mdns` feature for both endpoints, so a std build with `mdns` no longer keeps `PortableEndpoint` `Send` (the uninhabited `NoMdns` carrier from #345 is gone), but std programs use the std `Endpoint`.
- `smoltcp` is the main way `mdns` gets turned on in a portable build, and smoltcp endpoints are single-threaded regardless. They hold a `SharedEntropy` and run on a shared stack.
- So the only beneficiary is a non-smoltcp `mdns` build that also needs to move a portable endpoint between threads. That's rare on the `no_std` targets the portable endpoint is meant for.

This also follows #232, which chose not to add a public generic type when it "would only add type and feature complexity for callers." The current behaviour is documented on `PortableEndpoint` and in the `minip2p` README.

## When to revisit

A concrete user who needs a `Send` `PortableEndpoint` in a build where some dependency enables `mdns`. The private `Engine<T, E, M: Carrier>` is already generic, so most of the work would be in the public types.

## Prior requests

- #347: "PortableEndpoint: tie the loss of Send to configuring mDNS, not to the portable-mdns feature"
