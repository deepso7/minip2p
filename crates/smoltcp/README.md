# minip2p-smoltcp

Shared `no_std + alloc` ownership for a smoltcp device, interface, and socket
set. Embedded minip2p adapters clone the handle and install their own sockets
into the same network stack, allowing TCP and mDNS to use one physical link.
