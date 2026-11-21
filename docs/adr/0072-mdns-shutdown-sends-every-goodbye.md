# mDNS shutdown sends every goodbye, with a bounded drain

A goodbye is a claim with a zero TTL. An unsent one costs every peer a full TTL of pointing at a host that has gone, which is the whole reason a shutdown says one. So `MdnsDriver::shutdown` (crate `minip2p-mdns`) departs from the per-tick rules:

- **Every goodbye, not a budget's worth.** Shutdown drains all of `MdnsAgent::poll_action` after `MdnsAgent::shutdown`, ignoring `MAX_ACTIONS_PER_TICK`.
- **Congestion is drained in place, bounded.** There is no next turn to park a congested goodbye until, so shutdown polls the carrier and retries up to `SHUTDOWN_DRAIN_ATTEMPTS` times. It is bounded because a carrier that will not drain must not hold a shutdown open forever: a host waiting to exit gets to, and is told through the returned error and a final `MdnsEvent::Failed` that the goodbye did not make it.
- **A final `poll` before the carrier is dropped.** A stack that moves bytes only when driven would otherwise take every queued goodbye with it.
- **Dropping the driver is a shutdown.** `Drop` calls `shutdown`, dated with the last `Now` a caller supplied (`last_now`): a drop brings no clock, and a stale-but-real timestamp beats inventing one. `Drop` cannot return the error; it is still reported as `MdnsEvent::Failed`.
- **Taking the carrier out of `running` is what makes shutdown idempotent** and a stopped driver inert: one representation of "finished", not two that must agree.
