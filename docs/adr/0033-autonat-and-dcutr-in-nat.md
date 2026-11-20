# AutoNAT and DCUtR live in minip2p-nat

`minip2p-autonat` and `minip2p-dcutr` were separate crates, but their only production consumer was `minip2p-nat`, which needs both unconditionally. They had the costs ADR 0020 names (a manifest, a README, a publish-order slot, a `check-nostd` entry, a version bump per release), and `minip2p-dcutr` also sat in a dev-dependency cycle: `minip2p-swarm` dev-depended on it for `relay_holepunch_flow`, while `minip2p-nat` depends on `minip2p-swarm`.

## Decision

- **The crates become the public modules `minip2p_nat::autonat` and `minip2p_nat::dcutr`**, with their APIs unchanged. They stay public because the fuzz target and the Endpoint's NAT tests drive the protocol machines directly, and they get no cargo features of their own: NAT cannot run without either.
- **`relay_holepunch_flow` moves from `crates/swarm/tests` to `crates/nat/tests`**. It never used the swarm, and with it gone `minip2p-swarm` has no dev-dependencies, so the cycle is gone.
- **Retired crate names are yanked by hand**, as in ADR 0020.

## Consequences

- `fuzz/` depends on `minip2p-nat` (with `std`) instead of the two small crates, so its build pulls in the swarm. That is a build-time cost only.
- A user who wants only the AutoNAT or DCUtR wire machines takes all of `minip2p-nat`. None exists today.
- The publish list loses two crates (23 → 21).
