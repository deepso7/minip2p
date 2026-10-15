# Crate placement: platform in core, noise and yamux in secure-mux, smoltcp on its own

The workspace published a crate for every piece that had a clean seam, including pieces nothing used on its own. Each extra crate costs a manifest, a README, a place in the hand-kept publish order and `check-nostd` lists, and a version bump on every release, and it tells readers the piece is meant to be used standalone. #253 decided where three such pieces belong.

## Decision

- **`minip2p-platform` moves into core as `minip2p_core::platform`.** Every crate that depended on platform already depended on core, so the separate crate bought no smaller dependency graph. The API is unchanged and lives only under the `platform` module, with nothing re-exported at the core root, so the time and entropy contracts stay visibly separate from the address and wire types. `StdClock` and `StdEntropy` sit behind core's existing `std` feature, which now also enables `getrandom`; there is no separate clock or entropy feature.
- **`minip2p-noise` and `minip2p-yamux` become the public modules `minip2p_secure_mux::noise` and `minip2p_secure_mux::yamux`.** Secure-mux was their only production consumer and needs both unconditionally; nothing used either standalone. They stay public so the fuzz target, interop tests and benches keep reaching them, and they get no cargo features of their own. Secure-mux keeps its convenience re-exports such as `YamuxConfig` and `YamuxError`.
- **`minip2p-smoltcp` stays a separate crate.** It is concrete network-stack state (one smoltcp interface and socket set) shared by the TCP transport and mDNS when both run on the same embedded stack. Core holds no I/O and transport holds only contracts, so neither is the right home for it, and putting it in the TCP transport would make mDNS depend on TCP, which it must never do.
- **Retired crate names are yanked.** After the release that drops a crate, the maintainer yanks every published version of it by hand. minip2p has no external users, so there are no forwarding or notice crates.

## Rejected alternatives

- **Re-exporting the platform types at the core root.** `minip2p_core::Now` beside `minip2p_core::Multiaddr` would blur which types are platform contracts, and two paths to one type make imports inconsistent.
- **Feature-gating noise and yamux inside secure-mux.** Secure-mux cannot work without either, so a feature would only add matrix entries.
- **Folding smoltcp into core or transport.** Both are dependency-free contracts; a concrete network stack would pull smoltcp into every crate.
- **Keeping the retired crates as thin re-export shims.** They would need releasing forever for users that do not exist.

## Consequences

- The publish list loses three crates (25 → 22), and both `check-nostd` lists lose them too.
- Code that imported `minip2p_platform::X` now imports `minip2p_core::platform::X`; code that imported `minip2p_noise` or `minip2p_yamux` imports through `minip2p_secure_mux`.
- Crates that need a time or entropy contract but not core would have to take core anyway. None exists today.
