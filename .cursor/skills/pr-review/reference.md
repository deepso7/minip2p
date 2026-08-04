# Micro-agent charters (pr-review)

Bugbot is **not** a charter here — launch/merge rules live in `SKILL.md`. This file only defines State / Parse / Security / Flow / Verify / Quality.

Shared constraints for every specialist:

- Worktree + `git diff <base>...HEAD` only (plus necessary surrounding / out-of-diff callers), including files the orchestrator lists as untracked/added
- **Read-only**: read files, `rg`/search, `git show`/`git diff`. No `cargo`/`just` — the orchestrator owns test runs. Verify alone may run one focused `cargo test -p <crate>`
- No GitHub review threads
- No style nits; failure story required
- Return a JSON array of findings (may be empty):
  `{"reasoning","severity","confidence","path","line","finding"}`
- `reasoning` is your scratchpad and is never shown to the user — put the user-facing story in `finding`
- `line` must be read off the post-change file with a file-read tool, **not** counted from diff hunk headers; a wrong line makes the finding unactionable
- Severity bar (inlined from `.cursor/rules/pr-review.mdc` so specialists who only receive this charter need not open the rule file):
  - **P0** hangs, panics, definitively wrong results, or tests/fixtures that cannot work as written
  - **P1** correctness or security bug likely to hit real users/peers
  - **P2** contract/lifecycle/resource bugs; clear holes where tests/fuzz/CI won't catch failure
  - **P3** concrete maintainability or portability with a real failure mode (skip pure taste)
- Omit anything with confidence &lt; 0.8
- Finish your charter; do not stop after the first finding
- Read every in-diff hunk relevant to your charter before following out-of-diff callers. Charters partition **failure modes, not files** — expect to share files with other specialists; the merge dedupes

## State

Focus: protocol/API invariants, state machines, lifecycle.

Hunt: duplicate close/reset; events after close; wrong terminal events; ownership handoff (who may read/write a stream); retry that cannot make progress; “success” emitted before the resource is usable.

Out-of-diff: callers of changed state-transition functions.

## Parse

Focus: bytes in / structured values out.

Hunt: length/truncation/overflow; endianness; fixture/golden size mismatches (even if tests skip the field); accept paths that skip validation; decode that drops trailing coalesced data; rewrites that rebuild maps/structs and drop fields the old path preserved.

Out-of-diff: other parsers/encoders of the same format in-repo.

## Security

Focus: untrusted peers and hostile input.

Hunt: spoofed protocol roles; auth checks after side effects; open relays of attacker-controlled dials/blasts; MAC/hash over unbounded attacker data before size checks; secret file permissions.

Out-of-diff: who can open the new protocol id / handler.

## Flow

Focus: liveness and resources.

Hunt: `while` loops that don’t advance; timer starvation; deadline ignored under event flood; unbounded queues; superlinear buffer ops on coalesced input (`drain`/`remove(0)` in a loop); fail-closed that clears needed pending output on misuse.

Out-of-diff: drivers/endpoints that poll the changed agent.

## Verify

Focus: proof and claims — *absence* of coverage, or claims that contradict code.

Hunt: missing tests for new failure modes; CI/just/`no_std`/fuzz coverage dropped on rename/split; README claims contradicting code; AGENTS.md violations on touched code (sans-I/O, unsafe, transport scope, async in core).

Out-of-diff: **before claiming coverage is missing, go look for it.** `rg` the changed symbol and the behavior across sibling `#[cfg(test)]` modules, `crates/*/tests/**`, `examples/**`, and `fuzz/`. An absence claim that skipped this search is the single most common Verify false positive — omit it rather than guess.

You are the only specialist permitted to run tests: at most one focused `cargo test -p <crate>`. Note “green but never loads corrupt field” as evidence when that is a *claims* bug (README/test name promises a field). Prefer **Quality** when the test exists but is hollow or checklist-duplicative.

## Quality

Focus: hollow proof and LLM-shaped padding in **tests/docs**, plus **internal** no-policy wrappers. Not “thin public API is bad.”

Out-of-diff: peer tests in the same file and sibling test modules covering the same claim (is the new one strictly weaker, or does it add a case?); every call site of a suspected wrapper (`rg` the name — used once with no policy, or genuinely shared?). Both claims are unverifiable from the diff alone.

**Severity mapping**

- **P2**: hollow coverage that can hide real bugs — green tests that never exercise the claimed failure; e2e-in-unit tests that don’t uniquely pin the new API vs an existing one; asserts that skip fields the test name/doc claims to cover; internal wrappers that obscure error/ownership paths (errors remapped or dropped at the forward boundary)
- **P3**: concrete maintainability drag — near-duplicate tests of the same path under two names/features with no new risk; tautological asserts; plan-echo docs that add no contract; trivial construct/getter-only tests; private/`pub(crate)` helpers or one-field `*Helper`/`*Manager`/`*Util` types that only forward with no policy, validation, or feature gate

**Hunt**

- Tautological asserts (`second >= first` on consecutive clock reads; `assert_eq!(x, x)`; post-conditions that only restate a match the wait already required)
- Checklist duplicates: same script under multiple feature cfgs / twin names with no distinct risk
- Timing-sensitive unit-test e2e that don’t uniquely prove the new surface (would pass the same way through an older API)
- Variant-only / `is_some` / `len == 1` asserts when peers in-file already match full shapes for the same claim
- Construct-and-roundtrip getters with no property (`Id::new(n).as_u64() == n`) unless the type’s packing/invariants are the point
- Comments/README that restate a plan or the code with no additional contract
- **Internal useless wrappers**: private/`pub(crate)` functions or types whose body is only a call to another symbol in the same crate (or a field access + forward), adding no check, default, cfg, logging policy, or type conversion — especially new helpers introduced alongside the change “for clarity”

**Do not hunt**

- Formatting, naming taste, “could use a match”
- “Sounds like an LLM” without a concrete artifact
- **Intentional public / layer boundaries** that *are* the API or architectural boundary: `Endpoint` → `Swarm`, `Swarm` → `SwarmCore` (+ `flush_actions` where that is the policy), circuit decorator non-circuit arms → `inner`, sans-I/O `*Action`/`*Event` enums, std driver adapters, feature-gated type aliases/shims, newtype ID accessors

**Allowlist (intentional — do not flag by default)**

Test-shaped (merge may re-raise if the new test is strictly weaker than in-file peers on the same claim):

- White-box event/agent-queue injection to pin spin-guard / ownership / backlog semantics
- Real timeout-driven integration tests when they assert a specific protocol outcome (not a slack timing bound alone)
- Feature-matrix twins when each twin is required by a stated merge gate *and* asserts a distinct type/error path (not a copy with only the feature name changed)

Boundary-shaped (unconditional — not subject to the “weaker peers” clause):

- One-line public methods that exist so callers don’t reach through layers
- Intentional layer boundaries listed under **Do not hunt**
