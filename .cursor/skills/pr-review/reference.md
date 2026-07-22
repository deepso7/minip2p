# Micro-agent charters (pr-review)

Shared constraints for every specialist:

- Worktree + `git diff <base>...HEAD` only (plus necessary surrounding / out-of-diff callers)
- No GitHub review threads
- No style nits; failure story required
- Return a JSON array of findings (may be empty):
  `{"reasoning","severity","confidence","path","line","finding"}`
- Omit anything with confidence &lt; 0.8
- Finish your charter; do not stop after the first finding
- Read in-diff hunks for owned files before following out-of-diff callers

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

Focus: proof and claims.

Hunt: missing tests for new failure modes; CI/just/`no_std`/fuzz coverage dropped on rename/split; README claims contradicting code; AGENTS.md violations on touched code (sans-I/O, unsafe, transport scope, async in core).

Run focused tests when practical; note “green but never loads corrupt field” as evidence.
