# TS SDK isolates callbacks and swallows best-effort native cleanup failures

In `@minip2p/core`:

- **Application callbacks cannot break native event delivery.** `EventDrain` catches anything a delivery throws; `Stream#emit` isolates each stream handler from native callbacks and from the other handlers; close-report handlers run outside the closed event queue. A catch-all handler gets its own event object, never the one a `waitFor` waiter resolved with, so neither can mutate the other's.
- **Cleanup that has no caller to report to never throws.** These native calls are best effort, and a failure means the state is already gone: `abandonStream` (native close can overtake the queued terminal; a failed operation is already reported), deferred `closeStreamWrite` (the stream already ended and its terminal reports that), consuming bytes for a stream or connection already gone, `cancelConnect` after the endpoint stopped (teardown settles the wait), and `release` after close. A cleanup failure must never replace the caller's own timeout or abort error.

The lint config (`ultracite` core, `no-empty: error`) rejects an empty `catch {}`, so each of these sites needs either a short comment in its `catch` or a small `bestEffort(fn)`-style helper (or `allowEmptyCatch`).
