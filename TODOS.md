# TODOs

This file exists to document intentional soft-ratchets for the stop-hook's
`TDD-EXCEPTION` mechanism, plus cross-repo follow-ups that live-plumb
dependencies this repo cannot change unilaterally.

## Hook keyword note — "pending" is domain vocabulary

The stop-hook flags occurrences of "pending" in `shroudb-scroll-engine/src/engine.rs`
as potential stub markers. These are **false positives**: `PendingEntry` is a
spec'd domain type (SPEC §3) representing unacked deliveries in the
`scroll.pending` Store namespace. Every flagged occurrence is one of:

- A reference to the `PendingEntry` type (`let pending: PendingEntry`, `pending.offset`, etc.).
- A reference to the `scroll.pending` namespace constant.
- A comment or docstring describing `CLAIM` / `ACK` / DLQ semantics against pending records.
- An error message scoped to a pending-record Store operation (`"pending list: {e}"`, `"pending CAS: {e}"`).

None of these are stubs, placeholders, or TODOs. The term "pending" is
load-bearing in the Scroll design — renaming it would contradict SPEC §3,
§7, and the public `PendingEntry` type exported from `shroudb-scroll-core`.

Files carrying this vocabulary (not actionable debt):
- `shroudb-scroll-core/src/pending.rs`
- `shroudb-scroll-engine/src/groups.rs`
- `shroudb-scroll-engine/src/engine.rs`
- `shroudb-scroll-protocol/src/dispatch.rs`

## Cross-repo follow-ups

- **`shroudb-chronicle-core::Engine::Scroll` migration.** The variant itself
  is now in `shroudb-chronicle-core` 1.9.0 (added alongside Display /
  from_str_loose / serde coverage + tests). Scroll's `emit_audit` helper
  still uses `Engine::Custom("scroll".into())` because the published dep
  pin is `shroudb-chronicle-core = "1.7.3"` — migration is two mechanical
  edits (bump dep to `^1.9.0`, swap `Custom("scroll")` → `Scroll`) gated on
  chronicle-core 1.9.0 being published to the `shroudb` registry. Both
  representations round-trip to the identical wire string `"scroll"`, so
  consumers see no behaviour change either way.

- **Moat embedding — done** (shroudb-moat commit `7ba5229`). Scroll is now
  registered behind the `scroll` feature flag alongside the other nine
  engines, with prefix-routed command dispatch (`SCROLL APPEND ...`), an
  embedded `ScrollCipherOps` adapter over the co-located CipherEngine, and
  end-to-end integration coverage in `shroudb-moat/tests/integration.rs`.

## Deferred design questions (SPEC §17)

Resolution sequencing is operator-driven; see SPEC §17 for the full framing.

- **Q2 — Retention vs lagging groups.** Currently unconditional (Kafka
  semantics). Gate on slowest-group cursor via a
  `min_retention_behind_slowest_group` config when operators ask.
- **Q3 — CAS fairness.** Bounded retry budget is in place; no FIFO fairness
  queue. Revisit if pathological contention starves a tenant in production.
- **Q4 — DLQ replay.** `scroll.dlq` is terminal in v0.1. Operators drain
  out-of-band. `REPLAY <log> <group> <offset>` deferred pending demand.
- **Q7 — Reader-group idle GC.** No auto-delete of inactive groups or their
  pending entries. Add a scheduled sweep if groups accumulate.
