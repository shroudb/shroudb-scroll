# Changelog

All notable changes to the Scroll engine are documented in this file.

## [0.1.0] — 2026-04-17

Initial release. Everything listed below is P0 + P1 scope per `SPEC.md` §18.

### Added
- **Core types** (`shroudb-scroll-core`): `LogEntry`, `ReaderGroup`, `ReaderMember`, `PendingEntry`, `DlqEntry`, `ScrollError`, `AuditContext`, `ScrollOps` trait.
- **Engine** (`shroudb-scroll-engine`): `ScrollEngine<S: Store>` with 11 async methods covering the full P0/P1 command surface.
  - `APPEND` with per-log Cipher-envelope encryption (AES-256-GCM, AAD bound to tenant/log/offset), CAS-gated offset allocation, per-entry TTL via Store metadata.
  - `READ` with prefix-scoped list + decrypt.
  - `CREATE_GROUP` / `READ_GROUP` with CAS cursor advancement and `u64::MAX` sentinel for "no delivery yet" start-offset.
  - `ACK` (idempotent) and `CLAIM` with per-entry CAS.
  - `DLQ`: entries whose `delivery_count` crosses `max_delivery_count` during `CLAIM` are moved to `scroll.dlq` and dropped from pending.
  - `TRIM` with `MAX_LEN` and `MAX_AGE` selectors. `MAX_AGE` inspects Store-metadata `ts` without decrypting payloads.
  - `DELETE_LOG` crypto-shreds by destroying the wrapped-DEK row in `scroll.meta` after `delete_prefix`.
  - `LOG_INFO`, `GROUP_INFO` introspection.
  - `TAIL` via Store `subscribe` + tenant/log prefix filtering; `TailOverflow` on subscribe closure.
- **Capabilities** (`Capabilities`): optional Cipher/Sentry/Chronicle. Cipher-less engine rejects data-plane commands with `CapabilityMissing("cipher")`. Sentry gates *every* command. Chronicle audits every state-changing command (success and failure).
- **Protocol** (`shroudb-scroll-protocol`): RESP3 command parsing, ACL-gated dispatch, response helpers, `protocol.toml` source-of-truth.
- **Server** (`shroudb-scroll-server`): `shroudb-scroll` TCP binary with embedded/remote store modes, optional TLS, optional remote Cipher via `[cipher]` config section.
- **Client** (`shroudb-scroll-client`): typed Rust SDK wrapping all 11 commands + AUTH/HEALTH/PING/HELLO.
- **CLI** (`shroudb-scroll-cli`): `shroudb-scroll-cli` subcommand-style CLI covering every client method.

### Design decisions (SPEC §17)
- **Q1 — Payload encryption:** per-log Cipher envelope, fail-closed when Cipher absent.
- **Q5 — Tenant isolation:** flat `{tenant_id}/{log}/{offset:020}` key layout; apps embed hierarchy in the log name if they want it.
- **Q6 — Max-entry-size:** hard reject above `max_entry_bytes` with `ScrollError::EntryTooLarge`.

### Known follow-ups
- Open questions Q2 (retention vs. lagging groups), Q3 (CAS fairness), Q4 (DLQ replay), Q7 (reader-group idle GC) remain deferred per SPEC §17.

### Done (P2, cross-repo)
- **Moat embedding** shipped in shroudb-moat commit `7ba5229`. Scroll runs behind the `moat`-side `scroll` feature flag with prefix-routed command dispatch, embedded Cipher DEK wrapping, and an end-to-end integration test proving the full TCP → router → engine → Cipher path.
- **Chronicle `Engine::Scroll` variant** shipped in `shroudb-chronicle-core` v1.9.0. Scroll's `emit_audit` helper now uses the typed `ChronicleEngine::Scroll` instead of `Engine::Custom("scroll")`; dep pin bumped to `^1.9.0`.

### Coverage
96 tests across 6 crates. `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo deny check` all pass.
