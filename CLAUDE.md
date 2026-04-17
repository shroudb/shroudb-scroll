# ShrouDB Scroll

Durable append-only event log engine for the ShrouDB ecosystem. Ordered, encrypted, replayable log primitive with cursored readers and reader groups.

## Identity

Scroll is an **active work log engine**, not an audit trail and not an outbound delivery channel. Producers append; consumers drain entries at their own pace via cursored reader groups; retention is bounded.

- **vs Chronicle.** Chronicle answers "what happened?" (immutable audit). Scroll answers "what's next to handle?" (active work queue with advancing cursors).
- **vs Courier.** Courier delivers to *untrusted* external endpoints with JIT decryption. Scroll distributes to *trusted* consumers inside the ShrouDB trust boundary.
- **vs raw `subscribe`.** The Store's namespace subscribe emits every change. Scroll adds topic-level append/read, reader groups, retention, and claim/reclaim.

ShrouDB is **not Redis**. RESP3 is a wire protocol, not an identity.

## Architecture

Scroll follows the v1 engine architecture:
- `-core`: Domain types (LogEntry, ReaderGroup, PendingEntry), errors, ScrollOps trait (no I/O)
- `-engine`: Store-backed persistence, CAS offset allocation, group cursor mechanics, capability gating
- `-protocol`: RESP3 command parsing, ACL, dispatch
- `-server`: Standalone TCP + HTTP binary
- `-client`: Typed Rust SDK
- `-cli`: Command-line tool

### Storage model

See SPEC.md §4. Five Store namespaces, all with flat `{tenant_id}` prefix:
- `scroll.logs` — AES-256-GCM ciphertext of LogEntry (prefix-ordered by zero-padded offset)
- `scroll.offsets` — monotonic offset counter per log (CAS-gated)
- `scroll.groups` — ReaderGroup JSON (CAS-gated on cursor advance)
- `scroll.pending` — unacked PendingEntry JSON per group
- `scroll.meta` — per-log config **plus** the Cipher-wrapped DEK

No in-memory index — the Store's prefix scan is the query engine. Range reads and cursor advancement are natural Store operations.

### Delivery semantics

At-least-once within a reader group; per-log total order; readers must be idempotent on `(log, offset)`. See SPEC.md §7.

## Security posture

ShrouDB is security infrastructure. Every change must be evaluated through a security lens:

- **Fail closed, not open.** When in doubt, deny access, reject the request, or return an error.
- **Per-log envelope encryption.** Each log gets a dedicated AES-256-GCM DEK generated via Cipher `generate_data_key`. The wrapped DEK lives in `scroll.meta`; plaintext DEKs are held in `SensitiveBytes` (zeroized on drop) and cached per-process. Fresh 12-byte random nonce per entry, AAD bound to `"{tenant_id}\0{log}\0{offset:020}"`.
- **Cipher is optional at construction, required at use-site.** Follows Sigil's pattern: `Capabilities::cipher` is `Option<Arc<dyn ScrollCipherOps>>`. A Cipher-less engine rejects `APPEND` / `READ` / `READ_GROUP` with `ScrollError::CapabilityMissing("cipher")` — never a plaintext fallback. Metadata commands (`CREATE_GROUP`, `ACK`, `DELETE_LOG`, `LOG_INFO`, `GROUP_INFO`) don't need crypto and still work.
- **Sentry gates every command** when configured — including reads. Closes the read-path gap Sigil left open. `Deny` → `AccessDenied`; absent → skipped.
- **Chronicle audits every state-changing command** when configured — `APPEND`, `CREATE_GROUP`, `READ_GROUP`, `ACK`, `DELETE_LOG`. Reads are policy-gated but not audited. Both success and failure outcomes are recorded.
- **Every engine method takes `&AuditContext`** — bundles `actor` + `correlation_id`. New context fields extend the struct, not the method signatures.
- **Crypto-shred on DELETE_LOG.** `delete_prefix` on the log data, *then* destroy the wrapped DEK in `scroll.meta`. Works with or without Cipher (the wrapped DEK row is what matters — unwrapping is never needed to destroy it). Ciphertext residue in WAL archives or replicas is permanently unreadable once the DEK is gone.
- **Hard-reject oversize entries.** `APPEND` returns `EntryTooLarge` above `max_entry_bytes` — no warn-and-allow.
- **CAS-gated state transitions** prevent lost-update races under concurrent access.
- **Tenant isolation** enforced at the flat `{tenant_id}` key prefix. Cross-tenant reads impossible without cross-tenant ACL grants.
- **Every shortcut is a vulnerability.**

## Pre-push checklist (mandatory)

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

## Release process (mandatory after merging features)

Every feature merge must be followed by a full release. Do NOT push to main and move on without completing all steps.

1. **Bump version** in workspace `Cargo.toml`
2. **Regenerate Cargo.lock**: `cargo generate-lockfile`
3. **Verify**: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
4. **Commit**: `git commit -m "chore: bump to vX.Y.Z"`
5. **Publish crates** in dependency order to the `shroudb` registry:
   ```bash
   cargo publish -p shroudb-scroll-core --registry shroudb
   cargo publish -p shroudb-scroll-engine --registry shroudb
   cargo publish -p shroudb-scroll-protocol --registry shroudb
   cargo publish -p shroudb-scroll-client --registry shroudb
   cargo publish -p shroudb-scroll-server --registry shroudb
   cargo publish -p shroudb-scroll-cli --registry shroudb
   ```
6. **Tag**: `git tag vX.Y.Z`
7. **Push**: `git push && git push --tags`
8. **GitHub release**: `gh release create vX.Y.Z --title "vX.Y.Z" --notes "..."`

Skipping any step means the release is incomplete.

## Dependencies

- **Upstream (required):** shroudb-store (v0.2+ for CAS/TTL/delete_prefix), shroudb-acl, shroudb-crypto, shroudb-chronicle-core (for the `ChronicleOps` trait only — the audit engine itself is optional), shroudb-storage, shroudb-protocol-wire, shroudb-telemetry
- **Downstream:** shroudb-moat (embeds scroll-engine + scroll-protocol), application consumers of durable event logs
- **Engine integrations (optional via capability traits, not crate deps):** Cipher (for APPEND/READ/READ_GROUP), Sentry (ABAC gating), Chronicle (audit events on CREATE_GROUP/DELETE_LOG/DLQ)

## No dated audit markdown files

Audit findings live in two places:
1. Failing tests named `debt_<n>_<what>_must_<expected>` (hard ratchet — no `#[ignore]`).
2. This repo's `TODOS.md`, indexing the debt tests by ID and capturing cross-repo follow-ups.

Do NOT create:
- `ENGINE_REVIEW*.md`, `*_REVIEW*.md`, `AUDIT_*.md`, `REVIEW_*.md`
- Any dated snapshot (`*_2026-*.md`, etc.)
- Status / progress / summary markdown that ages out of date

Past audits accumulated 17+ `ENGINE_REVIEW_v*.md` files claiming "zero open items, production-ready" while real gaps went unfixed. New agents read them as truth. The forcing function now is `cargo test -p <crate> debt_` — the tests are the source, `TODOS.md` is the index, and nothing else counts.
