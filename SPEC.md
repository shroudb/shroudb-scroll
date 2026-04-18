# Scroll — ShrouDB Engine Spec

Durable append-only event log engine with cursored readers and reader groups. Provides an ordered, encrypted, replayable log primitive for coordination between services, engines, and applications running against ShrouDB.

**Status:** Pre-implementation spec. Requires ShrouDB v2 primitives (CAS, server-side TTL, `delete_prefix`) — see `shroudb/CAS.md`.

---

## 1. Scope

Accept ordered appends to a named log; deliver entries to readers at their own pace; coordinate exclusive-consumption among members of a reader group; retain entries per a configurable retention policy.

### Non-goals

- Ephemeral fanout without persistence. Every append is durable.
- Outbound delivery to external endpoints (email/SMS/webhook). That is Courier's role.
- Message routing, filtering, or transformation. Scroll delivers the bytes the producer appended; readers filter client-side.
- Exactly-once delivery. Scroll is at-least-once within a reader group; readers must be idempotent on entry offset.
- Global ordering across logs. Ordering is per-log.

---

## 2. Role in platform

Scroll sits alongside the other nine engines (Sigil, Cipher, Veil, Keep, Forge, Sentry, Stash, Chronicle, Courier). Distinctions worth pinning:

- **vs Chronicle.** Chronicle is an immutable audit record — write-once, queried by compliance tooling. Scroll is an active work log — readers drain entries and act on them, retention is bounded, cursors advance. Chronicle answers "what happened?"; Scroll answers "what's next to handle?"
- **vs Courier.** Courier is last-mile JIT-decrypted outbound delivery to *untrusted* external endpoints. Scroll is durable internal event distribution to *trusted* consumers inside the ShrouDB trust boundary. Different trust model, different failure semantics, different API shape.
- **vs raw `subscribe`.** ShrouDB's namespace-level subscribe primitive (see CAS.md §1) emits every change in a namespace. Scroll offers topic-level append/read with cursored consumption, consumer groups, retention, and claim/reclaim — the coordination layer the raw primitive doesn't provide.

---

## 3. Data model

```rust
pub struct LogEntry {
    pub offset: u64,              // monotonic per log; assigned on append
    pub tenant_id: String,
    pub log: String,              // log name (tenant-scoped)
    pub payload: Vec<u8>,         // opaque bytes (encrypted at rest)
    pub headers: BTreeMap<String, String>, // opaque passthrough, size-capped
    pub appended_at_ms: i64,
    pub expires_at_ms: Option<i64>, // server-enforced via Store TTL
}

pub struct ReaderGroup {
    pub tenant_id: String,
    pub log: String,
    pub group: String,
    pub last_delivered_offset: u64,
    pub members: BTreeMap<String, ReaderMember>, // reader_id -> state
    pub created_at_ms: i64,
    pub version: u64,                // for CAS on cursor advancement
}

pub struct ReaderMember {
    pub reader_id: String,
    pub last_seen_ms: i64,
    pub in_flight: u32,              // pending-entry count
}

pub struct PendingEntry {
    pub offset: u64,
    pub reader_id: String,
    pub delivered_at_ms: i64,
    pub delivery_count: u32,
}
```

---

## 4. Storage model (WAL namespaces)

| Namespace | Key | Value | TTL | Purpose |
|---|---|---|---|---|
| `scroll.logs` | `{tenant_id}/{log}/{offset:020}` | `nonce ‖ AES-256-GCM(LogEntry) ‖ tag` | `retention_ttl` (optional) | Entry storage (per-log DEK) |
| `scroll.offsets` | `{tenant_id}/{log}` | `{next_offset: u64}` | none | Monotonic offset counter per log (CAS-gated) |
| `scroll.groups` | `{tenant_id}/{log}/{group}` | JSON `ReaderGroup` | none | Group state + cursor |
| `scroll.pending` | `{tenant_id}/{log}/{group}/{offset:020}` | JSON `PendingEntry` | none | Unacked deliveries |
| `scroll.meta` | `{tenant_id}/{log}` | JSON log config + Cipher-wrapped DEK | none | Per-log configuration |

Tenant isolation is **flat**: a single `{tenant_id}` prefix segment, no sub-namespaces. Apps that need hierarchical grouping (`billing/invoices`, `billing/refunds`) embed the separator in the `log` name. All three-part-or-deeper keys use zero-padded offsets so prefix scans return in append order.

**Payload encryption (per-log Cipher envelope).** On first APPEND to a log, Scroll calls Cipher `generate_data_key` to produce a fresh 256-bit DEK. The wrapped DEK is persisted in `scroll.meta`; the plaintext DEK is held transiently (`SensitiveBytes`, zeroized on drop) and cached in-process for the log's lifetime. Each entry's `LogEntry` is serialized then encrypted with AES-256-GCM: a fresh 12-byte random nonce per entry and AAD bound to `"{tenant_id}\0{log}\0{offset:020}"` so transplanted ciphertexts fail authentication. `scroll.offsets`, `scroll.groups`, `scroll.pending` carry no secret payload — they ride the Store's normal operational-namespace encryption (backend-dependent). `scroll.meta` holds the wrapped DEK; its confidentiality rests on Cipher's key-hierarchy guarantees. `DELETE_LOG` destroys the wrapped DEK (and the `scroll.meta` row) *after* `delete_prefix` completes — once the wrapped DEK is gone, every ciphertext in `scroll.logs` under that log is permanently unreadable (crypto-shred).

Uses ShrouDB v2 primitives (see `shroudb/CAS.md`):
- `put_if_version` on `scroll.offsets` for monotonic offset allocation
- `put_if_version` on `scroll.groups` for cursor advancement and member registration
- `put_with_options` with TTL for entry retention
- `delete_prefix` for log teardown and tenant teardown

---

## 5. Commands (RESP3 wire surface)

All commands tenant-scoped and ACL-gated via `shroudb-acl` (`scroll.<log>` resource namespace).

| Command | ACL | Description |
|---------|-----|-------------|
| `APPEND <log> <payload_b64> [HEADERS <json>] [TTL <ms>]` | write `scroll.<log>` | Append entry. Returns `{offset}`. |
| `READ <log> <from_offset> <limit>` | read `scroll.<log>` | Range read. Returns `[LogEntry...]`. |
| `TAIL <log> <from_offset> <limit>` | read `scroll.<log>` | Live tail: blocks until `limit` entries available or timeout. |
| `CREATE_GROUP <log> <group> <start_offset>` | write `scroll.<log>` | Create reader group. `start_offset = 0` means "from earliest"; `-1` means "from latest". |
| `READ_GROUP <log> <group> <reader_id> <limit>` | read `scroll.<log>` | Fetch pending entries for this reader. Advances group cursor (CAS). Returns `[LogEntry...]`. |
| `ACK <log> <group> <offset>` | read `scroll.<log>` | Mark entry acked, remove from `scroll.pending`. |
| `CLAIM <log> <group> <reader_id> <min_idle_ms>` | read `scroll.<log>` | Reassign pending entries from stalled readers to `reader_id`. Returns claimed offsets. |
| `TRIM <log> <MAX_LEN n \| MAX_AGE ms>` | write `scroll.<log>` | Explicit retention trim. |
| `DELETE_LOG <log>` | write `scroll.<log>` | `delete_prefix` all log + group + pending state. |
| `LOG_INFO <log>` | read `scroll.<log>` | Stats: entry count, earliest/latest offset, group list. |
| `GROUP_INFO <log> <group>` | read `scroll.<log>` | Group state: cursor, members, pending count. |

`protocol.toml` is source of truth; CLI and client SDKs are codegen'd from it per CLAUDE.md rule 8.

### CLI

```
shroudb-scroll append <log> <payload>
shroudb-scroll read <log> --from 0 --limit 100
shroudb-scroll tail <log> --from latest --limit 10
shroudb-scroll create-group <log> <group> --start earliest
shroudb-scroll read-group <log> <group> <reader_id> --limit 10
shroudb-scroll ack <log> <group> <offset>
shroudb-scroll claim <log> <group> <reader_id> --min-idle 30s
shroudb-scroll trim <log> --max-len 1000000
shroudb-scroll delete-log <log>
```

---

## 6. Offset allocation

`APPEND` is the only path that mints offsets. Allocation is CAS-gated against `scroll.offsets/{tenant_id}/{log}`:

```
loop:
    current = get(scroll.offsets, {tenant, log})  // version + value
    next = current.next_offset + 1
    match put_if_version(
        ns: "scroll.offsets",
        key: "{tenant}/{log}",
        value: serialize({next_offset: next}),
        expected_version: current.version,
    ):
        Ok(_) => break with offset = current.next_offset
        Err(VersionConflict) => retry
    put(scroll.logs, "{tenant}/{log}/{offset:020}", entry, ttl)
```

Under active-active ShrouDB (if it lands), concurrent appends on different nodes will contend on the offset counter; CAS retry loop converges. Under single-writer, no contention. Either way, offsets are strictly monotonic per log with no gaps in the successful-append sequence.

---

## 7. Delivery semantics

**Guarantee:** at-least-once within a reader group. An entry appended at offset N is delivered to exactly one member of each reader group that has progressed past N-1. If the chosen reader crashes before ACK, `CLAIM` reassigns the entry; delivery count increments.

**Ordering:** per-log total order. Within a reader group, entries are delivered in offset order to the group as a whole. Between members of a group, ordering is not preserved — a faster member may pull offset 7 while a slower member is still processing offset 5.

**Readers must be idempotent on `(log, offset)`.** Duplicate delivery is possible on reader crash mid-processing.

### READ_GROUP flow

1. Load `ReaderGroup` with version.
2. Compute next batch: offsets `(last_delivered_offset, last_delivered_offset + limit]`.
3. `put_if_version` new group state with advanced cursor and updated member `last_seen_ms`.
4. On CAS success: batch-`put` `PendingEntry` records under `scroll.pending`, range-`get` entries from `scroll.logs`, return to caller.
5. On `VersionConflict`: another reader advanced the cursor; retry from step 1.

### ACK flow

`delete` on `scroll.pending/{tenant}/{log}/{group}/{offset:020}`. No CAS needed — ack is idempotent and final.

### CLAIM flow

Scan `scroll.pending` for the group; select entries where `delivered_at_ms < now - min_idle_ms`. For each, `put_if_version` a new `PendingEntry` with `reader_id = claimer`, `delivered_at_ms = now`, `delivery_count += 1`. CAS ensures only one claimer wins per stuck entry.

---

## 8. Retention

Two mechanisms, composable:

- **Per-entry TTL** (`APPEND ... TTL ms`): entry carries `expires_at_ms`, Store's TTL sweeper (CAS.md §2) deletes it. Replicates as normal Delete WAL entry.
- **Log-level retention** (`LOG_INFO` config): `max_len` or `max_age`. Enforced via explicit `TRIM` or background retention timer.

Retention does not inspect reader group cursors. An entry may be retained-away while a group is still lagging behind — the lagging group will get `CompactedRange` errors on `READ_GROUP` and advance past the retained-away range.

**Dead-letter handling:** entries whose `delivery_count` exceeds a configurable cap are moved to `scroll.dlq/{tenant}/{log}/{offset:020}` and dropped from `scroll.pending`. DLQ entries are readable but not redelivered.

---

## 9. Live tail

`TAIL` blocks until `limit` new entries are appended at or after `from_offset`, or until server-side timeout. Implementation subscribes to the `scroll.logs/{tenant}/{log}/` namespace (via ShrouDB's subscribe primitive) and streams entries as they arrive. Non-blocking `READ` remains available for polling consumers.

Subscribe-channel backpressure: if a `TAIL` consumer falls behind its channel buffer, the server closes the tail connection with `TAIL_OVERFLOW` and the client falls back to `READ` with an explicit offset.

---

## 10. Engine relationships

| Component | Direction | Required? | Purpose |
|---|---|---|---|
| `shroudb-store` (Store trait + v2 primitives) | out | Yes | Durable encrypted state; CAS, TTL, delete_prefix |
| Cipher | out | No (fail-closed at use) | Per-log envelope encryption via `generate_data_key` / `unwrap_data_key`. Required for `APPEND`, `READ`, `READ_GROUP` — those operations return `CapabilityMissing("cipher")` when absent. Metadata commands (`CREATE_GROUP`, `ACK`, `DELETE_LOG`, `LOG_INFO`, `GROUP_INFO`) work without Cipher. |
| Sentry | out | No | ABAC policy gate. Evaluated on **every** command when configured; `Deny` → `AccessDenied`. Absent → skipped. |
| Chronicle | out | No | Audit events on state-changing commands (`APPEND`, `CREATE_GROUP`, `READ_GROUP`, `ACK`, `DELETE_LOG`) and DLQ moves; success and failure both recorded. Absent → no-op. |
| `shroudb-acl` | out | Yes | Wire-level ACL per command |
| Moat | in | — | Embedded topology integration |

Capability gating follows Sigil's pattern: all three engine capabilities (Cipher, Sentry, Chronicle) are `Option<...>` in the engine's `Capabilities` struct. A missing capability is **never** a silent downgrade to plaintext; *data-path* capabilities fail-closed at the use site, *observability* capabilities are skipped silently.

- **Cipher-less operations that need crypto** (`APPEND`, `READ`, `READ_GROUP`) fail-closed with `CapabilityMissing("cipher")`.
- **Cipher-less operations that don't need crypto** (`CREATE_GROUP`, `ACK`, `DELETE_LOG`, `LOG_INFO`, `GROUP_INFO`) succeed. `DELETE_LOG` crypto-shreds by destroying the wrapped DEK row in `scroll.meta` — no unwrap required.
- **Sentry, when present, gates every command.** `APPEND`, `READ`, `READ_GROUP`, `CREATE_GROUP`, `ACK`, `DELETE_LOG`, `LOG_INFO`, and `GROUP_INFO` all go through `PolicyEvaluator::evaluate`; a `Deny` decision returns `AccessDenied`. Sentry-less deployments skip ABAC entirely (wire ACL via `shroudb-acl` still applies at the protocol layer). This closes the read-path gap Sigil left open: every operation is auditable against policy, not just the state-changing ones.
- **Chronicle, when present, records an event on every state-changing command** — `APPEND`, `CREATE_GROUP`, `READ_GROUP` (cursor advance), `ACK`, and `DELETE_LOG`. Both success and failure outcomes are recorded (a Sentry-denied `APPEND` still emits with `EventResult::Error`). Reads (`READ`, `LOG_INFO`, `GROUP_INFO`) are policy-gated but not audited — audit volume would drown the signal. Chronicle errors do not roll back the operation; they are logged via `tracing::warn` and discarded.
- **Call context.** Every engine method accepts a `&AuditContext` carrying `actor` and `correlation_id`. Threading a struct once avoids the pattern of growing signatures each time a new contextual field is added; the protocol layer populates it from the authenticated token (actor) and the RESP3 command envelope (correlation_id).

This lets an operator spin up a read-only / inspection / crypto-shred deployment of Scroll against an existing store without standing up Cipher, while still preventing any plaintext data path, and — when Sentry and Chronicle are wired in — have every command both policy-gated and (for state changes) audited.

---

## 11. Config

```toml
[scroll]
# Per-log defaults; override via LOG_INFO
default_retention_ttl_ms = 0       # 0 = no TTL; rely on explicit TRIM
default_max_entry_bytes = 1_048_576
default_max_header_bytes = 16_384
default_max_delivery_count = 16    # move to DLQ above this

# Group / reader
reader_idle_threshold_ms = 60_000    # default min_idle_ms for CLAIM suggestions
offset_cas_retry_max = 64            # O(N) worst case with N contending appenders
group_cursor_cas_retry_max = 8       # group cursor sees readers-per-group contention only

# Tail
tail_subscribe_buffer = 1024
tail_timeout_ms = 30_000

# DLQ
dlq_retention_ttl_ms = 2_592_000_000  # 30d; 0 = keep forever
```

---

## 12. Replication

No new replication semantics. Scroll writes produce standard `Put` / `Delete` / `PutIfVersion` WAL entries. Replicas replay unconditionally; CAS preconditions are validated on the primary before WAL append (CAS.md §1.WAL).

Under single-writer topology, only the primary accepts `APPEND`, `CREATE_GROUP`, `READ_GROUP`, `ACK`, `CLAIM`, `TRIM`, `DELETE_LOG`. Replicas serve `READ`, `LOG_INFO`, `GROUP_INFO`. `TAIL` on a replica follows the replica's applied WAL position — bounded by replication lag.

---

## 13. Metrics

ShrouDB's observability surface is `tracing` + OTEL (Prometheus was removed platform-wide). Scroll emits structured `tracing::info!` events under the `scroll::metrics` target — operators filter on that target to route them to a metrics sink, an OTEL collector, or plain file tail.

Each event carries a `metric` field naming the measurement plus dimensional fields matching the labels below. No Prometheus-style counters or histograms are registered; aggregation is the collector's job.

| Event (`metric=`) | Emitted at | Dimensional fields | Shape |
|---|---|---|---|
| `appends_total` | After successful APPEND | `tenant`, `log`, `offset`, `entries_minted` | counter signal (per-event) + derived gauge |
| `read_group_latency` | After READ_GROUP returns | `tenant`, `log`, `group`, `reader_id`, `latency_us`, `delivered` | histogram-ready sample |
| `delivery` (`outcome=delivered`) | After READ_GROUP hands out a batch | `tenant`, `log`, `group`, `count` | counter signal |
| `delivery` (`outcome=claimed`) | After CLAIM completes | `tenant`, `log`, `group`, `count` | counter signal |
| `delivery` (`outcome=dlq`) | After CLAIM moves entries to DLQ | `tenant`, `log`, `group`, `count` | counter signal |
| `pending_entries` | At GROUP_INFO time | `tenant`, `log`, `group`, `value` | gauge snapshot |
| `group_lag_offsets` | At GROUP_INFO time | `tenant`, `log`, `group`, `value` | gauge snapshot (`next_offset - last_delivered - 1`) |
| `tail_overflow` | When TAIL returns `TailOverflow` | `tenant`, `log` | counter signal |

Audit events (`APPEND`, `CREATE_GROUP`, `READ_GROUP`, `ACK`, `DELETE_LOG`, `CLAIM`, `TRIM`, `DLQ_MOVE`) are separately routed to Chronicle via `ChronicleOps::record` when configured — see §10. Metrics and audit serve different consumers and are not conflated.

---

## 14. Tests

- **Unit:** offset CAS allocation (contention, retry), cursor CAS advancement, claim/reclaim math, TTL expiry on entries, DLQ move on delivery-count breach, encoding round-trip.
- **Integration (`tests/scroll.rs`):** append→read round-trip, group delivery exclusivity (two readers, each entry to exactly one), stalled reader + CLAIM, crash mid-READ_GROUP (pending cleanup on restart), TRIM by max-len and max-age, DELETE_LOG teardown via `delete_prefix`, live-tail streaming + overflow, capability-absent modes (no Cipher / no Sentry / no Chronicle).
- **Concurrency:** N producers racing `APPEND` → all offsets unique and monotonic; M readers in a group racing `READ_GROUP` → no entry delivered twice without claim.
- **Replication:** primary appends, replica reads converge; replica rejects mutating commands; TAIL on replica honors lag.
- **Bench (`tests/bench_scroll.rs`):** append throughput per log, fan-out to 10 groups, 1M dormant entries startup time.

---

## 15. Architecture

Mirrors other engines:

```
shroudb-scroll-core/        — domain types (LogEntry, ReaderGroup, PendingEntry, ScrollError)
shroudb-scroll-engine/      — Store + coordination logic (ScrollEngine, capabilities, offset alloc, group mechanics)
shroudb-scroll-protocol/    — RESP3 command parsing + dispatch (Moat integration)
shroudb-scroll-server/      — standalone TCP server
shroudb-scroll-client/      — async Rust client
shroudb-scroll-cli/         — CLI
```

---

## 16. Dependencies

- **Upstream:** `shroudb-store` v0.2+ (requires CAS, TTL, delete_prefix from `shroudb/CAS.md`), `shroudb-acl`, `shroudb-crypto`
- **Downstream:** `shroudb-moat` (embedded), any application consuming durable event logs
- **Capability deps (optional):** Cipher, Sentry, Chronicle

---

## 17. Open design questions

Called out so they're not silently decided during implementation.

**Resolved (v0.1):**
1. **Payload encryption scope** → **per-log Cipher envelope, fail-closed when Cipher absent.** Each log owns a DEK wrapped in `scroll.meta`; `DELETE_LOG` destroys the wrapped DEK to crypto-shred the log. Cipher is optional at engine construction (Sigil pattern); `APPEND`, `READ`, and `READ_GROUP` reject with `CapabilityMissing("cipher")` when absent rather than falling back to plaintext. See §4 for the envelope layout and AAD binding; §10 for the full capability table.
2. **Retention vs lagging groups** → **hybrid: unconditional trim with `min_retention_behind_slowest_group` guardrail.** `TRIM_MAX_LEN` / `TRIM_MAX_AGE` and TTL reap entries unconditionally, but before deleting, the engine computes the slowest group cursor for the log and refuses to trim past `slowest_cursor - min_retention_behind_slowest_group` offsets. Default guardrail is 0 (Kafka-style unconditional) so it's opt-in. See §8 for the guardrail semantics.
3. **Ordering across append contention** → **per-log `tokio::sync::Mutex` serializer replaces CAS on `scroll.offsets`.** Each `(tenant_id, log)` gets a cached `Arc<Mutex<LogAppender>>` in a `DashMap`; `APPEND` acquires it, loads-or-uses-cached `next_offset`, writes the entry + advances the counter, then releases. FIFO fairness within a log without global locking, no retry loops under contention, and DEK load + offset bump + log write stay atomic under a single lock — required so `DELETE_LOG` cannot race an in-flight encrypt with the old DEK. Cross-log contention is still lock-free; the serializer is per-log. See §11.
4. **DLQ replay** → **explicit `REPLAY <log> <group> <offset>` command.** Reads the DLQ record at the offset, re-inserts a `PendingEntry` into `scroll.pending` with the original `reader_id` and fresh `delivered_at_ms`, and deletes the DLQ record (put-first, delete-second). Returns `DlqEntryNotFound` if the offset has no DLQ record for the log. DLQ is not terminal — operators can replay selectively without draining out-of-band.
5. **Tenant isolation scope** → **flat** `{tenant_id}/{log}/{offset:020}`. Apps needing sub-scoping embed it in the log name.
6. **Max-entry-size semantics** → **hard reject** above `max_entry_bytes` (`ScrollError::EntryTooLarge`). Fail-closed.
7. **Reader-group lifecycle** → **explicit `DELETE_GROUP <log> <group>` command; no TTL-based auto-delete.** Deletes the `scroll.groups` entry and all `scroll.pending` entries for the group (prefix delete). Auto-expiry on inactivity is deferred — absent activity telemetry it's guesswork, and stale-but-visible groups are safer than silently dropping pending work.

**Open:** none. All v0.1 open questions resolved.

---

## 18. Delivery phases

Assumes ShrouDB v2 primitives (`put_if_version`, TTL, `delete_prefix`) have landed.

**P0 (~2 weeks):** `shroudb-scroll-core` + `shroudb-scroll-engine` + `shroudb-scroll-protocol`. Commands: `APPEND`, `READ`, `CREATE_GROUP`, `READ_GROUP`, `ACK`, `DELETE_LOG`, `LOG_INFO`, `GROUP_INFO`. CAS-gated offset allocation and cursor advancement. Per-entry TTL retention. Capability integration (Cipher/Sentry/Chronicle optional). Tests + benches.

**P1 (~1 week):** `CLAIM`, `TRIM`, `TAIL`, DLQ. Live-tail subscribe integration. Dead-letter on delivery-count breach. Standalone server + CLI + client SDK. `protocol.toml` + SDK codegen.

**P2 (~1 week):** Moat embedding, Docker image, docs (README/ABOUT/DOCS/CHANGELOG), cross-repo dep bumps.

**P3+ (deferred):** DLQ replay commands (if Q4 resolves toward manual replay), hierarchical log namespaces (if Q5 resolves toward hierarchy), group idle-GC (Q7).

---

## 19. Security posture

- **Fail closed.** All mutating commands gated by `shroudb-acl`. Without ACL grants, commands are rejected before reaching the engine.
- **Per-log envelope encryption.** Each log has its own AES-256-GCM DEK, wrapped by Cipher and stored in `scroll.meta`. Fresh 12-byte nonce per entry, AAD bound to `"{tenant_id}\0{log}\0{offset:020}"` — transplanted ciphertexts fail authentication. Plaintext DEKs are held in `SensitiveBytes` (zeroized on drop).
- **Hard-reject oversize entries.** Appends above `max_entry_bytes` are rejected before reaching Store.
- **Crypto-shred on DELETE_LOG.** After `delete_prefix` on the log data, Scroll destroys the wrapped DEK in `scroll.meta`. Ciphertext residue in replica WAL archives or backups is permanently unreadable.
- **Offsets are not sensitive** — they leak append rate but not content. Group state leaks consumer identity and lag — evaluated as acceptable operational metadata.
- **CAS-gated state transitions** prevent lost-update races under concurrent access.
- **`DELETE_LOG` is destructive** and irreversible. Requires explicit `scroll.<log>` write grant; no soft-delete path. Operators wanting recoverable teardown should TRIM to zero first, then DELETE_LOG.
- **Tenant isolation** enforced at the flat `{tenant_id}` key prefix. Cross-tenant reads impossible without cross-tenant ACL grants.
