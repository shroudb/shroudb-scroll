# Scroll Engine DAG

## 1. Overview

Scroll is ShrouDB's durable append-only event log engine. Producers append
opaque byte payloads to a named, tenant-scoped log; consumers drain entries
through cursored reader groups with at-least-once delivery, stalled-reader
reclaim, and dead-letter handling. Every log owns a dedicated AES-256-GCM
data encryption key (DEK), generated on first append via Cipher and stored
wrapped in `scroll.meta`; entries on disk carry a fresh nonce per append
with AAD bound to `(tenant_id, log, offset:020)` so transplanted ciphertexts
fail authentication. `DELETE_LOG` crypto-shreds by destroying the wrapped
DEK row, rendering every residual ciphertext in `scroll.logs` (including
WAL archives and replicas) permanently unreadable. Scroll exposes a RESP3
wire surface on TCP 7200 with a JSON-envelope response format, speaks the
commands defined in `protocol.toml`, and persists state across five Store
namespaces: `scroll.logs`, `scroll.offsets`, `scroll.groups`,
`scroll.pending`, and `scroll.meta` (plus `scroll.dlq` for terminal
delivery failures).

## 2. Crate dependency DAG

Internal workspace crates:

```
                  +-------------------------+
                  |  shroudb-scroll-core    |
                  |  (types, errors,        |
                  |   ScrollOps trait,      |
                  |   AuditContext, DlqEntry)|
                  +-----------+-------------+
                              |
              +---------------+---------------+
              |                               |
              v                               v
   +-------------------------+      +-------------------------+
   |  shroudb-scroll-engine  |      |  shroudb-scroll-client  |
   |  (Store-backed engine,  |      |  (typed async Rust SDK, |
   |   Capabilities,         |      |   client-common-based)  |
   |   CAS offsets, groups,  |      +-----------+-------------+
   |   crypto, keys, meta)   |                  |
   +-----------+-------------+                  |
               |                                |
               v                                |
   +-------------------------+                  |
   | shroudb-scroll-protocol |                  |
   | (RESP3 parse, ACL,      |                  |
   |  dispatch, response)    |                  |
   +-----------+-------------+                  |
               |                                |
               v                                v
   +-------------------------+      +-------------------------+
   |  shroudb-scroll-server  |      |  shroudb-scroll-cli     |
   |  (TCP bin, config,      |      |  (clap CLI over the     |
   |   embedded+remote       |      |   client SDK)           |
   |   Cipher adapters)      |      +-------------------------+
   +-------------------------+
```

Notes:

- `shroudb-scroll-core` has zero `shroudb-*` dependencies — it is pure
  domain types, errors, and trait definitions.
- `shroudb-scroll-engine` depends on `shroudb-store`, `shroudb-acl`,
  `shroudb-audit` (source of the `ChronicleOps` trait wired into
  `Capabilities`), `shroudb-crypto`, `shroudb-chronicle-core` (for
  `Event` / `EventResult` / `Engine` types emitted when audit is
  enabled), and `shroudb-server-bootstrap` (for the tri-state
  `Capability<T>` used on every capability slot).
- `shroudb-scroll-protocol` layers RESP3 parsing and ACL on top of the
  engine. It does not take a Cipher dependency; that plugs in through the
  engine's `Capabilities`.
- `shroudb-scroll-server` constructs the Store and the Cipher adapter
  (embedded `CipherEngine` in the same process, or remote `CipherClient`
  over TCP) before instantiating `ScrollEngine`. It also pulls
  `shroudb-engine-bootstrap` for `AuditConfig::resolve` / `PolicyConfig::resolve`,
  which produce `Capability<…>` values for the audit and policy slots.
- `shroudb-scroll-client` is built on `shroudb-client-common` and depends
  only on `-core` types — it shares no code with `-engine` or `-protocol`.

## 3. Capabilities

- Durable append-only per-log event logs with monotonic `u64` offsets
  allocated under a per-log `tokio::sync::Mutex` serializer (FIFO within a
  log, lock-free across logs).
- Per-log envelope encryption: one AES-256-GCM DEK per log, generated via
  Cipher `generate_data_key`, wrapped in `scroll.meta`, cached in-process
  as `SensitiveBytes` (zeroized on drop). Each entry carries a fresh
  12-byte nonce with AAD bound to `{tenant_id}\0{log}\0{offset:020}`.
- Cursored reader groups with CAS-gated cursor advancement, member
  registration (`reader_id` + `last_seen_ms` + `in_flight` count), and
  per-entry `PendingEntry` tracking in `scroll.pending`.
- At-least-once delivery within a reader group, per-log total order,
  between-member ordering not preserved.
- `CLAIM` for stalled-reader reassignment with `min_idle_ms` gating and
  `delivery_count` tracking; entries that exceed `max_delivery_count`
  migrate to `scroll.dlq`.
- `REPLAY` moves a DLQ entry back into `scroll.pending` for a group
  (put-pending-first / delete-dlq-second ordering — crash leaves a
  duplicate, never a loss).
- Two retention mechanisms, composable: per-entry `TTL` (Store TTL
  sweeper) and explicit `TRIM MAX_LEN | MAX_AGE` with optional
  `min_retention_behind_slowest_group` guardrail.
- Live `TAIL` over the Store's subscribe primitive, with
  `tail_subscribe_buffer` backpressure that closes the call as
  `TailOverflow` so clients can fall back to `READ`.
- Crypto-shred `DELETE_LOG`: `delete_prefix` on log/group/pending
  namespaces, then destroy the wrapped DEK row — works with or without
  Cipher.
- `DELETE_GROUP` for single-group teardown without touching log data.
- Hard-reject appends above `max_entry_bytes` / `max_header_bytes`
  (`EntryTooLarge`) — no warn-and-allow.
- ACL-gated command dispatch via `shroudb-acl` (`scroll.<log>` resource
  namespace, `read` vs `write` scopes).
- Tenant isolation via flat `{tenant_id}/{log}/...` key prefixes.
- Standalone binary (`shroudb-scroll`) and embedded-library construction
  of `ScrollEngine` against any `Arc<dyn Store>`.

## 4. Engine dependencies

Scroll integrates with other ShrouDB engines through capability traits
rather than hard crate dependencies. Every capability slot on
`Capabilities` (see `shroudb-scroll-engine/src/capabilities.rs`) is a
tri-state `Capability<T>` from `shroudb-server-bootstrap` —
`Enabled(…)`, `DisabledForTests`, or `DisabledWithJustification("<reason>")`.
Absence is never silent: the `Capabilities::new` constructor requires a
value for every slot, so an operator must explicitly justify any opt-out.

The server binary pins `shroudb-cipher-client`, `shroudb-cipher-engine`,
and `shroudb-cipher-core` in its `Cargo.toml` so it can construct either
an embedded or remote Cipher adapter at startup. Chronicle flows through
two crates: `shroudb-audit`'s `ChronicleOps` trait (the capability wired
into `Capabilities.chronicle`) and `shroudb-chronicle-core`'s
`Event` / `EventResult` / `Engine` types (used to shape the events the
engine submits). Both are pinned in `shroudb-scroll-engine/Cargo.toml`.

### Dependency: Cipher (`shroudb-cipher`)

- **Pinned via.** `shroudb-cipher-client`, `shroudb-cipher-engine`,
  `shroudb-cipher-core` — all in `shroudb-scroll-server/Cargo.toml`.
  `shroudb-scroll-engine` itself does not depend on any Cipher crate; it
  defines the `ScrollCipherOps` trait that the server satisfies with
  either `EmbeddedCipherOps` or `RemoteCipherOps`.
- **What breaks without it.** Data-plane commands fail-closed with
  `ScrollError::CapabilityMissing("cipher")` at the use site:
  - `APPEND` — cannot generate a DEK for a new log or encrypt entries
    for an existing one.
  - `READ` — cannot unwrap the log's DEK to decrypt entries.
  - `READ_GROUP` — same decrypt path as `READ`.
  - `TAIL` — same decrypt path.
  There is no plaintext fallback. Metadata commands that do not touch
  ciphertext still succeed: `CREATE_GROUP`, `DELETE_GROUP`, `ACK`,
  `CLAIM`, `TRIM`, `DELETE_LOG`, `LOG_INFO`, `GROUP_INFO`, and the meta
  commands (`AUTH`, `HEALTH`, `PING`, `HELLO`, `COMMAND LIST`). In
  particular, `DELETE_LOG` still crypto-shreds correctly — destroying the
  wrapped DEK row does not require unwrapping it.
- **What works with it.** Full data plane: per-log DEK generation on
  first append, per-entry AES-256-GCM encryption with nonce + AAD
  binding, on-read unwrap of the cached plaintext DEK from
  `SensitiveBytes`, and subscribe-backed `TAIL` streaming of decrypted
  entries. The server supports two topologies: `cipher_embedded` (a
  `CipherEngine` on the same `StorageEngine` as Scroll in a distinct
  namespace, same master key) and `cipher_remote` (`CipherClient` over
  TCP behind a `tokio::sync::Mutex`).

### Dependency: Chronicle (`shroudb-chronicle`)

- **Pinned via.** `shroudb-audit` in
  `shroudb-scroll-engine/Cargo.toml` (source of the `ChronicleOps`
  trait the capability uses) plus `shroudb-chronicle-core` (for the
  `Event` / `EventResult` / `Engine` types the engine submits). The
  Chronicle engine binary is never a build-time dependency of Scroll;
  the capability is satisfied at runtime by any `Arc<dyn ChronicleOps>`
  the operator wires in (typically through
  `shroudb-engine-bootstrap::AuditConfig::resolve`).
- **What breaks without it.** No audit trail is recorded for
  state-changing commands. The engine silently skips the audit call
  (`tracing::warn!` on Chronicle submit errors when present — never a
  rollback). All engine operations continue to function; Scroll never
  blocks on audit availability.
- **What works with it.** Every state-changing command emits a
  structured audit event with actor, tenant, log, correlation id, and
  outcome: `APPEND`, `CREATE_GROUP`, `DELETE_GROUP`, `READ_GROUP` (on
  cursor advance), `ACK`, `CLAIM`, `TRIM`, `DELETE_LOG`, `REPLAY`, and
  `DLQ_MOVE`. Both success and failure outcomes are recorded — a
  Sentry-denied `APPEND` still emits with `EventResult::Error`. Read
  commands (`READ`, `LOG_INFO`, `GROUP_INFO`, `TAIL`) are policy-gated
  but intentionally not audited (audit volume would drown the signal).

## 5. Reverse dependencies

`shroudb-scroll-client` — no consumers inside the ShrouDB monorepo at the
Cargo-workspace level. It ships for external Rust applications that want
a typed async SDK against a running `shroudb-scroll` server.

`shroudb-scroll-core`, `shroudb-scroll-engine`, and
`shroudb-scroll-protocol` are embedded by **Moat** under the `scroll`
feature flag (`shroudb-moat/Cargo.toml`: `scroll = ["dep:shroudb-scroll-protocol",
"dep:shroudb-scroll-engine", "dep:shroudb-scroll-core", "cipher"]`). The
feature implies `cipher` because Moat must construct a Cipher capability
for Scroll's data-plane operations to function.

No other ShrouDB engine, CLI, or SDK crate in the monorepo links against
any scroll crate. Language SDKs (Go, Python, Ruby, TypeScript) currently
have no Scroll bindings generated from `protocol.toml`.

## 6. Deployment modes

Scroll supports two topologies, selected at binary startup by the
`[store].mode` config key and the presence of a `[cipher]` section:

### Standalone server

`cargo install shroudb-scroll-server` produces a `shroudb-scroll` binary
that listens on TCP 7200 (default) speaking RESP3. Two Store modes:

- `mode = "embedded"` — local `shroudb-storage::EmbeddedStore` on disk,
  bootstrap-provided master key. Cipher may be embedded in the same
  process via `cipher_embedded::EmbeddedCipherOps` (an in-process
  `CipherEngine` sharing the Scroll `StorageEngine` under a distinct
  namespace) or remote over TCP via `cipher_remote::RemoteCipherOps`.
- `mode = "remote"` — connects to an upstream ShrouDB server over
  `shroudb://` or `shroudb+tls://` via `shroudb-client::RemoteStore`. In
  remote mode, Scroll does not embed a `CipherEngine`; Cipher must be
  reached by TCP (`RemoteCipherOps`) or the server runs in
  inspection-only mode with no `[cipher]` section configured.

Omitting the `[cipher]` section entirely boots Scroll in inspection-only
mode — the server installs
`Capability::DisabledWithJustification("no [cipher] section configured …")`
so the absence is recorded at startup. Data-plane commands reject with
`CapabilityMissing("cipher")`, metadata commands work normally, and
`DELETE_LOG` still crypto-shreds. This is the documented posture for
read-only forensics and incident-response teardown of logs pulled from a
failed node.

The `[audit]` and `[policy]` sections follow a stricter contract: the
server refuses to boot without them. Each must name a mode (`"remote"`,
`"embedded"`, or `"disabled" justification = "<reason>"`) so that every
capability slot carries an explicit operator choice — no silent `None`
reaches `Capabilities::new`.

### Embedded library

Applications that already own a `shroudb-storage::StorageEngine` can
construct `ScrollEngine` directly from `shroudb-scroll-engine`:

```
let store = Arc::new(EmbeddedStore::new(storage, "scroll"));
let caps = Capabilities::new(
    Capability::Enabled(cipher_ops),
    Capability::Enabled(policy_evaluator),
    Capability::Enabled(chronicle_ops),
);
let engine = ScrollEngine::new(store, caps, EngineConfig::default()).await?;
```

`ScrollEngine` is `Send + Sync`; operators wrap in `Arc` and share across
tasks. This is the path **Moat** takes under the `scroll` feature —
Moat owns the storage, constructs the capabilities, and multiplexes
Scroll's RESP3 command surface alongside other engines on a single
listener via `shroudb-scroll-protocol`.
