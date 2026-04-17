# Scroll — Operations Guide

## Deployment

### Standalone (Docker)

```bash
docker run -d --name scroll \
  -p 7200:7200 \
  -v scroll-data:/data \
  -e RUST_LOG=info \
  ghcr.io/shroudb/shroudb-scroll
```

By default the server starts **without Cipher configured** — useful for smoke-testing, but APPEND/READ/READ_GROUP/TAIL will reject with `CapabilityMissing`. To enable data-plane operations, mount a config file with a `[cipher]` section:

```bash
docker run -d --name scroll \
  -p 7200:7200 \
  -v scroll-data:/data \
  -v $(pwd)/scroll.toml:/etc/scroll.toml:ro \
  ghcr.io/shroudb/shroudb-scroll /shroudb-scroll --config /etc/scroll.toml
```

### Standalone (binary)

```bash
cargo install shroudb-scroll-server --registry shroudb
shroudb-scroll --config scroll.toml
```

### Embedded (in-process)

Build your own binary that constructs `ScrollEngine` directly:

```rust
let store = Arc::new(shroudb_storage::EmbeddedStore::new(storage, "scroll"));
let caps = Capabilities::new()
    .with_cipher(my_cipher_ops)
    .with_chronicle(my_chronicle_ops);
let engine = ScrollEngine::new(store, caps, EngineConfig::default()).await?;
```

`ScrollEngine` is `Send + Sync` and reusable across tasks; wrap in `Arc` and share.

## Configuration reference

### `[server]`

| Key | Default | Description |
|---|---|---|
| `tcp_bind` | `0.0.0.0:7200` | TCP listen address |
| `log_level` | `info` | `tracing_subscriber` EnvFilter directive |
| `tls` | (unset) | Optional `shroudb_server_tcp::TlsConfig` — cert + key paths |

### `[store]`

| Key | Default | Description |
|---|---|---|
| `mode` | `embedded` | `embedded` (local `shroudb-storage`) or `remote` (ShrouDB TCP) |
| `data_dir` | `./scroll-data` | Embedded-mode data directory |
| `uri` | (unset) | Required in remote mode: `shroudb://token@host:port` or `shroudb+tls://...` |

### `[engine]`

| Key | Default | Purpose |
|---|---|---|
| `default_max_entry_bytes` | `1_048_576` | Hard cap on `APPEND` payload + headers. Hard reject above. |
| `default_max_header_bytes` | `16_384` | Hard cap on serialized headers alone. |
| `default_retention_ttl_ms` | (none) | Inherited by every entry whose `APPEND` omits `TTL`. |
| `offset_cas_retry_max` | `8` | Retry budget on `scroll.offsets` CAS. |
| `group_cursor_cas_retry_max` | `8` | Retry budget on `scroll.groups` CAS. |
| `max_delivery_count` | `16` | Once an entry's `delivery_count` hits this during `CLAIM`, it moves to DLQ. |

### `[cipher]` (optional)

| Key | Default | Description |
|---|---|---|
| `addr` | (required) | `host:port` of a running `shroudb-cipher` server |
| `keyring` | `scroll-logs` | Cipher keyring used for per-log DEK wrapping |
| `auth_token` | (unset) | Optional token passed via `AUTH` after connect |

Omit the whole section to start Scroll in inspection-only mode.

### `[auth]`

Standard ShrouDB `ServerAuthConfig`. See `shroudb-acl` docs.

## Operational primitives

### Crypto-shred a log

```bash
shroudb-scroll-cli delete-log <log>
```

Sequence: `delete_prefix` on `scroll.logs`, `scroll.groups`, `scroll.pending` → delete `scroll.offsets` row → delete `scroll.meta` row (which holds the wrapped DEK).

The DEK row is destroyed **last**, so a crash part-way through leaves replica reconciliation intact. Once the DEK row is gone every residual ciphertext is unreadable — even from WAL archives.

### Inspection-only deployment (no Cipher)

`LOG_INFO`, `GROUP_INFO`, `ACK`, `DELETE_LOG`, and `CREATE_GROUP` work without a Cipher capability. This is useful for:

- Read-only recovery/forensics where you've pulled a Scroll data directory from a failed node.
- Crypto-shredding logs during incident response without standing Cipher back up.
- Listing groups and pending counts as part of a migration audit.

`APPEND`/`READ`/`READ_GROUP`/`TAIL` will all return `CapabilityMissing("cipher")` — if you try to use them, the server logs `ERR capability not available: cipher` on the wire.

### Retention

Two composable mechanisms:

- **Per-entry TTL** via `APPEND ... TTL <ms>`. The Store's TTL sweeper deletes the ciphertext at `appended_at_ms + ttl`.
- **Explicit TRIM:**
  - `TRIM <log> MAX_LEN <n>` — deletes every entry with `offset < next_offset - n`. O(total-keep) list+delete.
  - `TRIM <log> MAX_AGE <ms>` — deletes every entry whose Store-metadata `ts` is older than `now - ms`. Does not decrypt payloads.

Retention is unconditional with respect to reader-group lag (Kafka semantics). If you need to block retention on the slowest group, wait for `min_retention_behind_slowest_group` config — tracked as §17 Q2.

### Dead-letter queue

When `CLAIM` would increment `delivery_count` past `max_delivery_count`, the entry is moved to `scroll.dlq/{tenant}/{log}/{offset:020}` instead. The DLQ is terminal in v0.1 — no `REPLAY` command yet (§17 Q4). To inspect, query the Store directly for the `scroll.dlq` namespace.

## Observability

When Chronicle is wired in, Scroll emits audit events:

| Operation | When | Event |
|---|---|---|
| `APPEND` | Every call | `Event { operation: "APPEND", result: Ok\|Error }` |
| `CREATE_GROUP` | Every call | `Event { operation: "CREATE_GROUP", ... }` |
| `READ_GROUP` | Every call (cursor advances) | `Event { operation: "READ_GROUP", ... }` |
| `ACK` | Every call | `Event { operation: "ACK", ... }` |
| `DELETE_LOG` | Every call | `Event { operation: "DELETE_LOG", ... }` |
| `CLAIM` | Every call | `Event { operation: "CLAIM", ... }` |
| `TRIM` | Every call | `Event { operation: "TRIM", ... }` |
| DLQ move | Per affected entry | `Event { operation: "DLQ_MOVE", resource: "{log}/{group}/{offset}" }` |

Reads (`READ`, `LOG_INFO`, `GROUP_INFO`, `TAIL`) are policy-gated but not audited — audit volume would drown the signal.

## Troubleshooting

**`CapabilityMissing("cipher")` on `APPEND`.** No `[cipher]` section in config. Add one pointing at a running Cipher server.

**`VersionConflict { target }`.** CAS retry budget exhausted on `scroll.offsets` or `scroll.groups`. Either raise the budget (`offset_cas_retry_max` / `group_cursor_cas_retry_max`) or investigate the contention source.

**`TailOverflow`.** The Store subscribe channel closed before `TAIL` met its limit. Client should fall back to `READ` with an explicit offset.

**`EntryTooLarge { size, max }`.** Producer is sending payloads above `default_max_entry_bytes`. Either shrink the payload or raise the cap. Fail-closed by design.

**`CompactedRange { earliest }`.** (Returned by future `READ_GROUP` calls if a lagging group's cursor is trimmed past.) Advance the group's cursor past `earliest` manually via a new `CREATE_GROUP` or accept the data loss.
