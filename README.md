# ShrouDB Scroll

Durable, append-only event log engine with cursored readers and reader groups. Provides an ordered, encrypted, replayable log primitive for coordination between services, engines, and applications running against ShrouDB.

## What it is

Producers append entries to a named log; consumers drain entries at their own pace via cursored reader groups. Every entry is encrypted with a per-log data encryption key (DEK) wrapped by Cipher — destroying the DEK row crypto-shreds the whole log.

**vs Chronicle.** Chronicle is an immutable audit record — write-once, queried by compliance tooling. Scroll is an active work log — readers drain entries and act on them, retention is bounded, cursors advance. Chronicle answers *"what happened?"*; Scroll answers *"what's next to handle?"*

**vs Courier.** Courier is last-mile JIT-decrypted outbound delivery to *untrusted* external endpoints. Scroll is durable internal event distribution to *trusted* consumers inside the ShrouDB trust boundary.

**vs raw `subscribe`.** ShrouDB's namespace-level subscribe primitive emits every change in a namespace. Scroll offers topic-level append/read with cursored consumption, consumer groups, retention, and claim/reclaim — the coordination layer the raw primitive doesn't provide.

## Wire commands

| Command | ACL | Purpose |
|---|---|---|
| `APPEND <log> <payload_b64> [HEADERS <json>] [TTL <ms>]` | write | Append entry; mints monotonic offset |
| `READ <log> <from_offset> <limit>` | read | Range read |
| `TAIL <log> <from_offset> <limit> [TIMEOUT <ms>]` | read | Live tail via subscribe |
| `CREATE_GROUP <log> <group> <start_offset>` | write | Create reader group ('earliest'/'latest'/N) |
| `READ_GROUP <log> <group> <reader_id> <limit>` | read | Advance cursor + pull batch |
| `ACK <log> <group> <offset>` | read | Remove pending record |
| `CLAIM <log> <group> <reader_id> <min_idle_ms>` | read | Reassign stalled pendings; DLQ on breach |
| `TRIM <log> MAX_LEN <n> \| MAX_AGE <ms>` | write | Explicit retention |
| `DELETE_LOG <log>` | write | Crypto-shred the log |
| `LOG_INFO <log>` | read | Stats |
| `GROUP_INFO <log> <group>` | read | Group stats |

See `protocol.toml` for the machine-readable specification.

## Quick start

```bash
# Run the server
shroudb-scroll --config scroll.toml

# Or via Docker
docker run -p 7200:7200 -v scroll-data:/data ghcr.io/shroudb/shroudb-scroll

# Use the CLI
shroudb-scroll-cli append orders 'hello, world'
shroudb-scroll-cli read orders --from 0 --limit 10

# Typed Rust SDK
let client = ScrollClient::connect("127.0.0.1:7200").await?;
client.append("orders", b"hello", None, None).await?;
let entries = client.read("orders", 0, 10).await?;
```

## Configuration

```toml
[server]
tcp_bind = "0.0.0.0:7200"

[store]
mode = "embedded"          # or "remote"
data_dir = "./scroll-data"

[engine]
default_max_entry_bytes = 1048576
default_max_header_bytes = 16384
max_delivery_count = 16

[cipher]
addr = "127.0.0.1:7175"
keyring = "scroll-logs"
auth_token = "..."
```

Omit `[cipher]` to start in inspection-only mode: metadata commands (`LOG_INFO`, `GROUP_INFO`, `DELETE_LOG`, `ACK`, `CREATE_GROUP`) still work; `APPEND`/`READ`/`READ_GROUP`/`TAIL` fail-closed with `CapabilityMissing("cipher")`.

## Security

- **Per-log envelope encryption.** Each log gets a dedicated AES-256-GCM DEK generated via Cipher. Fresh nonce per entry, AAD bound to `{tenant_id}\0{log}\0{offset:020}` — ciphertexts cannot be transplanted between logs, tenants, or offsets.
- **Crypto-shred on `DELETE_LOG`.** After `delete_prefix` on the log data, Scroll destroys the wrapped DEK. Ciphertext residue in WAL archives or backups is permanently unreadable.
- **Fail closed on missing capabilities.** Cipher-less deployments reject data-plane operations rather than falling back to plaintext (Sigil pattern).
- **CAS-gated state transitions** prevent lost-update races under concurrent appenders and multi-reader groups.
- **Sentry gates every command** when configured; Chronicle audits every state-changing command.

See `SPEC.md` for the detailed design and `CLAUDE.md` for contributor rules.

## Status

P0 + P1 shipped: all 11 wire commands, per-entry TTL, DLQ, live tail, standalone TCP server + Rust SDK + CLI. P2 pending: Moat embedding + Chronicle `Engine::Scroll` variant bump.
