# About Scroll

## The problem

Distributed systems need durable event logs as a coordination primitive: one service produces events, others consume them at their own pace, nothing is lost if consumers are offline, and events are replayable for recovery. Kafka, Redis Streams, and AWS Kinesis each solve this — but none of them are designed to live inside a security-infrastructure trust boundary where *every byte at rest must be encrypted*, *every operation must be auditable*, and *destroying a log must be cryptographically irreversible*.

Plaintext event logs are a constant breach surface: every replica, every backup, every WAL archive becomes another place where an attacker can recover event payloads — even long after you've nominally "deleted" the log. Rotating the encryption key helps, but only for entries written *after* the rotation; historical entries remain readable with the old key.

## What Scroll does differently

**Per-log data encryption keys, wrapped by Cipher.** Every log has its own AES-256-GCM DEK. Entries are encrypted with a fresh random nonce per append, bound via AAD to the `(tenant_id, log, offset)` tuple — transplanting a ciphertext to a different position fails authentication. The DEK itself lives wrapped in the `scroll.meta` namespace; destroying that one row renders every ciphertext in that log's `scroll.logs` prefix permanently unreadable, regardless of how many replicas or backups exist. `DELETE_LOG` is crypto-shred, not just `rm`.

**Fail-closed on missing capabilities.** Cipher is optional at engine construction time (so operators can stand up an inspection/teardown deployment without Cipher running), but any data-plane operation — `APPEND`, `READ`, `READ_GROUP`, `TAIL` — rejects with `CapabilityMissing("cipher")` when it's absent. No silent downgrade to plaintext, ever.

**Every state change is auditable.** When Chronicle is configured, `APPEND`, `CREATE_GROUP`, `READ_GROUP`, `ACK`, and `DELETE_LOG` each emit a structured audit event including the actor, tenant, log, and outcome (success or failure). When Sentry is configured, *every* command — reads included — is gated by ABAC policy before touching the store.

**CAS-gated concurrency on every mutable primitive.** Offset allocation, reader-group cursor advancement, and claim reassignments all go through `put_if_version`. Concurrent appenders and multi-reader groups converge without locks, and the retry budgets are configurable per command class.

## The shape of a deployment

```
  Producers ─→ [Scroll TCP/RESP3] ─→ Store (encrypted KV)
                   │
                   ├─→ Cipher         (required for APPEND/READ)
                   ├─→ Sentry         (optional: ABAC policy)
                   └─→ Chronicle      (optional: audit trail)
```

Scroll is a durable, encrypted work-log primitive that fits inside the same security posture as the rest of the ShrouDB platform — and refuses to operate in any mode that would weaken that posture.
