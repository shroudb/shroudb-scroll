use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use shroudb_acl::{PolicyEffect, PolicyPrincipal, PolicyRequest, PolicyResource};
use shroudb_chronicle_core::event::{Engine as ChronicleEngine, Event, EventResult};
use shroudb_scroll_core::{
    AuditContext, DlqEntry, LogEntry, PendingEntry, ReaderGroup, ReaderMember, ScrollError,
};
use shroudb_store::{
    EventType, MetadataValue, NamespaceConfig, PutOptions, Store, StoreError, Subscription,
    SubscriptionFilter,
};

use crate::capabilities::Capabilities;
use crate::crypto::{build_aad, decrypt_entry, encrypt_entry};
use crate::groups::{self, DLQ_NS, GROUPS_NS, PENDING_NS};
use crate::keys::{KeyManager, META_NS, ProvisionDefaults};
use crate::offsets::{self, OFFSETS_NS};

pub const LOGS_NS: &str = "scroll.logs";

/// Selector for `trim`: keep most-recent N entries, or delete entries older
/// than N milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrimBy {
    MaxLen(u64),
    MaxAgeMs(i64),
}

/// Engine-level configuration. Defaults match the `[scroll]` section of SPEC §11.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Hard upper bound for `APPEND` body size (payload + serialized headers).
    /// Above this, `append` returns `ScrollError::EntryTooLarge`.
    pub default_max_entry_bytes: u64,
    pub default_max_header_bytes: u64,
    /// If set, every entry inherits this TTL when the caller doesn't override.
    pub default_retention_ttl_ms: Option<i64>,
    /// CAS retry budget for the offset counter per `APPEND`.
    pub offset_cas_retry_max: u32,
    /// CAS retry budget for group cursor advancement per `READ_GROUP`.
    pub group_cursor_cas_retry_max: u32,
    /// Once an entry's `delivery_count` reaches this value, a subsequent
    /// `CLAIM` moves it to `scroll.dlq` instead of redelivering.
    pub max_delivery_count: u32,
    /// Default `min_idle_ms` recommended to `CLAIM` callers; also used as the
    /// idle threshold below which a reader is considered "fresh" in
    /// `GROUP_INFO` member listings. Operators tune this to their reader
    /// polling cadence (SPEC §11 `reader_idle_threshold_ms`).
    pub reader_idle_threshold_ms: i64,
    /// Default `TAIL` wait budget when the caller omits `TIMEOUT`.
    pub tail_default_timeout_ms: u64,
    /// Buffer size the Store-subscribe channel is configured with for `TAIL`.
    /// If a `TAIL` consumer falls behind this many events, the subscription
    /// closes and the call returns `TailOverflow`.
    pub tail_subscribe_buffer: usize,
    /// TTL applied to `scroll.dlq` entries at write time. `None` means DLQ
    /// entries live forever (operators must drain out-of-band). SPEC §11
    /// default: 30 days.
    pub dlq_retention_ttl_ms: Option<i64>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            default_max_entry_bytes: 1_048_576,
            default_max_header_bytes: 16_384,
            default_retention_ttl_ms: None,
            // Offsets see much higher contention than group cursors:
            // every APPEND on a given log races on `scroll.offsets`, whereas
            // `scroll.groups` only sees readers-per-group contention. With
            // N-way racing appenders, worst-case retries scale O(N), so 64
            // buys headroom for bursty producers. Tune up for pathological
            // contention (see SPEC §17 Q3 on fairness).
            offset_cas_retry_max: 64,
            group_cursor_cas_retry_max: 8,
            max_delivery_count: 16,
            reader_idle_threshold_ms: 60_000,
            tail_default_timeout_ms: 30_000,
            tail_subscribe_buffer: 1024,
            dlq_retention_ttl_ms: Some(2_592_000_000), // 30 days
        }
    }
}

/// Response payload for `LOG_INFO`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogInfo {
    pub log: String,
    /// Count of offsets minted so far. Equals `latest_offset + 1` when the log
    /// has any entries, or 0 when it is empty. Does not reflect retention.
    pub entries_minted: u64,
    /// Offset of the most recent append, or `None` if the log is empty.
    pub latest_offset: Option<u64>,
    pub groups: Vec<String>,
    pub created_at_ms: i64,
}

/// Response payload for `GROUP_INFO`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    pub log: String,
    pub group: String,
    pub last_delivered_offset: u64,
    pub members: Vec<ReaderMember>,
    pub pending_count: u64,
    pub created_at_ms: i64,
}

pub struct ScrollEngine<S: Store> {
    store: Arc<S>,
    caps: Arc<Capabilities>,
    keys: KeyManager,
    config: EngineConfig,
}

impl<S: Store> ScrollEngine<S> {
    /// Create a new engine. Ensures the five Store namespaces exist.
    ///
    /// No capability is required at construction — this mirrors Sigil. A
    /// Cipher-less engine rejects `APPEND` / `READ` / `READ_GROUP` at the
    /// use site with `ScrollError::CapabilityMissing("cipher")` (fail-closed,
    /// never plaintext fallback); metadata commands (`CREATE_GROUP`, `ACK`,
    /// `DELETE_LOG`, `LOG_INFO`, `GROUP_INFO`) remain usable so operators can
    /// inspect or crypto-shred existing logs in a recovery deployment.
    pub async fn new(
        store: Arc<S>,
        caps: Capabilities,
        config: EngineConfig,
    ) -> Result<Self, ScrollError> {
        let ns_config = NamespaceConfig::default();
        for ns in [LOGS_NS, OFFSETS_NS, GROUPS_NS, PENDING_NS, META_NS, DLQ_NS] {
            match store.namespace_create(ns, ns_config.clone()).await {
                Ok(()) => tracing::debug!(namespace = ns, "created scroll namespace"),
                Err(StoreError::NamespaceExists(_)) => {}
                Err(e) => {
                    return Err(ScrollError::Store(format!(
                        "failed to create namespace {ns}: {e}"
                    )));
                }
            }
        }
        Ok(Self {
            store,
            caps: Arc::new(caps),
            keys: KeyManager::new(),
            config,
        })
    }

    // ─────────────────────────── helpers ───────────────────────────

    fn entry_key(tenant_id: &str, log: &str, offset: u64) -> Vec<u8> {
        format!("{tenant_id}/{log}/{offset:020}").into_bytes()
    }

    fn entry_prefix(tenant_id: &str, log: &str) -> Vec<u8> {
        format!("{tenant_id}/{log}/").into_bytes()
    }

    fn log_prefix_in_offsets(tenant_id: &str, log: &str) -> Vec<u8> {
        format!("{tenant_id}/{log}").into_bytes()
    }

    fn groups_prefix(tenant_id: &str, log: &str) -> Vec<u8> {
        format!("{tenant_id}/{log}/").into_bytes()
    }

    fn meta_key(tenant_id: &str, log: &str) -> Vec<u8> {
        format!("{tenant_id}/{log}").into_bytes()
    }

    fn provision_defaults(&self, now_ms: i64) -> ProvisionDefaults {
        ProvisionDefaults {
            now_ms,
            max_entry_bytes: self.config.default_max_entry_bytes,
            max_header_bytes: self.config.default_max_header_bytes,
            default_ttl_ms: self.config.default_retention_ttl_ms,
        }
    }

    /// Resolve Cipher for operations that need it. APPEND, READ, and
    /// READ_GROUP all encrypt or decrypt payloads and cannot proceed without
    /// Cipher; this returns `CapabilityMissing("cipher")` fail-closed when
    /// absent rather than silently storing/returning plaintext.
    fn require_cipher(&self) -> Result<&dyn crate::capabilities::ScrollCipherOps, ScrollError> {
        self.caps
            .cipher
            .as_deref()
            .ok_or_else(|| ScrollError::CapabilityMissing("cipher".into()))
    }

    /// ABAC gate — evaluates every command when Sentry is configured.
    /// Without Sentry this is a no-op (wire-level ACL via `shroudb-acl`
    /// still applies at the protocol layer). A `PolicyEffect::Deny` decision
    /// returns `ScrollError::AccessDenied`; internal evaluation errors are
    /// mapped to `Internal` so Sentry outages don't silently fail-open.
    async fn check_policy(
        &self,
        tenant_id: &str,
        resource_id: &str,
        action: &str,
        ctx: &AuditContext,
    ) -> Result<(), ScrollError> {
        let Some(sentry) = self.caps.sentry.as_ref() else {
            return Ok(());
        };
        let mut attrs = HashMap::new();
        attrs.insert("tenant".to_string(), tenant_id.to_string());
        let request = PolicyRequest {
            principal: PolicyPrincipal {
                id: ctx.actor_or_anonymous().to_string(),
                roles: vec![],
                claims: HashMap::new(),
            },
            resource: PolicyResource {
                id: resource_id.to_string(),
                resource_type: "scroll".to_string(),
                attributes: attrs,
            },
            action: action.to_string(),
        };
        let decision = sentry
            .evaluate(&request)
            .await
            .map_err(|e| ScrollError::Internal(format!("sentry evaluation failed: {e}")))?;
        match decision.effect {
            PolicyEffect::Permit => Ok(()),
            PolicyEffect::Deny => Err(ScrollError::AccessDenied {
                action: action.to_string(),
                resource: resource_id.to_string(),
                policy: decision
                    .matched_policy
                    .unwrap_or_else(|| "default-deny".into()),
            }),
        }
    }

    /// Fire-and-forget audit event. No-op when Chronicle is absent; errors
    /// from Chronicle are logged, not propagated (a failed audit record
    /// must not roll back a successful state change).
    ///
    /// Emitted on state-changing commands (`APPEND`, `CREATE_GROUP`,
    /// `READ_GROUP`, `ACK`, `DELETE_LOG`). Reads (`READ`, `LOG_INFO`,
    /// `GROUP_INFO`) are gated by Sentry but not audited — audit volume
    /// would drown the signal.
    async fn emit_audit(
        &self,
        operation: &str,
        tenant_id: &str,
        resource_id: &str,
        result: EventResult,
        ctx: &AuditContext,
    ) {
        let Some(chronicle) = self.caps.chronicle.as_ref() else {
            return;
        };
        let mut event = Event::new(
            ChronicleEngine::Custom("scroll".to_string()),
            operation.to_string(),
            "scroll".to_string(),
            format!("{tenant_id}/{resource_id}"),
            result,
            ctx.actor_or_anonymous().to_string(),
        );
        event.tenant_id = Some(tenant_id.to_string());
        event.correlation_id = ctx.correlation_id.clone();
        if let Err(e) = chronicle.record(event).await {
            tracing::warn!(
                operation,
                tenant = tenant_id,
                resource = resource_id,
                error = %e,
                "failed to record audit event"
            );
        }
    }

    /// Current next-offset for a log (the value the next `APPEND` would mint),
    /// used by the protocol layer to translate `CREATE_GROUP ... latest` into
    /// a concrete `start_offset`. Returns 0 when the log has no entries yet.
    pub async fn current_next_offset(
        &self,
        tenant_id: &str,
        log: &str,
    ) -> Result<u64, ScrollError> {
        #[derive(Deserialize)]
        struct Counter {
            next: u64,
        }
        let key = offsets::offset_key(tenant_id, log);
        match self.store.get(OFFSETS_NS, &key, None).await {
            Ok(entry) => {
                let c: Counter = serde_json::from_slice(&entry.value)
                    .map_err(|e| ScrollError::Store(format!("corrupt offset counter: {e}")))?;
                Ok(c.next)
            }
            Err(StoreError::NotFound) => Ok(0),
            Err(e) => Err(ScrollError::Store(format!("offset get: {e}"))),
        }
    }

    // ─────────────────────────── commands ───────────────────────────

    /// APPEND. Mints a new offset via CAS, encrypts the entry with the per-log
    /// DEK, and stores it under `scroll.logs`. Returns the allocated offset.
    /// Sentry-gated; emits an `APPEND` audit event on both success and failure.
    pub async fn append(
        &self,
        tenant_id: &str,
        log: &str,
        payload: Vec<u8>,
        headers: BTreeMap<String, String>,
        ttl_ms: Option<i64>,
        ctx: &AuditContext,
    ) -> Result<u64, ScrollError> {
        let result = async {
            self.check_policy(tenant_id, log, "append", ctx).await?;
            let now_ms = now_ms();

            // Enforce size cap before anything else — fail-closed, pre-Store.
            let headers_bytes: usize = headers.iter().map(|(k, v)| k.len() + v.len()).sum();
            let total = payload.len() + headers_bytes;
            if total as u64 > self.config.default_max_entry_bytes {
                return Err(ScrollError::EntryTooLarge {
                    size: total,
                    max: self.config.default_max_entry_bytes as usize,
                });
            }
            if headers_bytes as u64 > self.config.default_max_header_bytes {
                return Err(ScrollError::EntryTooLarge {
                    size: headers_bytes,
                    max: self.config.default_max_header_bytes as usize,
                });
            }

            // Provision-or-load the log's DEK.
            let (dek, meta) = self
                .keys
                .get_or_create(
                    self.store.as_ref(),
                    self.require_cipher()?,
                    tenant_id,
                    log,
                    self.provision_defaults(now_ms),
                )
                .await?;

            // Effective TTL = caller override ∨ per-log default ∨ engine default.
            let effective_ttl = ttl_ms
                .or(meta.default_ttl_ms)
                .or(self.config.default_retention_ttl_ms);
            let expires_at_ms =
                effective_ttl.and_then(|ms| if ms > 0 { Some(now_ms + ms) } else { None });

            // Reserve offset via CAS on scroll.offsets.
            let offset = offsets::allocate(
                self.store.as_ref(),
                tenant_id,
                log,
                self.config.offset_cas_retry_max,
            )
            .await?;

            // Build the domain LogEntry, serialize, encrypt with AAD-bound DEK.
            let entry = LogEntry {
                offset,
                tenant_id: tenant_id.to_string(),
                log: log.to_string(),
                payload,
                headers,
                appended_at_ms: now_ms,
                expires_at_ms,
            };
            let plaintext = serde_json::to_vec(&entry)
                .map_err(|e| ScrollError::Internal(format!("entry encode: {e}")))?;
            let aad = build_aad(tenant_id, log, offset);
            let ciphertext = encrypt_entry(dek.as_bytes(), &plaintext, &aad)?;

            // Persist the ciphertext. TTL is entry-level; the Store sweeper
            // deletes it when `expires_at_ms` is reached. `appended_at_ms`
            // is attached as Store metadata so TRIM MAX_AGE can filter
            // without decrypting the payload (timestamps are not sensitive —
            // see SPEC §19).
            let mut meta = HashMap::new();
            meta.insert("ts".to_string(), MetadataValue::Integer(now_ms));
            let mut opts = PutOptions::default().with_metadata(meta);
            if let Some(exp) = expires_at_ms {
                let now = now_ms;
                let remaining = (exp - now).max(1) as u64;
                opts = opts.with_ttl(std::time::Duration::from_millis(remaining));
            }

            let key = Self::entry_key(tenant_id, log, offset);
            self.store
                .put_with_options(LOGS_NS, &key, &ciphertext, opts)
                .await
                .map_err(|e| ScrollError::Store(format!("entry put: {e}")))?;

            Ok(offset)
        }
        .await;
        if let Ok(offset) = result {
            // SPEC §13: scroll_appends_total{tenant,log}. `entries_minted` is
            // `offset + 1` (monotonic), exposing the `scroll_entries_stored`
            // gauge signal without a second Store round-trip.
            tracing::info!(
                target: "scroll::metrics",
                metric = "appends_total",
                tenant = tenant_id,
                log = log,
                offset = offset,
                entries_minted = offset + 1,
            );
        }
        self.emit_audit("APPEND", tenant_id, log, event_result(&result), ctx)
            .await;
        result
    }

    /// READ. Range read starting at `from_offset`, up to `limit` entries.
    /// Missing offsets (trimmed / TTL-expired) are skipped silently.
    /// Sentry-gated; no audit (reads are not state-changing).
    pub async fn read(
        &self,
        tenant_id: &str,
        log: &str,
        from_offset: u64,
        limit: u32,
        ctx: &AuditContext,
    ) -> Result<Vec<LogEntry>, ScrollError> {
        self.check_policy(tenant_id, log, "read", ctx).await?;
        if limit == 0 {
            return Ok(Vec::new());
        }
        let (dek, _meta) = self
            .keys
            .get_existing(self.store.as_ref(), self.require_cipher()?, tenant_id, log)
            .await?;

        let prefix = Self::entry_prefix(tenant_id, log);
        let from_key = Self::entry_key(tenant_id, log, from_offset);
        // LIST in this namespace is cursor-paginated; we can fetch up to `limit`
        // keys starting from a cursor bound to `from_offset`. We use a prefix
        // list and then filter by `>= from_key` to avoid depending on cursor
        // opacity.
        let mut out = Vec::with_capacity(limit as usize);
        let mut cursor: Option<String> = None;
        while out.len() < limit as usize {
            let page = self
                .store
                .list(LOGS_NS, Some(&prefix), cursor.as_deref(), limit as usize)
                .await
                .map_err(|e| ScrollError::Store(format!("entry list: {e}")))?;

            for key in page.keys {
                if key < from_key {
                    continue;
                }
                let entry_ct = match self.store.get(LOGS_NS, &key, None).await {
                    Ok(e) => e.value,
                    Err(StoreError::NotFound) => continue,
                    Err(e) => return Err(ScrollError::Store(format!("entry get: {e}"))),
                };
                let offset = offset_from_entry_key(&key)?;
                let aad = build_aad(tenant_id, log, offset);
                let plaintext = decrypt_entry(dek.as_bytes(), &entry_ct, &aad)?;
                let entry: LogEntry = serde_json::from_slice(&plaintext)
                    .map_err(|e| ScrollError::Store(format!("corrupt entry payload: {e}")))?;
                out.push(entry);
                if out.len() >= limit as usize {
                    break;
                }
            }
            match page.cursor {
                Some(c) if out.len() < limit as usize => cursor = Some(c),
                _ => break,
            }
        }
        Ok(out)
    }

    /// CREATE_GROUP. `start_offset` is the first offset the group should
    /// deliver. `0` means "from earliest" (include offset 0). The protocol
    /// layer is responsible for translating the spec's `-1` sentinel ("from
    /// latest") to the current `next_offset` before calling this method.
    /// Returns `GroupExists` if the group is already defined.
    ///
    /// Internally, `ReaderGroup::last_delivered_offset` is stored as
    /// `start_offset - 1`; `u64::MAX` is used as the sentinel for "no entry
    /// delivered yet" (i.e. `start_offset == 0`) so READ_GROUP can still
    /// deliver offset 0 as the first entry.
    pub async fn create_group(
        &self,
        tenant_id: &str,
        log: &str,
        group: &str,
        start_offset: u64,
        ctx: &AuditContext,
    ) -> Result<(), ScrollError> {
        let resource = format!("{log}/{group}");
        let result = async {
            self.check_policy(tenant_id, &resource, "create_group", ctx)
                .await?;
            // Require the log to exist — creating groups on phantom logs is a bug.
            self.ensure_log_exists(tenant_id, log).await?;

            let now = now_ms();
            let internal_last_delivered = if start_offset == 0 {
                u64::MAX
            } else {
                start_offset - 1
            };
            let g = ReaderGroup::new(
                tenant_id.to_string(),
                log.to_string(),
                group.to_string(),
                internal_last_delivered,
                now,
            );
            let key = groups::group_key(tenant_id, log, group);
            let value = serde_json::to_vec(&g)
                .map_err(|e| ScrollError::Internal(format!("group encode: {e}")))?;
            match self
                .store
                .put_if_version(GROUPS_NS, &key, &value, None, 0)
                .await
            {
                Ok(_) => Ok(()),
                Err(StoreError::VersionConflict { .. }) => Err(ScrollError::GroupExists {
                    log: log.to_string(),
                    group: group.to_string(),
                }),
                Err(e) => Err(ScrollError::Store(format!("group create: {e}"))),
            }
        }
        .await;
        self.emit_audit(
            "CREATE_GROUP",
            tenant_id,
            &resource,
            event_result(&result),
            ctx,
        )
        .await;
        result
    }

    /// READ_GROUP. Advances the group cursor by up to `limit` entries under
    /// CAS, registers `PendingEntry` records, and returns the decrypted
    /// batch. On `VersionConflict` retries up to the configured budget.
    pub async fn read_group(
        &self,
        tenant_id: &str,
        log: &str,
        group: &str,
        reader_id: &str,
        limit: u32,
        ctx: &AuditContext,
    ) -> Result<Vec<LogEntry>, ScrollError> {
        let resource = format!("{log}/{group}");
        let start = std::time::Instant::now();
        let result = self
            .read_group_inner(tenant_id, log, group, reader_id, limit, ctx)
            .await;
        let latency_us = start.elapsed().as_micros() as u64;
        if let Ok(ref entries) = result {
            // SPEC §13: scroll_read_group_latency_seconds (histogram) +
            // scroll_delivery_count_total{outcome=delivered}.
            tracing::info!(
                target: "scroll::metrics",
                metric = "read_group_latency",
                tenant = tenant_id,
                log = log,
                group = group,
                reader_id = reader_id,
                latency_us = latency_us,
                delivered = entries.len(),
            );
            if !entries.is_empty() {
                tracing::info!(
                    target: "scroll::metrics",
                    metric = "delivery",
                    tenant = tenant_id,
                    log = log,
                    group = group,
                    outcome = "delivered",
                    count = entries.len(),
                );
            }
        }
        self.emit_audit(
            "READ_GROUP",
            tenant_id,
            &resource,
            event_result(&result),
            ctx,
        )
        .await;
        result
    }

    async fn read_group_inner(
        &self,
        tenant_id: &str,
        log: &str,
        group: &str,
        reader_id: &str,
        limit: u32,
        ctx: &AuditContext,
    ) -> Result<Vec<LogEntry>, ScrollError> {
        let resource = format!("{log}/{group}");
        self.check_policy(tenant_id, &resource, "read_group", ctx)
            .await?;
        if limit == 0 {
            return Ok(Vec::new());
        }
        let (dek, _meta) = self
            .keys
            .get_existing(self.store.as_ref(), self.require_cipher()?, tenant_id, log)
            .await?;

        let now = now_ms();
        let mut delivered_offsets: Vec<u64> = Vec::new();

        // CAS cursor advancement. `last_delivered_offset == u64::MAX` is the
        // "nothing delivered yet" sentinel; see `create_group`.
        for _ in 0..=self.config.group_cursor_cas_retry_max {
            let (mut g, version) = groups::load(self.store.as_ref(), tenant_id, log, group).await?;
            let next_available = self.current_next_offset(tenant_id, log).await?;
            let start = if g.last_delivered_offset == u64::MAX {
                0
            } else {
                g.last_delivered_offset.saturating_add(1)
            };
            if start >= next_available {
                // Nothing new. Touch member, persist, return empty.
                g.touch_member(reader_id, now);
                match groups::put_cas(self.store.as_ref(), &g, version).await {
                    Ok(_) => return Ok(Vec::new()),
                    Err(ScrollError::VersionConflict { .. }) => continue,
                    Err(e) => return Err(e),
                }
            }
            let end = start.saturating_add(limit as u64).min(next_available);
            let batch: Vec<u64> = (start..end).collect();
            if batch.is_empty() {
                return Ok(Vec::new());
            }

            g.last_delivered_offset = end - 1;
            g.version += 1;
            g.touch_member(reader_id, now);

            match groups::put_cas(self.store.as_ref(), &g, version).await {
                Ok(_) => {
                    delivered_offsets = batch;
                    break;
                }
                Err(ScrollError::VersionConflict { .. }) => continue,
                Err(e) => return Err(e),
            }
        }
        if delivered_offsets.is_empty() {
            return Err(ScrollError::VersionConflict {
                target: format!("{GROUPS_NS}/{tenant_id}/{log}/{group}"),
            });
        }

        // Register PendingEntry records + fetch/decrypt entries.
        let mut entries: Vec<LogEntry> = Vec::with_capacity(delivered_offsets.len());
        for offset in &delivered_offsets {
            let pending = PendingEntry::new(*offset, reader_id.to_string(), now);
            let pk = groups::pending_key(tenant_id, log, group, *offset);
            let pv = serde_json::to_vec(&pending)
                .map_err(|e| ScrollError::Internal(format!("pending encode: {e}")))?;
            self.store
                .put(PENDING_NS, &pk, &pv, None)
                .await
                .map_err(|e| ScrollError::Store(format!("pending put: {e}")))?;

            let ek = Self::entry_key(tenant_id, log, *offset);
            let ct = match self.store.get(LOGS_NS, &ek, None).await {
                Ok(e) => e.value,
                Err(StoreError::NotFound) => continue,
                Err(e) => return Err(ScrollError::Store(format!("entry get: {e}"))),
            };
            let aad = build_aad(tenant_id, log, *offset);
            let pt = decrypt_entry(dek.as_bytes(), &ct, &aad)?;
            let entry: LogEntry = serde_json::from_slice(&pt)
                .map_err(|e| ScrollError::Store(format!("corrupt entry: {e}")))?;
            entries.push(entry);
        }
        Ok(entries)
    }

    /// CLAIM. Reassign stalled pending entries to `claimer_id`. For each
    /// pending record in the group older than `min_idle_ms`, increment its
    /// `delivery_count` under CAS and rewrite ownership to the claimer. If
    /// the incremented count would cross `max_delivery_count`, the entry
    /// moves to `scroll.dlq` instead (and is removed from pending). Returns
    /// the offsets successfully claimed.
    pub async fn claim(
        &self,
        tenant_id: &str,
        log: &str,
        group: &str,
        claimer_id: &str,
        min_idle_ms: i64,
        ctx: &AuditContext,
    ) -> Result<Vec<u64>, ScrollError> {
        let resource = format!("{log}/{group}");
        let result = async {
            self.check_policy(tenant_id, &resource, "claim", ctx)
                .await?;
            let now = now_ms();
            let idle_before = now.saturating_sub(min_idle_ms);
            let prefix = groups::pending_prefix(tenant_id, log, group);
            let mut cursor: Option<String> = None;
            let mut claimed: Vec<u64> = Vec::new();
            let mut dlq_moves: Vec<u64> = Vec::new();
            loop {
                let page = self
                    .store
                    .list(PENDING_NS, Some(&prefix), cursor.as_deref(), 256)
                    .await
                    .map_err(|e| ScrollError::Store(format!("pending list: {e}")))?;
                for key in &page.keys {
                    let entry = match self.store.get(PENDING_NS, key, None).await {
                        Ok(e) => e,
                        Err(StoreError::NotFound) => continue,
                        Err(e) => {
                            return Err(ScrollError::Store(format!("pending get: {e}")));
                        }
                    };
                    let mut pending: PendingEntry = serde_json::from_slice(&entry.value)
                        .map_err(|e| ScrollError::Store(format!("corrupt pending record: {e}")))?;
                    if pending.delivered_at_ms > idle_before {
                        continue; // Still fresh; not stale enough to claim.
                    }
                    let new_count = pending.delivery_count.saturating_add(1);
                    if new_count > self.config.max_delivery_count {
                        // Move to DLQ atomically from the caller's perspective:
                        // put DLQ first, then delete pending. A crash between
                        // leaves a duplicate DLQ record — acceptable vs. loss.
                        let dlq_record = DlqEntry {
                            offset: pending.offset,
                            reader_id: pending.reader_id.clone(),
                            delivered_at_ms: pending.delivered_at_ms,
                            delivery_count: pending.delivery_count,
                            moved_to_dlq_at_ms: now,
                            reason: "max_delivery_count_exceeded".into(),
                        };
                        let dlq_bytes = serde_json::to_vec(&dlq_record)
                            .map_err(|e| ScrollError::Internal(format!("dlq encode: {e}")))?;
                        let dk = groups::dlq_key(tenant_id, log, pending.offset);
                        // Apply DLQ retention TTL so dead-lettered entries don't
                        // accumulate forever. None = keep forever (§11 config).
                        let mut dlq_opts = PutOptions::default();
                        if let Some(ttl_ms) = self.config.dlq_retention_ttl_ms
                            && ttl_ms > 0
                        {
                            dlq_opts =
                                dlq_opts.with_ttl(std::time::Duration::from_millis(ttl_ms as u64));
                        }
                        self.store
                            .put_with_options(DLQ_NS, &dk, &dlq_bytes, dlq_opts)
                            .await
                            .map_err(|e| ScrollError::Store(format!("dlq put: {e}")))?;
                        // Remove from pending. CAS on the pending version so we
                        // don't race with another claimer.
                        match self
                            .store
                            .delete_if_version(PENDING_NS, key, entry.version)
                            .await
                        {
                            Ok(_) | Err(StoreError::NotFound) => {
                                dlq_moves.push(pending.offset);
                            }
                            Err(StoreError::VersionConflict { .. }) => continue,
                            Err(e) => {
                                return Err(ScrollError::Store(format!("pending delete: {e}")));
                            }
                        }
                    } else {
                        pending.reader_id = claimer_id.to_string();
                        pending.delivered_at_ms = now;
                        pending.delivery_count = new_count;
                        let bytes = serde_json::to_vec(&pending)
                            .map_err(|e| ScrollError::Internal(format!("pending encode: {e}")))?;
                        match self
                            .store
                            .put_if_version(PENDING_NS, key, &bytes, None, entry.version)
                            .await
                        {
                            Ok(_) => claimed.push(pending.offset),
                            Err(StoreError::VersionConflict { .. }) => continue,
                            Err(e) => {
                                return Err(ScrollError::Store(format!("pending CAS: {e}")));
                            }
                        }
                    }
                }
                match page.cursor {
                    Some(c) => cursor = Some(c),
                    None => break,
                }
            }
            // Emit one audit event per DLQ move (per SPEC §10).
            for offset in &dlq_moves {
                self.emit_audit(
                    "DLQ_MOVE",
                    tenant_id,
                    &format!("{log}/{group}/{offset}"),
                    EventResult::Ok,
                    ctx,
                )
                .await;
            }
            // SPEC §13: scroll_delivery_count_total{outcome=claimed|dlq}.
            if !claimed.is_empty() {
                tracing::info!(
                    target: "scroll::metrics",
                    metric = "delivery",
                    tenant = tenant_id,
                    log = log,
                    group = group,
                    outcome = "claimed",
                    count = claimed.len(),
                );
            }
            if !dlq_moves.is_empty() {
                tracing::info!(
                    target: "scroll::metrics",
                    metric = "delivery",
                    tenant = tenant_id,
                    log = log,
                    group = group,
                    outcome = "dlq",
                    count = dlq_moves.len(),
                );
            }
            Ok(claimed)
        }
        .await;
        self.emit_audit("CLAIM", tenant_id, &resource, event_result(&result), ctx)
            .await;
        result
    }

    /// ACK. Idempotent: a double-ack returns Ok.
    pub async fn ack(
        &self,
        tenant_id: &str,
        log: &str,
        group: &str,
        offset: u64,
        ctx: &AuditContext,
    ) -> Result<(), ScrollError> {
        let resource = format!("{log}/{group}");
        let result = async {
            self.check_policy(tenant_id, &resource, "ack", ctx).await?;
            let k = groups::pending_key(tenant_id, log, group, offset);
            match self.store.delete(PENDING_NS, &k).await {
                Ok(_) | Err(StoreError::NotFound) => Ok(()),
                Err(e) => Err(ScrollError::Store(format!("ack delete: {e}"))),
            }
        }
        .await;
        self.emit_audit("ACK", tenant_id, &resource, event_result(&result), ctx)
            .await;
        result
    }

    /// LOG_INFO. Returns stats derived from the Store without scanning
    /// payloads. Sentry-gated; no audit.
    pub async fn log_info(
        &self,
        tenant_id: &str,
        log: &str,
        ctx: &AuditContext,
    ) -> Result<LogInfo, ScrollError> {
        self.check_policy(tenant_id, log, "log_info", ctx).await?;
        let meta = self.load_meta_raw(tenant_id, log).await?;
        let next = self.current_next_offset(tenant_id, log).await?;
        let latest_offset = if next > 0 { Some(next - 1) } else { None };

        // Enumerate groups under this log.
        let mut groups_out: Vec<String> = Vec::new();
        let prefix = Self::groups_prefix(tenant_id, log);
        let mut cursor: Option<String> = None;
        loop {
            let page = self
                .store
                .list(GROUPS_NS, Some(&prefix), cursor.as_deref(), 256)
                .await
                .map_err(|e| ScrollError::Store(format!("group list: {e}")))?;
            for key in &page.keys {
                if let Some(g) = extract_group_name_from_key(key, &prefix) {
                    groups_out.push(g);
                }
            }
            match page.cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }

        Ok(LogInfo {
            log: log.to_string(),
            entries_minted: next,
            latest_offset,
            groups: groups_out,
            created_at_ms: meta.created_at_ms,
        })
    }

    /// GROUP_INFO. Sentry-gated; no audit.
    pub async fn group_info(
        &self,
        tenant_id: &str,
        log: &str,
        group: &str,
        ctx: &AuditContext,
    ) -> Result<GroupInfo, ScrollError> {
        let resource = format!("{log}/{group}");
        self.check_policy(tenant_id, &resource, "group_info", ctx)
            .await?;
        let (g, _version) = groups::load(self.store.as_ref(), tenant_id, log, group).await?;

        let mut pending_count: u64 = 0;
        let prefix = groups::pending_prefix(tenant_id, log, group);
        let mut cursor: Option<String> = None;
        loop {
            let page = self
                .store
                .list(PENDING_NS, Some(&prefix), cursor.as_deref(), 512)
                .await
                .map_err(|e| ScrollError::Store(format!("pending list: {e}")))?;
            pending_count += page.keys.len() as u64;
            match page.cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }

        // SPEC §13 gauges — computed from state already materialized here so
        // we pay one list (above) instead of a separate metrics scrape.
        let next_offset = self.current_next_offset(tenant_id, log).await.unwrap_or(0);
        let lag = if g.last_delivered_offset == u64::MAX {
            next_offset
        } else {
            next_offset.saturating_sub(g.last_delivered_offset.saturating_add(1))
        };
        tracing::info!(
            target: "scroll::metrics",
            metric = "pending_entries",
            tenant = tenant_id,
            log = log,
            group = group,
            value = pending_count,
        );
        tracing::info!(
            target: "scroll::metrics",
            metric = "group_lag_offsets",
            tenant = tenant_id,
            log = log,
            group = group,
            value = lag,
        );

        Ok(GroupInfo {
            log: log.to_string(),
            group: group.to_string(),
            last_delivered_offset: g.last_delivered_offset,
            members: g.members.into_values().collect(),
            pending_count,
            created_at_ms: g.created_at_ms,
        })
    }

    /// TAIL. Live-tail reader: returns at most `limit` entries at or after
    /// `from_offset`, waiting up to `timeout_ms` for new appends if the log
    /// doesn't already have `limit` entries in range. `timeout_ms = None`
    /// applies the engine's configured `tail_default_timeout_ms`.
    ///
    /// Sentry-gated; no audit (reads are not audited). Requires Cipher (every
    /// entry is decrypted before returning).
    ///
    /// Implementation: first drains already-persisted entries via READ, then
    /// subscribes to the `scroll.logs` namespace and filters on the
    /// `{tenant}/{log}/` prefix to collect new appends. Subscribe closure
    /// before `limit` is reached surfaces as `TailOverflow` — the client is
    /// expected to fall back to `READ` with an explicit offset.
    pub async fn tail(
        &self,
        tenant_id: &str,
        log: &str,
        from_offset: u64,
        limit: u32,
        timeout_ms: Option<u64>,
        ctx: &AuditContext,
    ) -> Result<Vec<LogEntry>, ScrollError> {
        self.check_policy(tenant_id, log, "tail", ctx).await?;
        if limit == 0 {
            return Ok(Vec::new());
        }
        let timeout_ms = timeout_ms.unwrap_or(self.config.tail_default_timeout_ms);
        let (dek, _meta) = self
            .keys
            .get_existing(self.store.as_ref(), self.require_cipher()?, tenant_id, log)
            .await?;

        // Drain the already-persisted tail first.
        let mut collected = self.read(tenant_id, log, from_offset, limit, ctx).await?;
        if collected.len() >= limit as usize {
            return Ok(collected);
        }

        // Subscribe before computing `next_seen` so we don't race past an append
        // that landed between the read above and the subscribe below.
        let filter = SubscriptionFilter {
            key: None,
            events: vec![EventType::Put],
        };
        let mut sub = self
            .store
            .subscribe(LOGS_NS, filter)
            .await
            .map_err(|e| ScrollError::Store(format!("subscribe: {e}")))?;

        // Filter events by tenant/log prefix; advance `next_seen` so we ignore
        // duplicates for offsets already pulled by READ.
        let prefix = Self::entry_prefix(tenant_id, log);
        let mut next_seen = match collected.last() {
            Some(e) => e.offset.saturating_add(1),
            None => from_offset,
        };

        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_millis(timeout_ms.max(1));

        while collected.len() < limit as usize {
            let event = match tokio::time::timeout_at(deadline, sub.recv()).await {
                Ok(Some(ev)) => ev,
                // Timeout reached — return whatever we've accumulated.
                Err(_) => break,
                // Subscription closed before we met the limit — treat as overflow.
                Ok(None) => {
                    // SPEC §13: scroll_tail_overflow_total{tenant,log}.
                    tracing::info!(
                        target: "scroll::metrics",
                        metric = "tail_overflow",
                        tenant = tenant_id,
                        log = log,
                    );
                    return Err(ScrollError::TailOverflow);
                }
            };
            if !event.key.starts_with(&prefix) {
                continue;
            }
            let offset = offset_from_entry_key(&event.key)?;
            if offset < next_seen {
                continue;
            }
            let ct = match self.store.get(LOGS_NS, &event.key, None).await {
                Ok(e) => e.value,
                Err(StoreError::NotFound) => continue,
                Err(e) => return Err(ScrollError::Store(format!("entry get: {e}"))),
            };
            let aad = build_aad(tenant_id, log, offset);
            let pt = decrypt_entry(dek.as_bytes(), &ct, &aad)?;
            let entry: LogEntry = serde_json::from_slice(&pt)
                .map_err(|e| ScrollError::Store(format!("corrupt entry: {e}")))?;
            next_seen = offset.saturating_add(1);
            collected.push(entry);
        }
        Ok(collected)
    }

    /// TRIM. Retention enforcement. `MaxLen(n)` keeps only the most recent
    /// `n` offsets by deleting everything below `next_offset - n`.
    /// `MaxAgeMs(ms)` deletes every entry whose Store-metadata `ts` is older
    /// than `now - ms`. Returns the number of entries actually deleted.
    pub async fn trim(
        &self,
        tenant_id: &str,
        log: &str,
        by: TrimBy,
        ctx: &AuditContext,
    ) -> Result<u64, ScrollError> {
        let result = async {
            self.check_policy(tenant_id, log, "trim", ctx).await?;
            match by {
                TrimBy::MaxLen(keep) => self.trim_max_len(tenant_id, log, keep).await,
                TrimBy::MaxAgeMs(age_ms) => self.trim_max_age(tenant_id, log, age_ms).await,
            }
        }
        .await;
        self.emit_audit("TRIM", tenant_id, log, event_result(&result), ctx)
            .await;
        result
    }

    async fn trim_max_len(
        &self,
        tenant_id: &str,
        log: &str,
        keep: u64,
    ) -> Result<u64, ScrollError> {
        let next = self.current_next_offset(tenant_id, log).await?;
        if next <= keep {
            return Ok(0);
        }
        let threshold = next - keep; // delete offsets strictly less than this
        let mut deleted: u64 = 0;
        let prefix = Self::entry_prefix(tenant_id, log);
        let mut cursor: Option<String> = None;
        loop {
            let page = self
                .store
                .list(LOGS_NS, Some(&prefix), cursor.as_deref(), 256)
                .await
                .map_err(|e| ScrollError::Store(format!("entry list: {e}")))?;
            for key in &page.keys {
                let offset = offset_from_entry_key(key)?;
                if offset >= threshold {
                    continue;
                }
                match self.store.delete(LOGS_NS, key).await {
                    Ok(_) => deleted += 1,
                    Err(StoreError::NotFound) => {}
                    Err(e) => return Err(ScrollError::Store(format!("entry delete: {e}"))),
                }
            }
            match page.cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
        Ok(deleted)
    }

    async fn trim_max_age(
        &self,
        tenant_id: &str,
        log: &str,
        age_ms: i64,
    ) -> Result<u64, ScrollError> {
        let cutoff = now_ms().saturating_sub(age_ms);
        let mut deleted: u64 = 0;
        let prefix = Self::entry_prefix(tenant_id, log);
        let mut cursor: Option<String> = None;
        loop {
            let page = self
                .store
                .list(LOGS_NS, Some(&prefix), cursor.as_deref(), 256)
                .await
                .map_err(|e| ScrollError::Store(format!("entry list: {e}")))?;
            for key in &page.keys {
                let entry = match self.store.get(LOGS_NS, key, None).await {
                    Ok(e) => e,
                    Err(StoreError::NotFound) => continue,
                    Err(e) => return Err(ScrollError::Store(format!("entry get: {e}"))),
                };
                let ts = match entry.metadata.get("ts") {
                    Some(MetadataValue::Integer(i)) => *i,
                    // Entries written before the metadata convention are never
                    // reaped by MAX_AGE — safer than guessing. They can still
                    // be reaped by MAX_LEN.
                    _ => continue,
                };
                if ts >= cutoff {
                    continue;
                }
                match self.store.delete(LOGS_NS, key).await {
                    Ok(_) => deleted += 1,
                    Err(StoreError::NotFound) => {}
                    Err(e) => return Err(ScrollError::Store(format!("entry delete: {e}"))),
                }
            }
            match page.cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
        Ok(deleted)
    }

    /// DELETE_LOG. Hard teardown: data → groups → pending → offsets → DEK.
    /// The DEK is destroyed **last** so that if we crash part-way, replicas
    /// can still reconcile via replay. After the meta row is deleted every
    /// residual ciphertext is unreadable (crypto-shred). Sentry-gated;
    /// emits a `DELETE_LOG` audit event on both success and failure.
    pub async fn delete_log(
        &self,
        tenant_id: &str,
        log: &str,
        ctx: &AuditContext,
    ) -> Result<(), ScrollError> {
        let result = self.delete_log_inner(tenant_id, log, ctx).await;
        self.emit_audit("DELETE_LOG", tenant_id, log, event_result(&result), ctx)
            .await;
        result
    }

    async fn delete_log_inner(
        &self,
        tenant_id: &str,
        log: &str,
        ctx: &AuditContext,
    ) -> Result<(), ScrollError> {
        self.check_policy(tenant_id, log, "delete_log", ctx).await?;
        let data_prefix = Self::entry_prefix(tenant_id, log);
        self.store
            .delete_prefix(LOGS_NS, &data_prefix)
            .await
            .map_err(|e| ScrollError::Store(format!("delete_prefix logs: {e}")))?;

        let groups_p = Self::groups_prefix(tenant_id, log);
        self.store
            .delete_prefix(GROUPS_NS, &groups_p)
            .await
            .map_err(|e| ScrollError::Store(format!("delete_prefix groups: {e}")))?;

        let pending_p = Self::groups_prefix(tenant_id, log);
        self.store
            .delete_prefix(PENDING_NS, &pending_p)
            .await
            .map_err(|e| ScrollError::Store(format!("delete_prefix pending: {e}")))?;

        let offset_k = Self::log_prefix_in_offsets(tenant_id, log);
        match self.store.delete(OFFSETS_NS, &offset_k).await {
            Ok(_) | Err(StoreError::NotFound) => {}
            Err(e) => return Err(ScrollError::Store(format!("offset delete: {e}"))),
        }

        // Crypto-shred: destroy the wrapped DEK.
        let meta_k = Self::meta_key(tenant_id, log);
        match self.store.delete(META_NS, &meta_k).await {
            Ok(_) | Err(StoreError::NotFound) => {}
            Err(e) => return Err(ScrollError::Store(format!("meta delete: {e}"))),
        }
        self.keys.evict(tenant_id, log);
        Ok(())
    }

    // ─────────────────────────── helpers ───────────────────────────

    async fn ensure_log_exists(&self, tenant_id: &str, log: &str) -> Result<(), ScrollError> {
        self.load_meta_raw(tenant_id, log).await.map(|_| ())
    }

    async fn load_meta_raw(
        &self,
        tenant_id: &str,
        log: &str,
    ) -> Result<crate::meta::LogMeta, ScrollError> {
        let key = Self::meta_key(tenant_id, log);
        match self.store.get(META_NS, &key, None).await {
            Ok(entry) => serde_json::from_slice(&entry.value)
                .map_err(|e| ScrollError::Store(format!("corrupt log meta: {e}"))),
            Err(StoreError::NotFound) => Err(ScrollError::LogNotFound(log.to_string())),
            Err(e) => Err(ScrollError::Store(format!("meta get: {e}"))),
        }
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn event_result<T>(result: &Result<T, ScrollError>) -> EventResult {
    if result.is_ok() {
        EventResult::Ok
    } else {
        EventResult::Error
    }
}

/// Parse the trailing `{offset:020}` segment of an entry key.
fn offset_from_entry_key(key: &[u8]) -> Result<u64, ScrollError> {
    let s =
        std::str::from_utf8(key).map_err(|_| ScrollError::Store("entry key not UTF-8".into()))?;
    let last = s
        .rsplit('/')
        .next()
        .ok_or_else(|| ScrollError::Store(format!("entry key missing offset segment: {s}")))?;
    last.parse::<u64>()
        .map_err(|_| ScrollError::Store(format!("entry key offset not u64: {last}")))
}

fn extract_group_name_from_key(key: &[u8], prefix: &[u8]) -> Option<String> {
    let rest = key.strip_prefix(prefix)?;
    Some(String::from_utf8_lossy(rest).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::{BoxFut, DataKeyPair, ScrollCipherOps};
    use dashmap::DashMap;
    use shroudb_acl::{AclError, PolicyDecision, PolicyRequest};
    use shroudb_chronicle_core::ops::ChronicleOps;
    use shroudb_crypto::{SensitiveBytes, sha256};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn ctx() -> AuditContext {
        AuditContext::default()
    }

    fn actor(id: &str) -> AuditContext {
        AuditContext::default().with_actor(id)
    }

    /// Test-only Cipher stand-in. Stores each generated DEK in an in-memory
    /// map keyed by its "wrapped" token so `unwrap_data_key` can round-trip.
    /// Not secure — real Cipher performs actual envelope encryption.
    struct FakeCipher {
        counter: AtomicU64,
        deks: DashMap<String, Vec<u8>>,
    }
    impl FakeCipher {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                counter: AtomicU64::new(0),
                deks: DashMap::new(),
            })
        }
    }
    impl ScrollCipherOps for FakeCipher {
        fn generate_data_key(&self, _bits: Option<u32>) -> BoxFut<'_, DataKeyPair> {
            Box::pin(async move {
                let id = self.counter.fetch_add(1, Ordering::SeqCst);
                let dek = sha256(format!("scroll-test-dek-{id}").as_bytes()).to_vec();
                let wrapped = format!("wrap-{id}");
                self.deks.insert(wrapped.clone(), dek.clone());
                Ok(DataKeyPair {
                    plaintext_key: SensitiveBytes::new(dek),
                    wrapped_key: wrapped,
                    key_version: 1,
                })
            })
        }
        fn unwrap_data_key(&self, wrapped_key: &str) -> BoxFut<'_, SensitiveBytes> {
            let wrapped = wrapped_key.to_string();
            Box::pin(async move {
                let dek = self.deks.get(&wrapped).map(|v| v.clone()).ok_or_else(|| {
                    ScrollError::Crypto(format!("unknown wrapped key: {wrapped}"))
                })?;
                Ok(SensitiveBytes::new(dek))
            })
        }
    }

    /// Configurable Sentry double: returns a fixed decision and records every
    /// request it evaluates for inspection.
    struct FakePolicy {
        decision: PolicyEffect,
        requests: Mutex<Vec<PolicyRequest>>,
    }
    impl FakePolicy {
        fn permit() -> Arc<Self> {
            Arc::new(Self {
                decision: PolicyEffect::Permit,
                requests: Mutex::new(Vec::new()),
            })
        }
        fn deny() -> Arc<Self> {
            Arc::new(Self {
                decision: PolicyEffect::Deny,
                requests: Mutex::new(Vec::new()),
            })
        }
    }
    impl shroudb_acl::PolicyEvaluator for FakePolicy {
        fn evaluate(
            &self,
            request: &PolicyRequest,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<PolicyDecision, AclError>> + Send + '_>,
        > {
            let req = request.clone();
            let effect = self.decision;
            self.requests.lock().unwrap().push(request.clone());
            Box::pin(async move {
                Ok(PolicyDecision {
                    effect,
                    matched_policy: Some(format!("test:{}", req.action)),
                    token: None,
                    cache_until: None,
                })
            })
        }
    }

    /// Chronicle double: captures every recorded Event so tests can assert on
    /// audit emission.
    struct FakeChronicle {
        events: Arc<Mutex<Vec<Event>>>,
    }
    impl FakeChronicle {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                events: Arc::new(Mutex::new(Vec::new())),
            })
        }
        fn events(&self) -> Vec<Event> {
            self.events.lock().unwrap().clone()
        }
    }
    impl ChronicleOps for FakeChronicle {
        fn record(
            &self,
            event: Event,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>>
        {
            self.events.lock().unwrap().push(event);
            Box::pin(async { Ok(()) })
        }
        fn record_batch(
            &self,
            events: Vec<Event>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>>
        {
            let store = self.events.clone();
            Box::pin(async move {
                store.lock().unwrap().extend(events);
                Ok(())
            })
        }
    }

    async fn new_engine() -> ScrollEngine<shroudb_storage::EmbeddedStore> {
        let store = shroudb_storage::test_util::create_test_store("scroll-test").await;
        let caps = Capabilities::new().with_cipher(FakeCipher::new());
        ScrollEngine::new(store, caps, EngineConfig::default())
            .await
            .expect("engine new")
    }

    async fn new_engine_without_cipher() -> ScrollEngine<shroudb_storage::EmbeddedStore> {
        let store = shroudb_storage::test_util::create_test_store("scroll-nocipher").await;
        ScrollEngine::new(store, Capabilities::new(), EngineConfig::default())
            .await
            .expect("engine new")
    }

    // ── Basic append / read ─────────────────────────────────────────────

    #[tokio::test]
    async fn append_mints_zero_first() {
        let eng = new_engine().await;
        let off = eng
            .append(
                "t",
                "orders",
                b"hello".to_vec(),
                BTreeMap::new(),
                None,
                &ctx(),
            )
            .await
            .unwrap();
        assert_eq!(off, 0);
    }

    #[tokio::test]
    async fn offsets_are_monotonic() {
        let eng = new_engine().await;
        for expected in 0..5u64 {
            let got = eng
                .append(
                    "t",
                    "l",
                    vec![expected as u8],
                    BTreeMap::new(),
                    None,
                    &ctx(),
                )
                .await
                .unwrap();
            assert_eq!(got, expected);
        }
    }

    #[tokio::test]
    async fn read_returns_appended_entries_decrypted() {
        let eng = new_engine().await;
        for i in 0..3u8 {
            eng.append("t", "l", vec![i], BTreeMap::new(), None, &ctx())
                .await
                .unwrap();
        }
        let got = eng.read("t", "l", 0, 10, &ctx()).await.unwrap();
        assert_eq!(got.len(), 3);
        for (i, e) in got.iter().enumerate() {
            assert_eq!(e.offset, i as u64);
            assert_eq!(e.payload, vec![i as u8]);
            assert_eq!(e.tenant_id, "t");
            assert_eq!(e.log, "l");
        }
    }

    #[tokio::test]
    async fn read_from_offset_skips_earlier_entries() {
        let eng = new_engine().await;
        for i in 0..5u8 {
            eng.append("t", "l", vec![i], BTreeMap::new(), None, &ctx())
                .await
                .unwrap();
        }
        let got = eng.read("t", "l", 3, 10, &ctx()).await.unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].offset, 3);
        assert_eq!(got[1].offset, 4);
    }

    #[tokio::test]
    async fn read_limit_caps_batch() {
        let eng = new_engine().await;
        for i in 0..10u8 {
            eng.append("t", "l", vec![i], BTreeMap::new(), None, &ctx())
                .await
                .unwrap();
        }
        let got = eng.read("t", "l", 0, 4, &ctx()).await.unwrap();
        assert_eq!(got.len(), 4);
    }

    // ── Size enforcement ────────────────────────────────────────────────

    #[tokio::test]
    async fn entry_too_large_hard_rejects() {
        let eng = new_engine().await;
        let oversized = vec![0u8; (EngineConfig::default().default_max_entry_bytes + 1) as usize];
        let err = eng
            .append("t", "l", oversized, BTreeMap::new(), None, &ctx())
            .await
            .unwrap_err();
        assert!(matches!(err, ScrollError::EntryTooLarge { .. }));
    }

    #[tokio::test]
    async fn header_too_large_hard_rejects() {
        let eng = new_engine().await;
        let mut headers = BTreeMap::new();
        headers.insert("k".to_string(), "x".repeat(20_000));
        let err = eng
            .append("t", "l", b"ok".to_vec(), headers, None, &ctx())
            .await
            .unwrap_err();
        assert!(matches!(err, ScrollError::EntryTooLarge { .. }));
    }

    // ── Reader groups ───────────────────────────────────────────────────

    #[tokio::test]
    async fn create_group_on_missing_log_returns_log_not_found() {
        let eng = new_engine().await;
        let err = eng
            .create_group("t", "ghost", "g", 0, &ctx())
            .await
            .unwrap_err();
        assert!(matches!(err, ScrollError::LogNotFound(_)));
    }

    #[tokio::test]
    async fn create_duplicate_group_returns_group_exists() {
        let eng = new_engine().await;
        eng.append("t", "l", b"x".to_vec(), BTreeMap::new(), None, &ctx())
            .await
            .unwrap();
        eng.create_group("t", "l", "g", 0, &ctx()).await.unwrap();
        let err = eng
            .create_group("t", "l", "g", 0, &ctx())
            .await
            .unwrap_err();
        assert!(matches!(err, ScrollError::GroupExists { .. }));
    }

    #[tokio::test]
    async fn read_group_delivers_in_offset_order() {
        let eng = new_engine().await;
        for i in 0..4u8 {
            eng.append("t", "l", vec![i], BTreeMap::new(), None, &ctx())
                .await
                .unwrap();
        }
        eng.create_group("t", "l", "g", 0, &ctx()).await.unwrap();
        let batch = eng
            .read_group("t", "l", "g", "r1", 10, &ctx())
            .await
            .unwrap();
        assert_eq!(batch.len(), 4);
        for (i, e) in batch.iter().enumerate() {
            assert_eq!(e.offset, i as u64);
        }
    }

    #[tokio::test]
    async fn second_read_group_sees_no_new_entries() {
        let eng = new_engine().await;
        for i in 0..2u8 {
            eng.append("t", "l", vec![i], BTreeMap::new(), None, &ctx())
                .await
                .unwrap();
        }
        eng.create_group("t", "l", "g", 0, &ctx()).await.unwrap();
        let first = eng
            .read_group("t", "l", "g", "r1", 10, &ctx())
            .await
            .unwrap();
        assert_eq!(first.len(), 2);
        let second = eng
            .read_group("t", "l", "g", "r1", 10, &ctx())
            .await
            .unwrap();
        assert!(second.is_empty());
    }

    #[tokio::test]
    async fn two_readers_in_group_get_disjoint_entries() {
        let eng = new_engine().await;
        for i in 0..6u8 {
            eng.append("t", "l", vec![i], BTreeMap::new(), None, &ctx())
                .await
                .unwrap();
        }
        eng.create_group("t", "l", "g", 0, &ctx()).await.unwrap();
        let a = eng
            .read_group("t", "l", "g", "r1", 3, &ctx())
            .await
            .unwrap();
        let b = eng
            .read_group("t", "l", "g", "r2", 3, &ctx())
            .await
            .unwrap();
        let off_a: Vec<u64> = a.iter().map(|e| e.offset).collect();
        let off_b: Vec<u64> = b.iter().map(|e| e.offset).collect();
        assert_eq!(off_a, vec![0, 1, 2]);
        assert_eq!(off_b, vec![3, 4, 5]);
    }

    #[tokio::test]
    async fn ack_removes_pending() {
        let eng = new_engine().await;
        for i in 0..2u8 {
            eng.append("t", "l", vec![i], BTreeMap::new(), None, &ctx())
                .await
                .unwrap();
        }
        eng.create_group("t", "l", "g", 0, &ctx()).await.unwrap();
        eng.read_group("t", "l", "g", "r1", 10, &ctx())
            .await
            .unwrap();

        let info = eng.group_info("t", "l", "g", &ctx()).await.unwrap();
        assert_eq!(info.pending_count, 2);

        eng.ack("t", "l", "g", 0, &ctx()).await.unwrap();
        eng.ack("t", "l", "g", 1, &ctx()).await.unwrap();

        let info2 = eng.group_info("t", "l", "g", &ctx()).await.unwrap();
        assert_eq!(info2.pending_count, 0);
    }

    #[tokio::test]
    async fn ack_is_idempotent() {
        let eng = new_engine().await;
        eng.append("t", "l", b"x".to_vec(), BTreeMap::new(), None, &ctx())
            .await
            .unwrap();
        eng.create_group("t", "l", "g", 0, &ctx()).await.unwrap();
        eng.read_group("t", "l", "g", "r1", 10, &ctx())
            .await
            .unwrap();
        eng.ack("t", "l", "g", 0, &ctx()).await.unwrap();
        eng.ack("t", "l", "g", 0, &ctx()).await.unwrap();
    }

    // ── Metadata commands ───────────────────────────────────────────────

    #[tokio::test]
    async fn log_info_reports_entries_and_groups() {
        let eng = new_engine().await;
        for i in 0..3u8 {
            eng.append("t", "l", vec![i], BTreeMap::new(), None, &ctx())
                .await
                .unwrap();
        }
        eng.create_group("t", "l", "g1", 0, &ctx()).await.unwrap();
        eng.create_group("t", "l", "g2", 0, &ctx()).await.unwrap();
        let info = eng.log_info("t", "l", &ctx()).await.unwrap();
        assert_eq!(info.entries_minted, 3);
        assert_eq!(info.latest_offset, Some(2));
        assert_eq!(info.groups.len(), 2);
        assert!(info.groups.contains(&"g1".to_string()));
        assert!(info.groups.contains(&"g2".to_string()));
    }

    #[tokio::test]
    async fn group_info_reports_cursor_and_pending() {
        let eng = new_engine().await;
        for i in 0..3u8 {
            eng.append("t", "l", vec![i], BTreeMap::new(), None, &ctx())
                .await
                .unwrap();
        }
        eng.create_group("t", "l", "g", 0, &ctx()).await.unwrap();
        eng.read_group("t", "l", "g", "r1", 10, &ctx())
            .await
            .unwrap();
        let info = eng.group_info("t", "l", "g", &ctx()).await.unwrap();
        assert_eq!(info.last_delivered_offset, 2);
        assert_eq!(info.pending_count, 3);
        assert!(!info.members.is_empty());
    }

    // ── Delete / crypto-shred ───────────────────────────────────────────

    #[tokio::test]
    async fn delete_log_removes_all_state() {
        let eng = new_engine().await;
        for i in 0..3u8 {
            eng.append("t", "l", vec![i], BTreeMap::new(), None, &ctx())
                .await
                .unwrap();
        }
        eng.create_group("t", "l", "g", 0, &ctx()).await.unwrap();
        eng.read_group("t", "l", "g", "r1", 10, &ctx())
            .await
            .unwrap();

        eng.delete_log("t", "l", &ctx()).await.unwrap();

        // Meta gone → read fails with LogNotFound.
        let err = eng.read("t", "l", 0, 10, &ctx()).await.unwrap_err();
        assert!(matches!(err, ScrollError::LogNotFound(_)));
        // log_info also fails — the DEK+meta row is destroyed.
        let err2 = eng.log_info("t", "l", &ctx()).await.unwrap_err();
        assert!(matches!(err2, ScrollError::LogNotFound(_)));
    }

    #[tokio::test]
    async fn delete_log_allows_subsequent_recreation_with_new_dek() {
        let eng = new_engine().await;
        eng.append("t", "l", b"v1".to_vec(), BTreeMap::new(), None, &ctx())
            .await
            .unwrap();
        eng.delete_log("t", "l", &ctx()).await.unwrap();

        // Recreating the log mints offset 0 again (offsets were dropped).
        let off = eng
            .append("t", "l", b"v2".to_vec(), BTreeMap::new(), None, &ctx())
            .await
            .unwrap();
        assert_eq!(off, 0);
        let got = eng.read("t", "l", 0, 10, &ctx()).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].payload, b"v2");
    }

    // ── Capability fallbacks (Sigil-style fail-closed) ──────────────────

    #[tokio::test]
    async fn append_without_cipher_fails_closed() {
        let eng = new_engine_without_cipher().await;
        let err = eng
            .append("t", "l", b"payload".to_vec(), BTreeMap::new(), None, &ctx())
            .await
            .unwrap_err();
        match err {
            ScrollError::CapabilityMissing(c) => assert_eq!(c, "cipher"),
            other => panic!("expected CapabilityMissing(cipher), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_without_cipher_fails_closed() {
        let eng = new_engine_without_cipher().await;
        let err = eng.read("t", "l", 0, 10, &ctx()).await.unwrap_err();
        assert!(matches!(err, ScrollError::CapabilityMissing(_)));
    }

    #[tokio::test]
    async fn metadata_commands_work_without_cipher() {
        let shared_ns = format!("scroll-cap-{}", uuid::Uuid::new_v4());

        // Phase 1: write with cipher.
        let store1 = shroudb_storage::test_util::create_test_store(&shared_ns).await;
        let caps = Capabilities::new().with_cipher(FakeCipher::new());
        let eng = ScrollEngine::new(store1.clone(), caps, EngineConfig::default())
            .await
            .unwrap();
        eng.append("t", "l", b"x".to_vec(), BTreeMap::new(), None, &ctx())
            .await
            .unwrap();
        eng.create_group("t", "l", "g", 0, &ctx()).await.unwrap();

        // Phase 2: same store, Cipher-less engine, metadata still inspectable.
        let bare = ScrollEngine::new(store1, Capabilities::new(), EngineConfig::default())
            .await
            .unwrap();
        let info = bare.log_info("t", "l", &ctx()).await.unwrap();
        assert_eq!(info.entries_minted, 1);
        let g = bare.group_info("t", "l", "g", &ctx()).await.unwrap();
        assert_eq!(g.last_delivered_offset, u64::MAX);

        bare.delete_log("t", "l", &ctx()).await.unwrap();
        let err = bare.log_info("t", "l", &ctx()).await.unwrap_err();
        assert!(matches!(err, ScrollError::LogNotFound(_)));
    }

    // ── Sentry gating ──────────────────────────────────────────────────

    #[tokio::test]
    async fn sentry_deny_blocks_append() {
        let store = shroudb_storage::test_util::create_test_store("scroll-sentry-deny").await;
        let policy = FakePolicy::deny();
        let caps = Capabilities::new()
            .with_cipher(FakeCipher::new())
            .with_sentry(policy.clone());
        let eng = ScrollEngine::new(store, caps, EngineConfig::default())
            .await
            .unwrap();
        let err = eng
            .append(
                "t",
                "l",
                b"x".to_vec(),
                BTreeMap::new(),
                None,
                &actor("alice"),
            )
            .await
            .unwrap_err();
        match err {
            ScrollError::AccessDenied {
                action, resource, ..
            } => {
                assert_eq!(action, "append");
                assert_eq!(resource, "l");
            }
            other => panic!("expected AccessDenied, got {other:?}"),
        }
        // Sentry should have been called exactly once with actor=alice.
        let reqs = policy.requests.lock().unwrap().clone();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].principal.id, "alice");
        assert_eq!(reqs[0].action, "append");
    }

    #[tokio::test]
    async fn sentry_deny_blocks_reads() {
        let store = shroudb_storage::test_util::create_test_store("scroll-sentry-reads").await;
        let caps = Capabilities::new()
            .with_cipher(FakeCipher::new())
            .with_sentry(FakePolicy::deny());
        let eng = ScrollEngine::new(store, caps, EngineConfig::default())
            .await
            .unwrap();
        for action in ["read", "read_group", "log_info", "group_info", "ack"] {
            let err = match action {
                "read" => eng.read("t", "l", 0, 10, &ctx()).await.unwrap_err(),
                "read_group" => eng
                    .read_group("t", "l", "g", "r", 1, &ctx())
                    .await
                    .unwrap_err(),
                "log_info" => eng.log_info("t", "l", &ctx()).await.unwrap_err(),
                "group_info" => eng.group_info("t", "l", "g", &ctx()).await.unwrap_err(),
                "ack" => eng.ack("t", "l", "g", 0, &ctx()).await.unwrap_err(),
                _ => unreachable!(),
            };
            assert!(
                matches!(err, ScrollError::AccessDenied { .. }),
                "{action} should be denied"
            );
        }
    }

    #[tokio::test]
    async fn sentry_permit_lets_operations_through() {
        let store = shroudb_storage::test_util::create_test_store("scroll-sentry-permit").await;
        let caps = Capabilities::new()
            .with_cipher(FakeCipher::new())
            .with_sentry(FakePolicy::permit());
        let eng = ScrollEngine::new(store, caps, EngineConfig::default())
            .await
            .unwrap();
        let off = eng
            .append("t", "l", b"ok".to_vec(), BTreeMap::new(), None, &ctx())
            .await
            .unwrap();
        assert_eq!(off, 0);
    }

    // ── Chronicle audit emission ───────────────────────────────────────

    #[tokio::test]
    async fn chronicle_records_append_create_ack_delete() {
        let store = shroudb_storage::test_util::create_test_store("scroll-chronicle").await;
        let chron = FakeChronicle::new();
        let caps = Capabilities::new()
            .with_cipher(FakeCipher::new())
            .with_chronicle(chron.clone());
        let eng = ScrollEngine::new(store, caps, EngineConfig::default())
            .await
            .unwrap();
        eng.append(
            "t",
            "l",
            b"x".to_vec(),
            BTreeMap::new(),
            None,
            &actor("svc"),
        )
        .await
        .unwrap();
        eng.create_group("t", "l", "g", 0, &actor("svc"))
            .await
            .unwrap();
        eng.read_group("t", "l", "g", "r", 10, &actor("svc"))
            .await
            .unwrap();
        eng.ack("t", "l", "g", 0, &actor("svc")).await.unwrap();
        eng.delete_log("t", "l", &actor("svc")).await.unwrap();

        let ops: Vec<String> = chron.events().iter().map(|e| e.operation.clone()).collect();
        assert_eq!(
            ops,
            vec!["APPEND", "CREATE_GROUP", "READ_GROUP", "ACK", "DELETE_LOG"]
        );
        // All events record the actor.
        for ev in chron.events() {
            assert_eq!(ev.actor, "svc");
            assert_eq!(ev.tenant_id.as_deref(), Some("t"));
            assert_eq!(ev.result, EventResult::Ok);
        }
    }

    #[tokio::test]
    async fn chronicle_records_failure_on_denied_append() {
        let store = shroudb_storage::test_util::create_test_store("scroll-chronicle-fail").await;
        let chron = FakeChronicle::new();
        let caps = Capabilities::new()
            .with_cipher(FakeCipher::new())
            .with_sentry(FakePolicy::deny())
            .with_chronicle(chron.clone());
        let eng = ScrollEngine::new(store, caps, EngineConfig::default())
            .await
            .unwrap();
        let err = eng
            .append(
                "t",
                "l",
                b"x".to_vec(),
                BTreeMap::new(),
                None,
                &actor("mallory"),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ScrollError::AccessDenied { .. }));

        let events = chron.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, "APPEND");
        assert_eq!(events[0].result, EventResult::Error);
        assert_eq!(events[0].actor, "mallory");
    }

    #[tokio::test]
    async fn chronicle_not_invoked_for_reads() {
        let store = shroudb_storage::test_util::create_test_store("scroll-chronicle-reads").await;
        let chron = FakeChronicle::new();
        let caps = Capabilities::new()
            .with_cipher(FakeCipher::new())
            .with_chronicle(chron.clone());
        let eng = ScrollEngine::new(store, caps, EngineConfig::default())
            .await
            .unwrap();
        eng.append("t", "l", b"x".to_vec(), BTreeMap::new(), None, &ctx())
            .await
            .unwrap();
        // read + log_info + group_info should not emit audit events.
        eng.read("t", "l", 0, 10, &ctx()).await.unwrap();
        eng.log_info("t", "l", &ctx()).await.unwrap();
        let before = chron.events().len();
        let _ = eng.group_info("t", "l", "missing", &ctx()).await;
        let after = chron.events().len();
        assert_eq!(before, after, "group_info must not emit");
        // Only APPEND should be in the log.
        let ops: Vec<String> = chron.events().iter().map(|e| e.operation.clone()).collect();
        assert_eq!(ops, vec!["APPEND"]);
    }

    // ── TAIL ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn tail_returns_already_persisted_entries() {
        let eng = new_engine().await;
        for i in 0..3u8 {
            eng.append("t", "l", vec![i], BTreeMap::new(), None, &ctx())
                .await
                .unwrap();
        }
        // All 3 already persisted — TAIL should return without waiting.
        let got = eng.tail("t", "l", 0, 10, Some(500), &ctx()).await.unwrap();
        assert_eq!(got.len(), 3);
    }

    #[tokio::test]
    async fn tail_waits_for_new_appends() {
        let eng = Arc::new(new_engine().await);
        // Log must exist (has DEK / meta) before tail can decrypt.
        eng.append("t", "l", b"seed".to_vec(), BTreeMap::new(), None, &ctx())
            .await
            .unwrap();

        let writer = eng.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            for i in 0..2u8 {
                let _ = writer
                    .append("t", "l", vec![i], BTreeMap::new(), None, &ctx())
                    .await;
            }
        });

        // Start tail at offset 1 (after the seed) — expect the 2 upcoming.
        let got = eng.tail("t", "l", 1, 2, Some(2_000), &ctx()).await.unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].offset, 1);
        assert_eq!(got[1].offset, 2);
    }

    #[tokio::test]
    async fn tail_timeout_returns_partial() {
        let eng = new_engine().await;
        eng.append("t", "l", b"seed".to_vec(), BTreeMap::new(), None, &ctx())
            .await
            .unwrap();
        // Ask for more than exist; no writer publishes; short timeout.
        let got = eng.tail("t", "l", 0, 10, Some(50), &ctx()).await.unwrap();
        assert_eq!(got.len(), 1);
    }

    #[tokio::test]
    async fn tail_zero_limit_returns_empty() {
        let eng = new_engine().await;
        let got = eng.tail("t", "l", 0, 0, Some(100), &ctx()).await.unwrap();
        assert!(got.is_empty());
    }

    // ── CLAIM + DLQ ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn claim_skips_fresh_entries() {
        let eng = new_engine().await;
        eng.append("t", "l", b"x".to_vec(), BTreeMap::new(), None, &ctx())
            .await
            .unwrap();
        eng.create_group("t", "l", "g", 0, &ctx()).await.unwrap();
        eng.read_group("t", "l", "g", "r1", 10, &ctx())
            .await
            .unwrap();
        // Entry just delivered — not idle yet.
        let claimed = eng
            .claim("t", "l", "g", "r2", 60_000, &ctx())
            .await
            .unwrap();
        assert!(claimed.is_empty());
    }

    #[tokio::test]
    async fn claim_reassigns_stale_entries() {
        let eng = new_engine().await;
        for i in 0..3u8 {
            eng.append("t", "l", vec![i], BTreeMap::new(), None, &ctx())
                .await
                .unwrap();
        }
        eng.create_group("t", "l", "g", 0, &ctx()).await.unwrap();
        eng.read_group("t", "l", "g", "r1", 10, &ctx())
            .await
            .unwrap();
        // min_idle_ms = 0 → every pending entry is "stale enough" to claim.
        let claimed = eng.claim("t", "l", "g", "r2", 0, &ctx()).await.unwrap();
        assert_eq!(claimed.len(), 3);
        // Pending records now owned by r2 with delivery_count=2.
        let info = eng.group_info("t", "l", "g", &ctx()).await.unwrap();
        assert_eq!(info.pending_count, 3);
    }

    #[tokio::test]
    async fn dlq_entries_carry_configured_ttl() {
        // A 50ms DLQ TTL: force one DLQ move, then wait past the TTL and
        // confirm the DLQ row is gone (Store sweeper evicted it).
        let store = shroudb_storage::test_util::create_test_store("scroll-dlq-ttl").await;
        let caps = Capabilities::new().with_cipher(FakeCipher::new());
        let cfg = EngineConfig {
            max_delivery_count: 1,
            dlq_retention_ttl_ms: Some(50),
            ..EngineConfig::default()
        };
        let eng = ScrollEngine::new(store.clone(), caps, cfg).await.unwrap();

        eng.append("t", "l", b"x".to_vec(), BTreeMap::new(), None, &ctx())
            .await
            .unwrap();
        eng.create_group("t", "l", "g", 0, &ctx()).await.unwrap();
        eng.read_group("t", "l", "g", "r1", 10, &ctx())
            .await
            .unwrap();
        // delivery_count = 1 after READ_GROUP. With max_delivery_count = 1,
        // the next CLAIM tips it over → DLQ move.
        eng.claim("t", "l", "g", "r2", 0, &ctx()).await.unwrap();

        let dk = crate::groups::dlq_key("t", "l", 0);
        // DLQ row is live immediately after the move.
        assert!(store.get(DLQ_NS, &dk, None).await.is_ok());

        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        // After the TTL elapses + a margin, the Store sweeper must have
        // reaped it. If it hasn't, TTL isn't being applied.
        let after = store.get(DLQ_NS, &dk, None).await;
        assert!(
            matches!(after, Err(shroudb_store::StoreError::NotFound)),
            "DLQ row should be TTL-evicted, got {after:?}"
        );
    }

    #[tokio::test]
    async fn claim_moves_to_dlq_on_delivery_breach() {
        // Use a tiny max_delivery_count so repeated CLAIMs tip over quickly.
        let store = shroudb_storage::test_util::create_test_store("scroll-dlq").await;
        let caps = Capabilities::new().with_cipher(FakeCipher::new());
        let cfg = EngineConfig {
            max_delivery_count: 2,
            ..EngineConfig::default()
        };
        let eng = ScrollEngine::new(store, caps, cfg).await.unwrap();

        eng.append("t", "l", b"x".to_vec(), BTreeMap::new(), None, &ctx())
            .await
            .unwrap();
        eng.create_group("t", "l", "g", 0, &ctx()).await.unwrap();
        eng.read_group("t", "l", "g", "r1", 10, &ctx())
            .await
            .unwrap();
        // delivery_count starts at 1 after READ_GROUP.
        let first = eng.claim("t", "l", "g", "r2", 0, &ctx()).await.unwrap();
        assert_eq!(first, vec![0]); // claimed, now delivery_count = 2
        let second = eng.claim("t", "l", "g", "r3", 0, &ctx()).await.unwrap();
        assert!(
            second.is_empty(),
            "third attempt should DLQ, not claim: {second:?}"
        );

        // Pending cleared, DLQ populated.
        let info = eng.group_info("t", "l", "g", &ctx()).await.unwrap();
        assert_eq!(info.pending_count, 0);
    }

    // ── TRIM ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn trim_max_len_deletes_oldest() {
        let eng = new_engine().await;
        for i in 0..10u8 {
            eng.append("t", "l", vec![i], BTreeMap::new(), None, &ctx())
                .await
                .unwrap();
        }
        let deleted = eng.trim("t", "l", TrimBy::MaxLen(3), &ctx()).await.unwrap();
        assert_eq!(deleted, 7);
        // Only the latest 3 should remain.
        let got = eng.read("t", "l", 0, 100, &ctx()).await.unwrap();
        let offsets: Vec<u64> = got.iter().map(|e| e.offset).collect();
        assert_eq!(offsets, vec![7, 8, 9]);
    }

    #[tokio::test]
    async fn trim_max_len_noop_when_below_cap() {
        let eng = new_engine().await;
        for i in 0..3u8 {
            eng.append("t", "l", vec![i], BTreeMap::new(), None, &ctx())
                .await
                .unwrap();
        }
        let deleted = eng
            .trim("t", "l", TrimBy::MaxLen(10), &ctx())
            .await
            .unwrap();
        assert_eq!(deleted, 0);
        let got = eng.read("t", "l", 0, 100, &ctx()).await.unwrap();
        assert_eq!(got.len(), 3);
    }

    #[tokio::test]
    async fn trim_max_age_deletes_older_entries() {
        // With age_ms = 0, every existing entry is older than the cutoff.
        let eng = new_engine().await;
        for i in 0..5u8 {
            eng.append("t", "l", vec![i], BTreeMap::new(), None, &ctx())
                .await
                .unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let deleted = eng
            .trim("t", "l", TrimBy::MaxAgeMs(1), &ctx())
            .await
            .unwrap();
        assert_eq!(deleted, 5);
        let got = eng.read("t", "l", 0, 100, &ctx()).await.unwrap();
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn trim_preserves_offsets_counter() {
        // After TRIM, new APPENDs continue from the next un-minted offset —
        // trim doesn't reset the counter.
        let eng = new_engine().await;
        for i in 0..5u8 {
            eng.append("t", "l", vec![i], BTreeMap::new(), None, &ctx())
                .await
                .unwrap();
        }
        eng.trim("t", "l", TrimBy::MaxLen(2), &ctx()).await.unwrap();
        let next = eng
            .append("t", "l", b"z".to_vec(), BTreeMap::new(), None, &ctx())
            .await
            .unwrap();
        assert_eq!(next, 5);
    }

    // ── Concurrency (SPEC §14) ──────────────────────────────────────────

    #[tokio::test]
    async fn concurrent_appends_mint_unique_monotonic_offsets() {
        // N producers racing APPEND on the same log at default config — the
        // CAS offset counter must hand out every u64 in [0, N) exactly once.
        // N == offset_cas_retry_max so we exercise the ceiling.
        const N: u64 = 64;
        let eng = Arc::new(new_engine().await);

        let mut handles = Vec::with_capacity(N as usize);
        for i in 0..N {
            let eng = eng.clone();
            handles.push(tokio::spawn(async move {
                eng.append("t", "l", vec![i as u8], BTreeMap::new(), None, &ctx())
                    .await
                    .expect("append failed")
            }));
        }
        let mut offsets: Vec<u64> = Vec::with_capacity(N as usize);
        for h in handles {
            offsets.push(h.await.unwrap());
        }
        offsets.sort_unstable();
        let expected: Vec<u64> = (0..N).collect();
        assert_eq!(
            offsets, expected,
            "expected every offset in 0..{N} to be minted exactly once"
        );
    }

    #[tokio::test]
    async fn concurrent_read_groups_deliver_each_offset_once() {
        // M readers race READ_GROUP on the same group. Every offset must be
        // delivered to exactly one reader (no duplicate delivery without
        // CLAIM). Matches the SPEC §7 exclusivity guarantee.
        const ENTRIES: u64 = 40;
        const READERS: usize = 5;
        let eng = Arc::new(new_engine().await);

        for i in 0..ENTRIES {
            eng.append("t", "l", vec![i as u8], BTreeMap::new(), None, &ctx())
                .await
                .unwrap();
        }
        eng.create_group("t", "l", "g", 0, &ctx()).await.unwrap();

        let mut handles = Vec::with_capacity(READERS);
        for r in 0..READERS {
            let eng = eng.clone();
            let reader_id = format!("r{r}");
            handles.push(tokio::spawn(async move {
                let mut collected: Vec<u64> = Vec::new();
                // Keep draining until READ_GROUP returns empty — hand-off
                // between readers happens via CAS conflicts inside
                // read_group; each call returns a disjoint batch.
                loop {
                    let batch = eng
                        .read_group("t", "l", "g", &reader_id, 5, &ctx())
                        .await
                        .expect("read_group failed");
                    if batch.is_empty() {
                        break;
                    }
                    collected.extend(batch.iter().map(|e| e.offset));
                }
                collected
            }));
        }

        let mut all: Vec<u64> = Vec::new();
        for h in handles {
            all.extend(h.await.unwrap());
        }
        all.sort_unstable();
        let expected: Vec<u64> = (0..ENTRIES).collect();
        assert_eq!(
            all, expected,
            "every offset 0..{ENTRIES} must be delivered exactly once across all readers"
        );
    }

    // ── Cross-tenant isolation ──────────────────────────────────────────

    #[tokio::test]
    async fn tenants_have_independent_offsets() {
        let eng = new_engine().await;
        let a = eng
            .append("t1", "l", b"a".to_vec(), BTreeMap::new(), None, &ctx())
            .await
            .unwrap();
        let b = eng
            .append("t2", "l", b"b".to_vec(), BTreeMap::new(), None, &ctx())
            .await
            .unwrap();
        assert_eq!(a, 0);
        assert_eq!(b, 0);
        let t1 = eng.read("t1", "l", 0, 10, &ctx()).await.unwrap();
        let t2 = eng.read("t2", "l", 0, 10, &ctx()).await.unwrap();
        assert_eq!(t1.len(), 1);
        assert_eq!(t2.len(), 1);
        assert_eq!(t1[0].payload, b"a");
        assert_eq!(t2[0].payload, b"b");
    }
}
