use base64::Engine as _;
use serde_json::json;
use shroudb_acl::AuthContext;
use shroudb_protocol_wire::WIRE_PROTOCOL;
use shroudb_scroll_core::AuditContext;
use shroudb_scroll_engine::ScrollEngine;
use shroudb_scroll_engine::engine::TrimBy;
use shroudb_store::Store;
use std::collections::BTreeMap;
use tracing::warn;

use crate::commands::{ScrollCommand, TrimArg, resolve_start_offset};
use crate::response::ScrollResponse;

const SUPPORTED_COMMANDS: &[&str] = &[
    "APPEND",
    "READ",
    "CREATE_GROUP",
    "READ_GROUP",
    "ACK",
    "DELETE_LOG",
    "LOG_INFO",
    "GROUP_INFO",
    "CLAIM",
    "TRIM",
    "TAIL",
    "REPLAY",
    "DELETE_GROUP",
    "AUTH",
    "HEALTH",
    "PING",
    "HELLO",
    "COMMAND LIST",
];

/// Tenant resolution. When an `AuthContext` is attached, its tenant wins.
/// Standalone/no-auth deployments fall back to `"default"` — the protocol
/// layer does not attempt to infer tenants from any other signal.
fn tenant(auth_context: Option<&AuthContext>) -> &str {
    auth_context.map(|c| c.tenant.as_str()).unwrap_or("default")
}

fn audit_context(auth_context: Option<&AuthContext>) -> AuditContext {
    match auth_context {
        Some(ctx) => AuditContext::default().with_actor(ctx.actor.clone()),
        None => AuditContext::default(),
    }
}

pub async fn dispatch<S: Store>(
    engine: &ScrollEngine<S>,
    cmd: ScrollCommand,
    auth_context: Option<&AuthContext>,
) -> ScrollResponse {
    // Wire-level ACL first. Engine-level Sentry gating runs inside each
    // command (so Sentry sees every call, even meta-like read commands).
    if let Err(e) = shroudb_acl::check_dispatch_acl(auth_context, &cmd.acl_requirement()) {
        return ScrollResponse::error(e.to_string());
    }

    let ctx = audit_context(auth_context);
    let tenant = tenant(auth_context).to_string();

    match cmd {
        ScrollCommand::Auth { .. } => {
            // AUTH is consumed at the connection layer before dispatch.
            ScrollResponse::error("AUTH handled at connection layer")
        }
        ScrollCommand::Health => ScrollResponse::health(),
        ScrollCommand::Ping => ScrollResponse::pong(),
        ScrollCommand::CommandList => ScrollResponse::command_list(),
        ScrollCommand::Hello => ScrollResponse::ok(json!({
            "engine": "scroll",
            "version": env!("CARGO_PKG_VERSION"),
            "protocol": WIRE_PROTOCOL,
            "commands": SUPPORTED_COMMANDS,
            "capabilities": Vec::<&str>::new(),
        })),

        ScrollCommand::Append {
            log,
            payload_b64,
            headers_json,
            ttl_ms,
        } => {
            handle_append(
                engine,
                &tenant,
                log,
                payload_b64,
                headers_json,
                ttl_ms,
                &ctx,
            )
            .await
        }

        ScrollCommand::Read {
            log,
            from_offset,
            limit,
        } => match engine.read(&tenant, &log, from_offset, limit, &ctx).await {
            Ok(entries) => ScrollResponse::entries(entries),
            Err(e) => {
                warn!(log, error = %e, "READ failed");
                ScrollResponse::error(e.to_string())
            }
        },

        ScrollCommand::CreateGroup {
            log,
            group,
            start_offset,
        } => handle_create_group(engine, &tenant, log, group, start_offset, &ctx).await,

        ScrollCommand::ReadGroup {
            log,
            group,
            reader_id,
            limit,
        } => match engine
            .read_group(&tenant, &log, &group, &reader_id, limit, &ctx)
            .await
        {
            Ok(entries) => ScrollResponse::entries(entries),
            Err(e) => {
                warn!(log, group, error = %e, "READ_GROUP failed");
                ScrollResponse::error(e.to_string())
            }
        },

        ScrollCommand::Ack { log, group, offset } => {
            match engine.ack(&tenant, &log, &group, offset, &ctx).await {
                Ok(()) => ScrollResponse::ok_status(),
                Err(e) => {
                    warn!(log, group, offset, error = %e, "ACK failed");
                    ScrollResponse::error(e.to_string())
                }
            }
        }

        ScrollCommand::DeleteLog { log } => match engine.delete_log(&tenant, &log, &ctx).await {
            Ok(()) => ScrollResponse::ok_status(),
            Err(e) => {
                warn!(log, error = %e, "DELETE_LOG failed");
                ScrollResponse::error(e.to_string())
            }
        },

        ScrollCommand::LogInfo { log } => match engine.log_info(&tenant, &log, &ctx).await {
            Ok(info) => ScrollResponse::log_info(info),
            Err(e) => ScrollResponse::error(e.to_string()),
        },

        ScrollCommand::GroupInfo { log, group } => {
            match engine.group_info(&tenant, &log, &group, &ctx).await {
                Ok(info) => ScrollResponse::group_info(info),
                Err(e) => ScrollResponse::error(e.to_string()),
            }
        }

        ScrollCommand::Claim {
            log,
            group,
            reader_id,
            min_idle_ms,
        } => match engine
            .claim(&tenant, &log, &group, &reader_id, min_idle_ms, &ctx)
            .await
        {
            Ok(offsets) => ScrollResponse::claimed(offsets),
            Err(e) => {
                warn!(log, group, error = %e, "CLAIM failed");
                ScrollResponse::error(e.to_string())
            }
        },

        ScrollCommand::Trim { log, by } => {
            let engine_by = match by {
                TrimArg::MaxLen(n) => TrimBy::MaxLen(n),
                TrimArg::MaxAgeMs(ms) => TrimBy::MaxAgeMs(ms),
            };
            match engine.trim(&tenant, &log, engine_by, &ctx).await {
                Ok(n) => ScrollResponse::trimmed(n),
                Err(e) => {
                    warn!(log, error = %e, "TRIM failed");
                    ScrollResponse::error(e.to_string())
                }
            }
        }

        ScrollCommand::Tail {
            log,
            from_offset,
            limit,
            timeout_ms,
        } => match engine
            .tail(&tenant, &log, from_offset, limit, timeout_ms, &ctx)
            .await
        {
            Ok(entries) => ScrollResponse::entries(entries),
            Err(e) => {
                warn!(log, error = %e, "TAIL failed");
                ScrollResponse::error(e.to_string())
            }
        },

        ScrollCommand::Replay { log, group, offset } => {
            match engine.replay(&tenant, &log, &group, offset, &ctx).await {
                Ok(()) => ScrollResponse::ok_status(),
                Err(e) => {
                    warn!(log, group, offset, error = %e, "REPLAY failed");
                    ScrollResponse::error(e.to_string())
                }
            }
        }

        ScrollCommand::DeleteGroup { log, group } => {
            match engine.delete_group(&tenant, &log, &group, &ctx).await {
                Ok(()) => ScrollResponse::ok_status(),
                Err(e) => {
                    warn!(log, group, error = %e, "DELETE_GROUP failed");
                    ScrollResponse::error(e.to_string())
                }
            }
        }
    }
}

async fn handle_append<S: Store>(
    engine: &ScrollEngine<S>,
    tenant: &str,
    log: String,
    payload_b64: String,
    headers_json: Option<String>,
    ttl_ms: Option<i64>,
    ctx: &AuditContext,
) -> ScrollResponse {
    let payload = match base64::engine::general_purpose::STANDARD.decode(&payload_b64) {
        Ok(v) => v,
        Err(e) => return ScrollResponse::error(format!("payload not valid base64: {e}")),
    };
    let headers: BTreeMap<String, String> = match headers_json {
        None => BTreeMap::new(),
        Some(ref s) => match serde_json::from_str(s) {
            Ok(map) => map,
            Err(e) => {
                return ScrollResponse::error(format!(
                    "HEADERS must be a JSON object of string→string ({e})"
                ));
            }
        },
    };
    match engine
        .append(tenant, &log, payload, headers, ttl_ms, ctx)
        .await
    {
        Ok(offset) => ScrollResponse::append_result(offset),
        Err(e) => {
            warn!(log, error = %e, "APPEND failed");
            ScrollResponse::error(e.to_string())
        }
    }
}

async fn handle_create_group<S: Store>(
    engine: &ScrollEngine<S>,
    tenant: &str,
    log: String,
    group: String,
    start_offset_raw: String,
    ctx: &AuditContext,
) -> ScrollResponse {
    // Resolve "latest" sentinel against the current next_offset.
    let needs_resolution = matches!(
        start_offset_raw.to_ascii_lowercase().as_str(),
        "latest" | "-1"
    );
    let next = if needs_resolution {
        match engine.current_next_offset(tenant, &log).await {
            Ok(n) => n,
            Err(e) => return ScrollResponse::error(e.to_string()),
        }
    } else {
        0
    };
    let start_offset = match resolve_start_offset(&start_offset_raw, next) {
        Ok(o) => o,
        Err(e) => return ScrollResponse::error(e),
    };
    match engine
        .create_group(tenant, &log, &group, start_offset, ctx)
        .await
    {
        Ok(()) => ScrollResponse::ok_status(),
        Err(e) => {
            warn!(log, group, error = %e, "CREATE_GROUP failed");
            ScrollResponse::error(e.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::parse_command;
    use dashmap::DashMap;
    use serde_json::Value;
    use shroudb_crypto::{SensitiveBytes, sha256};
    use shroudb_scroll_core::ScrollError;
    use shroudb_scroll_engine::capabilities::{BoxFut, DataKeyPair, ScrollCipherOps};
    use shroudb_scroll_engine::{Capabilities, EngineConfig};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Test-only Cipher stand-in mirroring the engine-crate fake.
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
                let dek = sha256(format!("protocol-test-{id}").as_bytes()).to_vec();
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

    async fn new_engine() -> ScrollEngine<shroudb_storage::EmbeddedStore> {
        let store = shroudb_storage::test_util::create_test_store("scroll-proto").await;
        let caps = Capabilities::for_tests().with_cipher(FakeCipher::new());
        ScrollEngine::new(store, caps, EngineConfig::default())
            .await
            .unwrap()
    }

    fn ok_body(resp: ScrollResponse) -> Value {
        match resp {
            ScrollResponse::Ok(v) => v,
            ScrollResponse::Error(e) => panic!("expected Ok, got Error({e})"),
        }
    }

    fn err_msg(resp: ScrollResponse) -> String {
        match resp {
            ScrollResponse::Error(e) => e,
            ScrollResponse::Ok(v) => panic!("expected Error, got Ok({v})"),
        }
    }

    #[tokio::test]
    async fn append_read_round_trip() {
        let eng = new_engine().await;
        // Base64-encode "hello".
        let append = parse_command(&["APPEND", "orders", "aGVsbG8="]).unwrap();
        let body = ok_body(dispatch(&eng, append, None).await);
        assert_eq!(body["status"], "ok");
        assert_eq!(body["offset"], 0);

        let read = parse_command(&["READ", "orders", "0", "10"]).unwrap();
        let body = ok_body(dispatch(&eng, read, None).await);
        let entries = body["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["offset"], 0);
        // Payload is base64-re-encoded on the wire.
        assert_eq!(entries[0]["payload_b64"], "aGVsbG8=");
    }

    #[tokio::test]
    async fn append_rejects_invalid_base64() {
        let eng = new_engine().await;
        let cmd = parse_command(&["APPEND", "l", "!!not-base64!!"]).unwrap();
        let msg = err_msg(dispatch(&eng, cmd, None).await);
        assert!(msg.contains("base64"), "message was: {msg}");
    }

    #[tokio::test]
    async fn append_rejects_invalid_headers_json() {
        let eng = new_engine().await;
        let cmd = parse_command(&[
            "APPEND", "l", "aGVsbG8=", "HEADERS", "not-json", "TTL", "1000",
        ])
        .unwrap();
        let msg = err_msg(dispatch(&eng, cmd, None).await);
        assert!(
            msg.contains("HEADERS") || msg.contains("JSON"),
            "message was: {msg}"
        );
    }

    #[tokio::test]
    async fn create_group_earliest_and_latest_resolve() {
        let eng = new_engine().await;
        // Seed 3 entries so latest = 3.
        for _ in 0..3 {
            let c = parse_command(&["APPEND", "l", "YQ=="]).unwrap();
            dispatch(&eng, c, None).await;
        }

        let c = parse_command(&["CREATE_GROUP", "l", "g1", "earliest"]).unwrap();
        ok_body(dispatch(&eng, c, None).await);

        let c = parse_command(&["CREATE_GROUP", "l", "g2", "latest"]).unwrap();
        ok_body(dispatch(&eng, c, None).await);

        // g1 (from earliest) should pull all 3 entries; g2 (from latest) pulls 0.
        let rg1 = parse_command(&["READ_GROUP", "l", "g1", "r", "10"]).unwrap();
        let body = ok_body(dispatch(&eng, rg1, None).await);
        assert_eq!(body["entries"].as_array().unwrap().len(), 3);

        let rg2 = parse_command(&["READ_GROUP", "l", "g2", "r", "10"]).unwrap();
        let body = ok_body(dispatch(&eng, rg2, None).await);
        assert_eq!(body["entries"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn ack_and_group_info_round_trip() {
        let eng = new_engine().await;
        dispatch(&eng, parse_command(&["APPEND", "l", "YQ=="]).unwrap(), None).await;
        dispatch(
            &eng,
            parse_command(&["CREATE_GROUP", "l", "g", "0"]).unwrap(),
            None,
        )
        .await;
        dispatch(
            &eng,
            parse_command(&["READ_GROUP", "l", "g", "r", "10"]).unwrap(),
            None,
        )
        .await;

        let info = ok_body(
            dispatch(
                &eng,
                parse_command(&["GROUP_INFO", "l", "g"]).unwrap(),
                None,
            )
            .await,
        );
        assert_eq!(info["pending_count"], 1);

        ok_body(dispatch(&eng, parse_command(&["ACK", "l", "g", "0"]).unwrap(), None).await);
        let info = ok_body(
            dispatch(
                &eng,
                parse_command(&["GROUP_INFO", "l", "g"]).unwrap(),
                None,
            )
            .await,
        );
        assert_eq!(info["pending_count"], 0);
    }

    #[tokio::test]
    async fn log_info_reports_entry_count_and_groups() {
        let eng = new_engine().await;
        for _ in 0..3 {
            dispatch(&eng, parse_command(&["APPEND", "l", "YQ=="]).unwrap(), None).await;
        }
        dispatch(
            &eng,
            parse_command(&["CREATE_GROUP", "l", "g1", "0"]).unwrap(),
            None,
        )
        .await;
        let info = ok_body(dispatch(&eng, parse_command(&["LOG_INFO", "l"]).unwrap(), None).await);
        assert_eq!(info["entries_minted"], 3);
        assert_eq!(info["latest_offset"], 2);
        assert_eq!(info["groups"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn delete_log_via_dispatch() {
        let eng = new_engine().await;
        dispatch(&eng, parse_command(&["APPEND", "l", "YQ=="]).unwrap(), None).await;
        ok_body(dispatch(&eng, parse_command(&["DELETE_LOG", "l"]).unwrap(), None).await);
        // Subsequent LOG_INFO should fail (log gone).
        let resp = dispatch(&eng, parse_command(&["LOG_INFO", "l"]).unwrap(), None).await;
        assert!(matches!(resp, ScrollResponse::Error(_)));
    }

    #[tokio::test]
    async fn claim_via_dispatch_reassigns() {
        let eng = new_engine().await;
        dispatch(&eng, parse_command(&["APPEND", "l", "YQ=="]).unwrap(), None).await;
        dispatch(
            &eng,
            parse_command(&["CREATE_GROUP", "l", "g", "0"]).unwrap(),
            None,
        )
        .await;
        dispatch(
            &eng,
            parse_command(&["READ_GROUP", "l", "g", "r1", "10"]).unwrap(),
            None,
        )
        .await;
        // min_idle_ms = 0 → the just-delivered entry is immediately claimable.
        let resp = dispatch(
            &eng,
            parse_command(&["CLAIM", "l", "g", "r2", "0"]).unwrap(),
            None,
        )
        .await;
        let body = ok_body(resp);
        assert_eq!(body["claimed"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn trim_max_len_via_dispatch() {
        let eng = new_engine().await;
        for _ in 0..5 {
            dispatch(&eng, parse_command(&["APPEND", "l", "YQ=="]).unwrap(), None).await;
        }
        let resp = dispatch(
            &eng,
            parse_command(&["TRIM", "l", "MAX_LEN", "2"]).unwrap(),
            None,
        )
        .await;
        let body = ok_body(resp);
        assert_eq!(body["deleted"], 3);
    }

    #[tokio::test]
    async fn trim_rejects_unknown_selector() {
        // Parse error caught at the commands layer.
        assert!(parse_command(&["TRIM", "l", "MAX_JUNK", "10"]).is_err());
    }

    #[tokio::test]
    async fn tail_via_dispatch_returns_existing_entries() {
        let eng = new_engine().await;
        for _ in 0..2 {
            dispatch(&eng, parse_command(&["APPEND", "l", "YQ=="]).unwrap(), None).await;
        }
        let resp = dispatch(
            &eng,
            parse_command(&["TAIL", "l", "0", "10", "TIMEOUT", "200"]).unwrap(),
            None,
        )
        .await;
        let body = ok_body(resp);
        assert_eq!(body["entries"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn delete_group_via_dispatch() {
        let eng = new_engine().await;
        dispatch(&eng, parse_command(&["APPEND", "l", "YQ=="]).unwrap(), None).await;
        dispatch(
            &eng,
            parse_command(&["CREATE_GROUP", "l", "g", "0"]).unwrap(),
            None,
        )
        .await;

        let resp = dispatch(
            &eng,
            parse_command(&["DELETE_GROUP", "l", "g"]).unwrap(),
            None,
        )
        .await;
        assert_eq!(ok_body(resp)["status"], "ok");

        // Subsequent GROUP_INFO must report the group gone.
        let resp = dispatch(
            &eng,
            parse_command(&["GROUP_INFO", "l", "g"]).unwrap(),
            None,
        )
        .await;
        assert!(matches!(resp, ScrollResponse::Error(_)));
    }

    #[tokio::test]
    async fn delete_group_missing_group_returns_error() {
        let eng = new_engine().await;
        dispatch(&eng, parse_command(&["APPEND", "l", "YQ=="]).unwrap(), None).await;
        let resp = dispatch(
            &eng,
            parse_command(&["DELETE_GROUP", "l", "ghost"]).unwrap(),
            None,
        )
        .await;
        let err = err_msg(resp);
        assert!(err.contains("group not found"), "got: {err}");
    }

    #[tokio::test]
    async fn replay_missing_dlq_entry_via_dispatch_returns_error() {
        let eng = new_engine().await;
        dispatch(&eng, parse_command(&["APPEND", "l", "YQ=="]).unwrap(), None).await;
        dispatch(
            &eng,
            parse_command(&["CREATE_GROUP", "l", "g", "0"]).unwrap(),
            None,
        )
        .await;
        let resp = dispatch(
            &eng,
            parse_command(&["REPLAY", "l", "g", "42"]).unwrap(),
            None,
        )
        .await;
        let err = err_msg(resp);
        assert!(
            err.contains("dlq entry not found"),
            "expected DlqEntryNotFound, got: {err}"
        );
    }

    #[tokio::test]
    async fn meta_commands() {
        let eng = new_engine().await;
        let ping = ok_body(dispatch(&eng, ScrollCommand::Ping, None).await);
        assert_eq!(ping, serde_json::json!("PONG"));

        let health = ok_body(dispatch(&eng, ScrollCommand::Health, None).await);
        assert_eq!(health["status"], "ok");

        let hello = ok_body(dispatch(&eng, ScrollCommand::Hello, None).await);
        assert_eq!(hello["engine"], "scroll");
        assert!(
            hello["commands"]
                .as_array()
                .unwrap()
                .contains(&serde_json::Value::String("APPEND".to_string()))
        );

        let list = ok_body(dispatch(&eng, ScrollCommand::CommandList, None).await);
        assert!(list["commands"].as_array().unwrap().len() >= 8);
    }
}
