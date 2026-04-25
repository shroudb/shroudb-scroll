use anyhow::Context;
use clap::Parser;
use shroudb_cipher_core::keyring::KeyringAlgorithm;
use shroudb_cipher_engine::engine::{CipherConfig, CipherEngine};
use shroudb_cipher_engine::scheduler;
use shroudb_scroll_engine::{
    Capabilities, EngineConfig as EngConfig, ScrollCipherOps, ScrollEngine,
};
use shroudb_storage::{EmbeddedStore, StorageEngine};
use shroudb_store::Store;
use std::sync::Arc;
use tokio::net::TcpListener;

mod cipher_embedded;
mod cipher_remote;
mod config;
mod tcp;

#[derive(Parser)]
#[command(name = "shroudb-scroll", version)]
struct Cli {
    #[arg(long)]
    config: Option<String>,
    #[arg(long)]
    data_dir: Option<String>,
    #[arg(long)]
    log_level: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let mut cfg = config::load_config(cli.config.as_deref()).context("failed to load config")?;

    if let Some(data_dir) = cli.data_dir {
        cfg.store.data_dir = data_dir;
    }

    if let Some(ref cipher_cfg) = cfg.cipher {
        cipher_cfg
            .validate(&cfg.store.mode)
            .context("invalid cipher config")?;
    }

    let log_level = cli
        .log_level
        .or(cfg.server.log_level.clone())
        .unwrap_or_else(|| "info".into());

    let key_source = shroudb_server_bootstrap::bootstrap(&log_level);

    match cfg.store.mode.as_str() {
        "embedded" => {
            let data_dir = std::path::PathBuf::from(&cfg.store.data_dir);
            let storage = shroudb_server_bootstrap::open_storage(&data_dir, key_source.as_ref())
                .await
                .context("failed to open storage engine")?;
            let scroll_store = Arc::new(EmbeddedStore::new(storage.clone(), "scroll"));
            let cipher_handle = build_cipher_embedded(&cfg, storage.clone()).await?;
            run_server(cfg, scroll_store, Some(storage), cipher_handle).await
        }
        "remote" => {
            let uri = cfg
                .store
                .uri
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("remote mode requires store.uri"))?;
            tracing::info!(uri, "connecting to remote store");
            let store = Arc::new(
                shroudb_client::RemoteStore::connect(uri)
                    .await
                    .context("failed to connect to remote store")?,
            );
            run_server(cfg, store, None, None).await
        }
        other => anyhow::bail!("unknown store mode: {other}"),
    }
}

/// Build an embedded `CipherEngine` if configured. Returns `None` when the
/// config selects remote or omits Cipher entirely — the caller wires the
/// remote client or leaves the capability absent (fail-closed at use site).
async fn build_cipher_embedded(
    cfg: &config::ScrollServerConfig,
    storage: Arc<StorageEngine>,
) -> anyhow::Result<Option<CipherEmbeddedHandle>> {
    let Some(cc) = cfg.cipher.as_ref() else {
        return Ok(None);
    };
    if !cc.is_embedded() {
        return Ok(None);
    }

    let cipher_store = Arc::new(EmbeddedStore::new(storage, "cipher"));
    let cipher_config = CipherConfig {
        default_rotation_days: cc.rotation_days,
        default_drain_days: cc.drain_days,
        scheduler_interval_secs: cc.scheduler_interval_secs,
    };
    let engine = CipherEngine::new(cipher_store, cipher_config, None, None)
        .await
        .map_err(|e| anyhow::anyhow!("embedded cipher init failed: {e}"))?;

    let algorithm: KeyringAlgorithm = cc
        .algorithm
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid cipher algorithm {:?}: {e}", cc.algorithm))?;

    match engine
        .keyring_create(&cc.keyring, algorithm, None, None, false, None)
        .await
    {
        Ok(_) => tracing::info!(keyring = %cc.keyring, "seeded embedded cipher keyring"),
        Err(e) => tracing::debug!(keyring = %cc.keyring, error = %e, "keyring seed skipped"),
    }

    let engine = Arc::new(engine);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let scheduler_handle =
        scheduler::start_scheduler(engine.clone(), cc.scheduler_interval_secs, shutdown_rx);

    tracing::info!(
        keyring = %cc.keyring,
        rotation_days = cc.rotation_days,
        "embedded cipher initialized"
    );

    Ok(Some(CipherEmbeddedHandle {
        engine,
        keyring: cc.keyring.clone(),
        scheduler: scheduler_handle,
        shutdown_tx,
    }))
}

struct CipherEmbeddedHandle {
    engine: Arc<CipherEngine<EmbeddedStore>>,
    keyring: String,
    scheduler: tokio::task::JoinHandle<()>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
}

async fn run_server<S: Store + 'static>(
    cfg: config::ScrollServerConfig,
    store: Arc<S>,
    storage: Option<Arc<shroudb_storage::StorageEngine>>,
    cipher_embedded: Option<CipherEmbeddedHandle>,
) -> anyhow::Result<()> {
    let data_dir = std::path::PathBuf::from(&cfg.store.data_dir);

    // Audit (Chronicle) capability — remote, embedded, or explicitly
    // disabled-with-justification. No silent None allowed.
    let audit_cfg = cfg.audit.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "missing [audit] config section. Pick one: \n  \
             [audit] mode = \"remote\" addr = \"chronicle.internal:7300\"\n  \
             [audit] mode = \"embedded\"\n  \
             [audit] mode = \"disabled\" justification = \"<reason>\""
        )
    })?;
    let audit_cap = audit_cfg
        .resolve(storage.clone())
        .await
        .context("failed to resolve [audit] capability")?;

    // Policy (Sentry) capability — same contract.
    let policy_cfg = cfg.policy.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "missing [policy] config section. Pick one: \n  \
             [policy] mode = \"remote\" addr = \"sentry.internal:7100\"\n  \
             [policy] mode = \"embedded\"\n  \
             [policy] mode = \"disabled\" justification = \"<reason>\""
        )
    })?;
    let policy_cap = policy_cfg
        .resolve(storage.clone(), audit_cap.as_ref().cloned())
        .await
        .context("failed to resolve [policy] capability")?;

    let mut cipher_cap: shroudb_server_bootstrap::Capability<
        Arc<dyn shroudb_scroll_engine::ScrollCipherOps>,
    > = shroudb_server_bootstrap::Capability::disabled(
        "no [cipher] section configured — explicitly opt out for teardown/inspection deployments",
    );

    let cipher_handle = match (cfg.cipher.as_ref(), cipher_embedded) {
        (Some(cc), Some(handle)) if cc.is_embedded() => {
            let ops = cipher_embedded::EmbeddedCipherOps::new(
                handle.engine.clone(),
                handle.keyring.clone(),
            );
            cipher_cap = shroudb_server_bootstrap::Capability::Enabled(
                Arc::new(ops) as Arc<dyn ScrollCipherOps>
            );
            tracing::info!(
                keyring = %handle.keyring,
                "cipher wired (embedded)"
            );
            Some(handle)
        }
        (Some(cc), _) if cc.is_remote() => {
            let addr = cc
                .addr
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("cipher.mode = \"remote\" requires cipher.addr"))?;
            let cipher = cipher_remote::RemoteCipherOps::connect(
                addr,
                cc.keyring.clone(),
                cc.auth_token.as_deref(),
            )
            .await
            .context("failed to connect to Cipher")?;
            cipher_cap = shroudb_server_bootstrap::Capability::Enabled(
                Arc::new(cipher) as Arc<dyn ScrollCipherOps>
            );
            tracing::info!(addr = addr, keyring = %cc.keyring, "cipher wired (remote)");
            None
        }
        _ => {
            tracing::warn!(
                "no [cipher] section configured — APPEND/READ/READ_GROUP/TAIL will \
                 reject with CapabilityMissing. Ensure this is intentional and record \
                 a Capability::DisabledWithJustification(…) at config time."
            );
            None
        }
    };

    let engine_config = EngConfig {
        default_max_entry_bytes: cfg.engine.default_max_entry_bytes,
        default_max_header_bytes: cfg.engine.default_max_header_bytes,
        default_retention_ttl_ms: cfg.engine.default_retention_ttl_ms,
        offset_cas_retry_max: cfg.engine.offset_cas_retry_max,
        group_cursor_cas_retry_max: cfg.engine.group_cursor_cas_retry_max,
        max_delivery_count: cfg.engine.max_delivery_count,
        reader_idle_threshold_ms: cfg.engine.reader_idle_threshold_ms,
        tail_default_timeout_ms: cfg.engine.tail_default_timeout_ms,
        tail_subscribe_buffer: cfg.engine.tail_subscribe_buffer,
        dlq_retention_ttl_ms: cfg.engine.dlq_retention_ttl_ms,
        min_retention_behind_slowest_group: cfg.engine.min_retention_behind_slowest_group,
    };
    let caps = Capabilities::new(cipher_cap, policy_cap, audit_cap);
    let engine = Arc::new(
        ScrollEngine::new(store, caps, engine_config)
            .await
            .context("failed to initialize scroll engine")?,
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let token_validator = cfg.auth.build_validator();

    // Audit-on requires an authenticated actor at the engine layer.
    // Refuse to start with [audit] enabled but [auth].tokens empty.
    audit_cfg
        .require_auth_validator(token_validator.is_some())
        .context("invalid [audit] / [auth] composition")?;

    let listener = TcpListener::bind(&cfg.server.tcp_bind)
        .await
        .context("failed to bind TCP listener")?;

    let tls_acceptor = cfg
        .server
        .tls
        .as_ref()
        .map(shroudb_server_tcp::build_tls_acceptor)
        .transpose()
        .context("failed to build TLS acceptor")?;

    shroudb_server_bootstrap::print_banner(
        "Scroll",
        env!("CARGO_PKG_VERSION"),
        &cfg.server.tcp_bind,
        &data_dir,
    );

    let tcp_engine = engine.clone();
    let tcp_validator = token_validator.clone();
    let tcp_handle = tokio::spawn(async move {
        tcp::run_tcp(
            listener,
            tcp_engine,
            tcp_validator,
            shutdown_rx,
            tls_acceptor,
        )
        .await;
    });

    shroudb_server_bootstrap::wait_for_shutdown(shutdown_tx).await?;
    let _ = tcp_handle.await;

    if let Some(handle) = cipher_handle {
        let _ = handle.shutdown_tx.send(true);
        let _ = handle.scheduler.await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_parses_with_no_args() {
        Cli::command().debug_assert();
    }

    #[test]
    fn cli_parses_config_flag() {
        let parsed = Cli::try_parse_from(["shroudb-scroll", "--config", "x.toml"]).unwrap();
        assert_eq!(parsed.config.as_deref(), Some("x.toml"));
    }
}
