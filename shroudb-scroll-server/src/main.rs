use anyhow::Context;
use clap::Parser;
use shroudb_scroll_engine::{Capabilities, EngineConfig as EngConfig, ScrollEngine};
use shroudb_store::Store;
use std::sync::Arc;
use tokio::net::TcpListener;

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
            let store = Arc::new(shroudb_storage::EmbeddedStore::new(storage, "scroll"));
            run_server(cfg, store).await
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
            run_server(cfg, store).await
        }
        other => anyhow::bail!("unknown store mode: {other}"),
    }
}

async fn run_server<S: Store + 'static>(
    cfg: config::ScrollServerConfig,
    store: Arc<S>,
) -> anyhow::Result<()> {
    let data_dir = std::path::PathBuf::from(&cfg.store.data_dir);

    // Cipher is optional. If configured, build a remote client impl and wire
    // it into `Capabilities`. If not, Scroll still starts — APPEND/READ/
    // READ_GROUP/TAIL will fail-closed with CapabilityMissing("cipher").
    let mut caps = Capabilities::new();
    if let Some(cipher_cfg) = cfg.cipher.clone() {
        let cipher = cipher_remote::RemoteCipherOps::connect(
            &cipher_cfg.addr,
            cipher_cfg.keyring.clone(),
            cipher_cfg.auth_token.as_deref(),
        )
        .await
        .context("failed to connect to Cipher")?;
        caps = caps.with_cipher(Arc::new(cipher));
        tracing::info!(
            addr = cipher_cfg.addr,
            keyring = cipher_cfg.keyring,
            "cipher wired"
        );
    } else {
        tracing::warn!(
            "no [cipher] section configured — APPEND/READ/READ_GROUP/TAIL will \
             reject with CapabilityMissing. Add [cipher] to enable."
        );
    }

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
    let engine = Arc::new(
        ScrollEngine::new(store, caps, engine_config)
            .await
            .context("failed to initialize scroll engine")?,
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let token_validator = cfg.auth.build_validator();

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
