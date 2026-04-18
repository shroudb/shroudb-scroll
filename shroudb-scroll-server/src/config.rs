use serde::Deserialize;
use shroudb_acl::ServerAuthConfig;
use shroudb_engine_bootstrap::{AuditConfig, PolicyConfig};

#[derive(Debug, Default, Deserialize)]
pub struct ScrollServerConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub store: StoreConfig,
    #[serde(default)]
    pub engine: EngineConfig,
    #[serde(default)]
    pub cipher: Option<CipherConfig>,
    /// Audit (Chronicle) capability slot. Absent = fail-closed at
    /// startup; operators must explicitly pick a mode.
    #[serde(default)]
    pub audit: Option<AuditConfig>,
    /// Policy (Sentry) capability slot. Same contract as `audit`.
    #[serde(default)]
    pub policy: Option<PolicyConfig>,
    #[serde(default)]
    pub auth: ServerAuthConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_tcp_bind")]
    pub tcp_bind: String,
    #[serde(default)]
    pub log_level: Option<String>,
    #[serde(default)]
    pub tls: Option<shroudb_server_tcp::TlsConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            tcp_bind: default_tcp_bind(),
            log_level: None,
            tls: None,
        }
    }
}

fn default_tcp_bind() -> String {
    "0.0.0.0:7200".into()
}

#[derive(Debug, Deserialize)]
pub struct StoreConfig {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    #[serde(default)]
    pub uri: Option<String>,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            data_dir: default_data_dir(),
            uri: None,
        }
    }
}

fn default_mode() -> String {
    "embedded".into()
}
fn default_data_dir() -> String {
    "./scroll-data".into()
}

#[derive(Debug, Deserialize)]
pub struct EngineConfig {
    #[serde(default = "default_max_entry_bytes")]
    pub default_max_entry_bytes: u64,
    #[serde(default = "default_max_header_bytes")]
    pub default_max_header_bytes: u64,
    #[serde(default)]
    pub default_retention_ttl_ms: Option<i64>,
    #[serde(default = "default_cas_retry")]
    pub offset_cas_retry_max: u32,
    #[serde(default = "default_cas_retry")]
    pub group_cursor_cas_retry_max: u32,
    #[serde(default = "default_max_delivery_count")]
    pub max_delivery_count: u32,
    #[serde(default = "default_reader_idle_threshold_ms")]
    pub reader_idle_threshold_ms: i64,
    #[serde(default = "default_tail_timeout_ms")]
    pub tail_default_timeout_ms: u64,
    #[serde(default = "default_tail_buffer")]
    pub tail_subscribe_buffer: usize,
    #[serde(default = "default_dlq_ttl_ms")]
    pub dlq_retention_ttl_ms: Option<i64>,
    /// Retention guardrail. `0` = Kafka semantics (default);
    /// `N > 0` = refuse TRIM within N offsets of slowest group's cursor.
    #[serde(default)]
    pub min_retention_behind_slowest_group: u64,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            default_max_entry_bytes: 1_048_576,
            default_max_header_bytes: 16_384,
            default_retention_ttl_ms: None,
            offset_cas_retry_max: 8,
            group_cursor_cas_retry_max: 8,
            max_delivery_count: 16,
            reader_idle_threshold_ms: default_reader_idle_threshold_ms(),
            tail_default_timeout_ms: default_tail_timeout_ms(),
            tail_subscribe_buffer: default_tail_buffer(),
            dlq_retention_ttl_ms: default_dlq_ttl_ms(),
            min_retention_behind_slowest_group: 0,
        }
    }
}

fn default_max_entry_bytes() -> u64 {
    1_048_576
}
fn default_max_header_bytes() -> u64 {
    16_384
}
fn default_cas_retry() -> u32 {
    8
}
fn default_max_delivery_count() -> u32 {
    16
}
fn default_reader_idle_threshold_ms() -> i64 {
    60_000
}
fn default_tail_timeout_ms() -> u64 {
    30_000
}
fn default_tail_buffer() -> usize {
    1024
}
fn default_dlq_ttl_ms() -> Option<i64> {
    Some(2_592_000_000)
}

/// Cipher wiring. Two modes:
///
/// - `mode = "remote"` (default): Scroll connects to an external
///   `shroudb-cipher` server over TCP. Requires `addr`.
/// - `mode = "embedded"`: Scroll builds an in-process `CipherEngine`
///   backed by the same `StorageEngine` as Scroll's own data
///   (different namespace prefix). Requires `store.mode = "embedded"`.
///
/// Omit the section entirely to run Scroll without Cipher — APPEND /
/// READ / READ_GROUP / TAIL will fail-closed with
/// `CapabilityMissing("cipher")`.
#[derive(Debug, Clone, Deserialize)]
pub struct CipherConfig {
    #[serde(default = "default_cipher_mode")]
    pub mode: String,
    #[serde(default = "default_keyring")]
    pub keyring: String,

    #[serde(default)]
    pub addr: Option<String>,
    #[serde(default)]
    pub auth_token: Option<String>,

    #[serde(default = "default_rotation_days")]
    pub rotation_days: u32,
    #[serde(default = "default_drain_days")]
    pub drain_days: u32,
    #[serde(default = "default_scheduler_interval_secs")]
    pub scheduler_interval_secs: u64,
    #[serde(default = "default_cipher_algorithm")]
    pub algorithm: String,
}

impl CipherConfig {
    pub fn is_embedded(&self) -> bool {
        self.mode == "embedded"
    }

    pub fn is_remote(&self) -> bool {
        self.mode == "remote"
    }

    pub fn validate(&self, store_mode: &str) -> anyhow::Result<()> {
        match self.mode.as_str() {
            "remote" => {
                if self.addr.is_none() {
                    anyhow::bail!("cipher.mode = \"remote\" requires cipher.addr");
                }
            }
            "embedded" => {
                if store_mode != "embedded" {
                    anyhow::bail!(
                        "cipher.mode = \"embedded\" requires store.mode = \"embedded\" \
                         (embedded Cipher shares the StorageEngine with Scroll)"
                    );
                }
            }
            other => anyhow::bail!(
                "unknown cipher.mode: {other:?} (expected \"remote\" or \"embedded\")"
            ),
        }
        Ok(())
    }
}

fn default_cipher_mode() -> String {
    "remote".into()
}

fn default_keyring() -> String {
    "scroll-logs".into()
}

fn default_rotation_days() -> u32 {
    90
}

fn default_drain_days() -> u32 {
    30
}

fn default_scheduler_interval_secs() -> u64 {
    3600
}

fn default_cipher_algorithm() -> String {
    "aes-256-gcm".into()
}

pub fn load_config(path: Option<&str>) -> anyhow::Result<ScrollServerConfig> {
    match path {
        Some(p) => {
            let content = std::fs::read_to_string(p)?;
            let config: ScrollServerConfig = toml::from_str(&content)?;
            Ok(config)
        }
        None => Ok(ScrollServerConfig::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_embedded_mode() {
        let cfg = ScrollServerConfig::default();
        assert_eq!(cfg.store.mode, "embedded");
        assert!(cfg.store.uri.is_none());
        assert_eq!(cfg.server.tcp_bind, "0.0.0.0:7200");
    }

    #[test]
    fn parses_cipher_section() {
        let toml = r#"
[cipher]
addr = "127.0.0.1:7175"
keyring = "scroll-prod"
auth_token = "secret"
"#;
        let cfg: ScrollServerConfig = toml::from_str(toml).unwrap();
        let c = cfg.cipher.unwrap();
        assert!(c.is_remote());
        assert_eq!(c.addr.as_deref(), Some("127.0.0.1:7175"));
        assert_eq!(c.keyring, "scroll-prod");
        assert_eq!(c.auth_token.as_deref(), Some("secret"));
    }

    #[test]
    fn cipher_section_optional() {
        let cfg: ScrollServerConfig = toml::from_str("").unwrap();
        assert!(cfg.cipher.is_none());
    }

    #[test]
    fn parses_embedded_cipher_section() {
        let toml = r#"
[cipher]
mode = "embedded"
keyring = "scroll-logs"
rotation_days = 60
drain_days = 14
"#;
        let cfg: ScrollServerConfig = toml::from_str(toml).unwrap();
        let c = cfg.cipher.unwrap();
        assert!(c.is_embedded());
        assert_eq!(c.keyring, "scroll-logs");
        assert_eq!(c.rotation_days, 60);
        assert_eq!(c.drain_days, 14);
        assert_eq!(c.algorithm, "aes-256-gcm");
    }

    #[test]
    fn defaults_remote_mode_when_mode_absent() {
        let toml = r#"
[cipher]
addr = "127.0.0.1:7175"
"#;
        let cfg: ScrollServerConfig = toml::from_str(toml).unwrap();
        let c = cfg.cipher.unwrap();
        assert!(c.is_remote());
    }

    #[test]
    fn remote_requires_addr() {
        let c = CipherConfig {
            mode: "remote".into(),
            keyring: "k".into(),
            addr: None,
            auth_token: None,
            rotation_days: 90,
            drain_days: 30,
            scheduler_interval_secs: 3600,
            algorithm: "aes-256-gcm".into(),
        };
        let err = c.validate("embedded").unwrap_err();
        assert!(err.to_string().contains("addr"));
    }

    #[test]
    fn embedded_requires_embedded_store() {
        let c = CipherConfig {
            mode: "embedded".into(),
            keyring: "k".into(),
            addr: None,
            auth_token: None,
            rotation_days: 90,
            drain_days: 30,
            scheduler_interval_secs: 3600,
            algorithm: "aes-256-gcm".into(),
        };
        let err = c.validate("remote").unwrap_err();
        assert!(err.to_string().contains("embedded"));
    }

    #[test]
    fn embedded_valid_with_embedded_store() {
        let c = CipherConfig {
            mode: "embedded".into(),
            keyring: "k".into(),
            addr: None,
            auth_token: None,
            rotation_days: 90,
            drain_days: 30,
            scheduler_interval_secs: 3600,
            algorithm: "aes-256-gcm".into(),
        };
        c.validate("embedded")
            .expect("embedded + embedded store should validate");
    }

    #[test]
    fn unknown_mode_rejected() {
        let c = CipherConfig {
            mode: "bogus".into(),
            keyring: "k".into(),
            addr: None,
            auth_token: None,
            rotation_days: 90,
            drain_days: 30,
            scheduler_interval_secs: 3600,
            algorithm: "aes-256-gcm".into(),
        };
        let err = c.validate("embedded").unwrap_err();
        assert!(err.to_string().contains("bogus"));
    }
}
