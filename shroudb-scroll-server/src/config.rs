use serde::Deserialize;
use shroudb_acl::ServerAuthConfig;

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

/// Remote Cipher wiring. `addr` is a TCP `host:port`; `keyring` is the
/// Cipher keyring used for per-log DEK generation; `auth_token` authenticates
/// the Cipher client. Omit the whole section to run Scroll without Cipher —
/// APPEND / READ / READ_GROUP / TAIL will fail-closed with
/// `CapabilityMissing("cipher")`.
#[derive(Debug, Clone, Deserialize)]
pub struct CipherConfig {
    pub addr: String,
    #[serde(default = "default_keyring")]
    pub keyring: String,
    #[serde(default)]
    pub auth_token: Option<String>,
}

fn default_keyring() -> String {
    "scroll-logs".into()
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
        assert_eq!(c.addr, "127.0.0.1:7175");
        assert_eq!(c.keyring, "scroll-prod");
        assert_eq!(c.auth_token.as_deref(), Some("secret"));
    }

    #[test]
    fn cipher_section_optional() {
        let cfg: ScrollServerConfig = toml::from_str("").unwrap();
        assert!(cfg.cipher.is_none());
    }
}
