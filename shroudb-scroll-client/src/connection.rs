use crate::error::ClientError;

/// TCP connection to a Scroll server speaking RESP3.
pub struct Connection(shroudb_client_common::Connection);

impl Connection {
    /// Connect directly to a standalone Scroll server.
    pub async fn connect(addr: &str) -> Result<Self, ClientError> {
        Ok(Self(
            shroudb_client_common::Connection::connect(addr).await?,
        ))
    }

    /// Connect to a Scroll engine through a Moat gateway. Commands are
    /// automatically prefixed with `SCROLL` for Moat routing; meta-commands
    /// (AUTH, HEALTH, PING) are sent without prefix.
    pub async fn connect_moat(addr: &str) -> Result<Self, ClientError> {
        Ok(Self(
            shroudb_client_common::Connection::connect_with_prefix(addr, "SCROLL").await?,
        ))
    }

    pub async fn command(&mut self, args: &[&str]) -> Result<serde_json::Value, ClientError> {
        Ok(self.0.send_command(args).await?)
    }

    pub async fn meta_command(&mut self, args: &[&str]) -> Result<serde_json::Value, ClientError> {
        Ok(self.0.send_meta_command(args).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_to_closed_port_returns_error() {
        // Port 1 is privileged and bound by nothing on a normal dev box; the
        // kernel should send RST immediately. This exercises the full
        // shroudb_client_common error → ClientError mapping.
        let err = Connection::connect("127.0.0.1:1")
            .await
            .err()
            .expect("expected error");
        assert!(
            matches!(err, ClientError::Connection(_) | ClientError::Protocol(_)),
            "expected transport-level error, got {err:?}"
        );
    }

    #[tokio::test]
    async fn connect_to_garbage_address_returns_error() {
        let err = Connection::connect("not a socket address")
            .await
            .err()
            .expect("expected error");
        assert!(matches!(err, ClientError::Connection(_)));
    }
}
