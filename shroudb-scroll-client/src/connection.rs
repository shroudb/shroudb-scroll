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
    // Connection requires a live server; exercised end-to-end via the server
    // crate's integration tests.
    #[test]
    fn placeholder() {}
}
