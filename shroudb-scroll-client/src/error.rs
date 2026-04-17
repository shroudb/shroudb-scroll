use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("connection error: {0}")]
    Connection(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("server error: {0}")]
    Server(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}

impl From<shroudb_client_common::ConnectionError> for ClientError {
    fn from(err: shroudb_client_common::ConnectionError) -> Self {
        match err {
            shroudb_client_common::ConnectionError::Io(e) => Self::Connection(e.to_string()),
            shroudb_client_common::ConnectionError::Protocol(s) => Self::Protocol(s),
            shroudb_client_common::ConnectionError::Server(s) => Self::Server(s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_covers_all_variants() {
        assert!(
            ClientError::Connection("x".into())
                .to_string()
                .contains("connection")
        );
        assert!(
            ClientError::Protocol("x".into())
                .to_string()
                .contains("protocol")
        );
        assert!(
            ClientError::Server("x".into())
                .to_string()
                .contains("server")
        );
        assert!(
            ClientError::Serialization("x".into())
                .to_string()
                .contains("serialization")
        );
    }
}
