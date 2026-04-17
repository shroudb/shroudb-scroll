use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;

use shroudb_acl::{AclRequirement, AuthContext, TokenValidator};
use shroudb_protocol_wire::Resp3Frame;
use shroudb_scroll_engine::ScrollEngine;
use shroudb_scroll_protocol::commands::{ScrollCommand, parse_command};
use shroudb_scroll_protocol::dispatch::dispatch;
use shroudb_scroll_protocol::response::ScrollResponse;
use shroudb_server_tcp::ServerProtocol;
use shroudb_store::Store;

pub struct ScrollProtocol<S>(PhantomData<S>);

impl<S: Store + 'static> ServerProtocol for ScrollProtocol<S> {
    type Command = ScrollCommand;
    type Response = ScrollResponse;
    type Engine = ScrollEngine<S>;

    fn engine_name(&self) -> &str {
        "scroll"
    }

    fn parse_command(&self, args: &[&str]) -> Result<Self::Command, String> {
        parse_command(args)
    }

    fn auth_token(cmd: &Self::Command) -> Option<&str> {
        if let ScrollCommand::Auth { token } = cmd {
            Some(token)
        } else {
            None
        }
    }

    fn acl_requirement(cmd: &Self::Command) -> AclRequirement {
        cmd.acl_requirement()
    }

    fn dispatch<'a>(
        &'a self,
        engine: &'a Self::Engine,
        cmd: Self::Command,
        auth: Option<&'a AuthContext>,
    ) -> Pin<Box<dyn Future<Output = Self::Response> + Send + 'a>> {
        Box::pin(dispatch(engine, cmd, auth))
    }

    fn response_to_frame(&self, response: &Self::Response) -> Resp3Frame {
        match response {
            ScrollResponse::Ok(data) => {
                let json = serde_json::to_string(data).unwrap_or_else(|_| "{}".into());
                Resp3Frame::BulkString(json.into_bytes())
            }
            ScrollResponse::Error(msg) => Resp3Frame::SimpleError(format!("ERR {msg}")),
        }
    }

    fn error_response(&self, msg: String) -> Self::Response {
        ScrollResponse::error(msg)
    }

    fn ok_response(&self) -> Self::Response {
        ScrollResponse::ok_status()
    }
}

pub async fn run_tcp<S: Store + 'static>(
    listener: tokio::net::TcpListener,
    engine: Arc<ScrollEngine<S>>,
    token_validator: Option<Arc<dyn TokenValidator>>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
) {
    shroudb_server_tcp::run_tcp_tls(
        listener,
        engine,
        Arc::new(ScrollProtocol::<S>(PhantomData)),
        token_validator,
        shutdown_rx,
        tls_acceptor,
    )
    .await;
}

#[cfg(test)]
mod tests {
    #[test]
    fn tcp_integration_covered_by_server_tests() {}
}
