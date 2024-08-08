pub mod oidc;
pub mod server_api;

use crate::utils::ctx::{ctx_get, ctx_store};
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::task::LocalSet;

#[derive(Debug, Clone)]
pub struct OauthCfg {
    pub issuer_uri: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

impl OauthCfg {
    pub fn cxt_store(&self) {
        ctx_store("issuer-uri", self.issuer_uri.clone());
        ctx_store("client-id", self.client_id.clone());
        ctx_store("client-secret", self.client_secret.clone());
        ctx_store("redirect-uri", self.redirect_uri.clone());
    }

    pub fn cxt_get() -> Self {
        let issuer_uri = ctx_get("issuer-uri").unwrap();
        let client_id = ctx_get("client-id").unwrap();
        let client_secret = ctx_get("client-secret").unwrap();
        let redirect_uri = ctx_get("redirect-uri").unwrap();
        Self {
            issuer_uri,
            client_id,
            client_secret,
            redirect_uri,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WireServer {
    pub port: u16,
    pub socket: SocketAddr,
}

impl WireServer {
    pub async fn run() -> WireServer {
        Self::run_on_port(0).await
    }

    pub async fn run_on_port(port: u16) -> WireServer {
        let listener = TcpListener::bind(format!("127.0.0.1:{port}")).await.unwrap();
        let socket = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let server_future = run_server(listener);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            LocalSet::new().block_on(&runtime, server_future)
        });

        Self { port, socket }
    }
}

async fn run_server(listener: TcpListener) {
    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let io = TokioIo::new(stream);
        tokio::spawn(async move {
            let service = hyper::service::service_fn(server_api::wire_api);
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("server error: {}", err);
            }
        });
    }
}
