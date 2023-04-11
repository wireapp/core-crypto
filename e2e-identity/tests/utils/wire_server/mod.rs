pub mod oidc;
pub mod server_api;

use crate::utils::ctx::{ctx_get, ctx_store};
use hyper::service::{make_service_fn, service_fn};
use std::net::SocketAddr;
use std::{
    net::{TcpListener, TcpStream},
    time::Duration,
};
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
        let listener = TcpListener::bind(format!("127.0.0.1:{port}")).unwrap();
        let socket = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let server_future = run_server(listener);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            LocalSet::new().block_on(&runtime, server_future)
        });

        // wait with backoff for tcp listener to be bound
        let backoff = Duration::from_millis(25);
        for _ in 0..40 {
            if TcpStream::connect_timeout(&socket, backoff).is_ok() {
                break;
            }
            tokio::time::sleep(backoff).await;
        }

        Self { port, socket }
    }
}

async fn run_server(listener: TcpListener) {
    let service = make_service_fn(|_| async { Ok::<_, std::io::Error>(service_fn(server_api::wire_api)) });
    let server = hyper::Server::from_tcp(listener).unwrap();
    server.serve(service).await.unwrap()
}
