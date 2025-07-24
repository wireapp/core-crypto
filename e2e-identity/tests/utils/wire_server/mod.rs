pub mod oidc;
pub mod server_api;

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
                eprintln!("server error: {err}");
            }
        });
    }
}
