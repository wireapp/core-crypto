use hyper::service::{make_service_fn, service_fn};
use std::{
    net::{TcpListener, TcpStream},
    time::Duration,
};
use tokio::task::LocalSet;

pub struct FakeWireServer {
    pub url: String,
    pub http_client: reqwest::Client,
}

impl FakeWireServer {
    pub async fn run() -> FakeWireServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
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
            if TcpStream::connect_timeout(&addr, backoff).is_ok() {
                break;
            }
            tokio::time::sleep(backoff).await;
        }
        let timeout = Duration::from_secs(1);
        let http_client = reqwest::ClientBuilder::new()
            .connect_timeout(timeout)
            .timeout(timeout)
            .connection_verbose(true)
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let url = format!("http://localhost:{}/", addr.port());
        Self { url, http_client }
    }
}

async fn run_server(listener: TcpListener) {
    let service = make_service_fn(|_| async { Ok::<_, std::io::Error>(service_fn(super::server_api::wire_api)) });
    let server = hyper::Server::from_tcp(listener).unwrap();
    server.serve(service).await.unwrap()
}
