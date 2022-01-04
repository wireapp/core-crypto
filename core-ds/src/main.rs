mod config;
mod error;
use futures_util::StreamExt;
use tracing_futures::Instrument;

pub use self::error::*;

#[tokio::main]
async fn main() -> DsResult<()> {
    tracing_subscriber::fmt::init();

    let addr: std::net::SocketAddr = "127.0.0.1:55696".parse()?;
    let (server_config, _server_cert) = config::configure_server()?;
    let (endpoint, mut incoming) = quinn::Endpoint::server(server_config, addr)?;
    tracing::info!("listening on {}", endpoint.local_addr()?);

    while let Some(conn) = incoming.next().await {
        tracing::trace!("Incoming connection from {}", conn.remote_address());
        let fut = handle_connection(conn);
        tokio::spawn(async move {
            if let Err(e) = fut.await {
                tracing::error!("connection failed: {}", e);
            }
        });
    }

    Ok(())
}

async fn handle_connection(conn: quinn::Connecting) -> DsResult<()> {
    let quinn::NewConnection {
        connection,
        mut bi_streams,
        ..
    } = conn.await?;

    let span = tracing::trace_span!(
        "connection",
        remote = %connection.remote_address(),
        protocol = %connection
            .handshake_data().unwrap()
            .downcast::<quinn::crypto::rustls::HandshakeData>().unwrap()
            .protocol
            .map_or_else(|| "<none>".into(), |x| String::from_utf8_lossy(&x).into_owned())
    );

    async {
        tracing::trace!("established");
        while let Some(stream) = bi_streams.next().await {
            let stream = match stream {
                Ok(s) => s,
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    tracing::trace!("connection closed");
                    return Ok(())
                },
                Err(e) => return Err(e),
            };

            let fut = handle_request(stream);
            tokio::spawn(async move {
                if let Err(e) = fut.await {
                    tracing::error!("failed: {}", e);
                }
            }.instrument(tracing::trace_span!("request")));
        }
        Ok(())
    }
    .instrument(span)
    .await?;

    Ok(())
}

async fn handle_request((mut send, recv): (quinn::SendStream, quinn::RecvStream)) -> DsResult<()> {
    todo!()
}
