
#[derive(Debug, thiserror::Error)]
pub enum DsError {
    #[error(transparent)]
    QuicConnectionError(#[from] quinn::ConnectionError),
    #[cfg(feature = "local-selfcert")]
    #[error(transparent)]
    LocalCertError(#[from] rcgen::RcgenError),
    #[error(transparent)]
    RustlsError(#[from] rustls::Error),
    #[error(transparent)]
    AddrParseError(#[from] std::net::AddrParseError),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    Other(#[from] eyre::Report),
}

pub type DsResult<T> = Result<T, DsError>;
