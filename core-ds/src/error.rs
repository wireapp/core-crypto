#[derive(Debug, thiserror::Error)]
pub enum DsError {
    #[error(transparent)]
    AddrParseError(#[from] std::net::AddrParseError),

    #[error(transparent)]
    DbError(#[from] sea_orm::DbErr),

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error(transparent)]
    ActixError(#[from] actix_web::Error),

    #[error(transparent)]
    HexError(#[from] hex::FromHexError),

    #[error(transparent)]
    RedisError(#[from] redis::RedisError),

    #[error(transparent)]
    UuidError(#[from] uuid::Error),

    #[error(transparent)]
    Other(#[from] color_eyre::Report),
}

impl actix_web::ResponseError for DsError {}

pub type DsResult<T> = Result<T, DsError>;
