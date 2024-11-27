//! MLS errors

pub type Result<T, E = Error> = core::result::Result<T, E>;

/// MLS errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Supplied User Id was not valid")]
    InvalidUserId,
}
