use rusty_jwt_tools::prelude::RustyJwtError;

use crate::pki_env::hooks::PkiEnvironmentHooksError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("a PKI environment hook failed")]
    HookFailed(#[from] PkiEnvironmentHooksError),
    #[error("JSON parsing failed")]
    Json(#[from] serde_json::Error),
    #[error("HTTP response is missing header '{0}'")]
    MissingHeader(&'static str),
    #[error(transparent)]
    Acme(#[from] crate::acme::RustyAcmeError),
    #[error(transparent)]
    RustyJwtError(#[from] RustyJwtError),
}
