#![allow(dead_code)]

use rusty_jwt_tools::prelude::ClientId;

#[cfg(not(target_family = "wasm"))]
pub mod cfg;
#[cfg(not(target_family = "wasm"))]
pub mod ctx;
#[cfg(not(target_family = "wasm"))]
pub mod display;
#[cfg(not(target_family = "wasm"))]
pub mod docker;
#[cfg(not(target_family = "wasm"))]
pub mod fmk;
#[cfg(not(target_family = "wasm"))]
pub mod helpers;
pub mod id_token;
pub mod keys;
#[cfg(not(target_family = "wasm"))]
pub mod wire_server;

pub(crate) fn rand_str(size: usize) -> String {
    use rand::distributions::{Alphanumeric, DistString};
    Alphanumeric.sample_string(&mut rand::thread_rng(), size)
}

pub fn rand_base64_str(size: usize) -> String {
    use base64::Engine as _;
    base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(rand_str(size))
}

pub fn rand_client_id(device_id: Option<u64>) -> ClientId {
    let device_id = device_id.unwrap_or_else(rand::random::<u64>);
    ClientId::try_from_raw_parts(
        uuid::Uuid::new_v4().as_ref(),
        device_id,
        format!("{}.com", rand_str(6)).as_bytes(),
    )
    .unwrap()
}

pub type TestResult<T> = Result<T, TestError>;

#[derive(Debug, thiserror::Error)]
pub enum TestError {
    #[error(transparent)]
    Acme(#[from] rusty_acme::prelude::RustyAcmeError),
    #[error(transparent)]
    Jwt(#[from] rusty_jwt_tools::prelude::RustyJwtError),
    #[cfg(not(target_family = "wasm"))]
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),
    #[error("wire-server error")]
    WireServerError,
    #[error("account creation error")]
    AccountCreationError,
    #[error("authorization creation error")]
    AuthzCreationError,
    #[error("dpop challenge verification error")]
    DpopChallengeError,
    #[error("oidc challenge verification error")]
    OidcChallengeError,
    #[error("Test is not rightfully implemented")]
    Internal,
}
