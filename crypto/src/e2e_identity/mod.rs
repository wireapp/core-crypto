mod crypto;
pub(crate) mod device_status;
mod error;
pub(crate) mod id;
pub(crate) mod identity;
mod pki_env;
pub(crate) use pki_env::restore_pki_env;
pub use pki_env::{E2eiDumpedPkiEnv, NewCrlDistributionPoints};
#[cfg(not(test))]
mod enrollment;
#[cfg(test)]
pub(crate) mod enrollment;
#[cfg(not(target_family = "wasm"))]
pub(crate) mod refresh_token;
pub mod types;

pub use enrollment::E2eiEnrollment;
pub use error::{Error, Result};

type Json = Vec<u8>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Supporting struct for CRL registration result
pub struct CrlRegistration {
    /// Whether this CRL modifies the old CRL (i.e. has a different revocated cert list)
    pub dirty: bool,
    /// Optional expiration timestamp
    pub expiration: Option<u64>,
}

/// A unique identifier for an enrollment a consumer can use to fetch it from the keystore when he
/// wants to resume the process
pub(crate) type EnrollmentHandle = Vec<u8>;
