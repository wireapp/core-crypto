mod crypto;
pub(crate) mod device_status;
#[cfg(not(test))]
mod enrollment;
#[cfg(test)]
pub(crate) mod enrollment;
mod error;
pub(crate) mod id;
pub(crate) mod identity;
pub mod types;

pub use enrollment::E2eiEnrollment;
pub use error::{Error, Result};

type Json = Vec<u8>;

pub use wire_e2e_identity::pki_env::NewCrlDistributionPoints;

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
