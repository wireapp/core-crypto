pub mod device_status;
pub mod id;

use super::error::{E2eIdentityError as Error, E2eIdentityResult as Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Supporting struct for CRL registration result
pub struct CrlRegistration {
    /// Whether this CRL modifies the old CRL (i.e. has a different revoked cert list)
    pub dirty: bool,
    /// Optional expiration timestamp
    pub expiration: Option<u64>,
}
