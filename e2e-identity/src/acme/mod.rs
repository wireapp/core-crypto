mod account;
mod authz;
mod certificate;
mod chall;
mod directory;
mod error;
mod finalize;
mod identifier;
mod identity;
mod jws;
mod order;
pub mod x509_check;

/// Prelude
pub mod prelude {
    pub use account::AcmeAccount;
    pub use authz::AcmeAuthz;
    pub use chall::{AcmeChallError, AcmeChallenge, AcmeChallengeType};
    pub use directory::AcmeDirectory;
    pub use error::{RustyAcmeError, RustyAcmeResult};
    pub use finalize::AcmeFinalize;
    pub use identifier::{AcmeIdentifier, WireIdentifier};
    pub use identity::{WireIdentity, WireIdentityReader, thumbprint::compute_raw_key_thumbprint};
    pub use jws::AcmeJws;
    pub use order::AcmeOrder;

    pub use super::RustyAcme;
    use super::*;
    pub use crate::x509_check as x509;
}

pub struct RustyAcme;
