use crate::AcmeChallenge;

/// Result of an authorization creation.
///
/// - See <https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5>
/// - See [core_crypto::e2e_identity::types::E2eiNewAcmeAuthz]
#[derive(Debug, uniffi::Record)]
pub struct NewAcmeAuthz {
    /// DNS entry associated with those challenge
    pub identifier: String,
    /// ACME challenge + ACME key thumbprint
    pub keyauth: Option<String>,
    /// Associated ACME Challenge
    pub challenge: AcmeChallenge,
}

impl From<core_crypto::E2eiNewAcmeAuthz> for NewAcmeAuthz {
    fn from(new_authz: core_crypto::E2eiNewAcmeAuthz) -> Self {
        Self {
            identifier: new_authz.identifier,
            keyauth: new_authz.keyauth,
            challenge: new_authz.challenge.into(),
        }
    }
}

impl From<NewAcmeAuthz> for core_crypto::E2eiNewAcmeAuthz {
    fn from(new_authz: NewAcmeAuthz) -> Self {
        Self {
            identifier: new_authz.identifier,
            keyauth: new_authz.keyauth,
            challenge: new_authz.challenge.into(),
        }
    }
}
