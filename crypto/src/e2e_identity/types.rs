//! We only expose byte arrays through the FFI so we do all the conversions here

use super::error::{Error, Result};

/// See [RFC 8555 Section 7.1.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct E2eiAcmeDirectory {
    /// For fetching a new nonce used in [crate::prelude::E2eiEnrollment::new_account_request]
    pub new_nonce: String,
    /// URL to call with [crate::prelude::E2eiEnrollment::new_account_request]
    pub new_account: String,
    /// URL to call with [crate::prelude::E2eiEnrollment::new_order_request]
    pub new_order: String,
    /// Not yet used
    pub revoke_cert: String,
}

impl From<wire_e2e_identity::prelude::AcmeDirectory> for E2eiAcmeDirectory {
    fn from(directory: wire_e2e_identity::prelude::AcmeDirectory) -> Self {
        Self {
            new_nonce: directory.new_nonce.to_string(),
            new_account: directory.new_account.to_string(),
            new_order: directory.new_order.to_string(),
            revoke_cert: directory.revoke_cert.to_string(),
        }
    }
}

impl TryFrom<&E2eiAcmeDirectory> for wire_e2e_identity::prelude::AcmeDirectory {
    type Error = Error;

    fn try_from(directory: &E2eiAcmeDirectory) -> Result<Self> {
        Ok(Self {
            new_nonce: directory.new_nonce.parse()?,
            new_account: directory.new_account.parse()?,
            new_order: directory.new_order.parse()?,
            revoke_cert: directory.revoke_cert.parse()?,
        })
    }
}

/// Result of an order creation
/// see [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4)
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct E2eiNewAcmeOrder {
    /// Opaque raw json value
    pub delegate: super::Json,
    /// Authorizations to create with [crate::prelude::E2eiEnrollment::new_authz_request]
    pub authorizations: Vec<String>,
}

impl TryFrom<wire_e2e_identity::prelude::E2eiNewAcmeOrder> for E2eiNewAcmeOrder {
    type Error = Error;

    fn try_from(new_order: wire_e2e_identity::prelude::E2eiNewAcmeOrder) -> Result<Self> {
        Ok(Self {
            authorizations: new_order.authorizations.iter().map(url::Url::to_string).collect(),
            delegate: serde_json::to_vec(&new_order.delegate)?,
        })
    }
}

impl TryFrom<E2eiNewAcmeOrder> for wire_e2e_identity::prelude::E2eiNewAcmeOrder {
    type Error = Error;

    fn try_from(new_order: E2eiNewAcmeOrder) -> Result<Self> {
        let authorizations = new_order
            .authorizations
            .iter()
            .map(|a| a.parse())
            .collect::<Result<Vec<url::Url>, url::ParseError>>()?
            .try_into()
            .map_err(|_| Error::ImplementationError)?;

        Ok(Self {
            authorizations,
            delegate: serde_json::to_value(new_order.delegate)?,
        })
    }
}

/// Result of an authorization creation
/// see [RFC 8555 Section 7.5](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct E2eiNewAcmeAuthz {
    /// DNS entry associated with those challenge
    pub identifier: String,
    /// ACME challenge + ACME key thumbprint
    pub keyauth: Option<String>,
    /// ACME Challenge
    pub challenge: E2eiAcmeChallenge,
}

impl TryFrom<wire_e2e_identity::prelude::E2eiAcmeAuthorization> for E2eiNewAcmeAuthz {
    type Error = Error;

    fn try_from(authz: wire_e2e_identity::prelude::E2eiAcmeAuthorization) -> Result<Self> {
        Ok(match authz {
            wire_e2e_identity::prelude::E2eiAcmeAuthorization::User {
                identifier,
                keyauth,
                challenge,
            } => Self {
                identifier,
                keyauth: Some(keyauth),
                challenge: challenge.try_into()?,
            },
            wire_e2e_identity::prelude::E2eiAcmeAuthorization::Device { identifier, challenge } => Self {
                identifier,
                keyauth: None,
                challenge: challenge.try_into()?,
            },
        })
    }
}

impl TryFrom<&E2eiNewAcmeAuthz> for wire_e2e_identity::prelude::E2eiAcmeAuthorization {
    type Error = Error;

    fn try_from(authz: &E2eiNewAcmeAuthz) -> Result<Self> {
        Ok(match &authz.keyauth {
            None => Self::Device {
                identifier: authz.identifier.clone(),
                challenge: (&authz.challenge).try_into()?,
            },
            Some(keyauth) => Self::User {
                identifier: authz.identifier.clone(),
                keyauth: keyauth.clone(),
                challenge: (&authz.challenge).try_into()?,
            },
        })
    }
}

/// For creating a challenge
/// see [RFC 8555 Section 7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct E2eiAcmeChallenge {
    /// Opaque raw json value
    pub delegate: super::Json,
    /// URL to call for the acme server to complete the challenge
    pub url: String,
    /// Non-standard, Wire specific claim. Indicates the consumer from where it should get the challenge
    /// proof. Either from wire-server "/access-token" endpoint in case of a DPoP challenge, or from
    /// an OAuth token endpoint for an OIDC challenge
    pub target: String,
}

impl TryFrom<wire_e2e_identity::prelude::E2eiAcmeChallenge> for E2eiAcmeChallenge {
    type Error = Error;

    fn try_from(chall: wire_e2e_identity::prelude::E2eiAcmeChallenge) -> Result<Self> {
        Ok(Self {
            delegate: serde_json::to_vec(&chall.delegate)?,
            url: chall.url.to_string(),
            target: chall.target.to_string(),
        })
    }
}

impl TryFrom<&E2eiAcmeChallenge> for wire_e2e_identity::prelude::E2eiAcmeChallenge {
    type Error = Error;

    fn try_from(chall: &E2eiAcmeChallenge) -> Result<Self> {
        Ok(Self {
            delegate: serde_json::from_slice(&chall.delegate[..])?,
            url: chall.url.parse()?,
            target: chall.target.parse()?,
        })
    }
}
